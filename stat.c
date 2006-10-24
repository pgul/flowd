#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef DO_MYSQL
#include <mysql.h>
#include <getopt.h>
#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID<32224
#define mysql_field_count mysql_num_fields
#endif
#endif
#include "flowd.h"

extern time_t snap_start;
extern FILE *fsnap;

void add_stat(u_long src, u_long srcip, u_long dstip, int in,
              u_long nexthop, u_long len, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto,
              u_short srcport, u_short dstport, u_long pkts)
{
  u_long local=0, remote=0, flowsrc;
#if NBITS>0
  int src_ua, dst_ua;
  u_short remote_class, src_class, dst_class;
#endif
  u_short local_if, remote_if, remote_as;
  u_short lport, rport;
  struct attrtype *pa;
  struct router_t *pr = NULL;
  sigset_t set, oset;
  u_long src_ip, dst_ip;
#ifdef DO_PERL
  char *p;
  static struct attrtype fakeattr;
  struct linktype *pl;
#endif

  src_ip = ntohl(srcip);
  dst_ip = ntohl(dstip);
  flowsrc = ntohl(src);
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGALRM);
  sigprocmask(SIG_BLOCK, &set, &oset);
#if NBITS>0
  src_class=find_mask(src_ip);
  dst_class=find_mask(dst_ip);
#endif
#ifdef DO_PERL
  p = pl_recv_pkt(&src, &srcip, &dstip, &in, &nexthop, &len, &input, &output,
                  &src_as, &dst_as, &proto, &srcport, &dstport, &pkts
#if NBITS>0
                  , &src_class, &dst_class
#endif
                 );
  src_ip  = ntohl(srcip);
  dst_ip  = ntohl(dstip);
  flowsrc = ntohl(src);
  if (p)
  {
    for (pl=linkhead; pl; pl=pl->next)
      if (strcmp(p, pl->name) == 0)
        break;
    if (pl == NULL)
    { pl = calloc(sizeof(struct linktype), 1);
      pl->next = linkhead;
      strncpy(pl->name, p, sizeof(pl->name)-1);
      linkhead = pl;
    }
    pa = &fakeattr;
    pa->link = pl;
    goto foundattr;
  }
#endif
  for (pr=routers; pr; pr=pr->next)
  {
    if (pr->addr != (u_long)-1 && pr->addr != src)
      continue;
  for (pa=pr->attrhead; pa; pa=pa->next)
  { if (in)
    { local=dst_ip;
      remote=src_ip;
      remote_if=input;
      local_if=output;
      remote_as=src_as;
#if NBITS>0
      remote_class=src_class;
#endif
      lport=ntohs(dstport);
      rport=ntohs(srcport);
    } else
    { local=src_ip;
      remote=dst_ip;
      remote_if=output;
      local_if=input;
      remote_as=dst_as;
#if NBITS>0
      remote_class=dst_class;
#endif
      lport=ntohs(srcport);
      rport=ntohs(dstport);
    }
    if ((((flowsrc & pa->srcmask)==pa->src) == (pa->not==0)) &&
         (pa->ip==(u_long)-1      || (remote & pa->mask)==pa->ip) &&
         (pa->remote==(u_long)-1  || (local  & pa->remotemask)==pa->remote) &&
         (pa->in==-1              || pa->in==(in^pa->reverse)) &&
         (pa->nexthop==(u_long)-1 || (pa->nexthop==nexthop)) &&
         (pa->as==(u_short)-1     || (pa->as==remote_as)) &&
         (pa->iface==(u_short)-1  || (pa->iface==remote_if)) &&
         (pa->liface==(u_short)-1 || (pa->liface==local_if)) &&
#if NBITS>0
         (pa->class==(u_short)-1  || (pa->class==remote_class)) &&
#endif
         (pa->proto==(u_short)-1  || pa->proto==proto) &&
         (pa->port1==(u_short)-1  || (pa->port1<=lport && pa->port2>=lport)) &&
         (pa->lport1==(u_short)-1 || (pa->lport1<=rport && pa->lport2>=rport))
        )
    {
      if (!pa->link && !pa->fallthru)
        break; // ignore
foundattr:
    if (fsnap /*&& !pa->fallthru*/)
    { 
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s"
#if NBITS>0
              ".%s2%s"
#endif
              ".%s) %lu bytes %lu pkts (AS%u->AS%u, nexthop %u.%u.%u.%u, if %u->%u, router %u.%u.%u.%u)%s\n",
        (in ? "<-" : "->"),
        ((char *)&srcip)[0], ((char *)&srcip)[1], ((char *)&srcip)[2], ((char *)&srcip)[3],
        ((char *)&dstip)[0], ((char *)&dstip)[1], ((char *)&dstip)[2], ((char *)&dstip)[3],
        pa->link->name,
#if NBITS>0
        uaname[uaindex[src_class]], uaname[uaindex[dst_class]],
#endif
        ((in^pa->reverse) ? "in" : "out"), len, pkts, src_as, dst_as,
        ((char *)&nexthop)[0], ((char *)&nexthop)[1], ((char *)&nexthop)[2], ((char *)&nexthop)[3],
        input, output,
        *((char *)&src),((char *)&src)[1],((char *)&src)[2],((char *)&src)[3],
        pa->fallthru ? " (fallthru)" : "");
    fflush(fsnap);
    if (snap_start + SNAP_TIME < time(NULL))
    { fclose(fsnap);
      fsnap = NULL;
    }
  }
#if NBITS>0
  src_ua=uaindex[src_class];
  dst_ua=uaindex[dst_class];
#endif
  if ((pa->link->bytes[in^pa->reverse]
#if NBITS>0
			  [src_ua][dst_ua]
#endif
			  +=len)>=0xf0000000lu)
    write_stat();
  if (!pa->fallthru)
    break;
    }
  }
  if (pa)
    break;
  }
  sigprocmask(SIG_SETMASK, &oset, NULL);
}

#ifdef DO_MYSQL
#define create_utable                                                   \
       "CREATE TABLE IF NOT EXISTS %s (                                 \
              user CHAR(20) NOT NULL,                                   \
              user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, \
              UNIQUE (user)                                             \
        )"
#define create_table                                 \
       "CREATE TABLE IF NOT EXISTS %s (              \
              time TIMESTAMP NOT NULL,               \
              user_id INT UNSIGNED NOT NULL,         \
              src ENUM(%s) NOT NULL,                 \
              dst ENUM(%s) NOT NULL,                 \
              direction ENUM('in', 'out') NOT NULL,  \
              bytes INT UNSIGNED NOT NULL,           \
              INDEX (user_id),                       \
              INDEX (time)                           \
        )"
#define create_table_noclasses                       \
       "CREATE TABLE IF NOT EXISTS %s (              \
              time TIMESTAMP NOT NULL,               \
              user_id INT UNSIGNED NOT NULL,         \
              bytes_in INT UNSIGNED NOT NULL,        \
              bytes_out INT UNSIGNED NOT NULL,       \
              INDEX (user_id),                       \
              INDEX (time)                           \
        )"

static void mysql_err(MYSQL *conn, char *message)
{
	error("%s", message);
	if (conn)
		error("Error %u (%s)",
		        mysql_errno(conn), mysql_error(conn));
}

static MYSQL *do_connect(char *host_name, char *user_name, char *password,
           char *db_name, unsigned port_num, char *socket_name, unsigned flags)
{
	MYSQL *conn;

	conn = mysql_init(NULL);
	if (conn==NULL)
	{	mysql_err(NULL, "mysql_init() failed");
		return NULL;
	}
#if defined(MYSQL_VERSION_ID) && MYSQL_VERSION_ID >= 32200
	if (mysql_real_connect(conn, host_name, user_name, password,
	             db_name, port_num, socket_name, flags) == NULL)
	{
		mysql_err(conn, "mysql_real_connect() failed");
		return NULL;
	}
#else
	if (mysql_real_connect(conn, host_name, user_name, password,
	             port_num, socket_name, flags) == NULL)
	{
		mysql_err(conn, "mysql_real_connect() failed");
		return NULL;
	}
	if (db_name)
	{	if (mysql_select_db(conn, dbname))
		{	mysql_err(conn, "mysql_select_db() failed");
			return NULL;
		}
	}
#endif
	return conn;
}

static void do_disconnect(MYSQL *conn)
{
	if (conn) mysql_close(conn);
}

void mysql_start(void)
{
	char *myargv_[] = {"flowd", NULL };
	char **myargv=myargv_;
	int  myargc=1, c, option_index=0;
	const char *groups[] = {"client", "flowd", NULL };
	struct option long_options[] = {
		{"host",     required_argument, NULL, 'h'},
		{"user",     required_argument, NULL, 'u'},
		{"password", required_argument, NULL, 'p'},
		{"port",     required_argument, NULL, 'P'},
		{"socket",   required_argument, NULL, 'S'},
		{"table",    required_argument, NULL, 'T'},
		{"utable",   required_argument, NULL, 'U'},
		{"db",       required_argument, NULL, 'D'},
		{0, 0, 0, 0 }
	};

	my_init();
	load_defaults("my", groups, &myargc, &myargv);
	optind = 1;
	while ((c = getopt_long(myargc, myargv, "h:p::u:P:S:T:U:D:", long_options, &option_index)) != EOF)
	{	switch (c)
		{
			case 'h':
				strncpy(mysql_host, optarg, sizeof(mysql_host));
				break;
			case 'u':
				strncpy(mysql_user, optarg, sizeof(mysql_user));
				break;
			case 'p':
				strncpy(mysql_pwd, optarg, sizeof(mysql_pwd));
				break;
			case 'P':
				mysql_port = (unsigned)atoi(optarg);
				break;
			case 'S':
				strncpy(mysql_socket, optarg, sizeof(mysql_socket));
				break;
			case 'T':
				strncpy(mysql_table, optarg, sizeof(mysql_table));
				break;
			case 'U':
				strncpy(mysql_utable, optarg, sizeof(mysql_utable));
				break;
			case 'D':
				strncpy(mysql_db, optarg, sizeof(mysql_db));
				break;
		}
	}
}
#endif

void write_stat(void)
{
  struct linktype *pl;
  FILE *fout;
#if NBITS>0
  int i, j, k;
#endif
#ifdef DO_MYSQL
  MYSQL *conn = NULL;
  char table[256], query[1024], stamp[15];
#if NBITS>0
#if NCLASSES>=256
  static
#endif
  char enums[(sizeof(uaname[0])+4)*NCLASSES];
  char *p;
#endif
  int  mysql_connected=0, table_created=0, utable_created=0;
  struct tm *tm_now;
#endif

  last_write=time(NULL);
  fout = fopen(logname, "a");
  if (fout==NULL) return;
  plstart();
#ifdef DO_MYSQL
  tm_now=localtime(&last_write);
  strftime( table, sizeof( table), mysql_table,   tm_now);
  strftime(stamp,  sizeof(stamp), "%Y%m%d%H%M%S", tm_now);
#if NBITS>0
  p=enums;
#if NCLASSES==65536
  for (i=0; i<65535; i++)
#else
  for (i=0; i<NCLASSES; i++)
#endif
  {
    if (strncmp(uaname[i], "class", 5) == 0)
      continue;
    if (uaname[i][0] == '\0')
      continue;
    if (p>enums)
    { strcpy(p, ", ");
      p+=2;
    }
    *p++='\'';
    strcpy(p, uaname[i]);
    p+=strlen(p);
    *p++='\'';
  }
  *p='\0';
#endif
#endif
  fprintf(fout, "----- %s", ctime(&last_write));
  for (pl=linkhead; pl; pl=pl->next)
  { 
#if NBITS>0
    for (i=0; i<2; i++)
      for (j=0; j<NCLASSES; j++)
        for (k=0; k<NCLASSES; k++)
          if (pl->bytes[i][j][k])
          { 
            plwrite(pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                    pl->bytes[i][j][k]);
#else
    if (pl->bytes[0] || pl->bytes[1])
    {
           plwrite(pl->name, pl->bytes[0], pl->bytes[1]);
#endif
#ifdef DO_MYSQL
            if (!mysql_connected)
            {
              conn = do_connect(
                  mysql_host[0] ? mysql_host : NULL,
                  mysql_user[0] ? mysql_user : NULL,
                  mysql_pwd[0] ? mysql_pwd : NULL,
                  mysql_db[0] ? mysql_db : NULL,
                  mysql_port,
                  mysql_socket[0] ? mysql_socket : NULL,
                  0);
              mysql_connected=1;
            }
            if (conn && !utable_created)
            {
              snprintf(query, sizeof(query)-1, create_utable, mysql_utable);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              utable_created=1;
            }
            if (conn && !table_created)
            {
#if NBITS>0
              snprintf(query, sizeof(query), create_table, table, enums, enums);
#else
              snprintf(query, sizeof(query), create_table_noclasses, table);
#endif
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              table_created=1;
            }
            if (conn && !pl->user_id)
            { char *p;
              MYSQL_RES *res_set;
              MYSQL_ROW row;

              strcpy(query, "SELECT user_id FROM ");
              strcat(query, mysql_utable);
              strcat(query, " WHERE user = '");
              p=query+strlen(query);
              p+=mysql_escape_string(p, pl->name, strlen(pl->name));
              strcpy(p, "'");
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
              else
              {
                res_set = mysql_store_result(conn);
                if (res_set == NULL)
                { mysql_err(conn, "mysql_store_result() failed");
                  do_disconnect(conn);
                  conn=NULL;
                }
                else
                {
                  if ((row = mysql_fetch_row(res_set)) != NULL)
                    pl->user_id = atoi(row[0]);
                  mysql_free_result(res_set);
                }
              }
              if (conn && !pl->user_id)
              { /* new user, add to table */
                strcpy(query, "INSERT ");
                strcat(query, mysql_utable);
                strcat(query, " SET user='");
                p=query+strlen(query);
                p+=mysql_escape_string(p, pl->name, strlen(pl->name));
                strcpy(p, "'");
                if (mysql_query(conn, query) != 0)
                { mysql_err(conn, "mysql_query() failed");
                  do_disconnect(conn);
                  conn=NULL;
                }
                else
                { if (mysql_query(conn, "SELECT LAST_INSERT_ID()") != 0)
                  { mysql_err(conn, "mysql_query() failed");
                    do_disconnect(conn);
                    conn=NULL;
                  }
                  else
                  {
                    res_set = mysql_store_result(conn);
                    if (res_set == NULL)
                    { mysql_err(conn, "mysql_store_result() failed");
                      do_disconnect(conn);
                      conn=NULL;
                    }
                    else
                    {
                      if ((row = mysql_fetch_row(res_set)) != NULL)
                        pl->user_id = atoi(row[0]);
                      mysql_free_result(res_set);
                    }
                  }
                }
              }
              if (conn && !pl->user_id)
              { error("internal error working with MySQL server");
                do_disconnect(conn);
                conn=NULL;
              }
            }
            if (conn)
            { sprintf(query,
                 "INSERT %s VALUES('%s', '%lu', "
#if NBITS>0
		 "'%s', '%s', '%s', "
#else
		 "'%lu', "
#endif
		 "'%lu')",
                 table, stamp, pl->user_id,
#if NBITS>0
		 uaname[j], uaname[k],
                 (i ? "in" : "out"), pl->bytes[i][j][k]
#else
		 pl->bytes[0], pl->bytes[1]
#endif
		);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
            }
#endif
            fprintf(fout, "%s"
#if NBITS>0
                    ".%s2%s.%s: %lu bytes"
#else
		    " %lu in, %lu out"
#endif
		    "\n",
                    pl->name,
#if NBITS>0
		    uaname[j], uaname[k], (i ? "in" : "out"), pl->bytes[i][j][k]
#else
		    pl->bytes[0], pl->bytes[1]
#endif
		   );
#if NBITS>0
            pl->bytes[i][j][k]=0;
#else
            pl->bytes[0] = pl->bytes[1] = 0;
#endif
          }
  }
  fputs("\n", fout);
  fclose(fout);
  plstop();
#ifdef DO_MYSQL
  if (conn) do_disconnect(conn);
#endif
}
