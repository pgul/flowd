#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef DO_PERL
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif
#endif
#ifdef DO_MYSQL
#include <mysql.h>
#include <getopt.h>
#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID<32224
#define mysql_field_count mysql_num_fields
#endif
#endif
#include "flowd.h"

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

extern long snap_traf;
extern FILE *fsnap;

void add_stat(u_long flowsrc, u_long srcip, u_long dstip, int in,
              u_long nexthop, u_long len, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto)
{
  u_long local=0, remote=0;
  int src_ua, dst_ua;
  u_short remote_if, remote_as, remote_class, src_class, dst_class;
  struct attrtype *pa;
  sigset_t set, oset;
  u_long src_ip, dst_ip;

  src_ip = ntohl(srcip);
  dst_ip = ntohl(dstip);
  flowsrc = ntohl(flowsrc);
  src_class=find_mask(src_ip);
  dst_class=find_mask(dst_ip);
  sigemptyset(&set);
  sigaddset(&set, SIGINFO);
  sigprocmask(SIG_BLOCK, &set, &oset);
  for (pa=attrhead; pa; pa=pa->next)
  { if (in^pa->reverse)
    { local=dst_ip;
      remote=src_ip;
      remote_if=input;
      remote_as=src_as;
      remote_class=src_class;
    } else
    { local=src_ip;
      remote=dst_ip;
      remote_if=output;
      remote_as=dst_as;
      remote_class=dst_class;
    }
    if ((((flowsrc & pa->srcmask)==pa->src) == (pa->not==0)) &&
         (pa->ip==(u_long)-1      || (remote & pa->mask)==pa->ip) &&
         (pa->nexthop==(u_long)-1 || (pa->nexthop==nexthop)) &&
         (pa->as==(u_short)-1     || (pa->as==remote_as)) &&
         (pa->iface==(u_short)-1  || (pa->iface==remote_if)) &&
         (pa->class==(u_short)-1  || (pa->class==remote_class)) &&
         (pa->proto==(u_short)-1  || pa->proto==proto))
    {
      if (!pa->link && !pa->fallthru)
        break; // ignore
  if (fsnap && !pa->fallthru)
  { 
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes (AS%u->AS%u, nexthop %u.%u.%u.%u, if %u->%u, router %u.%u.%u.%u)\n",
        ((in^pa->reverse) ? "<-" : "->"),
        ((char *)&srcip)[0], ((char *)&srcip)[1], ((char *)&srcip)[2], ((char *)&srcip)[3],
        ((char *)&dstip)[0], ((char *)&dstip)[1], ((char *)&dstip)[2], ((char *)&dstip)[3],
        pa->link->name, uaname[uaindex[src_class]], uaname[uaindex[dst_class]],
        ((in^pa->reverse) ? "in" : "out"), len, src_as, dst_as,
        ((char *)&nexthop)[0], ((char *)&nexthop)[1], ((char *)&nexthop)[2], ((char *)&nexthop)[3],
        input, output,
        ((char *)&flowsrc)[0], ((char *)&flowsrc)[1], ((char *)&flowsrc)[2], ((char *)&flowsrc)[3]);
    fflush(fsnap);
    if ((snap_traf-=len) <= 0)
    { fclose(fsnap);
      fsnap = NULL;
      snap_traf=0;
    }
  }
  src_ua=uaindex[src_class];
  dst_ua=uaindex[dst_class];
  if ((pa->link->bytes[in^pa->reverse][src_ua][dst_ua]+=len)>=0xf0000000lu)
    write_stat();
  if (!pa->fallthru)
    break;
    }
  }
  sigprocmask(SIG_SETMASK, &oset, NULL);
}

#ifdef DO_PERL
static PerlInterpreter *perl = NULL;

void boot_DynaLoader(CV *cv);

static void xs_init(void)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
} 

void exitperl(void)
{ 
  if (perl)
  { 
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

int PerlStart(void)
{
  int rc;
  char *perlargs[]={"", "", NULL};

  perlargs[1] = perlfile;
  if (access(perlfile, R_OK))
  { printf("Can't read %s: %s", perlfile, strerror(errno));
    return 1;
  }
  perl = perl_alloc();
  perl_construct(perl);
  rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
  if (rc)
  { printf("Can't parse %s", perlfile);
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
    return 1;
  }
  atexit(exitperl);
  return 0;
}

static void plstart(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstart, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

static void plstop(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstop, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

static void plwrite(char *user, char *src, char *dst, char *direct, int bytes)
{
  SV *svuser, *svsrc, *svdst, *svdirect, *svbytes;
  STRLEN n_a;

  dSP;
  svuser   = perl_get_sv("user",      TRUE);
  svsrc    = perl_get_sv("src",       TRUE);
  svdst    = perl_get_sv("dst",       TRUE);
  svdirect = perl_get_sv("direction", TRUE);
  svbytes  = perl_get_sv("bytes",     TRUE);
  sv_setpv(svuser,   user  );
  sv_setpv(svsrc,    src   );
  sv_setpv(svdst,    dst   );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwrite, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}
#endif

#ifdef DO_MYSQL
#define create_utable \
       "CREATE TABLE IF NOT EXISTS %s (
              user CHAR(20) NOT NULL,
              user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
              UNIQUE (user)
        )"
#define create_table \
       "CREATE TABLE IF NOT EXISTS %s (
              time TIMESTAMP NOT NULL,
              user_id INT UNSIGNED NOT NULL,
              src ENUM(%s) NOT NULL,
              dst ENUM(%s) NOT NULL,
              direction ENUM('in', 'out') NOT NULL,
              bytes INT UNSIGNED NOT NULL,
              INDEX (user_id),
              INDEX (time)
        )"
static void mysql_err(MYSQL *conn, char *message)
{
	fprintf(stderr, "%s\n", message);
	if (conn)
		fprintf(stderr, "Error %u (%s)\n",
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
  int i, j, k;
  struct linktype *pl;
  FILE *fout;
#ifdef DO_MYSQL
  MYSQL *conn = NULL;
  char table[256], query[1024], stamp[15];
#if NCLASSES>=256
  static
#endif
  char enums[(sizeof(uaname[0])+4)*NCLASSES];
  int  mysql_connected=0, table_created=0, utable_created=0;
  struct tm *tm_now;
  char *p;
#endif

  last_write=time(NULL);
  fout = fopen(logname, "a");
  if (fout==NULL) return;
#ifdef DO_PERL
  plstart();
#endif
#ifdef DO_MYSQL
  tm_now=localtime(&last_write);
  strftime( table, sizeof( table), mysql_table,   tm_now);
  strftime(stamp,  sizeof(stamp), "%Y%m%d%H%M%S", tm_now);
  p=enums;
#if NCLASSES==65536
  for (i=0; i<65535; i++)
#else
  for (i=0; i<NCLASSES; i++)
#endif
  { if (strncmp(uaname[i], "class", 5) == 0)
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
  fprintf(fout, "----- %s", ctime(&last_write));
  for (pl=linkhead; pl; pl=pl->next)
  { for (i=0; i<2; i++)
      for (j=0; j<NCLASSES; j++)
        for (k=0; k<NCLASSES; k++)
          if (pl->bytes[i][j][k])
          { 
#ifdef DO_PERL
            plwrite(pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                    pl->bytes[i][j][k]);
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
              snprintf(query, sizeof(query)-1, create_table, table, enums, enums);
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
              { fprintf(stderr, "internal error working with MySQL server\n");
                do_disconnect(conn);
                conn=NULL;
              }
            }
            if (conn)
            { sprintf(query,
                 "INSERT %s VALUES('%s', '%lu', '%s', '%s', '%s', '%lu')",
                 table, stamp, pl->user_id, uaname[j], uaname[k],
                 (i ? "in" : "out"), pl->bytes[i][j][k]);
              if (mysql_query(conn, query) != 0)
              { mysql_err(conn, "mysql_query() failed");
                do_disconnect(conn);
                conn=NULL;
              }
            }
#endif
            fprintf(fout, "%s.%s2%s.%s: %lu bytes\n",
                    pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                    pl->bytes[i][j][k]);
            pl->bytes[i][j][k]=0;
          }
  }
  fputs("\n", fout);
  fclose(fout);
#ifdef DO_PERL
  plstop();
#endif
#ifdef DO_MYSQL
  if (conn) do_disconnect(conn);
#endif
}
