#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "flowd.h"

struct linktype *linkhead=NULL;
char logname[256]=LOGNAME, snapfile[256]=SNAPFILE, aclname[256]=ACLNAME;
char pidfile[256]=PIDFILE;
int  write_interval=WRITE_INTERVAL;
u_long bindaddr=INADDR_ANY;
unsigned short port=PORT;
#if NBITS>0
int  reload_interval=RELOAD_INTERVAL;
long mapkey;
int  fromshmem, fromacl;
char uaname[NCLASSES][32];
int  uaindex[NCLASSES];
#endif
#ifdef DO_MYSQL
char mysql_user[256], mysql_pwd[256], mysql_host[256];
char mysql_socket[256], mysql_db[256];
char mysql_table[256], mysql_utable[256];
unsigned mysql_port;
#endif
struct router_t *routers;
static struct router_t *cur_router, *old_routers;

#ifdef DO_SNMP
static unsigned short get_ifindex(struct router_t*, enum ifoid_t, char **s);
#endif

void debug(int level, char *format, ...)
{
  va_list arg;
  va_start(arg, format);
  if (level<=verbose)
  { vfprintf(stderr, format, arg);
    fputs("\n", stderr);
    fflush(stderr);
  }
  va_end(arg);
}

static void freerouter(struct router_t *router)
{
  struct attrtype *pa;
#ifdef DO_SNMP
  int i;
  for (i=0; i<NUM_OIDS; i++)
    if (router->data[i])
    { free(router->data[i]);
      router->data[i] = NULL;
      router->nifaces[i] = 0;
    }
#endif
  for (pa=router->attrhead; pa;)
  {
    router->attrhead = pa;
    pa = pa->next;
    free(router->attrhead);
  }
}

static void read_ip(char *p, u_long *ip, u_long *mask)
{
  char c, *p1;
  long addr;

  for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
  c=*p1;
  *p1='\0';
  if ((addr=inet_addr(p)) == -1) {
    error("Error: %s is not correct IP-address!", p);
    exit(2);
  }
  *ip = ntohl(addr);
  if (c=='/')
    *mask<<=(32-atoi(p1+1));
  *p1=c;
  if ((*ip & *mask) != *ip)
  { unsigned long masked = (*ip & *mask);
    warning("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!",
           ((char *)ip)[3], ((char *)ip)[2],
           ((char *)ip)[1], ((char *)ip)[0],
           atoi(p1+1),
           ((char *)mask)[3], ((char *)mask)[2],
           ((char *)mask)[1], ((char *)mask)[0]);
    warning("ip & mask is %u.%u.%u.%u",
           ((char *)&masked)[3], ((char *)&masked)[2],
           ((char *)&masked)[1], ((char *)&masked)[0]);
  }
}

static void read_port(char *p, u_short *port, u_short proto)
{
  if (isdigit(*p))
    *port=atoi(p);
  else
  { struct servent *se;
    struct protoent *pe;
    char *sproto=NULL;
    if (proto!=(u_short)-1)
      if ((pe=getprotobynumber(proto)) != NULL)
        sproto=pe->p_name;
    if ((se=getservbyname(p, sproto)) == NULL)
      warning("Unknown port %s", p);
    else
      *port=ntohs(se->s_port);
  }
}

static void read_ports(char *p, u_short *pl, u_short *pg, u_short proto)
{
  char c, *p1;

  for (p1=p; *p1 && !isspace(*p1) && *p1!=':'; p1++);
  c=*p1;
  *p1='\0';
  read_port(p, pl, proto);
  *p1=c;
  if (c!=':' || *pl==(u_short)-1)
  { *pg=*pl;
    return;
  }
  p=p1+1;
  for (p1=p; *p1 && !isspace(*p1); p1++);
  c=*p1;
  *p1='\0';
  read_port(p, pg, proto);
  *p1=c;
  if (*pg==(u_short)-1)
    *pg=*pl;
}

static void read_proto(char *p, u_short *proto)
{
  if (isdigit(*p))
    *proto=atoi(p);
  else
  {
    struct protoent *pe;
    char c, *p1;
    for (p1=p; *p1 && !isspace(*p1); p1++);
    c=*p1;
    *p1='\0';
    pe=getprotobyname(p);
    if (pe==NULL)
      warning("Unknown protocol %s", p);
    else
      *proto=pe->p_proto;
    *p1=c;
  }
}

static int parse_line(char *str)
{
  char *p;
  struct hostent *he;
  struct linktype *pl;
  struct attrtype *pa;

  p=strchr(str, '\n');
  if (p) *p='\0';
  p=strchr(str, '#');
  if (p) *p='\0';
  for (p=str; isspace(*p); p++);
  if (*p=='\0') return 0;
  if (p!=str) strcpy(str, p);
  if (str[0]=='\0') return 0;
  for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
  // for (p=str; *p; p++) *p=tolower(*p);
  if (preproc)
    printf("%s\n", str);
  p=str;
  if (strncasecmp(p, "log=", 4)==0)
  { strncpy(logname, p+4, sizeof(logname)-1);
    return 0;
  }
  if (strncasecmp(p, "snap=", 5)==0)
  { strncpy(snapfile, p+5, sizeof(snapfile)-1);
    return 0;
  }
  if (strncasecmp(p, "pid=", 4)==0)
  { strncpy(pidfile, p+4, sizeof(pidfile)-1);
    return 0;
  }
  if (strncasecmp(p, "write-int=", 10)==0)
  { write_interval = atoi(p+10);
    if (write_interval == 0) write_interval=WRITE_INTERVAL;
    return 0;
  }
  if (strncasecmp(p, "bindaddr=", 9)==0)
  { bindaddr=inet_addr(p+9);
    return 0;
  }
  if (strncasecmp(p, "port=", 5)==0)
  { port=atoi(p+5);
    return 0;
  }
#if NBITS>0
  if (strncasecmp(p, "reload-int=", 11)==0)
  { reload_interval = atoi(p+11);
    if (reload_interval == 0) reload_interval=RELOAD_INTERVAL;
    return 0;
  }
  if (strncasecmp(p, "acl=", 4)==0)
  { strncpy(aclname, p+4, sizeof(aclname)-1);
    fromacl=1;
    return 0;
  }
  if (strncasecmp(p, "mapkey=", 7)==0)
  { mapkey = atol(p+7);
    if (mapkey == 0) mapkey=MAPKEY;
    fromshmem=1;
    return 0;
  }
  if (strncasecmp(p, "fromshmem=", 10)==0)
  { if (p[10]=='n' || p[10]=='N' || p[10]=='0' || p[10]=='f' || p[10]=='F')
      fromshmem=0;
    else
      fromshmem=1;
    return 0;
  }
  if (strncasecmp(p, "classes=", 8)==0)
  {
    int i, j;
    char *p1;

    p+=8;
    i=0;
    while (p && *p)
    {
      if (i==NCLASSES)
      { warning("Too many classes!");
        break;
      }
      for (p1=p; *p1 && !isspace(*p1) && *p1!=','; p1++);
      if (*p1) *p1++='\0';
      for (j=0; j<i; j++)
        if (strcmp(p, uaname[j]) == 0)
          break;
      uaindex[i]=j;
      if (j<i)
        uaname[i][0]='\0';
      else
        strncpy(uaname[i], p, sizeof(uaname[i])-1);
      for (p=p1; *p && (isspace(*p) || *p==','); p++);
      i++;
    }
    return 0;
  }
#endif
#ifdef DO_PERL
  if (strncasecmp(p, "perlwrite=", 10)==0)
  { char *p1 = p+10;
    p=strstr(p1, "::");
    if (p==NULL)
    { warning("Incorrect perlwrite=%s ignored!", p1);
      return 0;
    }
    *p=0;
    strncpy(perlfile, p1, sizeof(perlfile));
    strncpy(perlwrite, p+2, sizeof(perlwrite));
    return 0;
  }
#endif
#ifdef DO_MYSQL
  if (strncasecmp(p, "mysql_user=", 11)==0)
  { strncpy(mysql_user, p+11, sizeof(mysql_user)-1);
    return 0;
  }
  if (strncasecmp(p, "mysql_host=", 11)==0)
  { strncpy(mysql_host, p+11, sizeof(mysql_host)-1);
    p=strchr(mysql_host, ':');
    if (p)
    { mysql_port=atoi(p+1);
      *p=0;
    }
    return 0;
  }
  if (strncasecmp(p, "mysql_pwd=", 10)==0)
  { strncpy(mysql_pwd, p+10, sizeof(mysql_pwd)-1);
    return 0;
  }
  if (strncasecmp(p, "mysql_db=", 9)==0)
  { strncpy(mysql_db, p+9, sizeof(mysql_db)-1);
    return 0;
  }
  if (strncasecmp(p, "mysql_socket=", 13)==0)
  { strncpy(mysql_socket, p+13, sizeof(mysql_socket)-1);
    return 0;
  }
  if (strncasecmp(p, "mysql_table=", 12)==0)
  { strncpy(mysql_table, p+12, sizeof(mysql_table)-1);
    return 0;
  }
  if (strncasecmp(p, "mysql_utable=", 13)==0)
  { strncpy(mysql_utable, p+13, sizeof(mysql_utable)-1);
    return 0;
  }
#endif
  if (strncasecmp(p, "router=", 7)==0)
  {
    cur_router->next = calloc(1, sizeof(struct router_t));
    cur_router = cur_router->next;
    p+=7;
#ifdef DO_SNMP
    { char *p1;
      if ((p1=strchr(p, '@'))!=NULL)
      { *p1++='\0';
        strncpy(cur_router->community, p, sizeof(cur_router->community)-1);
        p=p1;
      } else
        strcpy(cur_router->community, "public");
    }
#endif
    /* get router address */
    if ((he=gethostbyname(p))==0 || he->h_addr_list[0]==NULL)
    { if (strcmp(p, "any")==0)
        cur_router->addr=(u_long)-1;
      else
        warning("Warning: Router %s not found", p);
      return 0;
    }
    /* use only first address */
    memcpy(&cur_router->addr, he->h_addr_list[0], he->h_length);
    return 0;
  }
  for (p=str; *p && !isspace(*p); p++);
  if (*p) *p++='\0';
  if (strchr(str, '=')) return 0; /* keyword */
  /* find link name */
  for (pl=linkhead; pl; pl=pl->next)
  { if (strcmp(pl->name, str)==0)
      break;
  }
  if (!pl && strcasecmp(str, "ignore"))
  { pl=calloc(1, sizeof(*pl));
    pl->next=linkhead;
    strcpy(pl->name, str);
    linkhead=pl;
  }
  /* create attribute structure */
  pa = calloc(1, sizeof(*pa));
  memset(pa, 0xff, sizeof(*pa));
  pa->link = pl;
  pa->next = NULL;
  pa->reverse=pa->fallthru=0;
  if (cur_router->addr!=(u_long)-1)
    pa->src=ntohl(cur_router->addr);	/* mask /32 */
  else
    pa->src=pa->srcmask=0;		/* match any */
  pa->not=0;
  if (cur_router->attrhead==NULL)
    cur_router->attrhead = pa;
  else
    cur_router->attrtail->next = pa;
  cur_router->attrtail = pa;
  /* fill attribute structure */
  while (*p)
  { while (*p && isspace(*p)) p++;
    if (!*p) break;
    if (strncasecmp(p, "reverse", 7)==0)
    { pa->reverse=1;
    }
    else if (strncasecmp(p, "fallthru", 8)==0)
      pa->fallthru=1;
    else if (strncasecmp(p, "in", 2)==0)
      pa->in=1;
    else if (strncasecmp(p, "out", 3)==0)
      pa->in=0;
    else if (strncasecmp(p, "proto=", 6)==0)
      read_proto(p+6, &pa->proto);
    else if (strncmp(p, "as=", 3)==0)
      pa->as=atoi(p+3);
    else if (strncasecmp(p, "ifindex=", 8)==0)
      pa->iface=atoi(p+8);
    else if (strncasecmp(p, "lifindex=", 8)==0)
      pa->liface=atoi(p+9);
    else if (strncasecmp(p, "class=", 6)==0)
      pa->class=atoi(p+6);
    else if (strncasecmp(p, "nexthop=", 8)==0)
      pa->nexthop=inet_addr(p+8);
    else if (strncasecmp(p, "ip=", 3)==0)
      read_ip(p+3, &pa->ip, &pa->mask);
    else if (strncasecmp(p, "remote=", 7)==0)
      read_ip(p+7, &pa->remote, &pa->remotemask);
    else if (strncasecmp(p, "port=", 5)==0)
      read_ports(p+5, &pa->port1, &pa->port2, pa->proto);
    else if (strncasecmp(p, "localport=", 10)==0)
      read_ports(p+10, &pa->lport1, &pa->lport2, pa->proto);
    else if (strncasecmp(p, "src=", 4)==0)
    {
      if (pa->srcmask == (u_long)-1)
        warning("src has no effect inside router section");
      else {
        p+=4;
        if (*p == '!')
        { p++;
          pa->not=1;
        }
        read_ip(p, &pa->src, &pa->srcmask);
      }
    }
#ifdef DO_SNMP
    else if (strncasecmp(p, "ifname=", 7)==0)
      pa->iface=get_ifindex(cur_router, IFNAME, &p);
    else if (strncasecmp(p, "ifdescr=", 8)==0)
      pa->iface=get_ifindex(cur_router, IFDESCR, &p);
    else if (strncasecmp(p, "ifalias=", 8)==0)
      pa->iface=get_ifindex(cur_router, IFALIAS, &p);
    else if (strncasecmp(p, "ifip=", 5)==0)
      pa->iface=get_ifindex(cur_router, IFIP, &p);
    else if (strncasecmp(p, "lifname=", 8)==0)
      pa->liface=get_ifindex(cur_router, IFNAME, &p);
    else if (strncasecmp(p, "lifdescr=", 9)==0)
      pa->liface=get_ifindex(cur_router, IFDESCR, &p);
    else if (strncasecmp(p, "lifalias=", 9)==0)
      pa->liface=get_ifindex(cur_router, IFALIAS, &p);
    else if (strncasecmp(p, "lifip=", 6)==0)
      pa->liface=get_ifindex(cur_router, IFIP, &p);
#endif
    while (*p && !isspace(*p)) p++;
  }
  return 0;
}

static int parse_file(FILE *f)
{
  FILE *finc;
  char str[256];
  char *p, *p1;

  while (fgets(str, sizeof(str), f))
  {
    if (strncasecmp(str, "@include", 8) == 0 && isspace(str[8]))
    {
      for (p=str+9; *p && isspace(*p); p++);
      if (*p=='\"')
      {
        p++;
        p1=strchr(p, '\"');
        if (p1==NULL)
        {
          warning("Unmatched quotes in include, ignored: %s", str);
          continue;
        }
        *p1='\0';
      } else
      { for (p1=p; *p1 && !isspace(*p1); p1++);
        *p1='\0';
      }
      if ((finc=fopen(p, "r")) == NULL)
      {
        warning("Can't open %s: %s, include ignored", p, strerror(errno));
        continue;
      }
      parse_file(finc);
      fclose(finc);
      continue;
    }
#ifdef DO_PERL
    if (strncasecmp(str, "@perl_include", 13) == 0 && isspace(str[13]))
    {
      char perlincfile[256], perlincfunc[256], *perlincargs[64], c;
      int i, h[2], pid;

      for (p=str+14; *p && isspace(*p); p++);
      p1=strstr(p, "::");
      if (p1==NULL)
      { warning("Incorrect perl_include ignored: %s", str);
        continue;
      }
      *p1='\0';
      strncpy(perlincfile, p, sizeof(perlincfile)-1);
      *p1=':';
      if (access(perlincfile, R_OK))
      {
        warning("Perl include file %s not found, ignored", perlincfile);
        continue;
      }
      p1+=2;
      p=strchr(p1, '(');
      if (p) *p++='\0';
      strncpy(perlincfunc, p1, sizeof(perlincfunc)-1);
      perlincargs[i=0]=NULL;
      debug(3, "perlinclude %s:%s(%s", perlincfile, perlincfunc, p ? p : ")");
      while (p && *p && isspace(*p)) p++;
      if (p && *p && *p!=')')
        while (p && *p)
        {
          if (*p=='\"')
          {
            p1=strchr(p+1, '\"');
            if (p1==NULL)
            {
              warning("Unmatched quotes in perl_include, params ignored");
              break;
            }
            *p1='\0';
            perlincargs[i++]=strdup(p+1);
            p=p1+1;
            while (*p && isspace(*p)) p++;
          } else
          {
            p1=strpbrk(p, " ,)");
            if (p1==NULL)
            {
              warning("Unmatched brackets in perl_include, params ignored");
              break;
            }
            while (*p1 && isspace(*p1)) *p1++='\0';
            c=*p1;
            *p1='\0';
            perlincargs[i++]=strdup(p);
            *p1=c;
            p=p1;
          }
          if (*p=='\0')
          {
            warning("Unmatched brackets in perl_include, params ignored");
            break;
          }
          if (*p==')') break;
          if (*p==',')
            for (p++; *p && isspace(*p); p++);
          if (i==sizeof(perlincargs)/sizeof(perlincargs[0])-1)
          { warning("Too many args in perl_include, rest ignored");
            break;
          }
        }
      perlincargs[i]=NULL;
      if (pipe(h))
      { warning("Can't create pipe: %s", strerror(errno));
        for (i=0; perlincargs[i]; i++)
        {
          free(perlincargs[i]);
          perlincargs[i]=NULL;
        }
        continue;
      }
      if (PerlStart(perlincfile)) /* is it better then do it on child? */
      {
        for (i=0; perlincargs[i]; i++)
        {
          free(perlincargs[i]);
          perlincargs[i]=NULL;
        }
        continue;
      }
      fflush(stdout);
      fflush(stderr);
      pid=fork();
      if (pid<0)
      { warning("Can't fork: %s!", strerror(errno));
        close(h[0]);
        close(h[1]);
        for (i=0; perlincargs[i]; i++)
        {
          free(perlincargs[i]);
          perlincargs[i]=NULL;
          continue;
        }
      }
      else if (pid==0)
      {
        close(h[0]);
        dup2(h[1], fileno(stdout));
        close(h[1]);
        perl_call(perlincfunc, perlincargs);
        debug(3, "perl_include(%s:%s) ok", perlincfile, perlincfunc);
        exit(0);
      }
      for (i=0; perlincargs[i]; i++)
      {
        free(perlincargs[i]);
        perlincargs[i]=NULL;
        continue;
      }
      close(h[1]);
      finc=fdopen(h[0], "r");
      parse_file(finc);
      waitpid(pid, NULL, 0);
      fclose(finc);
      continue;
    }
#endif
    parse_line(str);
  } 
  return 0;
}

int config(char *name)
{
  FILE *f;
  struct linktype *pl;

#if NBITS>0
  if (fromshmem) freeshmem();
  fromshmem=0;
  mapkey=MAPKEY;
#endif
#ifdef DO_PERL
  strcpy(perlfile,     "flowd.pl"  );
  strcpy(perlstart,    "startwrite");
  strcpy(perlwrite,    "writestat" );
  strcpy(perlstop,     "stopwrite" );
  strcpy(perlrcv,      "recv_pkt"  );
#endif
#ifdef DO_MYSQL
  mysql_user[0] = mysql_pwd[0] = mysql_host[0] = mysql_socket[0] = '\0';
  strcpy(mysql_db,     "flowd");
  strcpy(mysql_table,  "traffic_%Y_%m");
  strcpy(mysql_utable, "users");
  mysql_port=0;
  mysql_start();
#endif
  f=fopen(name, "r");
  if (f==NULL)
  { warning("Can't open %s: %s!", name, strerror(errno));
    return -1;
  }
  /* free links and routers */
  for (pl=linkhead; pl;)
  {
    linkhead = pl;
    pl = pl->next;
    free(linkhead);
  }
  linkhead = NULL;
  old_routers = routers;
  cur_router = routers = calloc(1, sizeof(struct router_t));
  cur_router->addr = (u_long)-1;
#if NBITS>0
  { int i;
    for (i=0; i<NCLASSES; i++)
    { uaindex[i]=i;
      snprintf(uaname[i], sizeof(uaname[i])-1, "class%u", i);
    }
  }
#endif
  parse_file(f);
  fclose(f);
  for (cur_router=old_routers; cur_router;)
  { freerouter(cur_router);
    old_routers = cur_router;
    cur_router = cur_router->next;
    free(old_routers);
  }
#if NBITS>0
  if (fromshmem && !preproc)
  { if (init_map())
    { warning("Can't init shared memory: %s", strerror(errno));
      return 1;
    }
  }
  if (access(aclname, R_OK)==0)
    fromacl=1;
  else if (!fromshmem && !preproc)
  { warning("Can't read acl %s!", aclname);
    return 1;
  } else
    uaname[0][0]='\0';
#endif
#ifdef DO_PERL
  if (!preproc)
  { PerlStart(perlfile);
    plcheckfuncs();
  }
#endif
  return 0;
}

#ifdef DO_SNMP
/* find ifindex by snmp param */
#ifdef NET_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#define ds_get_int(a, b)   netsnmp_ds_get_int(a, b)
#define DS_LIBRARY_ID      NETSNMP_DS_LIBRARY_ID
#define DS_LIB_SNMPVERSION NETSNMP_DS_LIB_SNMPVERSION
#else
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/asn1.h>
#include <ucd-snmp/snmp.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp_client.h>
#include <ucd-snmp/snmp_impl.h>
#include <ucd-snmp/snmp_parse_args.h>
#include <ucd-snmp/mib.h>
#include <ucd-snmp/system.h>
#include <ucd-snmp/default_store.h>
#endif

static char *oid2str(enum ifoid_t oid)
{
  switch (oid)
  { case IFNAME:  return "ifName";
    case IFDESCR: return "ifDescr";
    case IFALIAS: return "ifAlias";
    case IFIP:    return "ifIP";
  }
  return "";
}

static char *oid2oid(enum ifoid_t oid)
{
  switch (oid)
  { case IFNAME:  return "ifName";
    case IFDESCR: return "ifDescr";
    case IFALIAS: return "ifAlias";
    case IFIP:    return "ipAdEntIfIndex";
  }
  return "";
}

static int comp(const void *a, const void *b)
{
  return strcasecmp(((struct routerdata *)a)->val, ((struct routerdata *)b)->val);
}

static int snmpwalk(struct router_t *router, enum ifoid_t noid)
{
  struct snmp_session  session, *ss;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  oid    root[MAX_OID_LEN], name[MAX_OID_LEN];
  size_t rootlen, namelen;
  int    running, status, exitval=0, nifaces, varslen, ifindex;
  char   *oid, *curvar, ipbuf[16], soid[256];
  struct {
           unsigned short ifindex;
           char val[256];
  } *data;

  /* get the initial object and subtree */
  memset(&session, 0, sizeof(session));
  snmp_sess_init(&session);
  init_snmp("flowd");
  /* open an SNMP session */
  strcpy(ipbuf, inet_ntoa(*(struct in_addr *)(void *)&router->addr));
  session.peername = ipbuf;
  session.community = (unsigned char *)router->community;
  session.community_len = strlen(router->community);
  session.version = ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION);
  oid=oid2oid(noid);
  debug(1, "Do snmpwalk %s %s %s", ipbuf, router->community, oid);
  if ((ss = snmp_open(&session)) == NULL)
  { snmp_sess_perror("flowd", &session);
    return 1;
  }
  debug(6, "snmp session opened");
  while (router->ifnumber == 0 && noid!=IFIP) {
    rootlen=MAX_OID_LEN;
    if (snmp_parse_oid("ifNumber.0", root, &rootlen)==NULL)
    { warning("Can't parse oid ifNumber.0");
      snmp_perror("ifNumber.0");
      break;
    }
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, root, rootlen);
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        vars = response->variables;
        if (vars) {
          router->ifnumber = vars->val.integer[0];
          debug(2, "ifNumber = %d", router->ifnumber);
        }
      } else
        warning("snmpget response error");
    } else {
      warning("snmpget status error");
      snmp_sess_perror("flowd", ss);
    }
    if (response) snmp_free_pdu(response);
    break;
  }

  /* get first object to start walk */
  rootlen=MAX_OID_LEN;
  if (snmp_parse_oid(oid, root, &rootlen)==NULL)
  { warning("Can't parse oid %s", oid);
    snmp_perror(oid);
    return 1;
  }
  memmove(name, root, rootlen*sizeof(oid));
  namelen = rootlen;
  running = 1;
  nifaces = varslen = ifindex = 0;
  data = NULL;

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    if (router->ifnumber > 0 && noid != IFIP && running == 2) {
      snprintf(soid, sizeof(soid), "%s.%d", oid, ifindex+1);
      namelen=MAX_OID_LEN;
      if (snmp_parse_oid(soid, name, &namelen)==NULL)
      { warning("Can't parse oid %s", soid);
        snmp_perror(soid);
        break;
      }
      pdu = snmp_pdu_create(SNMP_MSG_GET);
    } else
      pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    snmp_add_null_var(pdu, name, namelen);
    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
      ifindex++;
      if (response->errstat == SNMP_ERR_NOERROR) {
        /* check resulting variables */
        for (vars = response->variables; vars; vars = vars->next_variable) {
          if ((vars->name_length < rootlen) ||
              (memcmp(root, vars->name, rootlen * sizeof(oid))!=0)) {
            /* not part of this subtree */
            running = 0;
            if (router->ifnumber > 0 && noid != IFIP) {
              if (ifindex < router->ifnumber) running = 2;
              debug(6, "%s.%d - not part of this subtree", oid, ifindex);
            } else
              debug(6, "Not part of this subtree");
            continue;
          }
          if (nifaces%16==0)
            data=realloc(data, (nifaces+16)*sizeof(data[0]));
          if (noid==IFIP)
          { sprintf(data[nifaces].val, "%lu.%lu.%lu.%lu",
                    vars->name_loc[vars->name_length-4],
                    vars->name_loc[vars->name_length-3],
                    vars->name_loc[vars->name_length-2],
                    vars->name_loc[vars->name_length-1]);
            data[nifaces++].ifindex=vars->val.integer[0];
          } else
          {
            strncpy(data[nifaces].val, (char *)vars->val.string, sizeof(data->val)-1);
            if (vars->val_len<sizeof(data->val))
              data[nifaces].val[vars->val_len]='\0';
            else
              data[nifaces].val[sizeof(data->val)-1]='\0';
            data[nifaces++].ifindex=(unsigned short)vars->name_loc[vars->name_length-1];
          }
          debug(6, "ifindex %u val '%s'", data[nifaces-1].ifindex, data[nifaces-1].val);
          varslen += strlen(data[nifaces-1].val)+1;
          if ((vars->type != SNMP_ENDOFMIBVIEW) &&
              (vars->type != SNMP_NOSUCHOBJECT) &&
              (vars->type != SNMP_NOSUCHINSTANCE)) {
            /* not an exception value */
            memmove((char *)name, (char *)vars->name,
                    vars->name_length * sizeof(oid));
            namelen = vars->name_length;
          } else
            /* an exception value, so stop */
            running = 0;
        }
      } else {
        /* error in response */
        if (response->errstat != SNMP_ERR_NOSUCHNAME) {
          warning("Error in snmp packet.");
          exitval = 2;
          running = 0;
        } else if (ifindex < router->ifnumber && noid != IFIP)
          debug(2, "%s.%d - no such name", oid, ifindex);
        else {
          debug(2, "snmpwalk successfully done");
          running = 0;
        }
      }
    } else if (status == STAT_TIMEOUT) {
      warning("snmp timeout");
      running = 0;
      exitval = 2;
    } else {    /* status == STAT_ERROR */
      warning("SNMP Error");
      snmp_sess_perror("flowd", ss);
      running = 0;
      exitval = 2;
    }
    if (response) snmp_free_pdu(response);
  }
  snmp_close(ss);
  if (exitval)
  { if (data) free(data);
    return exitval;
  }
  /* ok, copy data to router structure */
  if (router->data[noid]) free(router->data[noid]);
  router->data[noid] = malloc(sizeof(router->data[0][0])*nifaces+varslen);
  curvar=((char *)router->data[noid])+sizeof(router->data[0][0])*nifaces;
  router->nifaces[noid]=nifaces;
  for (nifaces=0; nifaces<router->nifaces[noid]; nifaces++)
  { router->data[noid][nifaces].ifindex=data[nifaces].ifindex;
    router->data[noid][nifaces].val=curvar;
    strcpy(curvar, data[nifaces].val);
    curvar+=strlen(curvar)+1;
  }
  if (data) free(data);
  /* data copied, sort it */
  qsort(router->data[noid], nifaces, sizeof(router->data[0][0]), comp);
  return 0;
}

static unsigned short get_ifindex(struct router_t *router, enum ifoid_t oid, char **s)
{
  int left, right, mid, i;
  char val[256], *p;

  if (router->addr==(u_long)-1)
  { warning("Router not specified for %s", oid2str(oid));
    return (unsigned short)-2; /* not matched for any interface */
  }
  if ((p=strchr(*s, '=')) == NULL)
  { error("Internal error");
    exit(2);
  }
  *s = p+1;
  if (router->data[oid] == NULL)
  {
    /* do snmpwalk for the oid */
    if (snmpwalk(router, oid))
    { /* snmpwalk failed, try to use data from old_routers */
      struct router_t *prouter;
      int i, varslen;
      char *curvar;

      for (prouter = old_routers; prouter; prouter = prouter->next)
      { if (router->addr==prouter->addr)
        {
          if (prouter->data[oid])
          {
            varslen = 0;
            for (i=0; i<prouter->nifaces[oid]; i++)
              varslen += strlen(prouter->data[oid][i].val)+1;
            router->data[oid] = malloc(i*sizeof(router->data[0][0])+varslen);
            curvar=((char *)router->data[oid])+sizeof(router->data[0][0])*i;
            for (i=0; i<prouter->nifaces[oid]; i++)
            { router->data[oid][i].ifindex = prouter->data[oid][i].ifindex;
              router->data[oid][i].val = curvar;
              strcpy(curvar, prouter->data[oid][i].val);
              curvar += strlen(curvar)+1;
            }
            router->nifaces[oid] = prouter->nifaces[oid];
          }
        }
      }
    }
  }
  /* copy value to val string */
  if (**s == '\"')
  { strncpy(val, *s+1, sizeof(val));
    val[sizeof(val)-1] = '\0';
    if ((p=strchr(val, '\"')) != NULL)
      *p='\0';
    if ((p=strchr(*s, '\"')) != NULL)
      *s=p+1;
  } else
  { strncpy(val, *s, sizeof(val));
    val[sizeof(val)-1] = '\0';
    for (p=val; *p && !isspace(*p); p++);
    *p='\0';
  }
  /* find ifindex for given val */
  left=0; right=router->nifaces[oid];
  while (left<right)
  { mid=(left+right)/2;
    if ((i=strcasecmp(router->data[oid][mid].val, val))==0)
    {
      debug(4, "ifindex for %s=%s at %s is %d", oid2str(oid), val, 
        inet_ntoa(*(struct in_addr *)(void *)&router->addr),
        router->data[oid][mid].ifindex);
      return router->data[oid][mid].ifindex;
    }
    if (i>0) right=mid;
    else left=mid+1;
  }
  warning("%s %s not found at %s", oid2str(oid), val,
         inet_ntoa(*(struct in_addr *)(void *)&(router->addr)));
  return (unsigned short)-2;
}
#endif

