#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "flowd.h"

struct linktype *linkhead=NULL;
struct attrtype *attrhead=NULL;
char logname[256]=LOGNAME, snapfile[256]=SNAPFILE, aclname[256]=ACLNAME;
char pidfile[256]=PIDFILE;
int  write_interval=WRITE_INTERVAL, reload_interval=RELOAD_INTERVAL;
u_long bindaddr=INADDR_ANY;
unsigned short port=PORT;
long mapkey;
int  fromshmem;
char uaname[NCLASSES][32];
int  uaindex[NCLASSES];
#ifdef DO_PERL
char perlfile[256], perlstart[256], perlwrite[256], perlstop[256];
#endif
#ifdef DO_MYSQL
char mysql_user[256], mysql_pwd[256], mysql_host[256];
char mysql_socket[256], mysql_db[256];
char mysql_table[256], mysql_utable[256];
unsigned mysql_port;
#endif
#ifdef DO_SNMP
static struct router_t *routers;
#endif

void debug(int level, char *format, ...)
{
  va_list arg;
  va_start(arg, format);
  if (level<=verbose)
  { vfprintf(stdout, format, arg);
    fputs("\n", stdout);
  }
  va_end(arg);
}

static void freerouter(struct router_t *router)
{
  memset(router, 0, sizeof(*router));
  router->addr = (u_long)-1;
}

static void read_ip(char *p, u_long *ip, u_long *mask)
{
  char c, *p1;
  long addr;

  for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
  c=*p1;
  *p1='\0';
  if ((addr=inet_addr(p)) == -1) {
    printf("Error: %s is not correct IP-address!\n", p);
    exit(2);
  }
  *ip = ntohl(addr);
  if (c=='/')
    *mask<<=(32-atoi(p1+1));
  *p1=c;
  if ((*ip & *mask) != *ip)
  { unsigned long masked = (*ip & *mask);
    printf("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!\n",
           ((char *)ip)[3], ((char *)ip)[2],
           ((char *)ip)[1], ((char *)ip)[0],
           atoi(p+1),
           ((char *)mask)[3], ((char *)mask)[2],
           ((char *)mask)[1], ((char *)mask)[0]);
    printf("ip & mask is %u.%u.%u.%u\n",
           ((char *)&masked)[3], ((char *)&masked)[2],
           ((char *)&masked)[1], ((char *)&masked)[0]);
  }
}

int config(char *name)
{
  FILE *f;
  struct linktype *pl;
  struct attrtype *pa, *attrtail;
  char str[256];
  char *p, *p1;
  int i, j;
  struct hostent *he;
  struct router_t cur_router;

  if (fromshmem) freeshmem();
  fromshmem=0;
  mapkey=MAPKEY;
#ifdef DO_PERL
  strcpy(perlfile,     "flowd.pl");
  strcpy(perlstart,    "startwrite");
  strcpy(perlwrite,    "write"     );
  strcpy(perlstop,     "stopwrite" );
#endif
#ifdef DO_MYSQL
  mysql_user[0] = mysql_pwd[0] = mysql_host[0] = mysql_socket[0] = '\0';
  strcpy(mysql_db, "flowd");
  strcpy(mysql_table,  "traffic_%Y_%m");
  strcpy(mysql_utable, "users");
  mysql_port=0;
  mysql_start();
#endif
  f=fopen(name, "r");
  if (f==NULL)
  { fprintf(stderr, "Can't open %s: %s!\n", name, strerror(errno));
    return -1;
  }
  /* free links and attrs */
  if (linkhead)
  { for (pl=linkhead->next; pl; pl=pl->next)
    { free(linkhead);
      linkhead=pl;
    }
    free(linkhead);
    linkhead=NULL;
  }
  if (attrhead)
  { for (pa=attrhead->next; pa; pa=pa->next)
    { free(attrhead);
      attrhead=pa;
    }
    free(attrhead);
    attrhead=NULL;
  }
  attrtail=NULL;
  for (i=0; i<NCLASSES; i++)
  { uaindex[i]=i;
    snprintf(uaname[i], sizeof(uaname[i])-1, "class%u", i);
  }
  cur_router.addr=(u_long)-1;
#ifdef DO_SNMP
  { struct router_t *prouter;
    for (prouter=routers; prouter; prouter=prouter->next)
    { for (i=0; i<NUM_OIDS; i++)
	if (prouter->data[i])
	{ free(prouter->data[i]);
	  prouter->data[i] = NULL;
	}
    }
  }
#endif
  while (fgets(str, sizeof(str), f))
  {
    p=strchr(str, '\n');
    if (p) *p='\0';
    p=strchr(str, '#');
    if (p) *p='\0';
    for (p=str; isspace(*p); p++);
    if (*p=='\0') continue;
    if (p!=str) strcpy(str, p);
    if (str[0]=='\0') continue;
    for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
    // for (p=str; *p; p++) *p=tolower(*p);
    p=str;
    if (strncasecmp(p, "log=", 4)==0)
    { strncpy(logname, p+4, sizeof(logname)-1);
      continue;
    }
    if (strncasecmp(p, "snap=", 5)==0)
    { strncpy(snapfile, p+5, sizeof(snapfile)-1);
      continue;
    }
    if (strncasecmp(p, "acl=", 4)==0)
    { strncpy(aclname, p+4, sizeof(aclname)-1);
      continue;
    }
    if (strncasecmp(p, "pid=", 4)==0)
    { strncpy(pidfile, p+4, sizeof(pidfile)-1);
      continue;
    }
    if (strncasecmp(p, "write-int=", 10)==0)
    { write_interval = atoi(p+10);
      if (write_interval == 0) write_interval=WRITE_INTERVAL;
      continue;
    }
    if (strncasecmp(p, "reload-int=", 11)==0)
    { reload_interval = atoi(p+11);
      if (reload_interval == 0) reload_interval=RELOAD_INTERVAL;
      continue;
    }
    if (strncasecmp(p, "bindaddr=", 9)==0)
    { bindaddr=inet_addr(p+9);
      continue;
    }
    if (strncasecmp(p, "port=", 5)==0)
    { port=atoi(p+5);
      continue;
    }
    if (strncasecmp(p, "mapkey=", 7)==0)
    { mapkey = atol(p+7);
      if (mapkey == 0) mapkey=MAPKEY;
      fromshmem=1;
      continue;
    }
    if (strncasecmp(p, "fromshmem=", 10)==0)
    { if (p[10]=='n' || p[10]=='N' || p[10]=='0' || p[10]=='f' || p[10]=='F')
        fromshmem=0;
      else
        fromshmem=1;
      continue;
    }
    if (strncasecmp(p, "classes=", 8)==0)
    {
      p+=8;
      i=0;
      while (p && *p)
      { 
        if (i==NCLASSES)
        { fprintf(stderr, "Too many classes!\n");
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
      continue;
    }
#ifdef DO_PERL
    if (strncasecmp(p, "perlwrite=", 10)==0)
    { char *p1 = p+10;
      p=strstr(p1, "::");
      if (p==NULL)
      { printf("Incorrect perlwrite=%s ignored!", p1);
        continue;
      }
      *p=0;
      strncpy(perlfile, p1, sizeof(perlfile));
      strncpy(perlwrite, p+2, sizeof(perlwrite));
      continue;
    }
#endif
#ifdef DO_MYSQL
    if (strncasecmp(p, "mysql_user=", 11)==0)
    { strncpy(mysql_user, p+11, sizeof(mysql_user)-1);
      continue;
    }
    if (strncasecmp(p, "mysql_host=", 11)==0)
    { strncpy(mysql_host, p+11, sizeof(mysql_host)-1);
      p=strchr(mysql_host, ':');
      if (p)
      { mysql_port=atoi(p+1);
        *p=0;
      }
      continue;
    }
    if (strncasecmp(p, "mysql_pwd=", 10)==0)
    { strncpy(mysql_pwd, p+10, sizeof(mysql_pwd)-1);
      continue;
    }
    if (strncasecmp(p, "mysql_db=", 9)==0)
    { strncpy(mysql_db, p+9, sizeof(mysql_db)-1);
      continue;
    }
    if (strncasecmp(p, "mysql_socket=", 13)==0)
    { strncpy(mysql_socket, p+13, sizeof(mysql_socket)-1);
      continue;
    }
    if (strncasecmp(p, "mysql_table=", 12)==0)
    { strncpy(mysql_table, p+12, sizeof(mysql_table)-1);
      continue;
    }
    if (strncasecmp(p, "mysql_utable=", 13)==0)
    { strncpy(mysql_utable, p+13, sizeof(mysql_utable)-1);
      continue;
    }
#endif
    if (strncasecmp(p, "router=", 7)==0)
    {
      p+=7;
      freerouter(&cur_router);
#ifdef DO_SNMP
      if ((p1=strchr(p, '@'))!=NULL)
      { *p1++='\0';
        strncpy(cur_router.community, p, sizeof(cur_router.community)-1);
        p=p1;
      } else
        strcpy(cur_router.community, "public");
#endif
      /* get router address */
      if ((he=gethostbyname(p))==0 || he->h_addr_list[0]==NULL)
      { if (strcmp(p, "any")==0)
          cur_router.addr=(u_long)-1;
        else
          printf("Warning: Router %s not found\n", p);
        continue;
      }
      /* use only first address */
      memcpy(&cur_router.addr, he->h_addr_list[0], he->h_length);
      continue;
    }
    for (p=str; *p && !isspace(*p); p++);
    if (*p) *p++='\0';
    if (strchr(str, '=')) continue; /* keyword */
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
    if (cur_router.addr!=(u_long)-1)
      pa->src=ntohl(cur_router.addr);	/* mask /32 */
    else
      pa->src=pa->srcmask=0;		/* match any */
    pa->not=0;
    if (attrhead==NULL)
      attrhead = pa;
    else
      attrtail->next = pa;
    attrtail = pa;
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
        pa->proto=atoi(p+6);
      else if (strncmp(p, "as=", 3)==0)
        pa->as=atoi(p+3);
      else if (strncasecmp(p, "ifindex=", 8)==0)
        pa->iface=atoi(p+8);
      else if (strncasecmp(p, "class=", 6)==0)
        pa->class=atoi(p+6);
      else if (strncasecmp(p, "nexthop=", 8)==0)
        pa->nexthop=inet_addr(p+8);
      else if (strncasecmp(p, "ip=", 3)==0)
        read_ip(p+3, &pa->ip, &pa->mask);
      else if (strncasecmp(p, "src=", 4)==0)
      { p+=4;
	if (*p == '!')
	{ p++;
	  pa->not=1;
	}
        read_ip(p, &pa->src, &pa->srcmask);
      }
      else if (strncasecmp(p, "remote=", 7)==0)
        read_ip(p+7, &pa->remote, &pa->remotemask);
#ifdef DO_SNMP
      else if (strncasecmp(p, "ifname=", 7)==0)
        pa->iface=get_ifindex(&cur_router, IFNAME, &p);
      else if (strncasecmp(p, "ifdescr=", 8)==0)
        pa->iface=get_ifindex(&cur_router, IFDESCR, &p);
      else if (strncasecmp(p, "ifalias=", 8)==0)
        pa->iface=get_ifindex(&cur_router, IFDESCR, &p);
      else if (strncasecmp(p, "ifip=", 5)==0)
        pa->iface=get_ifindex(&cur_router, IFIP, &p);
#endif
      while (*p && !isspace(*p)) p++;
    }
  }
  fclose(f);
  if (fromshmem)
  { if (init_map())
    { printf("Can't init shared memory: %s\n", strerror(errno));
      return 1;
    }
  }
  freerouter(&cur_router);
#ifdef DO_PERL
  exitperl();
  PerlStart();
#endif
  return 0;
}

#ifdef DO_SNMP
/* find ifindex by snmp param */
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
  return strcmp(((struct routerdata *)a)->val, ((struct routerdata *)b)->val);
}

static int snmpwalk(struct router_t *router, enum ifoid_t noid)
{
  struct snmp_session  session, *ss;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  oid    root[MAX_OID_LEN], name[MAX_OID_LEN];
  size_t rootlen, namelen;
  int    running, status, exitval=0, nifaces, varslen;
  char   *oid, *curvar, ipbuf[16];
  struct {
           unsigned short ifindex;
	   char val[256];
  } *data;

  /* get the initial object and subtree */
  memset(&session, 0, sizeof(session));
  snmp_sess_init(&session);
  init_snmp("snmpapp");
  rootlen=MAX_OID_LEN;
  oid=oid2oid(noid);
  if (snmp_parse_oid(oid, root, &rootlen)==NULL)
  { fprintf(stderr, "Can't parse oid %s\n", oid);
    snmp_perror(oid);
    return 1;
  }
  /* open an SNMP session */
  strcpy(ipbuf, inet_ntoa(*(struct in_addr *)&router->addr));
  session.peername = ipbuf;
  session.community = router->community;
  session.community_len = strlen(router->community);
  session.version = ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION);
  debug(1, "Do snmpwalk %s %s %s", ipbuf, router->community, oid);
  if ((ss = snmp_open(&session)) == NULL)
  { snmp_sess_perror("flowd", &session);
    return 1;
  }
  debug(6, "snmp session opened");
  /* get first object to start walk */
  memmove(name, root, rootlen*sizeof(oid));
  namelen = rootlen;
  running = 1;
  nifaces = varslen = 0;
  data = NULL;

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    snmp_add_null_var(pdu, name, namelen);
    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
      if (response->errstat == SNMP_ERR_NOERROR) {
        /* check resulting variables */
        for (vars = response->variables; vars; vars = vars->next_variable) {
          if ((vars->name_length < rootlen) ||
              (memcmp(root, vars->name, rootlen * sizeof(oid))!=0)) {
            /* not part of this subtree */
            running = 0;
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
            strncpy(data[nifaces].val, vars->val.string, sizeof(data->val)-1);
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
        running = 0;
        if (response->errstat != SNMP_ERR_NOSUCHNAME) {
          fprintf(stderr, "Error in packet.\n");
          exitval = 2;
        } else
          debug(2, "snmpwalk successfully done");
      }
    } else if (status == STAT_TIMEOUT) {
      fprintf(stderr, "Timeout\n");
      running = 0;
      exitval = 2;
    } else {    /* status == STAT_ERROR */
      fprintf(stderr, "SNMP Error\n");
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
  router->nifaces=nifaces;
  for (nifaces=0; nifaces<router->nifaces; nifaces++)
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

unsigned short get_ifindex(struct router_t *router, enum ifoid_t oid, char **s)
{
  int left, right, mid, i;
  char val[256], *p;
  struct router_t *prouter;

  if (router->addr==(u_long)-1)
  { printf("Warning: Router not specified for %s\n", oid2str(oid));
    return (unsigned short)-2; /* not matched for any interface */
  }
  if ((p=strchr(*s, '=')) == NULL)
  { printf("Internal error\n");
    exit(2);
  }
  *s = p+1;
  /* search this router/oid */
  for (prouter=routers; prouter; prouter=prouter->next)
  { if (prouter->addr==router->addr)
      break;
  }
  if (prouter==NULL)
  { prouter=malloc(sizeof(*prouter));
    memset(prouter, 0, sizeof(*prouter));
    prouter->addr=router->addr;
    prouter->next=routers;
    routers=prouter;
    strncpy(prouter->community, router->community, sizeof(router->community)-1);
  }
  router=prouter;
  if (router->data[oid] == NULL)
    /* do snmpwalk for the oid */
    snmpwalk(router, oid);
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
  left=0; right=router->nifaces;
  while (left<right)
  { mid=(left+right)/2;
    if ((i=strcmp(router->data[oid][mid].val, val))==0)
    {
      debug(4, "ifindex for %s=%s at %s is %d", oid2str(oid), val, 
        inet_ntoa(*(struct in_addr *)&router->addr),
	router->data[oid][mid].ifindex);
      return router->data[oid][mid].ifindex;
    }
    if (i>0) right=mid;
    else left=mid+1;
  }
  printf("Warning: %s %s not found at %s\n", oid2str(oid), val,
         inet_ntoa(*(struct in_addr *)&(router->addr)));
  return (unsigned short)-2;
}
#endif

