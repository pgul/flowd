#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

int config(char *name)
{
  FILE *f;
  struct linktype *pl;
  struct attrtype *pa, *attrtail;
  char str[256];
  char *p;

  if (fromshmem) freeshmem();
  fromshmem=0;
  mapkey=MAPKEY;
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
    p=str;
    if (strncmp(p, "log=", 4)==0)
    { strncpy(logname, p+4, sizeof(logname)-1);
      continue;
    }
    if (strncmp(p, "snap=", 5)==0)
    { strncpy(snapfile, p+5, sizeof(snapfile)-1);
      continue;
    }
    if (strncmp(p, "acl=", 4)==0)
    { strncpy(aclname, p+4, sizeof(aclname)-1);
      continue;
    }
    if (strncmp(p, "pid=", 4)==0)
    { strncpy(pidfile, p+4, sizeof(pidfile)-1);
      continue;
    }
    if (strncmp(p, "write-int=", 10)==0)
    { write_interval = atoi(p+10);
      if (write_interval == 0) write_interval=WRITE_INTERVAL;
      continue;
    }
    if (strncmp(p, "reload-int=", 11)==0)
    { reload_interval = atoi(p+11);
      if (reload_interval == 0) reload_interval=RELOAD_INTERVAL;
      continue;
    }
    if (strncmp(p, "bindaddr=", 9)==0)
    { bindaddr=inet_addr(p+9);
      continue;
    }
    if (strncmp(p, "port=", 5)==0)
    { port=atoi(p+5);
      continue;
    }
    if (strncmp(p, "mapkey=", 7)==0)
    { mapkey = atol(p+7);
      if (mapkey == 0) mapkey=MAPKEY;
      fromshmem=1;
      continue;
    }
    if (strncmp(p, "fromshmem=", 10)==0)
    { if (p[10]=='n' || p[10]=='N' || p[10]=='0' || p[10]=='f' || p[10]=='F')
        fromshmem=0;
      else
        fromshmem=1;
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
    if (!pl && strcmp(str, "ignore"))
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
    pa->src=pa->srcmask=0;
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
      if (strncmp(p, "reverse", 7)==0)
      { pa->reverse=1;
      }
      else if (strncmp(p, "fallthru", 8)==0)
      { pa->fallthru=1;
      }
      if (strncmp(p, "proto=", 6)==0)
        pa->proto=atoi(p+6);
      else if (strncmp(p, "as=", 3)==0)
        pa->as=atoi(p+3);
      else if (strncmp(p, "ifindex=", 8)==0)
        pa->iface=atoi(p+8);
      else if (strncmp(p, "nexthop=", 8)==0)
        pa->nexthop=inet_addr(p+8);
      else if (strncmp(p, "ip=", 3)==0)
      { char c, *p1;
        p+=3;
        for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
        c=*p1;
        *p1='\0';
        pa->ip = ntohl(inet_addr(p));
        if (c=='/')
          pa->mask<<=(32-atoi(p1+1));
        *p1=c; p=p1;
        if ((pa->ip & pa->mask) != pa->ip)
        { unsigned long masked = (pa->ip & pa->mask);
          printf("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!\n",
                 ((char *)&(pa->ip))[3], ((char *)&(pa->ip))[2],
                 ((char *)&(pa->ip))[1], ((char *)&(pa->ip))[0],
                 atoi(p+1),
                 ((char *)&(pa->mask))[3], ((char *)&(pa->mask))[2],
                 ((char *)&(pa->mask))[1], ((char *)&(pa->mask))[0]);
          printf("ip & mask is %u.%u.%u.%u\n",
                 ((char *)&masked)[3], ((char *)&masked)[2],
                 ((char *)&masked)[1], ((char *)&masked)[0]);
        }
      }
      else if (strncmp(p, "src=", 4)==0)
      { char c, *p1;
        p+=4;
        if (*p=='!') pa->not=1, p++;
        for (p1=p; *p1 && (isdigit(*p1) || *p1=='.'); p1++);
        c=*p1;
        *p1='\0';
        pa->src = ntohl(inet_addr(p));
        pa->srcmask = 0xfffffffful;
        if (c=='/')
          pa->srcmask<<=(32-atoi(p1+1));
        *p1=c; p=p1;
        if ((pa->src & pa->srcmask) != pa->src)
        { unsigned long masked = (pa->src & pa->srcmask);
          printf("Warning: %u.%u.%u.%u inconsistent with /%d (mask %u.%u.%u.%u)!\n",
                 ((char *)&(pa->src))[3], ((char *)&(pa->src))[2],
                 ((char *)&(pa->src))[1], ((char *)&(pa->src))[0],
                 atoi(p+1),
                 ((char *)&(pa->srcmask))[3], ((char *)&(pa->srcmask))[2],
                 ((char *)&(pa->srcmask))[1], ((char *)&(pa->srcmask))[0]);
          printf("ip & mask is %u.%u.%u.%u\n",
                 ((char *)&masked)[3], ((char *)&masked)[2],
                 ((char *)&masked)[1], ((char *)&masked)[0]);
        }
      }

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
  return 0;
}

