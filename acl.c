#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "flowd.h"

static char *acl;
static char bit[8]={1, 2, 4, 8, 16, 32, 64, 128};

static int reload_one_acl(char **acl, char *acl_name)
{
  int i;
  char *newacl, *oldacl;
  unsigned long addr;
  FILE *facl;
  char str[2048];
  char *p;

  last_reload=time(NULL);
  facl=fopen(acl_name, "r");
  if (facl==NULL)
  { warning("Can't open %s: %s!", acl_name, strerror(errno));
    return -1;
  }
  newacl = calloc(1<<(24-3), 1);
  if (!newacl)
  { error("Not enough core!");
    return -1;
  }
  while (fgets(str, sizeof(str), facl))
  {
#if 1
    if (str[0]!='*') continue;
    for (p=str+3; isdigit(*p) || *p=='.'; p++);
    if (*p=='/') i=atoi(p+1);
    else i=24;
    if (i<=0 || i>24) continue;
    *p='\0';
    addr=ntohl(inet_addr(str+3));
#else
    char *p1;
    if (str[0]!='O') continue;
    for (p=str+5; !isdigit(*p); p++);
    for (p1=p; isdigit(*p1) || *p1=='.'; p1++);
    if (*p1 != '/') continue;
    *p1='\0';
    i=atoi(p1+1);
    if (i<=0 || i>24) continue;
    addr=ntohl(inet_addr(p));
#endif
    if (addr==0) continue; /* default route */
    addr>>=8;
    if (i<=21)
    { addr>>=3;
      memset(newacl+addr, 255, 1<<(21-i));
    }
    else
    { int ndx=addr>>3, j;
      for (j=1<<(24-i); j>0; j--)
        newacl[ndx]|=bit[(addr++)%8];
    }
  }
  fclose(facl);
  oldacl=*acl;
  *acl=newacl;
  if (oldacl) free(oldacl);
  return (*acl ? 0 : 1);
}

int reload_acl(void)
{
  if (fromshmem) return 0;
  if (!fromacl) return 0;
  return reload_one_acl(&acl, aclname);
}

int find_mask(unsigned long remote)
{
  if (fromshmem) return getclass(htonl(remote));
  if (!fromacl) return 0;
  if (remote==0xe0000005ul)
    return 1; /* ospf multicast */
  if ((remote & 0xff000000u) == 0x0a000000u ||
      (remote & 0xff000000u) == 0x7f000000u)
    return 1; /* local */
  remote>>=8;
  if (acl[remote >> 3] & bit[remote & 7])
    return 1; /* ua */
  return 0;
}

#ifdef MAKETEST
time_t last_reload;
char *uaname[NCLASS][32]={"world","ua"};
int main(int argc, char *argv[])
{
  unsigned long addr;
  if (argc<2) return 0;
  addr=inet_addr(argv[1]);
  reload_acl();
  printf("%s\n", uaname[find_mask(ntohl(addr))]);
  return 0;
}
#endif
