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
#include "flowd.h"

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

static char *uaname[NCLASSES]={"world", "ua"};
extern long snap_traf;
extern FILE *fsnap;

void add_stat(u_long flowsrc, u_long src_ip, u_long dst_ip, int in,
              u_long nexthop, u_long len, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto)
{
  u_long local=0, remote=0;
  int src_ua, dst_ua;
  u_short remote_if, remote_as;
  struct attrtype *pa;
  sigset_t set, oset;

  src_ip = ntohl(src_ip);
  dst_ip = ntohl(dst_ip);
  flowsrc = ntohl(flowsrc);
  sigemptyset(&set);
  sigaddset(&set, SIGINFO);
  sigprocmask(SIG_BLOCK, &set, &oset);
  for (pa=attrhead; pa; pa=pa->next)
  { if (in^pa->reverse)
    { local=dst_ip;
      remote=src_ip;
      remote_if=input;
      remote_as=src_as;
    } else
    { local=src_ip;
      remote=dst_ip;
      remote_if=output;
      remote_as=dst_as;
    }
    if ((((flowsrc & pa->srcmask)==pa->src) == (pa->not==0)) &&
         (pa->ip==(u_long)-1      || (remote & pa->mask)==pa->ip) &&
         (pa->nexthop==(u_long)-1 || (pa->nexthop==nexthop)) &&
         (pa->as==(u_short)-1     || (pa->as==remote_as)) &&
         (pa->iface==(u_short)-1  || (pa->iface==remote_if)) &&
         (pa->proto==(u_short)-1  || pa->proto==proto))
    {
      if (!pa->link && !pa->fallthru)
        break; // ignore
  if (fsnap && !pa->fallthru)
  { 
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes\n",
        ((in^pa->reverse) ? "<-" : "->"),
        ((char *)&src_ip)[3], ((char *)&src_ip)[2], ((char *)&src_ip)[1], ((char *)&src_ip)[0],
        ((char *)&dst_ip)[3], ((char *)&dst_ip)[2], ((char *)&dst_ip)[1], ((char *)&dst_ip)[0],
        pa->link->name, uaname[find_mask(src_ip)], uaname[find_mask(dst_ip)],
        ((in^pa->reverse) ? "in" : "out"), len);
    fflush(fsnap);
    if ((snap_traf-=len) <= 0)
    { fclose(fsnap);
      fsnap = NULL;
      snap_traf=0;
    }
  }
  src_ua=find_mask(src_ip);
  dst_ua=find_mask(dst_ip);
  if ((pa->link->bytes[in^pa->reverse][src_ua][dst_ua]+=len)>=0xf0000000lu)
    write_stat();
  if (!pa->fallthru)
    break;
    }
  }
  sigprocmask(SIG_SETMASK, &oset, NULL);
}

void write_stat(void)
{
  int i, j, k;
  struct linktype *pl;
  FILE *fout;

  last_write=time(NULL);
  fout = fopen(logname, "a");
  if (fout==NULL) return;
  fprintf(fout, "----- %s", ctime(&last_write));
  for (pl=linkhead; pl; pl=pl->next)
  { for (i=0; i<2; i++)
      for (j=0; j<NCLASSES; j++)
        for (k=0; k<NCLASSES; k++)
          if (pl->bytes[i][j][k])
          { 
              fprintf(fout, "%s.%s2%s.%s: %lu bytes\n",
                      pl->name, uaname[j], uaname[k], (i ? "in" : "out"),
                      pl->bytes[i][j][k]);
              pl->bytes[i][j][k]=0;
          }
  }
  fputs("\n", fout);
  fclose(fout);
}
