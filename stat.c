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
      fprintf(fsnap, "%s %u.%u.%u.%u->%u.%u.%u.%u (%s.%s2%s.%s) %lu bytes (AS%u->AS%u, nexthop %u.%u.%u.%u, if %u->%u\n",
        ((in^pa->reverse) ? "<-" : "->"),
        ((char *)&srcip)[0], ((char *)&srcip)[1], ((char *)&srcip)[2], ((char *)&srcip)[3],
        ((char *)&dstip)[0], ((char *)&dstip)[1], ((char *)&dstip)[2], ((char *)&dstip)[3],
        pa->link->name, uaname[uaindex[src_class]], uaname[uaindex[dst_class]],
        ((in^pa->reverse) ? "in" : "out"), len, src_as, dst_as,
        ((char *)&nexthop)[0], ((char *)&nexthop)[1], ((char *)&nexthop)[2], ((char *)&nexthop)[3],
        input, output);
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
