#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "flowd.h"

#ifndef SIGINFO
#define SIGINFO SIGIO
#endif

int  sockfd, verbose;
time_t last_write, last_reload;
long snap_traf;
FILE *fsnap;
char *saved_argv[20];
char *confname;

struct head1 {
  short unsigned int version, count;
  unsigned int uptime, curtime, curnanosec;
} *head1;

struct data1 {
  unsigned int srcaddr, dstaddr, nexthop;
  unsigned short int input, output;
  unsigned int pkts, bytes, first, last;
  unsigned short int srcport, dstport, pad;
  unsigned char prot, tos, flags, pad1, pad2, pad3;
  unsigned int reserved;
} *data1;

struct head5 {
  short unsigned int version, count;
  unsigned int uptime, curtime, curnanosec;
  unsigned int seq, pad;
} *head5;

struct data5 {
  unsigned int srcaddr, dstaddr, nexthop;
  unsigned short int input, output;
  unsigned int pkts, bytes, first, last;
  unsigned short int srcport, dstport;
  unsigned char pad1, flags, prot, tos;
  unsigned short src_as, dst_as;
  unsigned char src_mask, dst_mask;
  unsigned short pad2;
} *data5;

void hup(int signo)
{
  if (signo==SIGHUP || signo==SIGTERM || signo==SIGINT || signo==SIGUSR2)
    write_stat();
  if (signo==SIGTERM)
  { unlink(pidfile);
    exit(0);
  }
  if (signo==SIGUSR1)
    reload_acl();
  if (signo==SIGUSR2)
    if (config(confname))
    { fprintf(stderr, "Config error!\n");
      exit(1);
    }
  if (signo==SIGINFO)
  { /* snap 10M of traffic */
    if (fsnap)
    { fclose(fsnap);
      fsnap=fopen(snapfile, "a");
    } else
    { time_t curtime=time(NULL);
      fsnap=fopen(snapfile, "a");
      if (fsnap) fprintf(fsnap, "\n\n----- %s\n", ctime(&curtime));
    }
    if (fsnap==NULL) snap_traf=0;
    else snap_traf=10*1024*1024; 
  }
  if (signo==SIGINT)
  { /* restart myself */
    close(sockfd);
    unlink(pidfile);
    execvp(saved_argv[0], saved_argv);
    exit(5);
  }
  signal(signo, hup);
}


#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
  int i;
  if (!nochdir) chdir("/");
  if (!noclose)
  {
    i=open("/dev/null", O_RDONLY);
    if (i!=-1)
    { if (i>0) dup2(i, 0);
      close(i);
    }
    i=open("/dev/null", O_WRONLY);
    if (i!=-1)
    { if (i>1) dup2(i, 1);
      if (i>2) dup2(i, 2);
      close(i);
    }
  }
  if ((i=fork()) == -1) return -1;
  if (i>0) exit(0);
  setsid();
  return 0;
}
#endif

int usage(void)
{
  printf("NetFlow collector      " __DATE__ "\n");
  printf("    Usage:\n");
  printf("flowd [-d] [-v] [config]\n");
  printf("  -d  - daemonize\n");
  printf("  -v  - increase verbose level\n");
  return 0;
}

int main(int argc, char *argv[])
{
  int  n, i, count, ver, seq=0, daemonize;
  FILE *f;
  struct sockaddr_in my_addr, remote_addr;
  char buf[MTU];

  confname=CONFNAME;
  daemonize=0;

  while ((i=getopt(argc, argv, "dh?v")) != -1)
  {
    switch (i)
    {
      case 'd': daemonize=1; break;
      case 'v': verbose++;   break;
      case 'h':
      case '?': usage(); return 1;
      default:  fprintf(stderr, "Unknown option -%c\n", (char)i);
		usage(); return 2;
    }
  }
  if (argc>optind)
    confname=argv[optind];

  if (config(confname))
  { fprintf(stderr, "Config error\n");
    return 1;
  }
  if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  { printf("socket: %s\n", strerror(errno));
    return 1;
  }
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = bindaddr;
  my_addr.sin_port = htons(port);
  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) != 0)
  {
    printf("bind: %s (addr %s)\n", strerror(errno), inet_ntoa(my_addr.sin_addr));
    close(sockfd);
    return 1;
  }
  for (i=0; i<=argc; i++)
    saved_argv[i]=argv[i];
  last_write=time(NULL);
  signal(SIGHUP,  hup);
  signal(SIGUSR1, hup);
  signal(SIGUSR2, hup);
  signal(SIGINT,  hup);
  signal(SIGTERM, hup);
  signal(SIGINFO, hup);
  if (reload_acl())
  { fprintf(stderr, "reload acl error!\n");
    /* return 1; */
  }
  if (daemonize && !verbose) daemon(0, 0);
  f=fopen(pidfile, "w");
  if (f)
  { fprintf(f, "%u\n", (unsigned)getpid());
    fclose(f);
  }

  while ((i=sizeof(remote_addr),
          memset(&remote_addr, 0, sizeof(remote_addr)),
          n=recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&remote_addr, &i)) != -1)
  {
    if (n==0) continue;
    ver = ntohs(*(short int *)buf);
    if (ver==1)
    {
      if (n<sizeof(struct head1))
      { printf("Error: received %d bytes, needed %d\n", n, sizeof(*head1));
        continue;
      }
      head1 = (struct head1 *)buf;
#if 0
      printf("Ver=1, count=%u, uptime=%lu, curtime=%lu, seq=%lu\n",
             ntohs(head1->count), ntohl(head1->uptime), ntohl(head1->curtime),
             ntohl(head1->seq));
#endif
      if (n!=sizeof(*head1)+ntohs(head1->count)*sizeof(*data1))
      { printf("Error: received %d bytes, needed %d\n", n,
               sizeof(*head1)+ntohs(head1->count)*sizeof(*data1));
        continue;
      }
      data1 = (struct data1 *)(head1+1);
      count=ntohs(head1->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data1[i].bytes);
        input=ntohs(data1[i].input);
        output=ntohs(data1[i].output);
        add_stat(remote_addr.sin_addr.s_addr,data1[i].srcaddr,data1[i].dstaddr,
                 1, 0, bytes, input, output, 0, 0, data1[i].prot,
		 data1[i].srcport, data1[i].dstport);
        add_stat(remote_addr.sin_addr.s_addr,data1[i].srcaddr,data1[i].dstaddr,
                 0, data1[i].nexthop, bytes, input, output, 0,0, data1[i].prot,
		 data1[i].srcport, data1[i].dstport);
      }
    }
    else if (ver==5)
    {
      if (n<sizeof(struct head5))
      { printf("Error: received %d bytes, needed %d\n", n, sizeof(*head5));
        continue;
      }
      head5 = (struct head5 *)buf;
#if 0
      printf("Ver=5, count=%u, uptime=%lu, curtime=%lu, seq=%lu\n",
             ntohs(head5->count), ntohl(head5->uptime), ntohl(head5->curtime),
             ntohl(head5->seq));
#endif
      if (n!=sizeof(*head5)+ntohs(head5->count)*sizeof(*data5))
      { printf("Error: received %d bytes, needed %d\n", n,
               sizeof(*head5)+ntohs(head5->count)*sizeof(*data5));
        continue;
      }
#if 0
      if (seq && seq!=ntohl(head5->seq))
        printf("Warning: seq mismatch (must %lu, real %lu)\n",
               seq, ntohl(head5->seq));
#endif
      seq = ntohl(head5->seq)+ntohs(head5->count);
      data5 = (struct data5 *)(head5+1);
      count=ntohs(head5->count);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output, src_as, dst_as;

        bytes=ntohl(data5[i].bytes);
        input=ntohs(data5[i].input);
        output=ntohs(data5[i].output);
        src_as=ntohs(data5[i].src_as);
        dst_as=ntohs(data5[i].dst_as);
        add_stat(remote_addr.sin_addr.s_addr,data5[i].srcaddr,data5[i].dstaddr,
                 1, 0, bytes, input, output, src_as, dst_as, data5[i].prot,
		 data5[i].srcport, data5[i].dstport);
        add_stat(remote_addr.sin_addr.s_addr,data5[i].srcaddr,data5[i].dstaddr,
                 0, data5[i].nexthop, bytes, input, output, src_as, dst_as,
                 data5[i].prot, data5[i].srcport, data5[i].dstport);
      }
    }
    else
    { printf("Error: unknown netflow version %d ignored\n", ver);
      continue;
    }
    if (last_write+write_interval<=time(NULL))
      write_stat();
    if (last_reload+reload_interval<=time(NULL))
      reload_acl();
  }
  unlink(pidfile);
  close(sockfd);
  return 0;
}

