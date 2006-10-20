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
#include <syslog.h>
#include <stdarg.h>
#ifdef WITH_THREADS
#include <pthread.h>
#elif defined(WITH_RECEIVER)
#include <sys/ipc.h>
#include <sys/shm.h>
#endif
#include "flowd.h"

int  sockfd, verbose, preproc;
time_t last_write, last_reload, snap_start;
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

#if defined(WITH_RECEIVER)
static struct shqueue_t *shq;
#ifdef WITH_THREADS
static u_long shq_head, shq_tail;
static pthread_t recv_tid;
#else
#define shq_head (*(u_long *)shbuf)
#define shq_tail (*((u_long *)shbuf+1))
static pid_t child_pid;
static int shbufid;
static void *shbuf;
#endif
#endif

static void exitfunc(void)
{
#ifdef WITH_THREADS
  flow_sem_destroy();
#elif defined(WITH_RECEIVER)
  struct shmid_ds buf;

  flow_sem_lock();
  if (shbufid != -1) {
    if (shbuf) {
      shq = NULL;
      shmdt(shbuf);
      shbuf = NULL;
    }
    if (shmctl(shbufid, IPC_STAT, &buf) == 0)
      if (buf.shm_nattch == 0)
        shmctl(shbufid, IPC_RMID, &buf);
    shbufid = -1;
  }
  flow_sem_unlock();
  if (child_pid && child_pid != -1) {
    kill(child_pid, SIGTERM);
    child_pid = -1;
  }
#endif
}

static void hup(int signo)
{
#if defined(WITH_RECEIVER) && !defined(WITH_THREADS)
  if (shq && child_pid == 0) {
    debug(1, "Received signal %u, exiting", signo);
    exitfunc();
    exit(0);
  }
#endif
  if (signo==SIGHUP || signo==SIGTERM || signo==SIGINT || signo==SIGALRM)
    write_stat();
  if (signo==SIGTERM)
  { unlink(pidfile);
    exitfunc();
    exit(0);
  }
#if NBITS>0
  if (signo==SIGUSR1)
    reload_acl();
#endif
  if (signo==SIGHUP)
    if (config(confname))
    { error("Config error, exiting!");
      exitfunc();
      exit(1);
    }
  if (signo==SIGUSR2)
  { /* snap traffic during SNAP_TIME */
    time_t curtime;

    curtime=time(NULL);
    if (fsnap)
    { fclose(fsnap);
      fsnap=fopen(snapfile, "a");
    } else
    { fsnap=fopen(snapfile, "a");
      if (fsnap==NULL)
        warning("Cannot open %s: %s", snapfile, strerror(errno));
      else
        fprintf(fsnap, "\n\n----- %s\n", ctime(&curtime));
    }
    if (fsnap) snap_start=curtime;
  }
  if (signo==SIGINT)
  { /* restart myself */
    close(sockfd);
    unlink(pidfile);
    exitfunc();
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
  printf("flowd [-d] [-v] [-E] [config]\n");
  printf("  -d          - daemonize\n");
  printf("  -v          - increase verbose level\n");
  printf("  -E          - dump preprocessed config and exit\n");
  return 0;
}

static int queue2buf(u_long *s_addr, char **buf, int *len)
{
  socklen_t sl;
  struct sockaddr_in remote_addr;
  int n;
  static char databuf[MTU];

#if defined(WITH_RECEIVER)
  if (shq == NULL) {
#endif
    sl=sizeof(remote_addr);
    memset(&remote_addr, 0, sizeof(remote_addr)),
    n = recvfrom(sockfd, databuf, sizeof(databuf), 0, (struct sockaddr *)&remote_addr, &sl);
    if (n == -1) return -1;
    *s_addr = remote_addr.sin_addr.s_addr;
    *len = n;
    *buf = databuf;
    return 0;
#if defined(WITH_RECEIVER)
  }
  flow_sem_zero();
  if (shq_head == shq_tail) {
    flow_sem_wait();
    if (shq_head == shq_tail) {
      *len = 0;
      return 0;
    }
  }
  *s_addr = shq[shq_tail].s_addr;
  *len = shq[shq_tail].psize;
  *buf = shq[shq_tail].data;
  if (shq_tail == SHQSIZE - 1)
    shq_tail = 0;
  else
    shq_tail++;
  return 0;
#endif
}

#if defined(WITH_THREADS) || defined(WITH_RECEIVER)
static int buf2queue(u_long s_addr, int n, char *buf)
{
  u_long newhead = (shq_head + 1) % SHQSIZE;

  if (newhead == shq_tail) {
    warning("shared buffed full (too slow cpu?)");
    return -1;
  }
  shq[shq_head].s_addr = s_addr;
  shq[shq_head].psize = n;
  memcpy(shq[shq_head].data, buf, n);
  flow_sem_lock();
  shq_head = newhead;
  flow_sem_post();
  flow_sem_unlock();
  return 0;
}

static void *recvpkts(void *args)
{
  socklen_t sl;
  struct sockaddr_in remote_addr;
  int n;
  char buf[MTU];

  while ((sl=sizeof(remote_addr),
         memset(&remote_addr, 0, sizeof(remote_addr)),
         n=recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&remote_addr, &sl)) != -1) {
    if (n == 0) continue;
    buf2queue(remote_addr.sin_addr.s_addr, n, buf);
  }
  warning("recvfrom error: %s", strerror(errno));
  return NULL;
}
#endif

int main(int argc, char *argv[])
{
  int  n, i, count, ver, daemonize;
  socklen_t sl;
  FILE *f;
  struct sockaddr_in my_addr;
  char *pbuf;
  u_long s_addr;

  confname=CONFNAME;
  daemonize=0;

  while ((i=getopt(argc, argv, "dh?vE")) != -1)
  {
    switch (i)
    {
      case 'd': daemonize=1; break;
      case 'v': verbose++;   break;
      case 'E': preproc=1;   break;
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
  if (preproc)
    return 0;
  if ((sockfd=socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  { printf("socket: %s\n", strerror(errno));
    return 1;
  }
#ifdef SO_RCVBUF
  sl = sizeof(i);
  if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &i, &sl))
    printf("getsockopt rcvbuf failed: %s\n", strerror(errno));
  else
    debug(1, "recv buffer size %u", i);
  i = RECVBUF;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &i, sizeof(i)))
    printf("setsockopt rcvbuf failed: %s\n", strerror(errno));
  else
    debug(1, "set recv buffer size to %u", i);
#endif
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
#if NBITS>0
  signal(SIGUSR1, hup);
#endif
  signal(SIGUSR2, hup);
  signal(SIGINT,  hup);
  signal(SIGTERM, hup);
  signal(SIGALRM, hup);
#if NBITS>0
  if (reload_acl())
  { fprintf(stderr, "reload acl error!\n");
    /* return 1; */
  }
#endif
  if (daemonize && !verbose) daemon(0, 0);
  f=fopen(pidfile, "w");
  if (f)
  { fprintf(f, "%u\n", (unsigned)getpid());
    fclose(f);
  }
  openlog("flowd", LOG_PID, LOG_DAEMON);
#ifdef WITH_THREADS
  if (flow_sem_init() == 0) {
    shq = calloc(SHQSIZE, sizeof(*shq));
  } else {
    warning("Can't create semaphore: %s", strerror(errno));
  }
  if (shq != NULL) {
    if (pthread_create(&recv_tid, NULL, recvpkts, NULL))
    {
      warning("Can't create thread: %s", strerror(errno));
      free(shq);
      shq = NULL;
    }
  }
#elif defined(WITH_RECEIVER)
  shbufid = -1;
  if (flow_sem_init() == 0) {
    key_t key = *(unsigned long *)"flow"; /* or IPC_PRIVATE? */
    shbufid = shmget(key, SHBUFSIZE, IPC_CREAT|0600);
    if (shbufid == -1) {
      warning("Can't allocate %u bytes of shared memory: %s", SHBUFSIZE, strerror(errno));
    }
  } else {
    warning("Can't create semaphore: %s", strerror(errno));
  }
  if (shbufid != -1) {
    shbuf =  shmat(shbufid, NULL, 0);
    if (shbuf == NULL) {
      exitfunc();
    } else {
      shq = (struct shqueue_t *)((u_long *)shbuf + 2);
    }
  }
  if (shbufid != -1) {
    child_pid = fork();
    if (child_pid == -1) {
      exitfunc();
    } else if (child_pid == 0) {
      flow_sem_init_poster();
      recvpkts(NULL);
      exitfunc();
      exit(0);
    } else {
      flow_sem_init_waiter();
      close(sockfd);
    }
  }
#endif
  while (queue2buf(&s_addr, &pbuf, &n) == 0)
  {
    if (n==0) continue;
    ver = ntohs(*(short int *)pbuf);
    if (ver==1)
    {
      if (n<sizeof(struct head1))
      { warning("Error: received %d bytes, needed %d", n, sizeof(*head1));
        continue;
      }
      head1 = (struct head1 *)pbuf;
#if 0
      printf("Ver=1, count=%u, uptime=%lu, curtime=%lu, seq=%lu\n",
             ntohs(head1->count), ntohl(head1->uptime), ntohl(head1->curtime),
             ntohl(head1->seq));
#endif
      if (n!=sizeof(*head1)+ntohs(head1->count)*sizeof(*data1))
      { warning("Error: received %d bytes, needed %d", n,
               sizeof(*head1)+ntohs(head1->count)*sizeof(*data1));
        continue;
      }
      data1 = (struct data1 *)(head1+1);
      count=ntohs(head1->count);
#if defined(WITH_RECEIVER)
      flow_sem_lock();
      i = shq ? (shq_head + SHQSIZE - shq_tail) % SHQSIZE : 0;
      flow_sem_unlock();
      debug(4, "Received %u v1-flows from %s (queue %u)",
            count, inet_ntoa(*(struct in_addr *)(void *)&s_addr), i);
#else
      debug(4, "Received %u v1-flows from %s",
            count, inet_ntoa(*(struct in_addr *)(void *)&s_addr));
#endif
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output;

        bytes=ntohl(data1[i].bytes);
        input=ntohs(data1[i].input);
        output=ntohs(data1[i].output);
        add_stat(s_addr, data1[i].srcaddr, data1[i].dstaddr,
                 1, 0, bytes, input, output, 0, 0, data1[i].prot,
                 data1[i].srcport, data1[i].dstport);
        add_stat(s_addr, data1[i].srcaddr, data1[i].dstaddr,
                 0, data1[i].nexthop, bytes, input, output, 0,0, data1[i].prot,
                 data1[i].srcport, data1[i].dstport);
      }
    }
    else if (ver==5)
    {
      struct router_t *pr;

      if (n<sizeof(struct head5))
      { warning("Error: received %d bytes, needed %d", n, sizeof(*head5));
        continue;
      }
      head5 = (struct head5 *)pbuf;
#if 0
      printf("Ver=5, count=%u, uptime=%lu, curtime=%lu, seq=%lu\n",
             ntohs(head5->count), ntohl(head5->uptime), ntohl(head5->curtime),
             ntohl(head5->seq));
#endif
      if (n!=sizeof(*head5)+ntohs(head5->count)*sizeof(*data5))
      { warning("Error: received %d bytes, needed %d", n,
               sizeof(*head5)+ntohs(head5->count)*sizeof(*data5));
        continue;
      }
      count=ntohs(head5->count);
#if 1
      /* check seq */
      for (pr=routers; pr; pr=pr->next)
        if (pr->addr == s_addr)
          break;
#if 0
      if (pr == NULL && routers->addr == (u_long)-1 && routers->next == NULL)
        pr = routers; /* single router accepts all flows -- MB single source? */
#endif
#if defined(WITH_RECEIVER)
      flow_sem_lock();
      i = shq ? (shq_head + SHQSIZE - shq_tail) % SHQSIZE : 0;
      flow_sem_unlock();
      debug(4, "Received %u flows from %s (seq %lu, queue %u)",
            count, inet_ntoa(*(struct in_addr *)(void *)&s_addr), ntohl(head5->seq), i);
#else
      debug(4, "Received %u flows from %s (seq %lu)",
            count, inet_ntoa(*(struct in_addr *)(void *)&s_addr), ntohl(head5->seq));
#endif
      if (pr) {
        unsigned seq = ntohl(head5->seq);
        for (i=0; i<MAXVRF; i++)
          if (pr->seq[i] == seq || pr->seq[i] == 0) break;
        if (pr->seq[i] != seq) {
          for (i=0; i<MAXVRF; i++) {
            if (pr->seq[i] == 0) break;
            if (seq - pr->seq[i] <= MAXLOST) {
#if defined(WITH_RECEIVER)
              u_long qfill;
              flow_sem_lock();
              qfill = shq ? (shq_head + SHQSIZE - shq_tail) % SHQSIZE : 0;
              flow_sem_unlock();
              warning("warning: lost %u flows (%u packets) from %s, qsize %lu",
                      seq - pr->seq[i], (seq - pr->seq[i]) / count,
                      inet_ntoa(*(struct in_addr *)(void *)&s_addr), qfill);
#else
              warning("warning: lost %u flows (%u packets) from %s",
                      seq - pr->seq[i], (seq - pr->seq[i]) / count,
                      inet_ntoa(*(struct in_addr *)(void *)&s_addr));
#endif
              break;
            }
          }
          if (i == MAXVRF) {
            warning("Bad seq counter. Too many lost packets or vrfs?");
            i = random() % MAXVRF;
          }
        }
        if (i > 0)
          memmove(pr->seq + 1, pr->seq, sizeof(pr->seq[0]) * i);
        pr->seq[0] = seq + count;
      }
#endif
      data5 = (struct data5 *)(head5+1);
      for (i=0; i<count; i++)
      {
        unsigned long bytes;
        unsigned short input, output, src_as, dst_as;

        bytes=ntohl(data5[i].bytes);
        input=ntohs(data5[i].input);
        output=ntohs(data5[i].output);
        src_as=ntohs(data5[i].src_as);
        dst_as=ntohs(data5[i].dst_as);
        add_stat(s_addr, data5[i].srcaddr, data5[i].dstaddr,
                 1, 0, bytes, input, output, src_as, dst_as, data5[i].prot,
                 data5[i].srcport, data5[i].dstport);
        add_stat(s_addr, data5[i].srcaddr, data5[i].dstaddr,
                 0, data5[i].nexthop, bytes, input, output, src_as, dst_as,
                 data5[i].prot, data5[i].srcport, data5[i].dstport);
      }
    }
    else
    { warning("Error: unknown netflow version %d ignored", ver);
      continue;
    }
    if (last_write+write_interval<=time(NULL))
      write_stat();
#if NBITS>0
    if (last_reload+reload_interval<=time(NULL))
      reload_acl();
#endif
  }
#if defined(WITH_RECEIVER) && !defined(WITH_THREADS)
  if (shq)
#endif
    close(sockfd);
  exitfunc();
  unlink(pidfile);
  return 0;
}

void warning(char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(LOG_WARNING, format, ap);
  va_end(ap);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(ap);
}

void error(char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsyslog(LOG_ERR, format, ap);
  va_end(ap);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  va_end(ap);
}

