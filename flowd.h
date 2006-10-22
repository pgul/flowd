#define CONFNAME	CONFDIR "/flowd.conf"
#define MTU		2048
#define PORT		741
#define LOGNAME		LOGDIR "/flow"
#define SNAPFILE	LOGDIR "/snap"
#define ACLNAME		CONFDIR "/flowd.acl"
#define PIDFILE		"/var/run/flowd.pid"
#define MAXLOST		3000 /* ~1000 packets */
#define MAXVRF		32
#define RECVBUF		262144
#define SHQSIZE		10000 /* pkts, bufsize ~2M */
#define WRITE_INTERVAL	(60*60)
#define RELOAD_INTERVAL	(60*10)
#define SNAP_TIME	60
#ifndef MAXPREFIX
#define MAXPREFIX       24
#endif
#ifndef NBITS
#define NBITS           2
#endif
#if NBITS>8
#define MAPSZIE		(1<<MAXPREFIX)*(NBITS/8)
#else
#define MAPSIZE         (1<<MAXPREFIX)/(8/NBITS)
#endif
#define MAPKEY          (*(long *)"gul@")

int flow_sem_init(void);
int flow_sem_init_poster(void);
int flow_sem_init_waiter(void);
int flow_sem_post(void);
int flow_sem_wait(void);
int flow_sem_zero(void);
int flow_sem_lock(void);
int flow_sem_unlock(void);
void flow_sem_destroy(void);

#if NBITS>8
typedef unsigned short classtype;
#else
typedef unsigned char classtype;
#endif
#define NCLASSES	(1<<NBITS)

#ifndef HAVE_SOCKLEN_T
  typedef int socklen_t;
#endif

struct linktype {
	char name[32];
#ifdef DO_MYSQL
	unsigned long user_id;
#endif
#if NBITS>0
	unsigned long bytes[2][NCLASSES][NCLASSES];
#else
	unsigned long bytes[2];
#endif
	struct linktype *next;
};

struct attrtype {
	u_long ip, mask;
	u_long remote, remotemask;
	u_long nexthop;
	u_long src, srcmask, not;
	struct linktype *link;
	struct attrtype *next;
	int reverse, fallthru, in;
	unsigned short iface, liface, as, class, proto;
	unsigned short port1, port2, lport1, lport2;
};

#ifdef DO_SNMP
enum ifoid_t { IFNAME, IFDESCR, IFALIAS, IFIP };
#define NUM_OIDS (IFIP+1)
#endif

struct router_t {
  u_long addr;
#ifdef DO_SNMP
  char community[256];
  int  ifnumber;
  int  nifaces[NUM_OIDS];
  struct routerdata {
    unsigned short ifindex;
    char *val;
  } *data[NUM_OIDS];
#endif
  unsigned seq[MAXVRF];
  struct attrtype *attrhead, *attrtail;
  struct router_t *next;
};

struct shqueue_t {
  u_long s_addr;
  int psize;
  char data[MTU];
};

#define SELFBUF		(sizeof(struct shqueue_t) * SHQSIZE)
#define SHBUFSIZE	(SELFBUF + 2 * sizeof(unsigned long))

extern struct router_t *routers;
extern time_t last_write, last_reload;
extern struct linktype *linkhead;
extern char logname[], snapfile[], pidfile[];
extern int write_interval;
extern int verbose, preproc;
extern unsigned long bindaddr;
extern unsigned short port;
#if NBITS>0
extern int  reload_interval, fromshmem, fromacl;
extern char aclname[];
extern long mapkey;
extern char uaname[NCLASSES][32];
extern int  uaindex[NCLASSES];
#endif

void add_stat(u_long flowsrc, u_long srcaddr, u_long dstaddr, int in,
              u_long nexthop, u_long bytes, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto,
              u_short srcport, u_short dstport);
void write_stat(void);
int  config(char *name);
void debug(int level, char *format, ...);
void warning(char *format, ...);
void error(char *format, ...);
#if NBITS>0
int  find_mask(unsigned long addr);
int  reload_acl(void);
classtype getclass(unsigned long addr);
int  init_map(void);
void freeshmem(void);
#endif

#ifdef DO_PERL
void exitperl(void);
int  PerlStart(char *perlfile);
void plstart(void);
void plstop(void);
char *pl_recv_pkt(u_long *src, u_long *srcip, u_long *dstip, int *in,
                  u_long *nexthop, u_long *len, u_short *input, u_short *output,
                  u_short *src_as, u_short *dst_as, u_short *proto,
                  u_short *src_port, u_short *dst_port
#if NBITS>0
                  , u_short *src_class, u_short *dst_class
#endif
                 );
#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct, unsigned int bytes);
#else
void plwrite(char *user, unsigned int bytes_in, unsigned int bytes_out);
#endif
void perl_call(char *file, char *func, char **args);

extern char perlfile[256], perlstart[256], perlwrite[256], perlstop[256];
extern char perlrcv[256];
#else
#define plstart()
#define plstop()
#if NBITS>0
#define plwrite(user, src, dst, direct, bytes)
#define pl_recv_pkt(src, srcip, dstip, in, nexthop, len, input, output, src_as, dst_as, proto, src_port, dst_port, src_class, dst_class)
#else
#define plwrite(user, bytes_in, bytes_out)
#define pl_recv_pkt(src, srcip, dstip, in, nexthop, len, input, output, src_as, dst_as, proto, src_port, dst_port)
#endif
#endif

#ifdef DO_MYSQL
extern char mysql_user[256], mysql_pwd[256], mysql_host[256];
extern char mysql_socket[256], mysql_db[256];
extern char mysql_table[256], mysql_utable[256], mysql_mtable[256];
extern char mysql_itable[256];
extern unsigned mysql_port; 

void mysql_start(void);
#endif 

