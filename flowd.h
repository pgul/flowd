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
#define SHQSIZE		100000 /* pkts, bufsize ~16M */
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
	uint32_t ip, mask;
	uint32_t remote, remotemask;
	uint32_t nexthop;
	uint32_t src, srcmask, not;
	struct linktype *link;
	struct attrtype *next;
	int reverse, fallthru, in;
	uint16_t iface, liface, as, class, proto;
	uint16_t port1, port2, lport1, lport2;
};

#ifdef DO_SNMP
enum ifoid_t { IFNAME, IFDESCR, IFALIAS, IFIP };
#define NUM_OIDS (IFIP+1)
#endif

struct router_t {
  uint32_t addr;
#ifdef DO_SNMP
  char community[256];
  int  ifnumber;
  int  nifaces[NUM_OIDS];
  struct routerdata {
    uint16_t ifindex;
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
extern uint32_t bindaddr;
extern uint16_t port;
#if NBITS>0
extern int  reload_interval, fromshmem, fromacl;
extern char aclname[];
extern long mapkey;
extern char uaname[NCLASSES][32];
extern int  uaindex[NCLASSES];
#endif

void add_stat(uint32_t flowsrc, uint32_t srcaddr, uint32_t dstaddr, int in,
              uint32_t nexthop, uint32_t bytes,   uint16_t input, uint16_t output,
              uint16_t src_as,  uint16_t dst_as,  uint16_t proto,
              uint16_t srcport, uint16_t dstport, uint32_t pkts);
void write_stat(void);
int  config(char *name);
void debug(int level, char *format, ...);
void warning(char *format, ...);
void error(char *format, ...);
#if NBITS>0
int  find_mask(uint32_t addr);
int  reload_acl(void);
classtype getclass(uint32_t addr);
int  init_map(void);
void freeshmem(void);
#endif

#ifdef DO_PERL
void exitperl(void);
int  PerlStart(char *perlfile);
void plstart(void);
void plstop(void);
char *pl_recv_pkt(uint32_t *src, uint32_t *srcip, uint32_t *dstip, int *in,
                  uint32_t *nexthop, uint32_t *len, uint16_t *input, uint16_t *output,
                  uint16_t *src_as, uint16_t *dst_as, uint16_t *proto,
                  uint16_t *src_port, uint16_t *dst_port, uint32_t *pkts
#if NBITS>0
                  , uint16_t *src_class, uint16_t *dst_class
#endif
                 );
#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct, unsigned int bytes);
#else
void plwrite(char *user, unsigned int bytes_in, unsigned int bytes_out);
#endif
void perl_call(char *func, char **args);
void plcheckfuncs(void);

extern char perlfile[256], perlstart[256], perlwrite[256], perlstop[256];
extern char perlrcv[256];
#else
#define plstart()
#define plstop()
#define exitperl()
#if NBITS>0
#define plwrite(user, src, dst, direct, bytes)
#define pl_recv_pkt(src, srcip, dstip, in, nexthop, len, input, output, src_as, dst_as, proto, src_port, dst_port, pkts, src_class, dst_class)
#else
#define plwrite(user, bytes_in, bytes_out)
#define pl_recv_pkt(src, srcip, dstip, in, nexthop, len, input, output, src_as, dst_as, proto, src_port, dst_port, pkts)
#endif
#endif

#ifdef DO_MYSQL
extern char mysql_user[256], mysql_pwd[256], mysql_host[256];
extern char mysql_socket[256], mysql_db[256];
extern char mysql_table[256], mysql_utable[256], mysql_mtable[256];
extern char mysql_itable[256];
extern unsigned int mysql_port; 

void mysql_start(void);
#endif 

