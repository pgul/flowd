#define CONFNAME	CONFDIR "/flowd.conf"
#define MTU		2048
#define PORT		741
#define LOGNAME		LOGDIR "/flow"
#define SNAPFILE	LOGDIR "/snap"
#define ACLNAME		CONFDIR "/flowd.acl"
#define PIDFILE		"/var/run/flowd.pid"
#define WRITE_INTERVAL	(60*60)
#define RELOAD_INTERVAL	(60*10)
#define MAXMACS		(16*256) /* size of hash-table */
#define MAXCOLOIP	16
#define MAXPREFIX       24

#define NBITS           4
#define MAPSIZE         (1<<MAXPREFIX)/(8/NBITS)
#define MAPKEY          (*(long *)"gul@")

#if NBITS>8
typedef unsigned short classtype;
#else
typedef unsigned char classtype;
#endif
#define NCLASSES	(1<<NBITS)

struct linktype {
	char name[32];
	unsigned long bytes[2][NCLASSES][NCLASSES];
	struct linktype *next;
};

struct attrtype {
	u_long ip, mask;
	u_long nexthop;
	u_long src, srcmask, not;
	struct linktype *link;
	struct attrtype *next;
	int reverse, fallthru;
	unsigned short iface, as, class, proto;
};

extern struct attrtype *attrhead;

extern time_t last_write, last_reload;
extern struct linktype *linkhead;
extern char logname[], snapfile[], aclname[], pidfile[];
extern int write_interval, reload_interval;
extern int fromshmem;
extern unsigned long bindaddr;
extern unsigned short port;
extern long mapkey;
extern char uaname[NCLASSES][32];
extern int  uaindex[NCLASSES];

int  find_mask(unsigned long addr);
int  reload_acl(void);
void add_stat(u_long flowsrc, u_long srcaddr, u_long dstaddr, int in,
              u_long nexthop, u_long bytes, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto);
void write_stat(void);
int  config(char *name);
classtype getclass(unsigned long addr);
int  init_map(void);
void freeshmem(void);
