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

#if NBITS>8
typedef unsigned short classtype;
#else
typedef unsigned char classtype;
#endif
#define NCLASSES	(1<<NBITS)

struct linktype {
	char name[32];
#ifdef DO_MYSQL
	unsigned long user_id;
#endif
	unsigned long bytes[2][NCLASSES][NCLASSES];
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
	unsigned short iface, as, class, proto;
	unsigned short port1, port2, lport1, lport2;
	u_long router;
};

extern struct attrtype *attrhead;
extern time_t last_write, last_reload;
extern struct linktype *linkhead;
extern char logname[], snapfile[], aclname[], pidfile[];
extern int write_interval, reload_interval;
extern int fromshmem, fromacl, verbose;
extern unsigned long bindaddr;
extern unsigned short port;
extern long mapkey;
extern char uaname[NCLASSES][32];
extern int  uaindex[NCLASSES];

int  find_mask(unsigned long addr);
int  reload_acl(void);
void add_stat(u_long flowsrc, u_long srcaddr, u_long dstaddr, int in,
              u_long nexthop, u_long bytes, u_short input, u_short output,
              u_short src_as, u_short dst_as, u_short proto,
              u_short srcport, u_short dstport);
void write_stat(void);
int  config(char *name);
classtype getclass(unsigned long addr);
int  init_map(void);
void freeshmem(void);
void debug(int level, char *format, ...);

#ifdef DO_PERL
void exitperl(void);
int  PerlStart(char *perlfile);
void plstart(void);
void plstop(void);
void plwrite(char *user, char *src, char *dst, char *direct, int bytes);
void perl_call(char *file, const char *func, char **args);

extern char perlfile[256], perlstart[256], perlwrite[256], perlstop[256];
#else
#define plstart()
#define plstop()
#define plwrite(user, src, dst, direct, bytes)
#endif

#ifdef DO_MYSQL
extern char mysql_user[256], mysql_pwd[256], mysql_host[256];
extern char mysql_socket[256], mysql_db[256];
extern char mysql_table[256], mysql_utable[256], mysql_mtable[256];
extern char mysql_itable[256];
extern unsigned mysql_port; 

void mysql_start(void);
#endif 

