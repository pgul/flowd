#define NBITS		2	// 1..16, power of 2
#define MAXPREFIX	24	// 0..32, maximum processible prefix length
// WARNING: NBITS 16 and MAXPREFIX 32 requires 8G of shared memory!
// NBITS 1 and MAXPREFIX 24 - 2M
// Memory:  NBITS * 2^(MAXPREFIX-3)

#if (MAXPREFIX>24) && (NBITS * (1<<(MAXPREFIX-24)) >= 8*256)
#error Too large NBITS and MAXPREFIX
#endif

#define MAPSIZE (NBITS * (1<<(MAXPREFIX-3)))

#if NBITS>8
typedef ushort class_type;
#else
typedef char class_type;
#endif

extern class_type *map;
extern ulong mapkey;
