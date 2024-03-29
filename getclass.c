#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "flowd.h"

static classtype *map;
static int shmid=-1;

classtype getclass(uint32_t addr)
{
#if NBITS>=8
	return map[addr];
#else
	unsigned char bits, mask;
	addr >>= (32-MAXPREFIX);
	bits = (addr%(8/NBITS))*NBITS;
	mask = (0xff >> (8-NBITS))<<bits;
	addr /= (8/NBITS);
	return (map[addr] & mask) >> bits;;
#endif
}

void freeshmem(void)
{
	struct shmid_ds buf;
	if (map)
	{	shmdt(map);
		map = NULL;
	}
	if (shmid != -1)
		if (shmctl(shmid, IPC_STAT, &buf) == 0)
			if (buf.shm_nattch == 0)
			{	shmctl(shmid, IPC_RMID, &buf);
				shmid = -1;
			}
}

int init_map(void)
{
	if (map) return 1;
	if (shmid==-1)
	{
		atexit(freeshmem);
		shmid = shmget(mapkey, MAPSIZE, 0444);
	}
	if (shmid != -1)
		map = shmat(shmid, NULL, SHM_RDONLY);
	if (map==NULL) return 1;
	return 0;
}

