
#include <sys/types.h>
#include <stdint.h>
#include "flowd.h"

#ifdef WITH_THREADS
#include <pthread.h>

static pthread_cond_t cond;
static pthread_mutex_t mutex;

int flow_sem_init(void)
{
  pthread_mutex_init(&mutex, NULL);
  return pthread_cond_init(&cond, NULL);
}

int flow_sem_init_poster(void)
{
  return 0;
}

int flow_sem_init_waiter(void)
{
  return 0;
}

int flow_sem_post(void)
{
  return pthread_cond_signal(&cond);
}
 
int flow_sem_wait(void)
{
  int r;

  r = pthread_cond_wait(&cond, &mutex);
  pthread_mutex_unlock(&mutex);
  return r;
}

int flow_sem_zero(void)
{
  return pthread_mutex_lock(&mutex);
}

int flow_sem_lock(void)
{
  return pthread_mutex_lock(&mutex);
}

int flow_sem_unlock(void)
{
  return pthread_mutex_unlock(&mutex);
}

void flow_sem_destroy(void)
{
  pthread_mutex_destroy(&mutex);
  pthread_cond_destroy(&cond);
}

#elif defined(POSIX_SEM) && defined(WITH_RECEIVER) /* POSIX SEMAPHORES */

#include <semaphore.h>
#include <errno.h>

static sem_t sem;

int flow_sem_init(void)
{
  return sem_init(&sem, 1, 1);
}

int flow_sem_init_poster(void)
{
  return 0;
}

int flow_sem_init_waiter(void)
{
  return 0;
}

int flow_sem_post(void)
{
  return sem_post(&sem);
}

int flow_sem_wait(void)
{
  return sem_wait(&sem);
}

int flow_sem_zero(void)
{
  while (sem_trywait(&sem) == 0);
  return (errno == EAGAIN) ? 0 : -1;
}

int flow_sem_lock(void)
{
  return 0; /* sem_wait(&sem2); */
}

int flow_sem_unlock(void)
{
  return 0; /* sem_post(&sem2); */
}

void flow_sem_destroy(void)
{
  sem_destroy(&sem);
}

#elif defined(WITH_RECEIVER) /* signaling via unnamed pipe */

#include <unistd.h>
#include <fcntl.h>

static int hpipe[2];
static  char buf[16384];

int flow_sem_init(void)
{
  return pipe(hpipe);
}

int flow_sem_init_poster(void)
{
  close(hpipe[0]);
  hpipe[0] = -1;
  return 0;
}

int flow_sem_init_waiter(void)
{
  close(hpipe[1]);
  hpipe[1] = -1;
  return 0;
}

int flow_sem_post(void)
{
  fcntl(hpipe[1], F_SETFL, O_NONBLOCK);
  write(hpipe[1], "", 1);
  return 0;
}

int flow_sem_wait(void)
{
  fcntl(hpipe[0], F_SETFL, 0);
  read(hpipe[0], buf, sizeof(buf));
  return 0;
}

int flow_sem_zero(void)
{
  fcntl(hpipe[0], F_SETFL, O_NONBLOCK);
  while (read(hpipe[0], buf, sizeof(buf)) > 0);
  return 0;
}

int flow_sem_lock(void)
{
  return 0; /* sem_wait(&sem2); */
}

int flow_sem_unlock(void)
{
  return 0; /* sem_post(&sem2); */
}

void flow_sem_destroy(void)
{
  if (hpipe[1] != -1)
  { close(hpipe[1]);
    hpipe[1] = -1;
  }
}

#endif

