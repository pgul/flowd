#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef DO_PERL
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif
#endif
#include "flowd.h"

char perlfile[256], perlstart[256], perlwrite[256], perlstop[256];
PerlInterpreter *perl = NULL;

#ifndef pTHX_
#define pTHX_
#endif
#ifndef pTHX
#define pTHX
#endif

void boot_DynaLoader (pTHX_ CV *);

static void xs_init(pTHX)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

void exitperl(void)
{
  if (perl)
  {
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

int PerlStart(char *perlfile)
{
  int rc;
  char *perlargs[]={"", "", NULL};

  perlargs[1] = perlfile;
  if (access(perlfile, R_OK))
  { char errstr[256];
#ifdef HAVE_STRERROR_R
    strerror_r(errno, errstr, sizeof(errstr));
#elif defined(HAVE_SYS_ERRLIST)
    strncpy(errstr, sys_errlist[errno], sizeof(errstr));
#else
    /* strange segfault in strerror() on threaded perl */
    strncpy(errstr, strerror(errno), sizeof(errstr));
#endif
    errstr[sizeof(errstr)-1]='\0';
    printf("Can't read %s: %s\n", perlfile, errstr);
    return 1;
  }
  perl = perl_alloc();
  perl_construct(perl);
  rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
  if (rc)
  { printf("Can't parse %s", perlfile);
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
    return 1;
  }
  atexit(exitperl);
  return 0;
}

void plstart(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstart, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void plstop(void)
{
  STRLEN n_a;

  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlstop, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct, int bytes)
{
  SV *svsrc, *svdst, *svdirect, *svbytes;
#else
void plwrite(char *user, int bytes_in, int bytes_out)
{
  SV *svbytesin, *svbytesout;
#endif
  SV *svuser;
  STRLEN n_a;

  dSP;
  svuser     = perl_get_sv("user",      TRUE);
#if NBITS>0
  svsrc      = perl_get_sv("src",       TRUE);
  svdst      = perl_get_sv("dst",       TRUE);
  svbytes    = perl_get_sv("bytes",     TRUE);
  svdirect   = perl_get_sv("direction", TRUE);
  sv_setpv(svsrc,    src   );
  sv_setpv(svdst,    dst   );
  sv_setpv(svdirect, direct);
  sv_setiv(svbytes,  bytes );
#else
  svbytesin  = perl_get_sv("bytes_in",  TRUE);
  svbytesout = perl_get_sv("bytes_out", TRUE);
  sv_setiv(svbytesin,  bytes_in );
  sv_setiv(svbytesout, bytes_out);
#endif
  sv_setpv(svuser,   user  );
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  PUTBACK;
  perl_call_pv(perlwrite, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
}

void perl_call(char *file, const char *func, char **args)
{
  STRLEN n_a;

  if (PerlStart(file))
    return;
  dSP;
  ENTER;
  SAVETMPS;
  PUSHMARK(SP);
  while (*args)
  {
    XPUSHs(sv_2mortal(newSVpv(*args, 0)));
    args++;
  }
  PUTBACK;
  perl_call_pv(func, G_EVAL|G_SCALAR);
  SPAGAIN;
  PUTBACK;
  FREETMPS;
  LEAVE;
  if (SvTRUE(ERRSV))
  {
    printf("Perl eval error: %s\n", SvPV(ERRSV, n_a));
    exit(4);
  }
  exitperl();
}
