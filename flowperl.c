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

char perlfile[256], perlstart[256], perlwrite[256], perlstop[256], perlrcv[256];
PerlInterpreter *perl = NULL;
static int plstart_ok, plstop_ok, plwrite_ok, plrcv_ok;

#ifndef pTHX_
#define pTHX_
#endif
#ifndef pTHX
#define pTHX
#endif

void boot_DynaLoader (pTHX_ CV *);

static void perl_warn_str(char *str)
{
  while (str && *str)
  { char *cp = strchr (str, '\n');
    char c  = 0;
    if (cp)
    { c = *cp;
      *cp = 0;
    }
    error("Perl error: %s", str);
    if (!cp)
      break;
    *cp = c;
    str = cp + 1;
  }
}

static void perl_warn_sv (SV *sv)
{ STRLEN n_a;
  char *str = (char *)SvPV(sv, n_a);
  perl_warn_str(str);
}

static XS(perl_warn)
{
  dXSARGS;
  if (items == 1) perl_warn_sv(ST(0));
    XSRETURN_EMPTY;
}

/* handle multi-line perl eval error message */
static void sub_err(char *sub)
{
  STRLEN len;
  char *s, *p;
  p = SvPV(ERRSV, len);
  if (len)
  { s = malloc(len+1);
    strncpy(s, p, len);
    s[len] = '\0';
  }
  else
    s = strdup("(empty error message)");
  if ((p = strchr(s, '\n')) == NULL || p[1] == '\0')
  { if (p) *p = '\0';
    error("Perl %s error: %s", sub, s);
  }
  else
  {
    error("Perl %s error below:", sub);
    while ( *p && (*p != '\n' || *(p+1)) )
    { char *r = strchr(p, '\n');
      if (r)
      { *r = 0;
        error("  %s", p);
        p = r + 1;
      }
      else
      {
        error("  %s", p);
        break;
      }
    }
  }
  free(s);
}

static void xs_init(pTHX)
{
  static char *file = __FILE__;
  dXSUB_SYS;
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
  newXS("flowd_warn", perl_warn, file);
}

void exitperl(void)
{
  if (perl)
  {
    perl_destruct(perl);
    perl_free(perl);
#ifdef PERL_SYS_TERM
    PERL_SYS_TERM();
#endif
    perl=NULL;
  }
}

int PerlStart(char *perlfile)
{
  const char *perlargs[]={"flowd", "-e", "0", NULL};
  char **argv = (char **)perlargs;
  char cmd[256];
  SV *sv;
  char **env  = { NULL };
  struct stat spfile;
  static struct stat sperlfile;

  if (access(perlfile, R_OK) || stat(perlfile, &spfile))
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
    warning("Can't read %s: %s", perlfile, errstr);
    return 1;
  }
  spfile.st_atime = spfile.st_mtime;
  if (perl && memcmp(&spfile, &sperlfile, sizeof(spfile)) == 0)
  { /* no changes - not needed to reload perl file */
    return 0;
  }
  memcpy(&sperlfile, &spfile, sizeof(spfile));

  if (!perl)
  {
    perl = perl_alloc();
    perl_construct(perl);
#ifdef PERL_EXIT_DESTRUCT_END
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif
    if (perl_parse(perl, xs_init, 3, argv, env))
    { warning("Can't parse %s", perlfile);
      exitperl();
      return 1;
    }
    /* Set warn and die hooks */
    if (PL_warnhook) SvREFCNT_dec (PL_warnhook);
    if (PL_diehook ) SvREFCNT_dec (PL_diehook );
    PL_warnhook = newRV_inc ((SV*) perl_get_cv ("flowd_warn", TRUE));
    PL_diehook  = newRV_inc ((SV*) perl_get_cv ("flowd_warn", TRUE));
    debug(2, "PerlStart: perl alloc and construct ok");
  }
  /* run main program body */
  snprintf(cmd, sizeof(cmd), "do '%s'; $@ ? $@ : '';", perlfile);
  sv = perl_eval_pv (cmd, TRUE);
  if (!SvPOK(sv)) {
    error("Syntax error in internal perl expression: %s", cmd);
    return 0;
  } else if (SvTRUE (sv)) {
    perl_warn_sv (sv);
    return 0;
  }
  debug(2, "PerlStart(%s) ok", perlfile);
  return 0;
}

void plcheckfuncs(void)
{
  if (!perl) return;
  plstart_ok = plstop_ok = plwrite_ok = plrcv_ok = 0;
  if (perl_get_cv(perlstart, FALSE)) plstart_ok = 1;
  if (perl_get_cv(perlstop,  FALSE)) plstop_ok  = 1;
  if (perl_get_cv(perlwrite, FALSE)) plwrite_ok = 1;
  if (perl_get_cv(perlrcv,   FALSE)) plrcv_ok   = 1;
}

void plstart(void)
{
  if (perl && plstart_ok)
  {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(perlstart, G_EVAL|G_DISCARD|G_NOARGS);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      sub_err("startwrite");
  }
}

void plstop(void)
{
  if (perl && plstop_ok)
  {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(perlstop, G_EVAL|G_DISCARD|G_NOARGS);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      sub_err("stopwrite");
  }
}

#if NBITS>0
void plwrite(char *user, char *src, char *dst, char *direct, unsigned int bytes)
{
  SV *svsrc, *svdst, *svdirect, *svbytes;
#else
void plwrite(char *user, unsigned int bytes_in, unsigned int bytes_out)
{
  SV *svbytesin, *svbytesout;
#endif
  SV *svuser;

  if (perl && plwrite_ok)
  {
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
    sv_setuv(svbytes,  bytes );
#else
    svbytesin  = perl_get_sv("bytes_in",  TRUE);
    svbytesout = perl_get_sv("bytes_out", TRUE);
    sv_setuv(svbytesin,  bytes_in );
    sv_setuv(svbytesout, bytes_out);
#endif
    sv_setpv(svuser,   user  );
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(perlwrite, G_EVAL|G_DISCARD|G_NOARGS);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      sub_err("writetraf");
  }
}

char *pl_recv_pkt(u_long *src, u_long *srcip, u_long *dstip, int *in,
                  u_long *nexthop, u_long *len, u_short *input, u_short *output,
                  u_short *src_as, u_short *dst_as, u_short *proto,
                  u_short *src_port, u_short *dst_port, u_long *pkts
#if NBITS>0
                  , u_short *src_class, u_short *dst_class
#endif
                 )
{
  u_long addr;
  char *prc, *p;
  static char pr[256];
  struct protoent *pe;
  STRLEN n_a;
  SV *svsrc, *svsrcip, *svdstip, *svin, *svnexthop, *svlen, *svinput, *svoutput;
  SV *svsrc_as, *svdst_as, *svproto, *svsrc_port, *svdst_port, *svret;
#if NBITS>0
  SV *svsrc_class, *svdst_class;
#endif

  prc = NULL;

  if (perl && plrcv_ok)
  {
    dSP;
    svsrc       = perl_get_sv("router",    TRUE);
    svsrcip     = perl_get_sv("srcip",     TRUE);
    svdstip     = perl_get_sv("dstip",     TRUE);
    svin        = perl_get_sv("direction", TRUE);
    svnexthop   = perl_get_sv("nexthop",   TRUE);
    svlen       = perl_get_sv("len",       TRUE);
    svinput     = perl_get_sv("input",     TRUE);
    svoutput    = perl_get_sv("output",    TRUE);
    svsrc_as    = perl_get_sv("src_as",    TRUE);
    svdst_as    = perl_get_sv("dst_as",    TRUE);
    svproto     = perl_get_sv("proto",     TRUE);
    svsrc_port  = perl_get_sv("src_port",  TRUE);
    svdst_port  = perl_get_sv("dst_port",  TRUE);
#if NBITS>0
    svsrc_class = perl_get_sv("src_class", TRUE);
    svdst_class = perl_get_sv("dst_class", TRUE);
#endif
    sv_setpv(svsrc,       inet_ntoa(*(struct in_addr *)src));
    sv_setpv(svsrcip,     inet_ntoa(*(struct in_addr *)srcip));
    sv_setpv(svdstip,     inet_ntoa(*(struct in_addr *)dstip));
    sv_setpv(svin,        (*in ? "in" : "out"));
    sv_setpv(svnexthop,   inet_ntoa(*(struct in_addr *)nexthop));
    sv_setuv(svlen,       *len      );
    sv_setuv(svinput,     *input    );
    sv_setuv(svoutput,    *output   );
    sv_setuv(svsrc_as,    ntohs(*src_as));
    sv_setuv(svdst_as,    ntohs(*dst_as));
    pe = getprotobynumber(*proto);
    if (pe) sv_setpv(svproto, pe->p_name);
    else    sv_setuv(svproto, *proto);
    sv_setuv(svsrc_port,  ntohs(*src_port));
    sv_setuv(svdst_port,  ntohs(*dst_port));
#if NBITS>0
    sv_setpv(svsrc_class, uaname[uaindex[*src_class]]);
    sv_setpv(svdst_class, uaname[uaindex[*dst_class]]);
#endif
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(perlrcv, G_EVAL|G_SCALAR|G_NOARGS);
    SPAGAIN;
    svret=POPs;
    if (SvTRUE(svret))
      prc = strdup(SvPV(svret, n_a));
    else
      prc = NULL;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      sub_err("recv_pkt");
    else 
    { if (n_a == 0 && prc)
      { free(prc);
        prc = NULL;
      }
      if (prc)
      {
        strncpy(pr, prc, sizeof(pr)-1);
        pr[sizeof(pr)-1] = '\0';
        free(prc);
      }
      /* update variables */
      p = SvPV(perl_get_sv("router", FALSE), n_a);
      if (n_a && p && inet_aton(p, (struct in_addr *)&addr) != -1) *src = addr;
      p = SvPV(perl_get_sv("srcip", FALSE), n_a);
      if (n_a && p && inet_aton(p, (struct in_addr *)&addr)) *srcip = addr;
      p = SvPV(perl_get_sv("dstip", FALSE), n_a);
      if (n_a && p && inet_aton(p, (struct in_addr *)&addr)) *dstip = addr;
      p = SvPV(perl_get_sv("direction", FALSE), n_a);
      if (n_a && p) {
        if (strcmp(p, "in") == 0) *in = 1;
        else if (strcmp(p, "out") == 0) *in = 0;
      }
      p = SvPV(perl_get_sv("nexthop", FALSE), n_a);
      if (n_a && p && inet_aton(p, (struct in_addr *)&addr)) *nexthop = addr;
      p = SvPV(perl_get_sv("len", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *len = atol(p);
      p = SvPV(perl_get_sv("input", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *input = atoi(p);
      p = SvPV(perl_get_sv("output", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *output = atoi(p);
      p = SvPV(perl_get_sv("src_as", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *src_as = atoi(p);
      p = SvPV(perl_get_sv("dst_as", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *src_as = atoi(p);
      p = SvPV(perl_get_sv("proto", FALSE), n_a);
      if (n_a && p)
      {
        if ((pe = getprotobyname(p)) != NULL)
          *proto = pe->p_proto;
        else if (isdigit(*p))
          *proto = atoi(p);
      }
      p = SvPV(perl_get_sv("src_port", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *src_port = atoi(p);
      p = SvPV(perl_get_sv("dst_port", FALSE), n_a);
      if (n_a && p && isdigit(*p)) *dst_port = atoi(p);
#if NBITS>0
      p = SvPV(perl_get_sv("src_class", FALSE), n_a);
      if (n_a && p && strcmp(p, uaname[uaindex[*src_class]]))
      { int i;
        for (i=0; i<NCLASSES; i++)
        { if (uaindex[i]==i && strcmp(p, uaname[i]) == 0)
          { *src_class = i;
            break;
          }
        }
      }
      p = SvPV(perl_get_sv("dst_class", FALSE), n_a);
      if (n_a && p && strcmp(p, uaname[uaindex[*dst_class]]))
      { int i;
        for (i=0; i<NCLASSES; i++)
        { if (uaindex[i]==i && strcmp(p, uaname[i]) == 0)
          { *dst_class = i;
            break;
          }
        }
      }
#endif
    }
  }
  return prc ? pr : NULL;
}

void perl_call(char *func, char **args)
{
  STRLEN n_a;
  SV *sv;

  sv = perl_eval_pv ("$|=1; '';", TRUE);
  if (!SvPOK(sv)) {
    error("Syntax error in internal perl expression");
    return;
  } else if (SvTRUE (sv)) {
    perl_warn_sv (sv);
    return;
  }
  {
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
    perl_call_pv(func, G_DISCARD);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (SvTRUE(ERRSV))
      warning("Perl eval error: %s", SvPV(ERRSV, n_a));
  }
}
