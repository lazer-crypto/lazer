#ifndef LAZER_H
#define LAZER_H

/**
 * \file   lazer.h
 * \brief  lazer's C interface.
 */

/* update on release. XXX */
#define LAZER_VERSION_MAJOR 0
#define LAZER_VERSION_MINOR 1
#define LAZER_VERSION_PATCH 0
#define LAZER_VERSION "0.1.0"

#if DEBUGINFO == DEBUGINFO_ENABLED
struct debuginfo
{
  int level;
  int print_function_entry;
  int print_function_return;
  int print_tocrt;
  int print_fromcrt;
  int print_rej;
};
extern struct debuginfo debug;

#define DEBUG_LEVEL debug.level
#define DEBUG_LEVEL_SET(_lvl_) debug.level = (_lvl_)
#define DEBUG_PRINT_REJ debug.print_rej
#define DEBUG_PRINT_REJ_START() debug.print_rej = 1
#define DEBUG_PRINT_REJ_STOP() debug.print_rej = 0
#define DEBUG_PRINT_TOCRT debug.print_tocrt
#define DEBUG_PRINT_TOCRT_START() debug.print_tocrt = 1
#define DEBUG_PRINT_TOCRT_STOP() debug.print_tocrt = 0
#define DEBUG_PRINT_FROMCRT debug.print_fromcrt
#define DEBUG_PRINT_FROMCRT_START() debug.print_fromcrt = 1
#define DEBUG_PRINT_FROMCRT_STOP() debug.print_fromcrt = 0
#define DEBUG_PRINT_FUNCTION_ENTRY debug.print_function_entry
#define DEBUG_PRINT_FUNCTION_ENTRY_START() debug.print_function_entry = 1
#define DEBUG_PRINT_FUNCTION_ENTRY_STOP() debug.print_function_entry = 0
#define DEBUG_PRINT_FUNCTION_RETURN debug.print_function_return
#define DEBUG_PRINT_FUNCTION_RETURN_START() debug.print_function_return = 1
#define DEBUG_PRINT_FUNCTION_RETURN_STOP() debug.print_function_return = 0

#define DEBUG_PRINTF(cnd, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      if (cnd)                                                                \
        printf ("DEBUG: " fmt "\n", __VA_ARGS__);                             \
    }                                                                         \
  while (0)
#else
#define DEBUG_LEVEL (void)0
#define DEBUG_LEVEL_SET(_lvl_) (void)(0)
#define DEBUG_PRINT_REJ (void)0
#define DEBUG_PRINT_REJ_START() (void)0
#define DEBUG_PRINT_REJ_STOP() (void)0
#define DEBUG_PRINT_TOCRT (void)0
#define DEBUG_PRINT_TOCRT_START() (void)0
#define DEBUG_PRINT_TOCRT_STOP() (void)0
#define DEBUG_PRINT_FROMCRT (void)0
#define DEBUG_PRINT_FROMCRT_START() (void)0
#define DEBUG_PRINT_FROMCRT_STOP() (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY_START() (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY_STOP() (void)0
#define DEBUG_PRINT_FUNCTION_RETURN (void)0
#define DEBUG_PRINT_FUNCTION_RETURN_START() (void)0
#define DEBUG_PRINT_FUNCTION_RETURN_STOP() (void)0
#define DEBUG_PRINTF(fmt, ...) (void)0
#endif

/********************************************************************
 * 1 Headers and defines
 */

#if __linux__

#define _OS_LINUX
#include <endian.h>

#elif __APPLE__

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE

#define _OS_IOS
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#include <strings.h>

#define explicit_bzero bzero

#define htobe16(x) OSSwapHostToBigInt16 (x)
#define htole16(x) OSSwapHostToLittleInt16 (x)
#define be16toh(x) OSSwapBigToHostInt16 (x)
#define le16toh(x) OSSwapLittleToHostInt16 (x)
#define htobe32(x) OSSwapHostToBigInt32 (x)
#define htole32(x) OSSwapHostToLittleInt32 (x)
#define be32toh(x) OSSwapBigToHostInt32 (x)
#define le32toh(x) OSSwapLittleToHostInt32 (x)
#define htobe64(x) OSSwapHostToBigInt64 (x)
#define htole64(x) OSSwapHostToLittleInt64 (x)
#define be64toh(x) OSSwapBigToHostInt64 (x)
#define le64toh(x) OSSwapLittleToHostInt64 (x)

#elif TARGET_OS_MAC

#define _OS_MACOS
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#include <strings.h>
#include <sys/random.h>

#define explicit_bzero bzero

#define htobe16(x) OSSwapHostToBigInt16 (x)
#define htole16(x) OSSwapHostToLittleInt16 (x)
#define be16toh(x) OSSwapBigToHostInt16 (x)
#define le16toh(x) OSSwapLittleToHostInt16 (x)
#define htobe32(x) OSSwapHostToBigInt32 (x)
#define htole32(x) OSSwapHostToLittleInt32 (x)
#define be32toh(x) OSSwapBigToHostInt32 (x)
#define le32toh(x) OSSwapLittleToHostInt32 (x)
#define htobe64(x) OSSwapHostToBigInt64 (x)
#define htole64(x) OSSwapHostToLittleInt64 (x)
#define be64toh(x) OSSwapBigToHostInt64 (x)
#define le64toh(x) OSSwapLittleToHostInt64 (x)

#endif

#else
#error "Unsupported platform"
#endif

#include <sys/cdefs.h> /* for __BEGIN_DECLS, __END_DECLS */

#include <stddef.h> /* for FILE */
#include <stdint.h> /* for exact-width int types */
#include <stdio.h>  /* for size_t */
#include <stdlib.h>
#include <string.h>

#if TARGET == TARGET_AMD64
#include <immintrin.h>
#include <x86intrin.h>
#endif

#include <gmp.h>

__BEGIN_DECLS

#define _ALIGN8 __attribute__ ((aligned (8)))
#define _ALIGN16 __attribute__ ((aligned (16)))
#define _ALIGN32 __attribute__ ((aligned (32)))
#define _ALIGN64 __attribute__ ((aligned (64)))

#define LIKELY(expr) __builtin_expect ((expr) != 0, 1)
#define UNLIKELY(expr) __builtin_expect ((expr) != 0, 0)
#define UNUSED __attribute__ ((unused))

#define BSWAP64(a) __builtin_bswap64 (a)
#define BSWAP(a) __builtin_bswap (a)

/* XXX allow 2^LOG2NADDS_CRTREP adds/subs in crt representation of polys */
#define LOG2NADDS_CRTREP 8

/* flags */
#define FZERO 1 /* object is zero */

/********************************************************************
 * 2 API types
 */

typedef struct
{
  uint64_t s[25];
  unsigned int pos;
  int final;
} shake128_state_struct;
typedef shake128_state_struct shake128_state_t[1];
typedef shake128_state_struct *shake128_state_ptr;
typedef const shake128_state_struct *shake128_state_srcptr;

typedef struct
{
#if TARGET == TARGET_GENERIC
  uint8_t expanded[4][60];
  uint8_t nonce[16];
  uint8_t cache[16];
  uint8_t *cache_ptr;
  unsigned int nbytes;
#elif TARGET == TARGET_AMD64
  __m128i rkeys[16];
  _ALIGN16 uint8_t n2[16];
  _ALIGN16 uint8_t cache[8 * 16]; /* LOOP (8) */
  uint8_t *cache_ptr;
  unsigned int nbytes;
#else
#error "Invalid target option."
#endif
} aes256ctr_state_struct;
typedef aes256ctr_state_struct aes256ctr_state_t[1];
typedef aes256ctr_state_struct *aes256ctr_state_ptr;
typedef const aes256ctr_state_struct *aes256ctr_state_srcptr;

typedef struct
{
#if RNG == RNG_SHAKE128
  shake128_state_t state;
#elif RNG == RNG_AES256CTR
  aes256ctr_state_t state;
#else
#error "Invalid rng option."
#endif
} rng_state_struct;
typedef rng_state_struct rng_state_t[1];
typedef rng_state_struct *rng_state_ptr;
typedef const rng_state_struct *rng_state_srcptr;

typedef uint64_t limb_t; /* XXX must match mp_limbt_t */
typedef int64_t crtcoeff_t;
#define CRTCOEFF_NBITS 64
#define CRTCOEFF_MAX INT64_MAX
typedef __int128 crtcoeff_dbl_t;

/*
 * 2^NBITS_LIMB bit signed integer
 */
typedef struct
{
  limb_t *limbs;
  unsigned int nlimbs;
  limb_t neg;
} int_struct;
typedef int_struct int_t[1];
typedef int_struct *int_ptr;
typedef const int_struct *int_srcptr;

/*
 * ECRT [1]:
 *
 * i in [0,s-1]
 *
 * precomputation:
 * P = prod(p[i]) product of moduli >= p[s-1]
 * Pp[i] = P/p[i]
 * k[i] * P/p[i] = 1 (mod p[i]), chose k[i] in [-(p[i]-1)/2,(p[i]-1)/2]
 *
 * computation:
 * x[i] = k[i] * u (mod p[i]), chose x[i] in [-(p[i]-1)/2,(p[i]-1)/2]
 * z = sum(x[i]/p[i])
 *
 * u = P * z - P * round(z) = sum(P/p[i] * x[i]) - P * round(z)
 *   = sum(Pp[i] * x[i]) - P * round(z)
 *
 * [1] https://cr.yp.to/papers.html#mmecrt
 */
typedef struct
{
  /* this modulus */
  const crtcoeff_t *roots;     /* in mont domain */
  const crtcoeff_t p;          /* modulus < 50 bit */
  const crtcoeff_t mont_pinv;  /* 1/p mod 2^32 */
  const crtcoeff_t mont_redr;  /* (2^32)^2 mod p, XXX needed ? == roots[0] */
  const crtcoeff_t intt_const; /* 1 / deg mod p */
  const crtcoeff_t m;          /* inverse of product of moduli > p mod p */
  /* product of moduli >= p */
  const int_srcptr P;
  const int_srcptr *Pp;
  const crtcoeff_t *k;
  const unsigned int nbits; /* bit-length */
} modulus_struct;
typedef modulus_struct modulus_t[1];
typedef modulus_struct *modulus_ptr;
typedef const modulus_struct *modulus_srcptr;

#include "src/moduli.h"

typedef struct
{
  /* allocated space (limbs||int structs)*/
  void *bytes;
  size_t nbytes;

  int_ptr elems;
  unsigned int nlimbs;
  unsigned int nelems;
  unsigned int stride_elems;
} intvec_struct;
typedef intvec_struct intvec_t[1];
typedef intvec_struct *intvec_ptr;
typedef const intvec_struct *intvec_srcptr;

typedef struct
{
  /* allocated space (limbs||ints structs)*/
  void *bytes;
  size_t nbytes;

  unsigned int cpr; /* cols per row */

  int_ptr elems;
  unsigned int nlimbs;

  unsigned int ncols;
  unsigned int stride_col;

  unsigned int nrows;
  unsigned int stride_row;
} intmat_struct;
typedef intmat_struct intmat_t[1];
typedef intmat_struct *intmat_ptr;
typedef const intmat_struct *intmat_srcptr;

typedef struct
{
  const int_srcptr q;       /* modulus */
  const unsigned int d;     /* degree */
  const unsigned int log2q; /* ceil(log(q-1)) bits represent int mod q */
  const unsigned int log2d; /* log(d) */

  const modulus_srcptr *moduli; /* crt moduli */
  const unsigned int nmoduli;   /* number of crt moduli */
  const int_srcptr Pmodq;
  const int_srcptr *Ppmodq;

  const int_srcptr inv2; /* 2^-1 mod q */
} polyring_struct;
typedef polyring_struct polyring_t[1];
typedef polyring_struct *polyring_ptr;
typedef const polyring_struct *polyring_srcptr;

typedef struct
{
  polyring_srcptr ring;

  intvec_ptr coeffs;
  crtcoeff_t *crtrep;

  void *mem;
  int crt;
  uint32_t flags;
} poly_struct;
typedef poly_struct poly_t[1];
typedef poly_struct *poly_ptr;
typedef const poly_struct *poly_srcptr;

typedef struct
{
  polyring_srcptr ring;

  poly_ptr elems;
  unsigned int nelems;
  unsigned int stride_elems;

  void *mem;
  uint32_t flags;
} polyvec_struct;
typedef polyvec_struct polyvec_t[1];
typedef polyvec_struct *polyvec_ptr;
typedef const polyvec_struct *polyvec_srcptr;

typedef struct
{
  polyring_srcptr ring;

  unsigned int cpr; /* cols per row */

  poly_ptr elems;

  unsigned int ncols;
  unsigned int stride_col;

  unsigned int nrows;
  unsigned int stride_row;

  void *mem;
  uint32_t flags;
} polymat_struct;
typedef polymat_struct polymat_t[1];
typedef polymat_struct *polymat_ptr;
typedef const polymat_struct *polymat_srcptr;

typedef struct
{
  poly_ptr poly;
  uint16_t elem;
} _spolyvec_struct;
typedef _spolyvec_struct _spolyvec_t[1];
typedef _spolyvec_struct *_spolyvec_ptr;
typedef const _spolyvec_struct *_spolyvec_srcptr;

typedef struct
{
  polyring_srcptr ring;
  unsigned int nelems_max;

  unsigned int nelems;
  _spolyvec_ptr elems;

  int sorted;
} spolyvec_struct;
typedef spolyvec_struct spolyvec_t[1];
typedef spolyvec_struct *spolyvec_ptr;
typedef const spolyvec_struct *spolyvec_srcptr;

typedef struct
{
  poly_ptr poly;
  uint16_t row;
  uint16_t col;
} _spolymat_struct;
typedef _spolymat_struct _spolymat_t[1];
typedef _spolymat_struct *_spolymat_ptr;
typedef const _spolymat_struct *_spolymat_srcptr;

typedef struct
{
  polyring_srcptr ring;
  unsigned int nrows;
  unsigned int ncols;
  unsigned int nelems_max;

  unsigned int nelems;
  _spolymat_ptr elems;

  int sorted;
} spolymat_struct;
typedef spolymat_struct spolymat_t[1];
typedef spolymat_struct *spolymat_ptr;
typedef const spolymat_struct *spolymat_srcptr;

typedef struct
{
  const uint8_t *in;
  uint8_t *out;
  unsigned int byte_off;
  unsigned int bit_off;
} coder_state_struct;
typedef coder_state_struct coder_state_t[1];
typedef coder_state_struct *coder_state_ptr;
typedef const coder_state_struct *coder_state_srcptr;

typedef struct
{
  const int_srcptr q;
  const int_srcptr qminus1;
  const int_srcptr m;
  const int_srcptr mby2;
  const int_srcptr gamma;
  const int_srcptr gammaby2;
  const int_srcptr pow2D;
  const int_srcptr pow2Dby2;
  const unsigned int D;
  const int m_odd;
  const unsigned int log2m;
} dcompress_params_struct;
typedef dcompress_params_struct dcompress_params_t[1];
typedef dcompress_params_struct *dcompress_params_ptr;
typedef const dcompress_params_struct *dcompress_params_srcptr;

typedef struct
{
  const polyring_srcptr ring;
  const dcompress_params_srcptr dcompress;
  /* dimensions  */
  const unsigned int m1;   /* length of "short" message s1 */
  const unsigned int m2;   /* length of randomness s2 */
  const unsigned int l;    /* length of "large" message m */
  const unsigned int lext; /* length of extension of m */
  const unsigned int kmsis;
  /* norms */
  const int_srcptr Bsqr; /* floor (B^2) */
  const int64_t nu;      /* s2 uniform in [-nu,nu]*/
  const int64_t omega;   /* challenges uniform in [-omega,omega], o(c)=c */
  const unsigned int log2omega;
  const uint64_t eta; /* sqrt(l1(o(c)*c)) <= eta XXX sqrt? */
  /* rejection sampling */
  const int rej1;                /* do rejection sampling on s1 */
  const unsigned int log2stdev1; /* stdev1 = 1.55 * 2^log2stdev1 */
  const int_srcptr scM1;         /* scaled M1: round(M1 * 2^128) */
  const int_srcptr stdev1sqr;
  const int rej2;                /* do rejection sampling on s2 */
  const unsigned int log2stdev2; /* stdev2 = 1.55 * 2^log2stdev2 */
  const int_srcptr scM2;         /* scaled M2: round(M2 * 2^128) */
  const int_srcptr stdev2sqr;
} abdlop_params_struct;
typedef abdlop_params_struct abdlop_params_t[1];
typedef abdlop_params_struct *abdlop_params_ptr;
typedef const abdlop_params_struct *abdlop_params_srcptr;

typedef struct
{
  const abdlop_params_srcptr quad_eval;
  const abdlop_params_srcptr quad_many;
  const unsigned int lambda;

} lnp_quad_eval_params_struct;
typedef lnp_quad_eval_params_struct lnp_quad_eval_params_t[1];
typedef lnp_quad_eval_params_struct *lnp_quad_eval_params_ptr;
typedef const lnp_quad_eval_params_struct *lnp_quad_eval_params_srcptr;

typedef struct
{
  abdlop_params_srcptr tbox;
  lnp_quad_eval_params_srcptr quad_eval;

  /* dimensions */
  const unsigned int nbin;
  const unsigned int *const n;
  const unsigned int nprime;
  const unsigned int Z;
  const unsigned int nex;

  /* rejection sampling */
  const int rej3;                /* do rejection sampling on s3 */
  const unsigned int log2stdev3; /* stdev3 = 1.55 * 2^log2stdev1 */
  const int_srcptr scM3;         /* scaled M3: round(M3 * 2^128) */
  const int_srcptr stdev3sqr;
  const int rej4;                /* do rejection sampling on s4 */
  const unsigned int log2stdev4; /* stdev4 = 1.55 * 2^log2stdev2 */
  const int_srcptr scM4;         /* scaled M4: round(M4 * 2^128) */
  const int_srcptr stdev4sqr;

  /* bounds */
  const int_srcptr Bz3sqr;
  const int_srcptr Bz4;
  const int_srcptr *l2Bsqr; /* squared euclidean norm bounds */

  const int_srcptr inv4;

  /* expected proof size in bytes */
  const unsigned long prooflen;
} lnp_tbox_params_struct;
typedef lnp_tbox_params_struct lnp_tbox_params_t[1];
typedef lnp_tbox_params_struct *lnp_tbox_params_ptr;
typedef const lnp_tbox_params_struct *lnp_tbox_params_srcptr;

typedef struct
{
  /* params */
  lnp_tbox_params_srcptr params;
  /* public params */
  uint8_t ppseed[32];
  polymat_t A1;
  polymat_t A2prime;
  polymat_t Bprime;
  /* commitment */
  polyvec_t tA1;
  polyvec_t tA2;
  polyvec_t tB;
  /* proof */
  polyvec_t h;
  polyvec_t hint;
  polyvec_t z1;
  polyvec_t z21;
  polyvec_t z3;
  polyvec_t z4;
  poly_t c;
  /* statement */
  spolymat_ptr *R2;
  spolyvec_ptr *r1;
  poly_ptr *r0;
  unsigned int N;
  spolymat_ptr *R2prime;
  spolyvec_ptr *r1prime;
  poly_ptr *r0prime;
  unsigned int M;
  polymat_ptr *Es, *Em;
  polyvec_ptr *v;
  polymat_ptr Ps, Pm;
  polyvec_ptr f;
  polymat_ptr Ds, Dm;
  polyvec_ptr u;
  /* hashes of (sub)statements */
  uint8_t hash_quadeqs[32];
  uint8_t hash_evaleqs[32];
  uint8_t hash_l2[32];
  uint8_t hash_bin[32];
  uint8_t hash_arp[32];
  /* init */
  int statement_l2_set;
  int statement_bin_set;
  int statement_arp_set;
} _lnp_state_struct;
typedef _lnp_state_struct _lnp_state_t[1];
typedef _lnp_state_struct *_lnp_state_ptr;
typedef const _lnp_state_struct *_lnp_state_srcptr;

typedef struct
{
  /* public */
  _lnp_state_t state;
  /* secret */
  polyvec_t s1;
  polyvec_t s2;
  polyvec_t m;
  int witness_set;
} lnp_prover_state_struct;
typedef lnp_prover_state_struct lnp_prover_state_t[1];
typedef lnp_prover_state_struct *lnp_prover_state_ptr;
typedef const lnp_prover_state_struct *lnp_prover_state_srcptr;

typedef struct
{
  _lnp_state_t state;
} lnp_verifier_state_struct;
typedef lnp_verifier_state_struct lnp_verifier_state_t[1];
typedef lnp_verifier_state_struct *lnp_verifier_state_ptr;
typedef const lnp_verifier_state_struct *lnp_verifier_state_srcptr;

typedef struct
{
  lnp_tbox_params_srcptr tbox_params;
  const unsigned int dprime;
  int_srcptr p;
  int_srcptr pinv;
  const unsigned int k;

  const unsigned int *const s1_indices;
  const unsigned int ns1_indices;
  const unsigned int *const m_indices;
  const unsigned int nm_indices;

  const unsigned int *const Ps;
  const unsigned int Ps_nrows;

  const unsigned int *const *const Es;
  const unsigned int *Es_nrows;

  const unsigned int *const *const Em;
  const unsigned int *Em_nrows;
} lin_params_struct;
typedef lin_params_struct lin_params_t[1];
typedef lin_params_struct *lin_params_ptr;
typedef const lin_params_struct *lin_params_srcptr;

typedef struct
{
  lin_params_srcptr params;

  polymat_ptr Ds;
  polymat_ptr Dm;
  polyvec_ptr u;
} _lin_state_struct;
typedef _lin_state_struct _lin_state_t[1];
typedef _lin_state_struct *_lin_state_ptr;
typedef const _lin_state_struct *_lin_state_srcptr;

typedef struct
{
  /* params */
  lnp_tbox_params_srcptr params;
  /* public params */
  uint8_t ppseed[32];
  polymat_t A1;
  polymat_t A2prime;
  polymat_t Bprime;
  /* commitment */
  polyvec_t tA1;
  polyvec_t tA2;
  polyvec_t tB;
  /* proof */
  polyvec_t h;
  polyvec_t hint;
  polyvec_t z1;
  polyvec_t z21;
  polyvec_t z3;
  polyvec_t z4;
  poly_t c;
  /* statement */
  polymat_ptr Ds, Dm;
  polyvec_ptr u;
  /* hashes of (sub)statements */
  uint8_t hash_arp[32];
  /* init */
  int statement_l2_set;
  int statement_bin_set;
  int statement_arp_set;
} __lnp_state_struct;
typedef __lnp_state_struct __lnp_state_t[1];
typedef __lnp_state_struct *__lnp_state_ptr;
typedef const __lnp_state_struct *__lnp_state_srcptr;

typedef struct
{
  /* public */
  __lnp_state_t state;
  /* secret */
  polyvec_t s1;
  polyvec_t s2;
  polyvec_t m;
  int witness_set;
} _lnp_prover_state_struct;
typedef _lnp_prover_state_struct _lnp_prover_state_t[1];
typedef _lnp_prover_state_struct *_lnp_prover_state_ptr;
typedef const _lnp_prover_state_struct *_lnp_prover_state_srcptr;

typedef struct
{
  __lnp_state_t state;
} _lnp_verifier_state_struct;
typedef _lnp_verifier_state_struct _lnp_verifier_state_t[1];
typedef _lnp_verifier_state_struct *_lnp_verifier_state_ptr;
typedef const _lnp_verifier_state_struct *_lnp_verifier_state_srcptr;

typedef struct
{
  _lnp_prover_state_t lnp_state;
  _lin_state_t state;
} lin_prover_state_struct;
typedef lin_prover_state_struct lin_prover_state_t[1];
typedef lin_prover_state_struct *lin_prover_state_ptr;
typedef const lin_prover_state_struct *lin_prover_state_srcptr;

typedef struct
{
  _lnp_verifier_state_t lnp_state;
  _lin_state_t state;
} lin_verifier_state_struct;
typedef lin_verifier_state_struct lin_verifier_state_t[1];
typedef lin_verifier_state_struct *lin_verifier_state_ptr;
typedef const lin_verifier_state_struct *lin_verifier_state_srcptr;

typedef struct
{
  /* secret */
  uint8_t privkey[1281];
  /* public */
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_verifier_state_t p1;
} signer_state_struct;
typedef signer_state_struct signer_state_t[1];
typedef signer_state_struct *signer_state_ptr;
typedef const signer_state_struct *signer_state_srcptr;

typedef struct
{
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_verifier_state_t p2;
} verifier_state_struct;
typedef verifier_state_struct verifier_state_t[1];
typedef verifier_state_struct *verifier_state_ptr;
typedef const verifier_state_struct *verifier_state_srcptr;

typedef struct
{
  /* secret */
  uint8_t m[512 / 8];
  int16_t r1[512];
  int16_t r2[512];
  /* public */
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_prover_state_t p1;
  lin_prover_state_t p2;
} user_state_struct;
typedef user_state_struct user_state_t[1];
typedef user_state_struct *user_state_ptr;
typedef const user_state_struct *user_state_srcptr;

/* forward declarations of internal stuff */
void *hexl_ntt_alloc (uint64_t d, uint64_t p);
void hexl_ntt_fwd (void *ntt, int64_t *out, uint64_t out_mod_factor,
                   const int64_t *in, uint64_t in_mod_factor);
void hexl_ntt_inv (void *ntt, int64_t *out, uint64_t out_mod_factor,
                   const int64_t *in, uint64_t in_mod_factor);
void hexl_ntt_free (void *ntt);

void hexl_ntt_add (int64_t *r, const int64_t *a, const int64_t *b, uint64_t d,
                   uint64_t p);
void hexl_ntt_sub (int64_t *r, const int64_t *a, const int64_t *b, uint64_t d,
                   uint64_t p);
void hexl_ntt_mul (int64_t *r, const int64_t *a, const int64_t *b,
                   uint64_t in_mod_factor, uint64_t d, uint64_t p);
void hexl_ntt_scale (int64_t *r, const uint64_t s, const int64_t *b, int64_t d,
                     uint64_t p, uint64_t in_mod_factor);
void hexl_ntt_red (int64_t *r, uint64_t out_mod_factor, const int64_t *a,
                   uint64_t in_mod_factor, uint64_t d, uint64_t p);

/********************************************************************
 * 3.1 API functions and macros
 */

// __attribute__ ((constructor))  // XXX does not work with hexl init
void lazer_init (void);

unsigned int lazer_get_version_major (void);
unsigned int lazer_get_version_minor (void);
unsigned int lazer_get_version_patch (void);
const char *lazer_get_version (void);

void lazer_set_memory_functions (void *(*nalloc) (size_t),
                                 void *(*nrealloc) (void *, size_t, size_t),
                                 void (*nfree) (void *, size_t));
void lazer_get_memory_functions (void *(**nalloc) (size_t),
                                 void *(**nrealloc) (void *, size_t, size_t),
                                 void (**nfree) (void *, size_t));

void bytes_urandom (uint8_t *bytes, const size_t len);
void bytes_clear (uint8_t *bytes, const size_t len);
size_t bytes_out_str (FILE *stream, const uint8_t *bytes, size_t len);
size_t bytes_inp_str (uint8_t *bytes, size_t len, FILE *stream);
size_t bytes_out_raw (FILE *stream, const uint8_t *bytes, size_t len);
size_t bytes_inp_raw (uint8_t *bytes, size_t len, FILE *stream);

void shake128_init (shake128_state_t state);
void shake128_absorb (shake128_state_t state, const uint8_t *in, size_t len);
void shake128_squeeze (shake128_state_t state, uint8_t *out, size_t len);
void shake128_clear (shake128_state_t state);

void rng_init (rng_state_t state, const uint8_t seed[32], uint64_t dom);
void rng_urandom (rng_state_t state, uint8_t *out, size_t outlen);
void rng_clear (rng_state_t state);

#define INT_T(__name__, __nlimbs__)                                           \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_int_data (__nlimbs__)];           \
  int_t __name__;                                                             \
  _int_init (__name__, __nlimbs__, __name__##bytes__);

void int_alloc (int_ptr r, unsigned int nlimbs);
void int_free (int_ptr r);
static inline void int_set_zero (int_t r);
static inline void int_set_one (int_t r);
static inline unsigned int int_get_nlimbs (const int_t a);
static inline void int_set (int_t r, const int_t a);
static inline void int_set_zero (int_t r);
static inline void int_set_one (int_t r);
static inline void int_set_i64 (int_t r, int64_t a);
static inline int64_t int_get_i64 (const int_t r);
static inline int int_sgn (const int_t a);
static inline void int_neg (int_t r, const int_t a);
static inline void int_mul_sgn_self (int_t r, int sgn);
static inline void int_neg_self (int_t r);
static inline void int_abs (int_t r, const int_t a);
static inline int int_eqzero (const int_t a);
static inline int int_eq (const int_t a, const int_t b);
static inline int int_lt (const int_t a, const int_t b);
static inline int int_le (const int_t a, const int_t b);
static inline int int_gt (const int_t a, const int_t b);
static inline int int_ge (const int_t a, const int_t b);
static inline int int_abseq (const int_t a, const int_t b);
static inline int int_abslt (const int_t a, const int_t b);
static inline int int_absle (const int_t a, const int_t b);
static inline int int_absgt (const int_t a, const int_t b);
static inline int int_absge (const int_t a, const int_t b);
static inline void int_rshift (int_t r, const int_t a, unsigned int n);
static inline void int_lshift (int_t r, const int_t a, unsigned int n);
static inline void int_add (int_t r, const int_t a, const int_t b);
static inline void int_add_ct (int_t r, const int_t a, const int_t b); // XXX
static inline void int_sub (int_t r, const int_t a, const int_t b);
static inline void int_sub_ct (int_t r, const int_t a, const int_t b); // XXX
static inline void int_redc (int_t r, const int_t a, const int_t m);
static inline void int_redc_ct (int_t r, const int_t a, const int_t m);
void int_mul (int_t r, const int_t a, const int_t b);
void int_sqr (int_t r, const int_t a);
void int_addmul (int_t r, const int_t a, const int_t b);
void int_submul (int_t r, const int_t a, const int_t b);
void int_addsqr (int_t r, const int_t a);
void int_subsqr (int_t r, const int_t a);
void int_div (int_t rq, int_t rr, const int_t a, const int_t b);
void int_mod (int_t r, const int_t a, const int_t m);
void int_invmod (int_t r, const int_t a, const int_t m);
void int_redc (int_t r, const int_t a, const int_t m);
void int_redp (int_t r, const int_t a, const int_t m);
void int_brandom (int_t r, unsigned int k, const uint8_t seed[32],
                  uint32_t dom);
void int_grandom (int_t r, unsigned int log2o, const uint8_t seed[32],
                  uint32_t dom);
void int_urandom (int_t r, const int_t mod, unsigned int log2mod,
                  const uint8_t seed[32], uint32_t dom);
void int_urandom_bnd (int_t r, const int_t lo, const int_t hi,
                      const uint8_t seed[32], uint32_t dom);
void int_binexp (poly_t upsilon, poly_t powB, int_srcptr B);
size_t int_out_str (FILE *stream, int base, const int_t a);
size_t int_inp_str (int_t r, FILE *stream, int base);
void int_import (int_t r, const uint8_t *bytes, size_t nbytes);
void int_export (uint8_t *bytes, size_t *nbytes, const int_t a);
void int_dump (int_t z);
void int_clear (int_t r);

#define INTVEC_T(__name__, __nelems__, __nlimbs__)                            \
  _ALIGN8 uint8_t                                                             \
      __name__##bytes__[_sizeof_intvec_data (__nelems__, __nlimbs__)];        \
  intvec_t __name__;                                                          \
  _intvec_init (__name__, __nelems__, __nlimbs__, __name__##bytes__);

void intvec_alloc (intvec_ptr r, unsigned int nelems, unsigned int nlimbs);
void intvec_free (intvec_ptr r);
static inline void intvec_set_zero (intvec_t r);
static inline void intvec_set_one (intvec_t r, unsigned int idx);
static inline void intvec_set_ones (intvec_t r);
static inline unsigned int intvec_get_nlimbs (const intvec_t a);
size_t intvec_out_str (FILE *stream, int base, const intvec_t a);
static inline unsigned int intvec_get_nelems (const intvec_t r);
static inline int_ptr intvec_get_elem (const intvec_t a, unsigned int col);
static inline int_srcptr intvec_get_elem_src (const intvec_t a,
                                              unsigned int col);
static inline void intvec_set_elem (intvec_t a, unsigned int col,
                                    const int_t elem);
static inline void intvec_set (intvec_t r, const intvec_t a);
static inline void intvec_set_i64 (intvec_t r, const int64_t *a);
static inline void intvec_set_i32 (intvec_t r, const int32_t *a);
static inline void intvec_set_i16 (intvec_t r, const int16_t *a);
static inline void intvec_get_i16 (int16_t *r, const intvec_t a);
static inline void intvec_get_i32 (int32_t *r, const intvec_t a);
static inline void intvec_get_i64 (int64_t *r, const intvec_t a);
static inline int64_t intvec_get_elem_i64 (const intvec_t a,
                                           unsigned int elem);
static inline void intvec_set_elem_i64 (intvec_t a, unsigned int elem,
                                        int64_t val);
void intvec_mul_sgn_self (intvec_t r, int sgn);
int intvec_eq (const intvec_t a, const intvec_t b);
int intvec_lt (const intvec_t a, const int_t m);
int intvec_gt (const intvec_t a, const int_t m);
int intvec_le (const intvec_t a, const int_t m);
int intvec_ge (const intvec_t a, const int_t m);
void intvec_rshift (intvec_t r, const intvec_t a, unsigned int n);
void intvec_lshift (intvec_t r, const intvec_t a, unsigned int n);
void intvec_rrot (intvec_t r, const intvec_t a, unsigned int n);
void intvec_lrot (intvec_t r, const intvec_t a, unsigned int n);
void intvec_add (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_sub (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_mul (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_scale (intvec_t r, const int_t a, const intvec_t b);
void intvec_div (intvec_t rq, intvec_t rr, const intvec_t a, const intvec_t b);
void intvec_mod (intvec_t r, const intvec_t a, const int_t m);
void intvec_redc (intvec_t r, const intvec_t a, const int_t m);
void intvec_redp (intvec_t r, const intvec_t a, const int_t m);
void intvec_dot (int_t r, const intvec_t a, const intvec_t b);
void intvec_l2sqr (int_t r, const intvec_t a);
void intvec_linf (int_t r, const intvec_t a);
void intvec_urandom_autostable (intvec_t r, int64_t bnd, unsigned int log2,
                                const uint8_t seed[32], uint32_t dom);
void intvec_brandom (intvec_t r, unsigned int k, const uint8_t seed[32],
                     uint32_t dom);
void intvec_grandom (intvec_t r, unsigned int log2o, const uint8_t seed[32],
                     uint32_t dom);
void intvec_urandom (intvec_t r, const int_t mod, unsigned int log2mod,
                     const uint8_t seed[32], uint32_t dom);
void intvec_urandom_bnd (intvec_t r, const int_t lo, const int_t hi,
                         const uint8_t seed[32], uint32_t dom);
void intvec_get_subvec (intvec_t subvec, const intvec_t vec, unsigned int col,
                        unsigned int ncols, unsigned int stride);
void intvec_mul_matvec (intvec_t r, const intmat_t mat, const intvec_t vec);
void intvec_auto (intvec_t r, const intvec_t a);
void intvec_auto_self (intvec_t r);
void intvec_dump (intvec_t z);
void intvec_clear (intvec_t r);

#define INTMAT_T(__name__, __nrows__, __ncols__, __nlimbs__)                  \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_intmat_data (                     \
      __nrows__, __ncols__, __nlimbs__)];                                     \
  intmat_t __name__;                                                          \
  _intmat_init (__name__, __nrows__, __ncols__, __nlimbs__, __name__##bytes__);

void intmat_alloc (intmat_ptr r, unsigned int nrows, unsigned int ncols,
                   unsigned int nlimbs);
void intmat_free (intmat_ptr r);
static inline unsigned int intmat_get_nlimbs (const intmat_t a);
static inline unsigned int intmat_get_nrows (const intmat_t mat);
static inline unsigned int intmat_get_ncols (const intmat_t mat);
static inline void intmat_set_zero (intmat_t r);
static inline void intmat_set_one (intmat_t r);
static inline void intmat_get_row (intvec_t subvec, const intmat_t mat,
                                   unsigned int row);
static inline void intmat_set_row (intmat_t mat, const intvec_t vec,
                                   unsigned int row);
static inline void intmat_get_col (intvec_t subvec, const intmat_t mat,
                                   unsigned int col);
static inline void intmat_set_col (intmat_t mat, const intvec_t vec,
                                   unsigned int col);
static inline void intmat_get_diag (intvec_t vec, const intmat_t mat,
                                    int diag);
static inline void intmat_set_diag (intmat_t mat, const intvec_t vec,
                                    int diag);
static inline void intmat_get_antidiag (intvec_t vec, const intmat_t mat,
                                        int antidiag);
static inline void intmat_set_antidiag (intmat_t mat, const intvec_t vec,
                                        int antidiag);
static inline void intmat_get_submat (intmat_t submat, const intmat_t mat,
                                      unsigned int row, unsigned int col,
                                      unsigned int nrows, unsigned int ncols,
                                      unsigned int stride_row,
                                      unsigned int stride_col);
static inline void intmat_set_submat (intmat_t mat, const intmat_t submat,
                                      unsigned int row, unsigned int col,
                                      unsigned int nrows, unsigned int ncols,
                                      unsigned int stride_row,
                                      unsigned int stride_col);
static inline int_ptr intmat_get_elem (const intmat_t a, unsigned int row,
                                       unsigned int col);
static inline int_srcptr
intmat_get_elem_src (const intmat_t a, unsigned int row, unsigned int col);
static inline void intmat_set_elem (intmat_t a, unsigned int row,
                                    unsigned int col, const int_t elem);
static inline void intmat_set (intmat_t r, const intmat_t a);
static inline void intmat_set_elem (intmat_t a, unsigned int row,
                                    unsigned int col, const int_t elem);
static inline void intmat_set_elem_i64 (intmat_t a, unsigned int row,
                                        unsigned int col, int64_t elem);
static inline void intmat_set_i64 (intmat_t r, const int64_t *a);
static inline void intmat_get_i64 (int64_t *r, const intmat_t a);
static inline void intmat_set_i32 (intmat_t r, const int32_t *a);
static inline void intmat_get_i32 (int32_t *r, const intmat_t a);
void intmat_brandom (intmat_t r, unsigned int k, const uint8_t seed[32],
                     uint32_t dom);
void intmat_urandom (intmat_t r, const int_t mod, unsigned int log2mod,
                     const uint8_t seed[32], uint32_t dom);
int intmat_eq (const intmat_t a, const intmat_t b);
void intmat_mul_sgn_self (intmat_t r, int sgn);
size_t intmat_out_str (FILE *stream, int base, const intmat_t a);
void intmat_dump (intmat_t mat);
void intmat_clear (intmat_t r);

#define POLYRING_T(__name__, __q__, __d__)                                    \
  polyring_t __name__                                                         \
      = { { (__q__), (__d__), 0, 0, NULL, 0, NULL, NULL, NULL } }

static inline unsigned int polyring_get_deg (const polyring_t ring);
static inline int_srcptr polyring_get_mod (const polyring_t ring);
static inline unsigned int polyring_get_log2q (const polyring_t ring);
static inline unsigned int polyring_get_log2deg (const polyring_t ring);

#define POLY_T(__name__, __ring__)                                            \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_poly_data (__ring__)];            \
  poly_t __name__;                                                            \
  _poly_init (__name__, __ring__, __name__##bytes__);

/**
 * Allocate a polynomial over a ring.
 *
 * \param r The returned polynomial.
 * \param ring The polynomial ring.
 */
void poly_alloc (poly_ptr r, const polyring_t ring);

/**
 * Free a polynomial.
 *
 * \param r The polynomial to be freed.
 */
void poly_free (poly_ptr r);

static inline void poly_set_zero (poly_t r);
static inline void poly_set_one (poly_t r);
static inline unsigned int poly_get_nlimbs (const poly_t a);
static inline polyring_srcptr poly_get_ring (const poly_t poly);
static inline int_ptr poly_get_coeff (poly_t poly, unsigned int idx);
static inline void poly_set_coeff (poly_t poly, unsigned int idx,
                                   const int_t val);
static inline intvec_ptr poly_get_coeffvec (poly_t poly);
void poly_brandom (poly_t r, unsigned int k, const uint8_t seed[32],
                   uint32_t dom);
void poly_grandom (poly_t r, unsigned int log2o, const uint8_t seed[32],
                   uint32_t dom);
void poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
                   const uint8_t seed[32], uint32_t dom);
void poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                       const uint8_t seed[32], uint32_t dom);
void poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                              const uint8_t seed[32], uint32_t dom);
int poly_eq (poly_t a, poly_t b);
void poly_set (poly_t r, const poly_t a);
void poly_add (poly_t r, poly_t a, poly_t b, int crt);
void poly_sub (poly_t r, poly_t a, poly_t b, int crt);
void poly_scale (poly_t r, const int_t a, poly_t b);
void poly_mul (poly_t r, poly_t a, poly_t b);
void poly_rshift (poly_t r, poly_t a, unsigned int n);
void poly_lshift (poly_t r, poly_t a, unsigned int n);
void poly_rrot (poly_t r, poly_t a, unsigned int n);
void poly_lrot (poly_t r, poly_t a, unsigned int n);
void poly_mod (poly_t r, poly_t a);
void poly_redc (poly_t r, poly_t a);
void poly_redp (poly_t r, poly_t a);
void poly_tocrt (poly_t r);
void poly_addmul (poly_t r, poly_t a, poly_t b, int crt);
void poly_submul (poly_t r, poly_t a, poly_t b, int crt);
void poly_addmul2 (poly_t r, polymat_t a, polyvec_t b, int crt);
void poly_submul2 (poly_t r, polymat_t a, polyvec_t b, int crt);
void poly_adddot (poly_t r, polyvec_t a, polyvec_t b, int crt);
void poly_adddot2 (poly_t r, spolyvec_t a, polyvec_t b, int crt);
void poly_subdot (poly_t r, polyvec_t a, polyvec_t b, int crt);
void poly_fromcrt (poly_t r);
void poly_dcompress_power2round (poly_t r, poly_t a,
                                 const dcompress_params_t params);
void poly_dcompress_decompose (poly_t r1, poly_t r0, poly_t r,
                               const dcompress_params_t params);
void poly_dcompress_use_ghint (poly_t ret, poly_t y, poly_t r,
                               const dcompress_params_t params);
void poly_dcompress_make_ghint (poly_t ret, poly_t z, poly_t r,
                                const dcompress_params_t params);
void poly_l2sqr (int_t r, poly_t a);
void poly_linf (int_t r, poly_t a);
static inline void poly_set_coeffvec (poly_t r, const intvec_t v);
static inline void poly_set_coeffvec2 (poly_t r, intvec_ptr v);
static inline void poly_set_coeffvec_i64 (poly_t r, const int64_t *a);
static inline void poly_set_coeffvec_i32 (poly_t r, const int32_t *a);
static inline void poly_set_coeffvec_i16 (poly_t r, const int16_t *a);
static inline void poly_get_coeffvec_i64 (int64_t *r, poly_t a);
static inline void poly_get_coeffvec_i32 (int32_t *r, poly_t a);
void poly_auto (poly_t r, poly_t a);
void poly_auto_self (poly_t r);
void poly_tracemap (poly_t r, poly_t a);
void poly_toisoring (polyvec_t vec, poly_t a);
void poly_fromisoring (poly_t a, polyvec_t vec);
size_t poly_out_str (FILE *stream, int base, poly_t a);
void poly_dump (poly_t a);

#define POLYVEC_T(__name__, __ring__, __nelems__)                             \
  _ALIGN8 uint8_t                                                             \
      __name__##bytes__[_sizeof_polyvec_data (__ring__, __nelems__)];         \
  polyvec_t __name__;                                                         \
  _polyvec_init (__name__, __ring__, __nelems__, __name__##bytes__)

void polyvec_alloc (polyvec_ptr r, const polyring_t ring, unsigned int nelems);
void polyvec_free (polyvec_ptr r);
static inline void polyvec_fill (polyvec_t r, poly_t a);
static inline void polyvec_set_zero (polyvec_t r);
static inline void polyvec_set_one (polyvec_t r, unsigned int idx);
static inline void polyvec_set_ones (polyvec_t r);
static inline unsigned int polyvec_get_nlimbs (const polyvec_t a);
static inline unsigned int polyvec_get_nelems (const polyvec_t a);
static inline polyring_srcptr polyvec_get_ring (const polyvec_t a);
static inline poly_ptr polyvec_get_elem (const polyvec_t a, unsigned int elem);
static inline poly_srcptr polyvec_get_elem_src (const polyvec_t a,
                                                unsigned int elem);
static inline void polyvec_set_elem (polyvec_t a, unsigned int idx,
                                     const poly_t elem);
static inline void polyvec_set (polyvec_t r, const polyvec_t a);
static inline void polyvec_set_coeffvec_i64 (polyvec_t r, const int64_t *a);
static inline void polyvec_set_coeffvec_i32 (polyvec_t r, const int32_t *a);
static inline void polyvec_get_coeffvec_i32 (int32_t *r, const polyvec_t a);
static inline void polyvec_get_coeffvec_i64 (int64_t *r, const polyvec_t a);
void polyvec_get_subvec (polyvec_t subvec, const polyvec_t vec,
                         unsigned int elem, unsigned int nelems,
                         unsigned int stride);
static inline void polyvec_set_coeffvec (polyvec_t r, const intvec_t v);
static inline void polyvec_set_coeffvec2 (polyvec_t r, intvec_ptr v);
int polyvec_eq (polyvec_t a, polyvec_t b);
void polyvec_rshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_lshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_rrot (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_lrot (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_add (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
void polyvec_sub (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
// XXXvoid polyvec_mul (polyvec_t r, polyvec_t a, polyvec_t b);
void polyvec_scale (polyvec_t r, const int_t a, polyvec_t b);
void polyvec_addscale (polyvec_t r, const int_t a, polyvec_t b, int crt);
void polyvec_subscale (polyvec_t r, const int_t a, polyvec_t b, int crt);
void polyvec_scale2 (polyvec_t r, poly_t a, polyvec_t b);
void polyvec_addscale2 (polyvec_t r, poly_t a, polyvec_t b, int crt);
void polyvec_subscale2 (polyvec_t r, poly_t a, polyvec_t b, int crt);
void polymat_rrot (polymat_t r, polymat_t a, unsigned int n);
void polymat_rrotdiag (polymat_t r, polymat_t a, unsigned int n);
void polymat_lrot (polymat_t r, polymat_t a, unsigned int n);
void polymat_lrotdiag (polymat_t r, polymat_t a, unsigned int n);
void polyvec_tocrt (polyvec_t r);
void polyvec_fromcrt (polyvec_t r);
void polyvec_mod (polyvec_t r, polyvec_t a);
void polyvec_redc (polyvec_t r, polyvec_t a);
void polyvec_redp (polyvec_t r, polyvec_t a);
void poly_neg (poly_t r, poly_t b);
void polyvec_auto_self (polyvec_t r);
void polyvec_auto (polyvec_t r, polyvec_t a);
void polyvec_urandom_autostable (polyvec_t r, int64_t bnd, unsigned int log2,
                                 const uint8_t seed[32], uint32_t dom);
void polyvec_dcompress_power2round (polyvec_t r, polyvec_t a,
                                    const dcompress_params_t params);
void polyvec_dcompress_decompose (polyvec_t r1, polyvec_t r0, polyvec_t r,
                                  const dcompress_params_t params);
void polyvec_dcompress_use_ghint (polyvec_t ret, polyvec_t y, polyvec_t r,
                                  const dcompress_params_t params);
void polyvec_dcompress_make_ghint (polyvec_t ret, polyvec_t z, polyvec_t r,
                                   const dcompress_params_t params);
void polyvec_dot (poly_t r, polyvec_t a, polyvec_t b);
void polyvec_dot2 (poly_t r, spolyvec_t a, polyvec_t b);
void polyvec_linf (int_t r, polyvec_t a);
void polyvec_l2sqr (int_t r, polyvec_t a);
void polyvec_grandom (polyvec_t r, unsigned int log2o, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_brandom (polyvec_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_urandom (polyvec_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polyvec_urandom_bnd (polyvec_t r, const int_t lo, const int_t hi,
                          const uint8_t seed[32], uint32_t dom);
void polyvec_mul (polyvec_t r, polymat_t a, polyvec_t b);
void polyvec_muldiag (polyvec_t r, polymat_t diag, polyvec_t b);
void polyvec_mul2 (polyvec_t r, polyvec_t a, polymat_t b);
void polyvec_muldiag2 (polyvec_t r, polyvec_t a, polymat_t diag);
void polyvec_addmul (polyvec_t r, polymat_t a, polyvec_t b, int crt);
void polyvec_addmul2 (polyvec_t r, polyvec_t a, polymat_t b, int crt);
void polyvec_submul (polyvec_t r, polymat_t a, polyvec_t b, int crt);
void polyvec_submul2 (polyvec_t r, polyvec_t a, polymat_t b, int crt);
void poly_addscale (poly_t r, int_t a, poly_t b, int crt);
void poly_subscale (poly_t r, int_t a, poly_t b, int crt);
void polyvec_addrshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_subrshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_addlshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_sublshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_toisoring (polyvec_t vec, polyvec_t a);
void polyvec_fromisoring (polyvec_t a, polyvec_t vec);
void polyvec_elem_mul (polyvec_t r, polyvec_t a, polyvec_t b);
size_t polyvec_out_str (FILE *stream, int base, polyvec_t a);
void polyvec_dump (polyvec_t vec);

#define POLYMAT_T(__name__, __ring__, __nrows__, __ncols__)                   \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_polymat_data (                    \
      __ring__, __nrows__, __ncols__)];                                       \
  polymat_t __name__;                                                         \
  _polymat_init (__name__, __ring__, __nrows__, __ncols__, __name__##bytes__)

void polymat_alloc (polymat_ptr r, const polyring_t ring, unsigned int nrows,
                    unsigned int ncols);
void polymat_free (polymat_ptr r);
static inline void polymat_fill (polymat_t r, poly_t a);
static inline void polymat_set_zero (polymat_t r);
static inline void polymat_set_one (polymat_t r);
static inline unsigned int polymat_get_nlimbs (const polymat_t a);
static inline unsigned int polymat_get_nrows (const polymat_t mat);
static inline unsigned int polymat_get_ncols (const polymat_t mat);
static inline poly_ptr polymat_get_elem (const polymat_t a, unsigned int row,
                                         unsigned int col);
static inline poly_srcptr
polymat_get_elem_src (const polymat_t a, unsigned int row, unsigned int col);
static inline void polymat_set_elem (polymat_t a, unsigned int row,
                                     unsigned int col, const poly_t elem);
static inline polyring_srcptr polymat_get_ring (const polymat_t a);
static inline void polymat_get_row (polyvec_t subvec, const polymat_t mat,
                                    unsigned int row);
static inline void polymat_set_row (polymat_t mat, const polyvec_t vec,
                                    unsigned int row);
static inline void polymat_get_col (polyvec_t subvec, const polymat_t mat,
                                    unsigned int col);
static inline void polymat_set_col (polymat_t mat, const polyvec_t vec,
                                    unsigned int col);
static inline void polymat_get_diag (polyvec_t subvec, const polymat_t mat,
                                     int diag);
static inline void polymat_set_diag (polymat_t mat, const polyvec_t vec,
                                     int diag);
static inline void polymat_get_antidiag (polyvec_t subvec, const polymat_t mat,
                                         int antidiag);
static inline void polymat_set_antidiag (polymat_t mat, const polyvec_t vec,
                                         int antidiag);
int polymat_is_upperdiag (polymat_t a);
void polymat_subdiags_set_zero (polymat_t r);
static inline void polymat_get_submat (polymat_t submat, const polymat_t mat,
                                       unsigned int row, unsigned int col,
                                       unsigned int nrows, unsigned int ncols,
                                       unsigned int stride_row,
                                       unsigned int stride_col);
static inline void polymat_set_submat (polymat_t mat, const polymat_t submat,
                                       unsigned int row, unsigned int col,
                                       unsigned int nrows, unsigned int ncols,
                                       unsigned int stride_row,
                                       unsigned int stride_col);
static inline void polymat_set (polymat_t r, const polymat_t a);
static inline void polymat_set_i64 (polymat_t r, const int64_t *a);
static inline void polymat_set_i32 (polymat_t r, const int32_t *a);
static inline void polymat_get_i64 (int64_t *r, const polymat_t a);
static inline void polymat_get_i32 (int32_t *r, const polymat_t a);
void polymat_fromcrt (polymat_t r);
void polymat_fromcrtdiag (polymat_t r);
void polymat_tocrt (polymat_t r);
void polymat_tocrtdiag (polymat_t r);
void polymat_mod (polymat_t r, polymat_t a);
void polymat_moddiag (polymat_t r, polymat_t a);
void polymat_redc (polymat_t r, polymat_t a);
void polymat_redp (polymat_t r, polymat_t a);
void polymat_add (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_sub (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_adddiag (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_subdiag (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_addscalediag (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_subscalediag (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_scale (polymat_t r, const int_t a, polymat_t b);
void polymat_scalediag (polymat_t r, const int_t a, polymat_t b);
void polymat_addscale (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_subscale (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_scale2 (polymat_t r, poly_t a, polymat_t b);
void polymat_scalediag2 (polymat_t r, poly_t a, polymat_t b);
void polymat_addscale2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_addscalediag2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_subscale2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_subscalediag2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_urandom (polymat_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polymat_brandom (polymat_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polymat_auto (polymat_t r, polymat_t a);
size_t polymat_out_str (FILE *stream, int base, const polymat_t a);
void polymat_dump (polymat_t mat);

void spolyvec_sort (spolyvec_ptr r);
void spolyvec_alloc (spolyvec_ptr r, const polyring_t ring,
                     unsigned int nelems, unsigned int nelems_max);
void spolyvec_set (spolyvec_ptr r, spolyvec_ptr a);
void spolyvec_redc (spolyvec_ptr r);
void spolyvec_redp (spolyvec_ptr r);
void spolyvec_add (spolyvec_t r, spolyvec_t a, spolyvec_t b, int crt);
void spolyvec_fromcrt (spolyvec_t r);
void spolyvec_lrot (spolyvec_t r, spolyvec_t b, unsigned int n);
void spolyvec_mod (spolyvec_ptr r, spolyvec_ptr b);
void spolyvec_scale (spolyvec_t r, const int_t a, spolyvec_t b);
void spolyvec_scale2 (spolyvec_t r, poly_t a, spolyvec_t b);
void spolyvec_urandom (spolyvec_t r, const int_t mod, unsigned int log2mod,
                       const uint8_t seed[32], uint32_t dom);
void spolyvec_brandom (spolyvec_t r, unsigned int k, const uint8_t seed[32],
                       uint32_t dom);
poly_ptr spolyvec_insert_elem (spolyvec_ptr r, unsigned int elem);
void spolyvec_free (spolyvec_ptr r);
poly_ptr spolyvec_get_elem2 (spolyvec_ptr a, unsigned int elem);
size_t spolyvec_out_str (FILE *stream, int base, spolyvec_t a);
void spolyvec_dump (spolyvec_t vec);

void spolymat_alloc (spolymat_ptr r, const polyring_t ring, unsigned int nrows,
                     unsigned int ncols, unsigned int nelems_max);
poly_ptr spolymat_get_elem2 (spolymat_ptr a, unsigned int row,
                             unsigned int col);
void spolymat_scale (spolymat_t r, const int_t a, spolymat_t b);
void spolymat_scale2 (spolymat_t r, poly_t a, spolymat_t b);
poly_ptr spolymat_insert_elem (spolymat_ptr r, unsigned int row,
                               unsigned int col);
void spolymat_urandom (spolymat_t r, const int_t mod, unsigned int log2mod,
                       const uint8_t seed[32], uint32_t dom);
void spolymat_brandom (spolymat_t r, unsigned int k, const uint8_t seed[32],
                       uint32_t dom);
void spolymat_add (spolymat_t r, spolymat_t a, spolymat_t b, int crt);
void polyvec_mulsparse (polyvec_t r, spolymat_t a, polyvec_t b);
void spolymat_redc (spolymat_ptr r);
void spolymat_redp (spolymat_ptr r);
int spolymat_is_upperdiag (spolymat_ptr r);
void spolymat_sort (spolymat_ptr r);
void spolymat_mod (spolymat_ptr r, spolymat_ptr b);
void spolymat_lrot (spolymat_t r, spolymat_t b, unsigned int n);
void spolymat_set (spolymat_ptr r, spolymat_ptr a);
void spolymat_fromcrt (spolymat_t r);
void spolymat_free (spolymat_ptr r);
void spolymat_dump (spolymat_t mat);
size_t spolymat_out_str (FILE *stream, int base, spolymat_t a);

void quad_toisoring (polymat_ptr R2[], polyvec_ptr r1[], poly_ptr r0[],
                     polymat_ptr R2prime, polyvec_ptr r1prime,
                     poly_ptr r0prime);
void lin_toisoring (polymat_t r1, polyvec_t r0, polymat_t r1prime,
                    polyvec_t r0prime);

#define CODER_STATE_T(__name__)                                               \
  coder_state_t __name__ = { { NULL, NULL, 0, 0 } }
void coder_enc_begin (coder_state_t state, uint8_t *out);
void coder_dec_begin (coder_state_t state, const uint8_t *in);
void coder_enc_end (coder_state_t state);
int coder_dec_end (coder_state_t state);
unsigned int coder_get_offset (coder_state_t state);
void coder_enc_urandom (coder_state_t state, const intvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_bytes (coder_state_t state, const uint8_t *bytes,
                      unsigned int nbytes);
int coder_dec_urandom (coder_state_t state, intvec_t v, const int_t m,
                       unsigned int mbits);
void coder_enc_grandom (coder_state_t state, const intvec_t v,
                        unsigned int log2o);
void coder_enc_ghint (coder_state_t state, const intvec_t ghint);
int coder_dec_bytes (coder_state_t state, uint8_t *bytes, unsigned int nbytes);
void coder_dec_grandom (coder_state_t state, intvec_t v, unsigned int log2o);
void coder_dec_ghint (coder_state_t state, intvec_t ghint);

void coder_enc_urandom2 (coder_state_t state, poly_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom2 (coder_state_t state, poly_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_enc_ghint2 (coder_state_t state, poly_t ghint);
void coder_dec_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_dec_ghint2 (coder_state_t state, poly_t ghint);

void coder_enc_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);
void coder_enc_ghint3 (coder_state_t state, polyvec_t ghint);
void coder_dec_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);
void coder_dec_ghint3 (coder_state_t state, polyvec_t ghint);
void coder_enc_urandom4 (coder_state_t state, polymat_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom4 (coder_state_t state, polymat_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_urandom4diag (coder_state_t state, polymat_t v, const int_t m,
                             unsigned int mbits);
int coder_dec_urandom4diag (coder_state_t state, polymat_t v, const int_t m,
                            unsigned int mbits);
void coder_enc_urandom5 (coder_state_t state, spolymat_t v, const int_t m,
                         unsigned int mbits);
void coder_dec_urandom5 (coder_state_t state, spolymat_t v, const int_t m,
                         unsigned int mbits);
void coder_enc_urandom6 (coder_state_t state, spolyvec_t v, const int_t m,
                         unsigned int mbits);
void coder_dec_urandom6 (coder_state_t state, spolyvec_t v, const int_t m,
                         unsigned int mbits);

int rej_standard (rng_state_t state, const intvec_t z, const intvec_t v,
                  const int_t scM, const int_t sigma2);
int rej_bimodal (rng_state_t state, const intvec_t z, const intvec_t v,
                 const int_t scM, const int_t sigma2);

static inline unsigned int dcompress_get_d (const dcompress_params_t params);
static inline int_srcptr dcompress_get_gamma (const dcompress_params_t params);
static inline int_srcptr dcompress_get_m (const dcompress_params_t params);
static inline unsigned int
dcompress_get_log2m (const dcompress_params_t params);
void dcompress_decompose (intvec_t r1, intvec_t r0, const intvec_t r,
                          const dcompress_params_t params);
void dcompress_power2round (intvec_t ret, const intvec_t r,
                            const dcompress_params_t params);
void dcompress_use_ghint (intvec_t ret, const intvec_t y, const intvec_t r,
                          const dcompress_params_t params);
void dcompress_make_ghint (intvec_t ret, const intvec_t z, const intvec_t r,
                           const dcompress_params_t params);

void abdlop_keygen (polymat_t A1, polymat_t A2prime, polymat_t Bprime,
                    const uint8_t seed[32], const abdlop_params_t params);

void abdlop_commit (polyvec_t tA1, polyvec_t tA2, polyvec_t tB, polyvec_t s1,
                    polyvec_t m, polyvec_t s2, polymat_t A1, polymat_t A2prime,
                    polymat_t Bprime, const abdlop_params_t params);
void abdlop_enccomm (uint8_t *buf, size_t *buflen, polyvec_t tA1, polyvec_t tB,
                     const abdlop_params_t params);
void abdlop_hashcomm (uint8_t hash[32], polyvec_t tA1, polyvec_t tB,
                      const abdlop_params_t params);
void abdlop_prove (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                   polyvec_t h, polyvec_t tA2, polyvec_t s1, polyvec_t s2,
                   polymat_t A1, polymat_t A2prime, const uint8_t seed[32],
                   const abdlop_params_t params);
int abdlop_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                   polyvec_t h, polyvec_t tA1, polymat_t A1, polymat_t A2prime,
                   const abdlop_params_t params);

void lnp_quad_prove (uint8_t hash[32], polyvec_t tB, poly_t c, polyvec_t z1,
                     polyvec_t z21, polyvec_t h, polyvec_t s1, polyvec_t m,
                     polyvec_t s2, polyvec_t tA2, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_t R2,
                     spolyvec_t r1, const uint8_t seed[32],
                     const abdlop_params_t params);
int lnp_quad_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                     polyvec_t h, polyvec_t tA1, polyvec_t tB, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_t R2,
                     spolyvec_t r1, poly_t r0, const abdlop_params_t params);

void lnp_quad_many_prove (uint8_t hash[32], polyvec_t tB, poly_t c,
                          polyvec_t z1, polyvec_t z21, polyvec_t h,
                          polyvec_t s1, polyvec_t m, polyvec_t s2,
                          polyvec_t tA2, polymat_t A1, polymat_t A2prime,
                          polymat_t Bprime, spolymat_ptr R2i[],
                          spolyvec_ptr r1i[], unsigned int N,
                          const uint8_t seed[32],
                          const abdlop_params_t params);
int lnp_quad_many_verify (uint8_t hash[32], poly_t c, polyvec_t z1,
                          polyvec_t z21, polyvec_t h, polyvec_t tA1,
                          polyvec_t tB, polymat_t A1, polymat_t A2prime,
                          polymat_t Bprime, spolymat_ptr R2i[],
                          spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                          const abdlop_params_t params);

void lnp_quad_eval_prove (uint8_t hash[32], polyvec_t tB, polyvec_t h,
                          poly_t c, polyvec_t z1, polyvec_t z21,
                          polyvec_t hint, polyvec_t s1, polyvec_t m,
                          polyvec_t s2, polyvec_t tA2, polymat_t A1,
                          polymat_t A2prime, polymat_t Bprime,
                          spolymat_ptr R2i[], spolyvec_ptr r1i[],
                          unsigned int N, spolymat_ptr Rprime2i[],
                          spolyvec_ptr rprime1i[], poly_ptr rprime0i[],
                          unsigned int M, const uint8_t seed[32],
                          const lnp_quad_eval_params_t params);
int lnp_quad_eval_verify (uint8_t hash[32], polyvec_t h, poly_t c,
                          polyvec_t z1, polyvec_t z21, polyvec_t hint,
                          polyvec_t tA1, polyvec_t tB, polymat_t A1,
                          polymat_t A2prime, polymat_t Bprime,
                          spolymat_ptr R2i[], spolyvec_ptr r1i[],
                          poly_ptr r0i[], unsigned int N,
                          spolymat_ptr Rprime2i[], spolyvec_ptr rprime1i[],
                          poly_ptr rprime0i[], unsigned int M,
                          const lnp_quad_eval_params_t params);

void lnp_tbox_prove (uint8_t hash[32], polyvec_t tB, polyvec_t h, poly_t c,
                     polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3,
                     polyvec_t z4, polyvec_t s1, polyvec_t m, polyvec_t s2,
                     polyvec_t tA2, polymat_t A1, polymat_t A2prime,
                     polymat_t Bprime, spolymat_ptr R2i[], spolyvec_ptr r1i[],
                     unsigned int N, spolymat_ptr Rprime2i[],
                     spolyvec_ptr rprime1i[], poly_ptr rprime0i[],
                     unsigned int M, polymat_ptr Esi[], polymat_ptr Emi[],
                     polyvec_ptr vi[], polymat_t Ps, polymat_t Pm, polyvec_t f,
                     polymat_t Ds, polymat_t Dm, polyvec_t u,
                     const uint8_t seed[32], const lnp_tbox_params_t params);

int lnp_tbox_verify (uint8_t hash[32], polyvec_t h, poly_t c, polyvec_t z1,
                     polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
                     polyvec_t tA1, polyvec_t tB, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_ptr R2i[],
                     spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                     spolymat_ptr Rprime2i[], spolyvec_ptr rprime1i[],
                     poly_ptr rprime0i[], unsigned int M, polymat_ptr Esi[],
                     polymat_ptr Emi[], polyvec_ptr vi[], polymat_t Ps,
                     polymat_t Pm, polyvec_t f, polymat_t Ds, polymat_t Dm,
                     polyvec_t u, const lnp_tbox_params_t params);

void lnp_prover_init (lnp_prover_state_t state, const uint8_t ppseed[32],
                      const lnp_tbox_params_t params);
void lnp_verifier_init (lnp_verifier_state_t state, const uint8_t ppseed[32],
                        const lnp_tbox_params_t params);

void lnp_prover_set_witness (lnp_prover_state_t state, polyvec_t s1,
                             polyvec_t m);
void lnp_prover_set_statement_quadeqs (lnp_prover_state_t state,
                                       spolymat_ptr R2[], spolyvec_ptr r1[],
                                       poly_ptr r0[], unsigned int N);
void lnp_verifier_set_statement_quadeqs (lnp_verifier_state_t state,
                                         spolymat_ptr R2[], spolyvec_ptr r1[],
                                         poly_ptr r0[], unsigned int N);
void lnp_prover_set_statement_evaleqs (lnp_prover_state_t state,
                                       spolymat_ptr R2prime[],
                                       spolyvec_ptr r1prime[],
                                       poly_ptr r0prime[], unsigned int M);
void lnp_verifier_set_statement_evaleqs (lnp_verifier_state_t state,
                                         spolymat_ptr R2prime[],
                                         spolyvec_ptr r1prime[],
                                         poly_ptr r0prime[], unsigned int M);
void lnp_prover_set_statement_l2 (lnp_prover_state_t state, polymat_ptr Es[],
                                  polymat_ptr Em[], polyvec_ptr v[]);
void lnp_verifier_set_statement_l2 (lnp_verifier_state_t state,
                                    polymat_ptr Es[], polymat_ptr Em[],
                                    polyvec_ptr v[]);
void lnp_prover_set_statement_bin (lnp_prover_state_t state, polymat_t Ps,
                                   polymat_t Pm, polyvec_t f);
void lnp_verifier_set_statement_bin (lnp_verifier_state_t state, polymat_t Ps,
                                     polymat_t Pm, polyvec_t f);
void lnp_prover_set_statement_arp (lnp_prover_state_t state, polymat_t Ds,
                                   polymat_t Dm, polyvec_t u);
void lnp_verifier_set_statement_arp (lnp_verifier_state_t state, polymat_t Ds,
                                     polymat_t Dm, polyvec_t u);

void lnp_prover_prove (lnp_prover_state_t state_, uint8_t *proof, size_t *len,
                       const uint8_t seed[32]);
int lnp_verifier_verify (lnp_verifier_state_t state_, const uint8_t *proof,
                         size_t *len);

void lnp_prover_clear (lnp_prover_state_t state);
void lnp_verifier_clear (lnp_verifier_state_t state);

void signer_keygen (uint8_t sk[1281], uint8_t pk[897]);
void signer_init (signer_state_t state, const uint8_t pubkey[897],
                  const uint8_t privkey[1281]);
int signer_sign (signer_state_t state, uint8_t *blindsig, size_t *blindsiglen,
                 const uint8_t *masked_msg, size_t maked_msglen);
void signer_clear (signer_state_t state);

void verifier_init (verifier_state_t state, const uint8_t pubkey[897]);
int verifier_vrfy (verifier_state_t state, const uint8_t m[512 / 8],
                   const uint8_t *sig, size_t siglen);
void verifier_clear (verifier_state_t state);

void user_init (user_state_t state, const uint8_t pubkey[897]);
void user_maskmsg (user_state_t state, uint8_t *masked_msg,
                   size_t *masked_msglen, const uint8_t msg[512 / 8]);
int user_sign (user_state_t state, uint8_t *sig, size_t *siglen,
               const uint8_t *blindsig, size_t blindsiglen);
void user_clear (user_state_t state);

unsigned long lin_params_get_prooflen (const lin_params_t params);

void lin_prover_init (lin_prover_state_t state, const uint8_t ppseed[32],
                      const lin_params_t params);
void lin_prover_set_statement_A (lin_prover_state_t state, polymat_t A);
void lin_prover_set_statement_t (lin_prover_state_t state, polyvec_t t);
void lin_prover_set_statement (lin_prover_state_t state, polymat_t A,
                               polyvec_t t);
void lin_prover_set_witness (lin_prover_state_t state, polyvec_t w);
void lin_prover_prove (lin_prover_state_t state, uint8_t *proof, size_t *len,
                       const uint8_t coins[32]);
void lin_prover_clear (lin_prover_state_t state);
void lin_verifier_init (lin_verifier_state_t state, const uint8_t ppseed[32],
                        const lin_params_t params);
void lin_verifier_set_statement_A (lin_verifier_state_t state, polymat_t A);
void lin_verifier_set_statement_t (lin_verifier_state_t state, polyvec_t t);
void lin_verifier_set_statement (lin_verifier_state_t state, polymat_t A,
                                 polyvec_t t);
int lin_verifier_verify (lin_verifier_state_t state, const uint8_t *proof,
                         size_t *len);
void lin_verifier_clear (lin_verifier_state_t state);

void print_stopwatch_user_maskmsg (unsigned int indent);
void print_stopwatch_signer_sign (unsigned int indent);
void print_stopwatch_user_sign (unsigned int indent);
void print_stopwatch_verifier_vrfy (unsigned int indent);
void print_stopwatch_lnp_prover_prove (unsigned int indent);
void print_stopwatch_lnp_verifier_verify (unsigned int indent);
void print_stopwatch_lnp_tbox_prove (unsigned int indent);
void print_stopwatch_lnp_tbox_verify (unsigned int indent);
void print_stopwatch_lnp_quad_eval_prove (unsigned int indent);
void print_stopwatch_lnp_quad_eval_verify (unsigned int indent);
void print_stopwatch_lnp_quad_many_prove (unsigned int indent);
void print_stopwatch_lnp_quad_many_verify (unsigned int indent);
void print_stopwatch_lnp_quad_prove (unsigned int indent);
void print_stopwatch_lnp_quad_verify (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_tg (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_z34 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_auto (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_beta3 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_beta4 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_upsilon (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_bin (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_l2 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_z4 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_z3 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_auto (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_hi (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_beta3 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_beta4 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_upsilon (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_bin (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_l2 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_z4 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_z3 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_auto (unsigned int indent);

void falcon_redc (int16_t c[512]);
void falcon_add (int16_t c[512], const int16_t a[512], const int16_t b[512]);
void falcon_mul (int16_t c[512], const int16_t a[512], const int16_t b[512]);
void falcon_keygen (uint8_t sk[1281], uint8_t pk[897]);
void falcon_decode_pubkey (int16_t h[512], const uint8_t pk[897]);
void falcon_preimage_sample (int16_t s1[512], int16_t s2[512],
                             const int16_t t[512], const uint8_t sk[1281]);

void falcon1024_redc (int16_t c[1024]);
void falcon1024_add (int16_t c[1024], const int16_t a[1024], const int16_t b[1024]);
void falcon1024_mul (int16_t c[1024], const int16_t a[1024], const int16_t b[1024]);
void falcon1024_keygen (uint8_t sk[2305], uint8_t pk[1793]);
void falcon1024_decode_pubkey (int16_t h[1024], const uint8_t pk[1793]);
void falcon1024_preimage_sample (int16_t s1[1024], int16_t s2[1024],
                                 const int16_t t[1024], const uint8_t sk[2305]);

/********************************************************************
 * 3.2 Internal functions and macros
 */

/* XXX internal sizeof(limb_t) * 8 */
#define NBITS_LIMB ((limb_t)(sizeof (limb_t) << 3))

/* XXX internal */
#define CEIL(x, y) (((x) + (y) - 1) / (y))
#define FLOOR(x, y) ((x) / (y))

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

#define ERR(expr, fmt, ...)                                                   \
  do                                                                          \
    {                                                                         \
      if (UNLIKELY ((expr)))                                                  \
        {                                                                     \
          fprintf (stderr, "lazer: error: " fmt "\n", __VA_ARGS__);           \
          abort ();                                                           \
        }                                                                     \
    }                                                                         \
  while (0)

#define WARN(expr, fmt, ...)                                                  \
  do                                                                          \
    {                                                                         \
      if (UNLIKELY ((expr)))                                                  \
        fprintf (stderr, "lazer: warning: " fmt "\n", __VA_ARGS__);           \
    }                                                                         \
  while (0)

#if ASSERT == ASSERT_ENABLED
#define ASSERT_ERR(expr)                                                      \
  ERR (!(expr), "assertion %s failed (%s:%d).", #expr, __FILE__, __LINE__)
#define ASSERT_WARN(expr)                                                     \
  WARN (!(expr), "assertion %s failed (%s:%d).", #expr, __FILE__, __LINE__)
#else
#define ASSERT_ERR(expr) (void)0
#define ASSERT_WARN(expr) (void)0
#endif

#define _VEC_FOREACH_ELEM(__vec__, __it__)                                    \
  for ((__it__) = 0; (__it__) < (__vec__)->nelems; (__it__)++)

#define _MAT_FOREACH_ROW(__mat__, __itr__)                                    \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)

#define _MAT_FOREACH_COL(__mat__, __itc__)                                    \
  for ((__itc__) = 0; (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _MAT_FOREACH_ELEM(__mat__, __itr__, __itc__)                          \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)              \
    for ((__itc__) = 0; (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _SVEC_FOREACH_ELEM(__vec__, __ite__)                                  \
  for ((__ite__) = 0; (__ite__) < (__vec__)->nelems; (__ite__)++)

#define _SMAT_FOREACH_ELEM(__mat__, __ite__)                                  \
  for ((__ite__) = 0; (__ite__) < (__mat__)->nelems; (__ite__)++)

#define _MAT_FOREACH_ELEM_UPPER(__mat__, __itr__, __itc__)                    \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)              \
    for ((__itc__) = (__itr__); (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _POLYRING_FOREACH_P(__ring__, __it__)                                 \
  for ((__it__) = 0; (__it__) < (__ring__)->nmoduli; (__it__)++)

static inline int
_neg2sign (limb_t neg)
{
  return (int)1 - (((int)neg) << 1);
}

static inline limb_t
_sign2neg (int sign)
{
  return ((limb_t)(1 - sign)) >> 1;
}

static inline limb_t
_i642neg (int64_t si)
{
  return ((limb_t)1 & (limb_t)(si >> ((sizeof (int64_t) << 3) - 1)));
}

static inline int
_i642sign (int64_t si)
{
  return _neg2sign (_i642neg (si));
}

static inline size_t
_sizeof_int_data (unsigned int nlimbs)
{
  return nlimbs * sizeof (limb_t);
}

static inline size_t
_sizeof_int (unsigned int nlimbs)
{
  return _sizeof_int_data (nlimbs) + sizeof (int_t);
}

static inline size_t
_sizeof_intvec_data (unsigned int nelems, unsigned int nlimbs)
{
  return nelems * _sizeof_int_data (nlimbs) + nelems * sizeof (int_t);
}

static inline size_t
_sizeof_intmat_data (unsigned int nrows, unsigned int ncols,
                     unsigned int nlimbs)
{
  return nrows * ncols * _sizeof_int_data (nlimbs)
         + nrows * ncols * sizeof (int_t);
}

static inline size_t
_sizeof_intmat (unsigned int nrows, unsigned int ncols, unsigned int nlimbs)
{
  return _sizeof_intmat_data (nrows, ncols, nlimbs) + sizeof (intmat_t);
}

static inline size_t
_sizeof_crtrep_data (polyring_srcptr ring)
{
  return sizeof (crtcoeff_t) * ring->d * ring->nmoduli;
}

static inline size_t
_sizeof_poly_data (polyring_srcptr ring)
{
  return /*_sizeof_crtrep_data (ring)
         + XXX*/
      _sizeof_intvec_data (ring->d, ring->q->nlimbs) + sizeof (intvec_t);
}

static inline size_t
_sizeof_poly (polyring_srcptr ring)
{
  return _sizeof_poly_data (ring) + sizeof (poly_t);
}

static inline size_t
_sizeof_polyvec_data (polyring_srcptr ring, unsigned int nelems)
{
  return nelems * _sizeof_poly_data (ring) + nelems * sizeof (poly_t);
}

static inline size_t
_sizeof_polyvec (polyring_srcptr ring, unsigned int nelems)
{
  return _sizeof_polyvec_data (ring, nelems) + sizeof (polyvec_t);
}

static inline size_t
_sizeof_polymat_data (polyring_srcptr ring, unsigned int nrows,
                      unsigned int ncols)
{
  return nrows * ncols * _sizeof_poly_data (ring)
         + nrows * ncols * sizeof (poly_t);
}

static inline size_t
_sizeof_polymat (polyring_srcptr ring, unsigned int nrows, unsigned int ncols)
{
  return _sizeof_polymat_data (ring, nrows, ncols + sizeof (polymat_t));
}

static inline void
_int_init (int_t r, unsigned int nlimbs, void *mem)
{
  r->limbs = (limb_t *)mem;
  r->nlimbs = nlimbs;
  r->neg = 0;
}

static inline void
_intvec_init (intvec_t r, unsigned int nelems, unsigned int nlimbs, void *mem)
{
  int_ptr elem;
  unsigned int i;

  r->bytes = mem;
  r->nbytes = nelems * _sizeof_int (nlimbs);

  r->elems = (int_ptr)((uint8_t *)mem + nelems * _sizeof_int_data (nlimbs));
  r->nlimbs = nlimbs;
  r->nelems = nelems;
  r->stride_elems = 1;

  _VEC_FOREACH_ELEM (r, i)
  {
    elem = intvec_get_elem (r, i);
    _int_init (elem, nlimbs, (uint8_t *)mem + i * _sizeof_int_data (nlimbs));
  }
}

static inline void
_intmat_init (intmat_t r, unsigned int nrows, unsigned int ncols,
              unsigned int nlimbs, void *mem)
{
  unsigned int i, j;
  int_ptr elem;

  r->bytes = mem;
  r->nbytes = nrows * ncols * _sizeof_int (nlimbs);

  r->cpr = ncols;

  r->elems
      = (int_ptr)((uint8_t *)mem + nrows * ncols * _sizeof_int_data (nlimbs));
  r->nlimbs = nlimbs;

  r->nrows = nrows;
  r->stride_row = 1;

  r->ncols = ncols;
  r->stride_col = 1;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    elem = intmat_get_elem (r, i, j);
    _int_init (elem, nlimbs,
               (uint8_t *)mem + ((i * ncols) + j) * _sizeof_int_data (nlimbs));
  }
}

static inline void
_poly_init (poly_t r, polyring_srcptr ring, void *mem)
{
  r->ring = ring;
  r->crtrep = NULL;
  r->crt = 0;
  r->mem = NULL;
  r->flags = 0;
  r->coeffs = (intvec_ptr)((uint8_t *)mem /*+ _sizeof_crtrep_data (ring)XXX*/
                           + _sizeof_intvec_data (ring->d, ring->q->nlimbs));
  _intvec_init (r->coeffs, ring->d, ring->q->nlimbs,
                (uint8_t *)mem /*XXX+ _sizeof_crtrep_data (ring)*/);
}

static inline void
_polyvec_init (polyvec_t r, polyring_srcptr ring, unsigned int nelems,
               void *mem)
{
  poly_ptr elem;
  unsigned int i;

  r->ring = ring;
  r->nelems = nelems;
  r->elems = (poly_ptr)((uint8_t *)mem + nelems * _sizeof_poly_data (ring));
  r->stride_elems = 1;
  r->mem = NULL;
  r->flags = 0;

  _VEC_FOREACH_ELEM (r, i)
  {
    elem = polyvec_get_elem (r, i);
    _poly_init (elem, ring, (uint8_t *)mem + i * _sizeof_poly_data (ring));
  }
}

static inline void
_polymat_init (polymat_t r, polyring_srcptr ring, unsigned int nrows,
               unsigned int ncols, void *mem)
{
  unsigned int i, j;
  poly_ptr elem;

  r->ring = ring;
  r->cpr = ncols;

  r->elems
      = (poly_ptr)((uint8_t *)mem + nrows * ncols * _sizeof_poly_data (ring));

  r->nrows = nrows;
  r->stride_row = 1;

  r->ncols = ncols;
  r->stride_col = 1;

  r->mem = NULL;
  r->flags = 0;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    elem = polymat_get_elem (r, i, j);
    _poly_init (elem, ring,
                (uint8_t *)mem + ((i * ncols) + j) * _sizeof_poly_data (ring));
  }
}

static inline void
_tocrt (poly_t r)
{
  if (!r->crt)
    {
      poly_tocrt (r);
      r->crt = 1;
    }
}

static inline void
_fromcrt (poly_t r)
{
  if (r->crt)
    {
      poly_fromcrt (r);
      r->crt = 0;
    }
}

static inline int
_to_same_dom (poly_t a, poly_t b, int crt)
{
  if (a->crt ^ b->crt)
    {
      if (crt)
        {
          _tocrt (a);
          _tocrt (b);
        }
      else
        {
          _fromcrt (a);
          _fromcrt (b);
        }
      return crt;
    }
  return a->crt;
}

static inline crtcoeff_t *
_get_crtcoeff (crtcoeff_t *crtrep, unsigned int pi, unsigned int coeff,
               unsigned int deg)
{
  ASSERT_ERR (coeff < deg);

  return crtrep + pi * deg + coeff;
}

static inline intvec_srcptr
_get_coeffvec_src (const poly_t poly)
{
  return poly->coeffs;
}

static inline intvec_ptr
_get_coeffvec (poly_t poly)
{
  return poly->coeffs;
}

#ifndef _OS_IOS
#include <immintrin.h>
#include <x86intrin.h>
#endif

static inline void limbs_cpy (limb_t *a, const limb_t *b, unsigned int n);
static inline void limbs_set (limb_t *a, limb_t b, unsigned int n);

static inline limb_t limb_eq_ct (const limb_t a, const limb_t b);

static inline limb_t limbs_eq_zero_ct (const limb_t *a, unsigned int n);

static inline limb_t limbs_eq_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_lt_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_le_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_gt_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_ge_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_add (limb_t *r, const limb_t *a, const limb_t *b,
                                uint8_t c, unsigned int nlimbs);
static inline limb_t limbs_sub (limb_t *r, const limb_t *a, const limb_t *b,
                                uint8_t c, unsigned int nlimbs);

static inline void limbs_cnd_select (limb_t *r, limb_t *a, limb_t *b,
                                     unsigned int nlimbs, limb_t c);
static inline void limbs_to_twoscom (limb_t *out, const limb_t *in,
                                     unsigned int nlimbs, limb_t neg);
static inline limb_t limbs_from_twoscom (limb_t *limbs, unsigned int nlimbs);
static inline void limbs_to_twoscom_ct (limb_t *limbs, unsigned int nlimbs,
                                        limb_t neg);
static inline limb_t limbs_from_twoscom_ct (limb_t *limbs,
                                            unsigned int nlimbs);

static inline unsigned char
_addcarry_u64_ (unsigned char c, unsigned long long x, unsigned long long y,
                unsigned long long *p)
{
#ifdef _OS_IOS
  unsigned long long cout;

  *p = __builtin_addcll (x, y, c, &cout);
  return cout;
#else
  return _addcarry_u64 (c, x, y, p);
#endif
}

static inline unsigned char
_subborrow_u64_ (unsigned char c, unsigned long long x, unsigned long long y,
                 unsigned long long *p)
{
#ifdef _OS_IOS
  unsigned long long cout;

  *p = __builtin_subcll (x, y, c, &cout);
  return cout;
#else
  return _subborrow_u64 (c, x, y, p);
#endif
}

#define NBITS_LIMB ((limb_t)(sizeof (limb_t) << 3))

static inline void
limbs_cpy (limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    a[i] = b[i];
}

static inline void
limbs_set (limb_t *a, limb_t b, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    a[i] = b;
}

static inline limb_t
limb_eq_ct (const limb_t a, const limb_t b)
{
  limb_t t;

  t = a ^ b;
  return (limb_t)1 ^ ((t | -t) >> (NBITS_LIMB - 1));
}

static inline limb_t
limbs_eq_zero_ct (const limb_t *a, unsigned int n)
{
  unsigned int i;
  limb_t r;

  r = 0;
  for (i = 0; i < n; i++)
    r |= a[i];
  return limb_eq_ct (r, 0);
}

static inline limb_t
limbs_eq_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;
  limb_t r;

  r = 0;
  for (i = 0; i < n; i++)
    r |= (a[i] ^ b[i]);
  return limb_eq_ct (r, 0);
}

static inline limb_t
limbs_lt (const limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;

  for (i = n; i > 0; i--)
    {
      if (a[i - 1] != b[i - 1])
        {
          if (a[i - 1] < b[i - 1])
            return 1;
          else
            return 0;
        }
    }

  return 0; /* equality */
}

static inline limb_t
limbs_lt_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, a, b, 0, n);
  return carry;
}

static inline limb_t
limbs_le_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, a, b, 0, n);
  return carry | limbs_eq_zero_ct (tmp, n);
}

static inline limb_t
limbs_gt_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, b, a, 0, n);
  return carry;
}

static inline limb_t
limbs_ge_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, b, a, 0, n);
  return carry | limbs_eq_zero_ct (tmp, n);
}

static inline limb_t
limbs_add (limb_t *r, const limb_t *a, const limb_t *b, uint8_t c,
           unsigned int nlimbs)
{
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    c = _addcarry_u64_ (c, a[i], b[i], (unsigned long long *)&r[i]);

  return c;
}

static inline limb_t
limbs_sub (limb_t *r, const limb_t *a, const limb_t *b, uint8_t c,
           unsigned int nlimbs)
{
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    c = _subborrow_u64_ (c, a[i], b[i], (unsigned long long *)&r[i]);

  return c;
}

static inline void
limbs_cnd_select (limb_t *r, limb_t *a, limb_t *b, unsigned int nlimbs,
                  limb_t c)
{
  const limb_t mask1 = (limb_t)(-((long long)c)); /* c == 1 : mask1 == ~0 */
  const limb_t mask2 = ~mask1;                    /* c == 1 : mask2 == 0 */
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    r[i] = a[i] ^ b[i] ^ (a[i] & mask1) ^ (b[i] & mask2);
}

static inline void
limbs_to_twoscom (limb_t *out, const limb_t *in, unsigned int nlimbs,
                  limb_t neg)
{
  unsigned int i;

  if (neg)
    {
      const limb_t mask = ~(limb_t)0;
      unsigned char c = 1;

      for (i = 0; i < nlimbs; i++)
        {
          out[i] = in[i] ^ mask;
          c = _addcarry_u64_ (c, out[i], 0, (unsigned long long *)&out[i]);
        }
    }
  else
    {
      for (i = 0; i < nlimbs; i++)
        {
          out[i] = in[i];
        }
    }
}

static inline limb_t
limbs_from_twoscom (limb_t *limbs, unsigned int nlimbs)
{
  limb_t neg;

  neg = (limbs[nlimbs - 1] >> (NBITS_LIMB - 1));
  limbs_to_twoscom (limbs, limbs, nlimbs, neg);
  return neg;
}

static inline void
limbs_to_twoscom_ct (limb_t *limbs, unsigned int nlimbs, limb_t neg)
{
  limb_t scratch[mpn_sec_add_1_itch (nlimbs)];
  limb_t comp[nlimbs];

  mpn_com (comp, limbs, nlimbs);
  mpn_sec_add_1 (comp, comp, nlimbs, 1, scratch);
  mpn_cnd_swap (neg, limbs, comp, nlimbs);
}

static inline limb_t
limbs_from_twoscom_ct (limb_t *limbs, unsigned int nlimbs)
{
  limb_t neg;

  neg = limbs[nlimbs - 1] >> (NBITS_LIMB - 1);
  limbs_to_twoscom_ct (limbs, nlimbs, neg);
  return neg;
}

/********************************************************************
 * 3.3 Implementations of API inline functions
 */

static inline unsigned int
int_get_nlimbs (const int_t a)
{
  return a->nlimbs;
}

static inline void
int_neg_self (int_t r)
{
  r->neg ^= 1;
}

static inline void
intvec_neg_self (intvec_t r)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_neg_self (rptr);
  }
}

static inline void
intvec_neg (intvec_t r, intvec_srcptr b)
{
  unsigned int i;
  int_ptr rptr, bptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    bptr = intvec_get_elem (b, i);
    int_neg (rptr, bptr);
  }
}

static inline void
int_set_zero (int_t r)
{
  int_set_i64 (r, 0);
}

static inline void
int_set_one (int_t r)
{
  int_set_i64 (r, 1);
}

static inline void
int_set (int_t r, const int_t a)
{
  unsigned int i, nlimbs;

  for (i = r->nlimbs - 1; i >= a->nlimbs; i--)
    r->limbs[i] = 0;

  nlimbs = MIN (a->nlimbs, r->nlimbs);

  limbs_cpy (r->limbs, a->limbs, nlimbs);
  r->neg = a->neg;
}

static inline void
int_set_i64 (int_t r, int64_t a)
{
  r->neg = _i642neg (a);
  r->limbs[0] = _i642sign (a) * a;
  limbs_set (r->limbs + 1, 0, r->nlimbs - 1);
}

static inline int64_t
int_get_i64 (const int_t r)
{
  return _neg2sign (r->neg) * r->limbs[0];
}

static inline void
int_neg (int_t r, const int_t a)
{
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  int_set (r, a);
  r->neg ^= 1;
}

static inline void
int_abs (int_t r, const int_t a)
{
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  int_set (r, a);
  r->neg = 0;
}

/* also return 1 for negative zero */
static inline int
int_sgn (const int_t a)
{
  const limb_t b = limbs_eq_zero_ct (a->limbs, a->nlimbs);

  return ((int)-1 + (b << 1)) & (_neg2sign (a->neg));
}

static inline void
int_mul_sgn_self (int_t r, int sgn)
{
  ASSERT_ERR (sgn == 1 || sgn == -1);

  r->neg = _sign2neg (int_sgn (r) * sgn);
}

static inline void
int_mul1 (int_t r, const int_t a, crtcoeff_t b)
{
#if 1
  crtcoeff_t c = 0;
  crtcoeff_dbl_t prod;
  unsigned int i;

  ASSERT_ERR (r->nlimbs == a->nlimbs + 1);

  r->neg = a->neg ^ (((uint64_t)b) >> 63); // get sign bit;
  if (b < 0)
    b = -b;

  for (i = 0; i < a->nlimbs; i++)
    {
      prod = (crtcoeff_dbl_t)a->limbs[i] * b + c;
      r->limbs[i] = prod & 0xffffffffffffffffULL;
      c = prod >> 64;
    }
  r->limbs[a->nlimbs] = c;
#else
  ASSERT_ERR (r->nlimbs == a->nlimbs + 1);

  r->neg = a->neg ^ (((uint64_t)b) >> 63); // get sign bit;
  if (b < 0)
    b = -b;

  r->limbs[a->nlimbs] = mpn_mul_1 (r->limbs, a->limbs, a->nlimbs, b);
#endif
}

static inline int
int_eqzero (const int_t a)
{
  return limbs_eq_zero_ct (a->limbs, a->nlimbs);
}

static inline int
int_abseq (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_abslt (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absle (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_le_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absgt (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absge (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_ge_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_eq (const int_t a, const int_t b)
{
  limb_t an, bn, eq;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  return (1 ^ an ^ bn) & eq;
}

static inline int
int_lt (const int_t a, const int_t b)
{
  limb_t an, bn, eq, lt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  lt = limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & an) | (an & bn & (1 ^ lt) & (1 ^ eq))
         | ((1 ^ an) & (1 ^ bn) & lt);
}

static inline int
int_le (const int_t a, const int_t b)
{
  limb_t an, bn, eq, lt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  lt = limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & an) | (an & bn & (1 ^ lt))
         | ((1 ^ an) & (1 ^ bn) & (lt | eq));
}

static inline int
int_gt (const int_t a, const int_t b)
{
  limb_t an, bn, eq, gt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  gt = limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt) & (1 ^ eq))
         | ((1 ^ an) & (1 ^ bn) & gt);
}

static int
int_ge (const int_t a, const int_t b)
{
  limb_t an, bn, eq, gt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  gt = limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt))
         | ((1 ^ an) & (1 ^ bn) & (gt | eq));
}

static inline void
int_rshift (int_t r, const int_t a, unsigned int n)
{
  unsigned int nlimbs, nbits, i;

  nlimbs = n / NBITS_LIMB;
  nbits = n - nlimbs * NBITS_LIMB;

  if (UNLIKELY (nlimbs >= a->nlimbs))
    {
      nlimbs = a->nlimbs;
      nbits = 0;
    }

  for (i = 0; i < MIN (r->nlimbs, a->nlimbs - nlimbs); i++)
    r->limbs[i] = a->limbs[i + nlimbs];
  for (; i < r->nlimbs; i++)
    r->limbs[i] = 0;

  if (nbits > 0)
    mpn_rshift (r->limbs, r->limbs, r->nlimbs, nbits);

  r->neg = a->neg;
}

static inline void
int_lshift (int_t r, const int_t a, unsigned int n)
{
  unsigned int nlimbs, nbits;
  long i;

  nlimbs = n / NBITS_LIMB;
  nbits = n - nlimbs * NBITS_LIMB;

  for (i = r->nlimbs - 1; i >= a->nlimbs + nlimbs; i--)
    r->limbs[i] = 0;
  for (; i >= nlimbs; i--)
    r->limbs[i] = a->limbs[i - nlimbs];
  for (; i >= 0; i--)
    r->limbs[i] = 0;

  if (nbits > 0)
    mpn_lshift (r->limbs, r->limbs, r->nlimbs, nbits);

  r->neg = a->neg;
}

#if 0
static inline void
int_add (int_t r, const int_t a, const int_t b)
{
  limb_t ta[r->nlimbs];
  limb_t tb[r->nlimbs];
  unsigned char c = 0;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_to_twoscom (ta, a->limbs, r->nlimbs, a->neg);
  limbs_to_twoscom (tb, b->limbs, r->nlimbs, b->neg);

  limbs_add (r->limbs, ta, tb, c, r->nlimbs);

  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}
#else
static inline void
int_add (int_t r, const int_t a, const int_t b)
{
  limb_t c;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  if (a->neg == b->neg)
    {
      limbs_add (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      r->neg = a->neg;
    }
  else
    {
      c = limbs_sub (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      if (c)
        {
          limbs_from_twoscom (r->limbs, r->nlimbs);
          r->neg = b->neg;
        }
      else
        {
          r->neg = a->neg;
        }
    }
}
#endif

static inline void
int_add_ct (int_t r, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], _b[b->nlimbs];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  mpn_copyi (_a, a->limbs, a->nlimbs);
  mpn_copyi (_b, b->limbs, b->nlimbs);

  limbs_to_twoscom_ct (_a, a->nlimbs, a->neg);
  limbs_to_twoscom_ct (_b, b->nlimbs, b->neg);

  limbs_add (r->limbs, _a, _b, 0, r->nlimbs);
  r->neg = limbs_from_twoscom_ct (r->limbs, r->nlimbs);
}

#if 0
static inline void
int_sub (int_t r, const int_t a, const int_t b)
{
  limb_t ta[r->nlimbs];
  limb_t tb[r->nlimbs];
  unsigned char c = 0;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_to_twoscom (ta, a->limbs, r->nlimbs, a->neg);
  limbs_to_twoscom (tb, b->limbs, r->nlimbs, b->neg);

  limbs_sub (r->limbs, ta, tb, c, r->nlimbs);

  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}
#else
static inline void
int_sub (int_t r, const int_t a, const int_t b)
{
  limb_t c;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  if (a->neg != b->neg)
    {
      limbs_add (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      r->neg = a->neg;
    }
  else
    {
      c = limbs_sub (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      if (c)
        {
          limbs_from_twoscom (r->limbs, r->nlimbs);
          r->neg = !b->neg;
        }
      else
        {
          r->neg = a->neg;
        }
    }
}
#endif

static inline void
int_sub_ct (int_t r, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], _b[b->nlimbs];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  mpn_copyi (_a, a->limbs, a->nlimbs);
  mpn_copyi (_b, b->limbs, b->nlimbs);

  limbs_to_twoscom_ct (_a, a->nlimbs, a->neg);
  limbs_to_twoscom_ct (_b, b->nlimbs, 1 ^ b->neg);

  limbs_add (r->limbs, _a, _b, 0, r->nlimbs);
  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}

/* [-(m-1),...,(m-1)] -> [-(m-1)/2,...,(m-1)/2] */
static inline void
int_redc (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_sub (tmp, m->limbs, a->limbs, 0, m->nlimbs);

  b = limbs_lt (tmp, a->limbs, m->nlimbs);
  if (b)
    {
      limbs_cpy (r->limbs, tmp, m->nlimbs);
    }
  else
    {
      limbs_cpy (r->limbs, a->limbs, m->nlimbs);
    }
  r->neg = b ^ a->neg;
}

/* [-(m-1),...,(m-1)] -> [-(m-1)/2,...,(m-1)/2] */
static inline void
int_redc_ct (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_cpy (r->limbs, a->limbs, m->nlimbs);
  limbs_sub (tmp, m->limbs, a->limbs, 0, m->nlimbs);

  b = limbs_lt_ct (tmp, r->limbs, m->nlimbs);
  limbs_cnd_select (r->limbs, r->limbs, tmp, m->nlimbs, b);
  r->neg = b ^ a->neg;
}

// XXX
/* result in [-(m-1),...,m-1] */
static inline crtcoeff_t
int_mod_XXX (const int_t a, crtcoeff_t m)
{
  limb_t d1, d2, r;
  int k;

  r = 0;
  for (k = a->nlimbs - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = a->limbs[k];
      r = (((crtcoeff_dbl_t)d1 << CRTCOEFF_NBITS) + d2) % m; // XXX
    }

  return a->neg ? -r : r;
}
// XXX
// XXX
/* result in [-(m-1),...,m-1] */
static inline uint64_t
int_mod_XXX_hexl (const int_t a, crtcoeff_t m)
{
  limb_t d1, d2, r;
  int k;

  r = 0;
  for (k = a->nlimbs - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = a->limbs[k];
      r = (((crtcoeff_dbl_t)d1 << CRTCOEFF_NBITS) + d2) % m; // XXX
    }

  return a->neg ? m - r : r;
}

static inline unsigned int
intvec_get_nlimbs (const intvec_t a)
{
  return a->nlimbs;
}

static inline unsigned int
intvec_get_nelems (const intvec_t r)
{
  return r->nelems;
}

static inline void
intvec_set_zero (intvec_t r)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);
    int_set_zero (ri);
  }
}

static inline void
intvec_set_ones (intvec_t r)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);
    int_set_one (ri);
  }
}

static inline void
intvec_set_one (intvec_t r, unsigned int idx)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);

    if (i == idx)
      int_set_one (ri);
    else
      int_set_zero (ri);
  }
}

static inline int_ptr
intvec_get_elem (const intvec_t a, unsigned int elem)
{
  ASSERT_ERR (elem < a->nelems);

  return &(a->elems[elem * a->stride_elems]);
}

static inline int_srcptr
intvec_get_elem_src (const intvec_t a, unsigned int elem)
{
  return intvec_get_elem (a, elem);
}

static inline void
intvec_set_elem (intvec_t a, unsigned int idx, const int_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (idx < a->nelems);

  ptr = intvec_get_elem (a, idx);
  int_set (ptr, elem);
}

static inline int64_t
intvec_get_elem_i64 (const intvec_t a, unsigned int elem)
{
  return int_get_i64 (intvec_get_elem_src (a, elem));
}

static inline void
intvec_set_elem_i64 (intvec_t a, unsigned int elem, int64_t val)
{
  int_ptr ptr;

  ptr = intvec_get_elem (a, elem);
  int_set_i64 (ptr, val);
}

static inline void
intvec_set (intvec_t r, const intvec_t a)
{
  INT_T (zero, 1);
  unsigned int i;
  int_srcptr ai;

  ASSERT_ERR (r->nelems >= a->nelems);

  int_set_i64 (zero, 0);

  for (i = r->nelems - 1; i >= a->nelems; i--)
    intvec_set_elem (r, i, zero);

  _VEC_FOREACH_ELEM (a, i)
  {
    ai = intvec_get_elem_src (a, i);
    intvec_set_elem (r, i, ai);
  }
}

static inline void
intvec_set_i64 (intvec_t r, const int64_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i32 (intvec_t r, const int32_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i16 (intvec_t r, const int16_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i8 (intvec_t r, const int8_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_get_i8 (int8_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT8_MIN);
    ASSERT_ERR (tmp <= INT8_MAX);

    r[i] = (int8_t)tmp;
  }
}

static inline void
intvec_get_i16 (int16_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT16_MIN);
    ASSERT_ERR (tmp <= INT16_MAX);

    r[i] = (int16_t)tmp;
  }
}

static inline void
intvec_get_i32 (int32_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT32_MIN);
    ASSERT_ERR (tmp <= INT32_MAX);

    r[i] = (int32_t)tmp;
  }
}

static inline void
intvec_get_i64 (int64_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    r[i] = (int64_t)tmp;
  }
}

static inline unsigned int
intmat_get_nlimbs (const intmat_t a)
{
  return a->nlimbs;
}

static inline unsigned int
intmat_get_nrows (const intmat_t mat)
{
  return mat->nrows;
}

static inline unsigned int
intmat_get_ncols (const intmat_t mat)
{
  return mat->ncols;
}

static inline void
intmat_set_zero (intmat_t r)
{
  unsigned int i, j;
  int_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = intmat_get_elem (r, i, j);
    int_set_zero (ri);
  }
}

static inline void
intmat_set_one (intmat_t r)
{
  intvec_t diag;
  unsigned int i, j;
  int_ptr ri;

  intmat_get_diag (diag, r, 0);
  intvec_set_ones (diag);

  _MAT_FOREACH_ELEM (r, i, j)
  {
    if (i != j)
      {
        ri = intmat_get_elem (r, i, j);
        int_set_zero (ri);
      }
  }
}

static inline int_ptr
intmat_get_elem (const intmat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return &(a->elems[row * a->stride_row * a->cpr + col * a->stride_col]);
}

static inline int_srcptr
intmat_get_elem_src (const intmat_t a, unsigned int row, unsigned int col)
{
  return intmat_get_elem (a, row, col);
}

static inline int64_t
intmat_get_elem_i64 (const intmat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return int_get_i64 (intmat_get_elem_src (a, row, col));
}

static inline void
intmat_set_elem (intmat_t a, unsigned int row, unsigned int col,
                 const int_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = intmat_get_elem (a, row, col);
  int_set (ptr, elem);
}

static inline void
intmat_set_elem_i64 (intmat_t a, unsigned int row, unsigned int col,
                     int64_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = intmat_get_elem (a, row, col);
  int_set_i64 (ptr, elem);
}

static inline void
intmat_get_row (intvec_t subvec, const intmat_t mat, unsigned int row)
{
  ASSERT_ERR (row < mat->nrows);

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  subvec->elems = intmat_get_elem (mat, row, 0);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = mat->ncols;
  subvec->stride_elems = mat->stride_col;
}

static inline void
intmat_set_row (intmat_t mat, const intvec_t vec, unsigned int row)
{
  intvec_t tmp;

  intmat_get_row (tmp, mat, row);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_col (intvec_t subvec, const intmat_t mat, unsigned int col)
{
  ASSERT_ERR (col < mat->ncols);

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  subvec->elems = intmat_get_elem (mat, 0, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = mat->nrows;
  subvec->stride_elems = mat->stride_row * mat->cpr;
}

static inline void
intmat_set_col (intmat_t mat, const intvec_t vec, unsigned int col)
{
  intvec_t tmp;

  intmat_get_col (tmp, mat, col);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_diag (intvec_t subvec, const intmat_t mat, int diag)
{
  unsigned int row = 0, col = 0;
  unsigned int nelems;

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  if (diag > 0)
    col += (unsigned int)diag;
  if (diag < 0)
    row += (unsigned int)(-diag);
  nelems = MIN (mat->nrows - row, mat->ncols - col);

  subvec->elems = intmat_get_elem (mat, row, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr + 1);
}

static inline void
intmat_set_diag (intmat_t mat, const intvec_t vec, int diag)
{
  intvec_t tmp;

  intmat_get_diag (tmp, mat, diag);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_antidiag (intvec_t subvec, const intmat_t mat, int antidiag)
{
  unsigned int row = 0, col = mat->ncols - 1, nelems;

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  if (antidiag > 0)
    col -= (unsigned int)antidiag;
  if (antidiag < 0)
    row += (unsigned int)(-antidiag);
  nelems = MIN (mat->nrows - row, col + 1);

  subvec->elems = intmat_get_elem (mat, row, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr - 1);
}

static inline void
intmat_set_antidiag (intmat_t mat, const intvec_t vec, int antidiag)
{
  intvec_t tmp;

  intmat_get_antidiag (tmp, mat, antidiag);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_submat (intmat_t submat, const intmat_t mat, unsigned int row,
                   unsigned int col, unsigned int nrows, unsigned int ncols,
                   unsigned int stride_row, unsigned int stride_col)
{
  ASSERT_ERR (row + stride_row * (nrows - 1) < mat->nrows);
  ASSERT_ERR (col + stride_col * (ncols - 1) < mat->ncols);

  submat->bytes = mat->bytes;
  submat->nbytes = mat->nbytes;

  submat->cpr = mat->cpr;

  submat->elems = intmat_get_elem (mat, row, col);
  submat->nlimbs = mat->nlimbs;

  submat->nrows = nrows;
  submat->stride_row = stride_row * mat->stride_row;

  submat->ncols = ncols;
  submat->stride_col = stride_col * mat->stride_col;
}

static inline void
intmat_set_submat (intmat_t mat, const intmat_t submat, unsigned int row,
                   unsigned int col, unsigned int nrows, unsigned int ncols,
                   unsigned int stride_row, unsigned int stride_col)
{
  intmat_t tmp;

  intmat_get_submat (tmp, mat, row, col, nrows, ncols, stride_row, stride_col);
  intmat_set (tmp, submat);
}

static inline void
intmat_set (intmat_t r, const intmat_t a)
{
  unsigned int i, j;

  ASSERT_ERR (r->nrows == a->nrows);
  ASSERT_ERR (r->ncols == a->ncols);

  _MAT_FOREACH_ELEM (a, i, j)
  {
    intmat_set_elem (r, i, j, intmat_get_elem_src (a, i, j));
  }
}

static inline void
intmat_set_i64 (intmat_t r, const int64_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, a[i * r->ncols + j]);
  }
}

static inline void
intmat_set_i32 (intmat_t r, const int32_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, (int64_t)(a[i * r->ncols + j]));
  }
}

static inline void
intmat_set_i8 (intmat_t r, const int8_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, (int64_t)(a[i * r->ncols + j]));
  }
}

static inline void
intmat_get_i64 (int64_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);
    r[i * a->ncols + j] = int_get_i64 (rptr);
  }
}

static inline void
intmat_get_i32 (int32_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;
  int64_t tmp;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);

    tmp = int_get_i64 (rptr);
    ASSERT_ERR (tmp >= INT32_MIN);
    ASSERT_ERR (tmp <= INT32_MAX);
    r[i * a->ncols + j] = (int32_t)tmp;
  }
}

static inline void
intmat_get_i8 (int8_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;
  int64_t tmp;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);

    tmp = int_get_i64 (rptr);
    ASSERT_ERR (tmp >= INT8_MIN);
    ASSERT_ERR (tmp <= INT8_MAX);
    r[i * a->ncols + j] = (int8_t)tmp;
  }
}

static inline unsigned int
polyring_get_deg (const polyring_t ring)
{
  return ring->d;
}

static inline int_srcptr
polyring_get_mod (const polyring_t ring)
{
  return ring->q;
}

static inline unsigned int
polyring_get_log2q (const polyring_t ring)
{
  return ring->log2q;
}

static inline unsigned int
polyring_get_log2deg (const polyring_t ring)
{
  return ring->log2d;
}

static inline unsigned int
poly_get_nlimbs (const poly_t a)
{
  return a->ring->q->nlimbs;
}

static inline polyring_srcptr
poly_get_ring (const poly_t poly)
{
  return poly->ring;
}

static inline intvec_ptr
poly_get_coeffvec (poly_t poly)
{
  _fromcrt (poly);

  poly->crt = 0;
  return poly->coeffs;
}

static inline int_ptr
poly_get_coeff (poly_t poly, unsigned int idx)
{
  _fromcrt (poly);

  poly->crt = 0;
  return intvec_get_elem (poly->coeffs, idx);
}

static inline void
poly_set_coeff (poly_t poly, unsigned int idx, const int_t val)
{
  int_ptr coeff;

  coeff = poly_get_coeff (poly, idx);
  int_set (coeff, val);
}

static inline void
poly_set_zero (poly_t r)
{
  intvec_set_zero (r->coeffs);
  r->crt = 0;
}

static inline void
poly_set_one (poly_t r)
{
  intvec_ptr rcoeffs = r->coeffs;
  const unsigned int nelems = intvec_get_nelems (rcoeffs);
  int_ptr rcoeff;
  unsigned int i;

  rcoeff = intvec_get_elem (rcoeffs, 0);
  int_set_one (rcoeff);

  for (i = 1; i < nelems; i++)
    {
      rcoeff = intvec_get_elem (rcoeffs, i);
      int_set_zero (rcoeff);
    }
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i64 (poly_t r, const int64_t *a)
{
  intvec_set_i64 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i32 (poly_t r, const int32_t *a)
{
  intvec_set_i32 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i16 (poly_t r, const int16_t *a)
{
  intvec_set_i16 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_get_coeffvec_i64 (int64_t *r, poly_t a)
{
  _fromcrt (a);
  intvec_get_i64 (r, a->coeffs);
  a->crt = 0;
}

static inline void
poly_get_coeffvec_i32 (int32_t *r, poly_t a)
{
  _fromcrt (a);
  intvec_get_i32 (r, a->coeffs);
  a->crt = 0;
}

static inline void
poly_neg_self (poly_t a)
{
#ifdef XXX

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt neg self");
#endif

  _fromcrt (a);
  intvec_neg_self (a->coeffs);
  a->crt = 0;
#endif

  if (a->crt == 1)
    {
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i;
      crtcoeff_t *c;

      _POLYRING_FOREACH_P (ring, i)
      {
        c = _get_crtcoeff (a->crtrep, i, 0, deg);
        hexl_ntt_scale (c, ring->moduli[i]->p - 1, c, deg, ring->moduli[i]->p,
                        1);
      }
    }
  else
    {
      intvec_neg_self (a->coeffs);
    }
}

static inline void
poly_set_coeffvec (poly_t r, const intvec_t v)
{
  ASSERT_ERR (polyring_get_deg (poly_get_ring (r)) == v->nelems);
  ASSERT_ERR (poly_get_nlimbs (r) == intvec_get_nlimbs (v));

  intvec_set (r->coeffs, v);
  r->crt = 0;
}

static inline void
poly_set_coeffvec2 (poly_t r, intvec_ptr v)
{
  ASSERT_ERR (polyring_get_deg (poly_get_ring (r)) == v->nelems);
  ASSERT_ERR (poly_get_nlimbs (r) == intvec_get_nlimbs (v));

  r->crt = 0;
  r->coeffs = v;
}

static inline unsigned int
polyvec_get_nelems (const polyvec_t a)
{
  return a->nelems;
}

static inline poly_ptr
polyvec_get_elem (const polyvec_t a, unsigned int elem)
{
  ASSERT_ERR (elem < a->nelems);

  return &(a->elems[elem * a->stride_elems]);
}

static inline polyring_srcptr
polyvec_get_ring (const polyvec_t a)
{
  return a->ring;
}

static inline unsigned int
polyvec_get_nlimbs (const polyvec_t a)
{
  return a->ring->q->nlimbs;
}

static inline poly_srcptr
polyvec_get_elem_src (const polyvec_t a, unsigned int elem)
{
  return polyvec_get_elem (a, elem);
}

static inline void
polyvec_set_zero (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set_zero (ri);
  }
}

static inline void
polyvec_set_one (polyvec_t r, unsigned int idx)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);

    if (i == idx)
      poly_set_one (ri);
    else
      poly_set_zero (ri);
  }
}

static inline void
polyvec_set_ones (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set_one (ri);
  }
}

static inline void
polyvec_set_elem (polyvec_t a, unsigned int idx, const poly_t elem)
{
  poly_ptr ptr;

  ASSERT_ERR (idx < a->nelems);

  ptr = polyvec_get_elem (a, idx);
  poly_set (ptr, elem);
}

static inline void
polyvec_neg_self (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_neg_self (ri);
  }
}

static inline void
polyvec_set (polyvec_t r, const polyvec_t a)
{
  unsigned int i;
  poly_srcptr ai;

  ASSERT_ERR (r->nelems == a->nelems);

  _VEC_FOREACH_ELEM (r, i)
  {
    ai = polyvec_get_elem_src (a, i);
    polyvec_set_elem (r, i, ai);
  }
}

static inline void
polyvec_fill (polyvec_t r, poly_t a)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set (ri, a);
  }
}

static inline void
polyvec_set_coeffvec (polyvec_t r, const intvec_t v)
{
  const unsigned int d = polyring_get_deg (polyvec_get_ring (r));
  unsigned int i;
  intvec_t subv;
  poly_ptr poly;

  ASSERT_ERR (d * polyvec_get_nelems (r) == intvec_get_nelems (v));
  ASSERT_ERR (polyvec_get_nlimbs (r) == intvec_get_nlimbs (v));

  _VEC_FOREACH_ELEM (r, i)
  {
    poly = polyvec_get_elem (r, i);

    intvec_get_subvec (subv, v, i * d, d, 1);

    poly_set_coeffvec (poly, subv);
    poly->crt = 0;
  }
}

static inline void
polyvec_set_coeffvec2 (polyvec_t r, intvec_ptr v)
{
  const unsigned int d = polyring_get_deg (polyvec_get_ring (r));
  unsigned int i;
  intvec_ptr coeffvec;
  intvec_t subv;
  poly_ptr poly;

  ASSERT_ERR (d * polyvec_get_nelems (r) == intvec_get_nelems (v));
  ASSERT_ERR (polyvec_get_nlimbs (r) == intvec_get_nlimbs (v));

  _VEC_FOREACH_ELEM (r, i)
  {
    poly = polyvec_get_elem (r, i);
    coeffvec = poly->coeffs;

    intvec_get_subvec (subv, v, i * d, d, 1);

    memcpy (coeffvec, subv, sizeof (intvec_t));
    poly->crt = 0;
  }
}

static inline void
polyvec_set_coeffvec_i64 (polyvec_t r, const int64_t *a)
{
  unsigned int i;
  poly_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = polyvec_get_elem (r, i);
    poly_set_coeffvec_i64 (rptr, a + i * r->ring->d);
  }
}

static inline void
polyvec_set_coeffvec_i32 (polyvec_t r, const int32_t *a)
{
  unsigned int i;
  poly_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = polyvec_get_elem (r, i);
    poly_set_coeffvec_i32 (rptr, a + i * r->ring->d);
  }
}

static inline void
polyvec_get_coeffvec_i32 (int32_t *r, const polyvec_t a)
{
  unsigned int i;
  poly_ptr ptr;

  _VEC_FOREACH_ELEM (a, i)
  {
    ptr = polyvec_get_elem (a, i);
    poly_get_coeffvec_i32 (r + i * a->ring->d, ptr);
  }
}

static inline void
polyvec_get_coeffvec_i64 (int64_t *r, const polyvec_t a)
{
  unsigned int i;
  poly_ptr ptr;

  _VEC_FOREACH_ELEM (a, i)
  {
    ptr = polyvec_get_elem (a, i);
    poly_get_coeffvec_i64 (r + i * a->ring->d, ptr);
  }
}

static inline unsigned int
polymat_get_nlimbs (const polymat_t a)
{
  return a->ring->q->nlimbs;
}

static inline unsigned int
polymat_get_nrows (const polymat_t mat)
{
  return mat->nrows;
}

static inline unsigned int
polymat_get_ncols (const polymat_t mat)
{
  return mat->ncols;
}

static inline polyring_srcptr
polymat_get_ring (const polymat_t a)
{
  return a->ring;
}

static inline void
polymat_fill (polymat_t r, poly_t a)
{
  unsigned int i, j;
  poly_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    poly_set (ri, a);
  }
}

static inline void
polymat_set_zero (polymat_t r)
{
  unsigned int i, j;
  poly_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    poly_set_zero (ri);
  }
}

static inline void
polymat_set_one (polymat_t r)
{
  polyvec_t diag;
  unsigned int i, j;
  poly_ptr ri;

  polymat_get_diag (diag, r, 0);
  polyvec_set_ones (diag);

  _MAT_FOREACH_ELEM (r, i, j)
  {
    if (i != j)
      {
        ri = polymat_get_elem (r, i, j);
        poly_set_zero (ri);
      }
  }
}

static inline poly_ptr
polymat_get_elem (const polymat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return &(a->elems[row * a->stride_row * a->cpr + col * a->stride_col]);
}

static inline poly_srcptr
polymat_get_elem_src (const polymat_t a, unsigned int row, unsigned int col)
{
  return polymat_get_elem (a, row, col);
}

static inline void
polymat_set_elem (polymat_t a, unsigned int row, unsigned int col,
                  const poly_t elem)
{
  poly_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = polymat_get_elem (a, row, col);
  poly_set (ptr, elem);
}

static inline void
polymat_get_row (polyvec_t subvec, const polymat_t mat, unsigned int row)
{
  ASSERT_ERR (row < mat->nrows);

  subvec->elems = polymat_get_elem (mat, row, 0);
  subvec->ring = mat->ring;

  subvec->nelems = mat->ncols;
  subvec->stride_elems = mat->stride_col;
}

static inline void
polymat_set_row (polymat_t mat, const polyvec_t vec, unsigned int row)
{
  polyvec_t tmp;

  polymat_get_row (tmp, mat, row);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_col (polyvec_t subvec, const polymat_t mat, unsigned int col)
{
  ASSERT_ERR (col < mat->ncols);

  subvec->elems = polymat_get_elem (mat, 0, col);
  subvec->ring = mat->ring;

  subvec->nelems = mat->nrows;
  subvec->stride_elems = mat->stride_row * mat->cpr;
}

static inline void
polymat_set_col (polymat_t mat, const polyvec_t vec, unsigned int col)
{
  polyvec_t tmp;

  polymat_get_col (tmp, mat, col);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_diag (polyvec_t subvec, const polymat_t mat, int diag)
{
  unsigned int row = 0, col = 0;
  unsigned int nelems;

  if (diag > 0)
    col += (unsigned int)diag;
  if (diag < 0)
    row += (unsigned int)(-diag);
  nelems = MIN (mat->nrows - row, mat->ncols - col);

  subvec->elems = polymat_get_elem (mat, row, col);
  subvec->ring = mat->ring;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr + 1);

  subvec->mem = NULL;
}

static inline void
polymat_set_diag (polymat_t mat, const polyvec_t vec, int diag)
{
  polyvec_t tmp;

  polymat_get_diag (tmp, mat, diag);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_antidiag (polyvec_t subvec, const polymat_t mat, int antidiag)
{
  unsigned int row = 0, col = mat->ncols - 1, nelems;

  if (antidiag > 0)
    col -= (unsigned int)antidiag;
  if (antidiag < 0)
    row += (unsigned int)(-antidiag);
  nelems = MIN (mat->nrows - row, col + 1);

  subvec->elems = polymat_get_elem (mat, row, col);
  subvec->ring = mat->ring;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr - 1);

  subvec->mem = NULL;
}

static inline void
polymat_set_antidiag (polymat_t mat, const polyvec_t vec, int antidiag)
{
  polyvec_t tmp;

  polymat_get_antidiag (tmp, mat, antidiag);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_submat (polymat_t submat, const polymat_t mat, unsigned int row,
                    unsigned int col, unsigned int nrows, unsigned int ncols,
                    unsigned int stride_row, unsigned int stride_col)
{
  ASSERT_ERR (row + stride_row * (nrows - 1) < mat->nrows);
  ASSERT_ERR (col + stride_col * (ncols - 1) < mat->ncols);

  submat->cpr = mat->cpr;

  submat->elems = polymat_get_elem (mat, row, col);
  submat->ring = mat->ring;

  submat->nrows = nrows;
  submat->stride_row = stride_row * mat->stride_row;

  submat->ncols = ncols;
  submat->stride_col = stride_col * mat->stride_col;

  submat->mem = NULL;
}

static inline void
polymat_set_submat (polymat_t mat, const polymat_t submat, unsigned int row,
                    unsigned int col, unsigned int nrows, unsigned int ncols,
                    unsigned int stride_row, unsigned int stride_col)
{
  polymat_t tmp;

  polymat_get_submat (tmp, mat, row, col, nrows, ncols, stride_row,
                      stride_col);
  polymat_set (tmp, submat);
}

static inline void
polymat_set (polymat_t r, const polymat_t a)
{
  unsigned int i, j;

  ASSERT_ERR (r->nrows == a->nrows);
  ASSERT_ERR (r->ncols == a->ncols);

  _MAT_FOREACH_ELEM (a, i, j)
  {
    polymat_set_elem (r, i, j, polymat_get_elem_src (a, i, j));
  }
}

static inline void
polymat_set_i64 (polymat_t r, const int64_t *a)
{
  const unsigned int d = r->ring->d;
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = polymat_get_elem (r, i, j);
    poly_set_coeffvec_i64 (rptr, &a[d * (i * r->ncols + j)]);
  }
}

static inline void
polymat_set_i32 (polymat_t r, const int32_t *a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = polymat_get_elem (r, i, j);
    poly_set_coeffvec_i32 (rptr, &a[i * r->ncols + j]);
  }
}

static inline void
polymat_get_i64 (int64_t *r, const polymat_t a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = polymat_get_elem (a, i, j);
    poly_get_coeffvec_i64 (&r[i * a->ncols + j], rptr);
  }
}

static inline void
polymat_get_i32 (int32_t *r, const polymat_t a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = polymat_get_elem (a, i, j);
    poly_get_coeffvec_i32 (&r[i * a->ncols + j], rptr);
  }
}

static inline unsigned int
dcompress_get_d (const dcompress_params_t params)
{
  return params->D;
}

static inline int_srcptr
dcompress_get_gamma (const dcompress_params_t params)
{
  return params->gamma;
}

static inline int_srcptr
dcompress_get_m (const dcompress_params_t params)
{
  return params->m;
}

static inline unsigned int
dcompress_get_log2m (const dcompress_params_t params)
{
  return params->log2m;
}

static inline polyring_srcptr
spolyvec_get_ring (spolyvec_ptr r)
{
  return r->ring;
}
static inline unsigned int
spolyvec_get_elem_ (spolyvec_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].elem;
}
static inline void
spolyvec_set_elem_ (spolyvec_ptr r, unsigned int i, unsigned int elem)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].elem = elem;
}
static inline void
spolyvec_set_nelems (spolyvec_ptr r, unsigned int nelems)
{
  ASSERT_ERR (nelems < r->nelems_max);
  r->nelems = nelems;
}
static inline void
spolyvec_set_empty (spolyvec_ptr r)
{
  r->nelems = 0;
}
static inline poly_ptr
spolyvec_get_elem (spolyvec_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].poly;
}
static inline unsigned int
spolyvec_get_nelems (spolyvec_ptr r)
{
  return r->nelems;
}

static inline polyring_srcptr
spolymat_get_ring (spolymat_ptr r)
{
  return r->ring;
}
static inline unsigned int
spolymat_get_row (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].row;
}
static inline unsigned int
spolymat_get_col (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].col;
}
static inline void
spolymat_set_row (spolymat_ptr r, unsigned int i, unsigned int row)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].row = row;
}
static inline void
spolymat_set_col (spolymat_ptr r, unsigned int i, unsigned int col)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].col = col;
}
static inline void
spolymat_set_nelems (spolymat_ptr r, unsigned int nelems)
{
  ASSERT_ERR (nelems < r->nelems_max);
  r->nelems = nelems;
}
static inline void
spolymat_set_empty (spolymat_ptr r)
{
  r->nelems = 0;
}
static inline poly_ptr
spolymat_get_elem (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].poly;
}
static inline unsigned int
spolymat_get_nrows (spolymat_ptr r)
{
  return r->nrows;
}
static inline unsigned int
spolymat_get_ncols (spolymat_ptr r)
{
  return r->ncols;
}

__END_DECLS
#endif
