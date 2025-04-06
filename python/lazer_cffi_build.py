# python 3 lazer_cffi_build.py <lazerdir>

import cffi
import sys
import os

assert len(sys.argv) <= 2
prefix = os.path.abspath('..')
if len(sys.argv) > 1:
  prefix = os.path.abspath(sys.argv[1])

cdefs_labrador = """

typedef struct
{
  ...;
}PREFIXsmplstmnt;

typedef struct
{
  ...;
}PREFIXwitness;
typedef PREFIXwitness PREFIXwitness_t[1];

typedef struct
{
  ...;
}PREFIXcommitment;

typedef struct
{
  ...;
}PREFIXcomposite;

void PREFIXinit_witness_raw(PREFIXwitness *wt, size_t r, size_t n[]);
int PREFIXset_witness_vector_raw(PREFIXwitness *wt, size_t i, size_t n, size_t deg, const int64_t s[]);
void PREFIXinit_smplstmnt_raw(PREFIXsmplstmnt *st, size_t r, size_t n[], uint64_t betasq[], size_t k);
int PREFIXset_smplstmnt_lincnst_raw(PREFIXsmplstmnt *st, size_t i, size_t nz, size_t idx[], size_t n[], size_t deg, int64_t *phi, int64_t *b);
int PREFIXsimple_verify(const PREFIXsmplstmnt *st, const PREFIXwitness *wt);
int PREFIXcomposite_prove_simple(PREFIXcomposite *proof, PREFIXcommitment *com, const PREFIXsmplstmnt *st, const PREFIXwitness *wt);
int PREFIXcomposite_verify_simple(const PREFIXcomposite *proof, const PREFIXcommitment *com, const PREFIXsmplstmnt *st);
void PREFIXinit_comkey(size_t n);
void PREFIXfree_comkey();
void PREFIXfree_commitment(PREFIXcommitment *com);
void PREFIXfree_witness(PREFIXwitness *wt);
void PREFIXfree_composite(PREFIXcomposite *proof);
void PREFIXfree_smplstmnt(PREFIXsmplstmnt *st);
"""

cdefs_lazer = """

// types

typedef uint64_t limb_t;

typedef struct
{
  limb_t *limbs;
  unsigned int nlimbs;
  limb_t neg;
} int_struct;
typedef int_struct int_t[1];
typedef int_struct *int_ptr;
typedef const int_struct *int_srcptr;

typedef struct
{
  ...;
} intvec_struct;
typedef intvec_struct intvec_t[1];
typedef intvec_struct *intvec_ptr;
typedef const intvec_struct *intvec_srcptr;

typedef struct
{
  ...;
} modulus_struct;
typedef modulus_struct modulus_t[1];
typedef modulus_struct *modulus_ptr;
typedef const modulus_struct *modulus_srcptr;

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
  ...;
} poly_struct;
typedef poly_struct poly_t[1];
typedef poly_struct *poly_ptr;
typedef const poly_struct *poly_srcptr;

typedef struct
{
  ...;
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
  ...;
} lin_prover_state_struct;
typedef lin_prover_state_struct lin_prover_state_t[1];
typedef lin_prover_state_struct *lin_prover_state_ptr;
typedef const lin_prover_state_struct *lin_prover_state_srcptr;

typedef struct
{
  ...;
} lin_verifier_state_struct;
typedef lin_verifier_state_struct lin_verifier_state_t[1];
typedef lin_verifier_state_struct *lin_verifier_state_ptr;
typedef const lin_verifier_state_struct *lin_verifier_state_srcptr;

typedef struct
{
  ...;
} lin_params_struct;
typedef lin_params_struct lin_params_t[1];
typedef lin_params_struct *lin_params_ptr;
typedef const lin_params_struct *lin_params_srcptr;

typedef struct
{
  ...;
} coder_state_struct;
typedef coder_state_struct coder_state_t[1];
typedef coder_state_struct *coder_state_ptr;
typedef const coder_state_struct *coder_state_srcptr;


// function prototypes

FILE *fmemopen (void *buf, size_t size, const char *mode);
int fclose (FILE *stream);

void lazer_init (void);

void int_alloc (int_ptr r, unsigned int nlimbs);
void int_free (int_ptr r);
size_t int_out_str (FILE *stream, int base, const int_t a);
void int_set (int_t r, const int_t a);

void int_add (int_t r, const int_t a, const int_t b);
void int_sub (int_t r, const int_t a, const int_t b);
void int_mul (int_t r, const int_t a, const int_t b);

int int_eq (const int_t a, const int_t b);
int int_lt (const int_t a, const int_t b);
int int_le (const int_t a, const int_t b);
int int_gt (const int_t a, const int_t b);
int int_ge (const int_t a, const int_t b);

void int_brandom (int_t r, unsigned int k, const uint8_t seed[32],
                  uint32_t dom);
void int_grandom (int_t r, unsigned int log2o, const uint8_t seed[32],
                  uint32_t dom);
void int_urandom (int_t r, const int_t mod, unsigned int log2mod,
                  const uint8_t seed[32], uint32_t dom);
void int_urandom_bnd (int_t r, const int_t lo, const int_t hi,
                      const uint8_t seed[32], uint32_t dom);

void int_dump (int_t z);

void intvec_alloc (intvec_ptr r, unsigned int nelems, unsigned int nlimbs);
void intvec_free (intvec_ptr r);
static inline void intvec_set_zero (intvec_t r);
static inline void intvec_set_elem (intvec_t a, unsigned int col,
                                    const int_t elem);
static inline int_ptr intvec_get_elem (const intvec_t a, unsigned int col);

void intvec_add (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_sub (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_mul (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_dot (int_t r, const intvec_t a, const intvec_t b);
void intvec_scale (intvec_t r, const int_t a, const intvec_t b);

void intvec_dump (intvec_t z);



static inline unsigned int polyring_get_deg (const polyring_t ring);
static inline int_srcptr polyring_get_mod (const polyring_t ring);

void poly_alloc (poly_ptr r, const polyring_t ring);
void poly_free (poly_ptr r);
size_t poly_out_str (FILE *stream, int base, poly_t a);
static inline void poly_set_coeff (poly_t poly, unsigned int idx,
                                   const int_t val);

void poly_add (poly_t r, poly_t a, poly_t b, int crt);
void poly_sub (poly_t r, poly_t a, poly_t b, int crt);
void poly_scale (poly_t r, const int_t a, poly_t b);
void poly_mul (poly_t r, poly_t a, poly_t b);
void poly_redc (poly_t r, poly_t a);
void poly_redp (poly_t r, poly_t a);
void poly_set (poly_t r, const poly_t a);
void poly_set_coeffvec_i64 (poly_t r, const int64_t *a);
void poly_set_coeffvec_i16 (poly_t r, const int16_t *a);
void poly_get_coeffvec_i64 (int64_t *r, poly_t a);
static inline int_ptr poly_get_coeff (poly_t poly, unsigned int idx);
static inline void poly_neg_self (poly_t a);
void poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
                   const uint8_t seed[32], uint32_t dom);
void poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                       const uint8_t seed[32], uint32_t dom);
void poly_grandom (poly_t r, unsigned int log2o, const uint8_t seed[32],
                   uint32_t dom);
int poly_eq (poly_t a, poly_t b);
void poly_l2sqr (int_t r, poly_t a);
void poly_linf (int_t r, poly_t a);
void poly_dump (poly_t a);

void polyvec_alloc (polyvec_ptr r, const polyring_t ring, unsigned int nelems);
void polyvec_free (polyvec_ptr r);
void polyvec_set_coeffvec_i64 (polyvec_t r, const int64_t *a);
void polyvec_get_coeffvec_i64 (int64_t *r, polyvec_t a);
static inline void polyvec_set_zero (polyvec_t r);
static inline poly_ptr polyvec_get_elem (const polyvec_t a, unsigned int elem);
static inline void polyvec_set_elem (polyvec_t a, unsigned int idx,
                                     const poly_t elem);
static inline void polyvec_set (polyvec_t r, const polyvec_t a);
static inline void polyvec_set_coeffvec (polyvec_t r, const intvec_t v);
int polyvec_eq (polyvec_t a, polyvec_t b);
void polyvec_add (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
void polyvec_sub (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
void polyvec_scale (polyvec_t r, const int_t a, polyvec_t b);
void polyvec_scale2 (polyvec_t r, poly_t a, polyvec_t b);
void polyvec_dot (poly_t r, polyvec_t a, polyvec_t b);
void polyvec_elem_mul (polyvec_t r, polyvec_t a, polyvec_t b);
static inline void polyvec_neg_self (polyvec_t r);
void intvec_set_i64 (intvec_t r, const int64_t *a);
void intvec_get_i64 (int64_t *r, const intvec_t a);
void polyvec_grandom (polyvec_t r, unsigned int log2o, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_brandom (polyvec_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_urandom (polyvec_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polyvec_urandom_bnd (polyvec_t r, const int_t lo, const int_t hi,
                          const uint8_t seed[32], uint32_t dom);
void polyvec_mul (polyvec_t r, polymat_t a, polyvec_t b);
void polyvec_mul2 (polyvec_t r, polyvec_t a, polymat_t b);
void polyvec_linf (int_t r, polyvec_t a);
void polyvec_l2sqr (int_t r, polyvec_t a);
void polyvec_redc (polyvec_t r, polyvec_t a);
void polyvec_redp (polyvec_t r, polyvec_t a);
void polyvec_dump (polyvec_t vec);

void polymat_alloc (polymat_ptr r, const polyring_t ring, unsigned int nrows,
                    unsigned int ncols);
void polymat_free (polymat_ptr r);
static inline void polymat_set_zero (polymat_t r);
static inline poly_ptr polymat_get_elem (const polymat_t a, unsigned int row,
                                         unsigned int col);
static inline void polymat_set_elem (polymat_t a, unsigned int row,
                                     unsigned int col, const poly_t elem);
static inline void polymat_get_row (polyvec_t subvec, const polymat_t mat,
                                    unsigned int row);
static inline void polymat_set_row (polymat_t mat, const polyvec_t vec,
                                    unsigned int row);
static inline void polymat_get_col (polyvec_t subvec, const polymat_t mat,
                                    unsigned int col);
static inline void polymat_set_col (polymat_t mat, const polyvec_t vec,
                                    unsigned int col);
static inline void polymat_set (polymat_t r, const polymat_t a);
void polymat_add (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_sub (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_scale2 (polymat_t r, poly_t a, polymat_t b);
void polymat_urandom (polymat_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polymat_brandom (polymat_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polymat_redc (polymat_t r, polymat_t a);                  
void polymat_dump (polymat_t mat);

void poly_tocrt (poly_t r);
void poly_fromcrt (poly_t r);
void polyvec_tocrt (polyvec_t r);
void polyvec_fromcrt (polyvec_t r);
void polymat_tocrt (polymat_t r);
void polymat_fromcrt (polymat_t r);

void falcon_redc (int16_t c[]);
void falcon_add (int16_t c[], const int16_t a[], const int16_t b[]);
void falcon_mul (int16_t c[], const int16_t a[], const int16_t b[]);
void falcon_keygen (uint8_t sk[], uint8_t pk[]);
void falcon_decode_pubkey (int16_t h[], const uint8_t pk[]);
void falcon_preimage_sample (int16_t s1[], int16_t s2[], const int16_t t[], const uint8_t sk[]);

void poly_toisoring (polyvec_t vec, poly_t a);
void poly_fromisoring (poly_t a, polyvec_t vec);
void polyvec_toisoring (polyvec_t vec, polyvec_t a);
void polyvec_fromisoring (polyvec_t a, polyvec_t vec);
void lin_toisoring (polymat_t r1, polyvec_t r0, polymat_t r1prime,
                    polyvec_t r0prime);

unsigned long lin_params_get_prooflen(const lin_params_t params);

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

void coder_enc_begin (coder_state_t state, uint8_t *out);
void coder_dec_begin (coder_state_t state, const uint8_t *in);
void coder_enc_end (coder_state_t state);
int coder_dec_end (coder_state_t state);
unsigned int coder_get_offset (coder_state_t state);
void coder_enc_urandom (coder_state_t state, const intvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_urandom2 (coder_state_t state, poly_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom (coder_state_t state, intvec_t v, const int_t m,
                       unsigned int mbits);
int coder_dec_urandom2 (coder_state_t state, poly_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_bytes (coder_state_t state, const uint8_t *bytes,
                      unsigned int nbytes);
int coder_dec_bytes (coder_state_t state, uint8_t *bytes, unsigned int nbytes);
void coder_enc_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_enc_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);
void coder_dec_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_dec_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);

void print_stopwatch_lnp_prover_prove (unsigned int indent);
void print_stopwatch_lnp_verifier_verify (unsigned int indent);

// global constants

static const modulus_srcptr moduli_d64[];
static const modulus_srcptr moduli_d128[];


"""


includedirs = [prefix]
# XXX get hexl path from build system
libdirs = [prefix, f"{prefix}/third_party/hexl-development/build/hexl/lib/", f"{prefix}/third_party/hexl-development/build/hexl/lib64/"]
runtimelibdirs = [prefix, f"{prefix}/third_party/hexl-development/build/hexl/lib/", f"{prefix}/third_party/hexl-development/build/hexl/lib64/"]
libs_lazer = ['lazer', 'hexl', 'mpfr', 'gmp', 'm', 'stdc++']
source_lazer = """
#include "lazer.h"
"""
source_labrador = """
#include "src/labradorLOGQ_py.h"
"""

cdefs = cdefs_lazer
source = source_lazer
libs = libs_lazer

if os.path.isfile('../liblabrador24.so'):
   cdefs += cdefs_labrador.replace("PREFIX","labrador24_")
   source += source_labrador.replace("LOGQ","24")
   libs += ['labrador24']
if os.path.isfile('../liblabrador32.so'):
   cdefs += cdefs_labrador.replace("PREFIX","labrador32_")
   source += source_labrador.replace("LOGQ","32")
   libs += ['labrador32']
if os.path.isfile('../liblabrador40.so'):
   cdefs += cdefs_labrador.replace("PREFIX","labrador40_")
   source += source_labrador.replace("LOGQ","40")
   libs += ['labrador40']
if os.path.isfile('../liblabrador48.so'):
   cdefs += cdefs_labrador.replace("PREFIX","labrador48_")
   source += source_labrador.replace("LOGQ","48")
   libs += ['labrador48']


ffibuilder = cffi.FFI()
ffibuilder.cdef(cdefs)
ffibuilder.set_source("_lazer_cffi", source, libraries=libs, include_dirs=includedirs,
                      library_dirs=libdirs, runtime_library_dirs=runtimelibdirs)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
