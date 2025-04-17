#ifndef LABRADOS38_PY_H
#define LABRADOS38_PY_H

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#define LABRADOR38_N 64
#define LABRADOR38_K 6
#define LABRADOR38_L 3

typedef union{
  __m512i v[LABRADOR38_N/32];
  int16_t c[LABRADOR38_N];
} labrador38_vecn;

typedef struct{
  labrador38_vecn vec[1];
} labrador38_poly;

typedef struct{
  labrador38_vecn limbs[LABRADOR38_L];
} labrador38_polz;

typedef struct _labrador38_polx{
  double width;
  labrador38_poly proj[LABRADOR38_K];
} labrador38_polx[1];

typedef struct _labrador38_polxvec{
  size_t alloc;
  size_t off;
  ssize_t stride;
  size_t len;
  double *widths;
  labrador38_poly *proj[LABRADOR38_K];
} labrador38_polxvec[1];

typedef struct _labrador38_witness{
  size_t r;
  size_t *n;
  labrador38_poly **s;
#ifndef NDEBUG
  size_t maxr;
#endif
} labrador38_witness[1];

typedef struct _labrador38_quadfunc{
  size_t len;
  size_t *rows;
  size_t *cols;
  labrador38_polx *coeffs;
} labrador38_quadfunc[1];

typedef struct _labrador38_linfunc{
  size_t rank;
  size_t nparts;
  size_t *off;
  labrador38_polxvec *phi;
} labrador38_linfunc[1];

typedef struct _labrador38_sparsecnst{
  labrador38_quadfunc quad;
  labrador38_linfunc lin;
  labrador38_polxvec b;
} labrador38_sparsecnst[1];

typedef struct _labrador38_comcnst{
  size_t rank;
  labrador38_polxvec b;

  size_t ncom;
  size_t *comk_off;
  size_t *comw_off;
  size_t *comw_len;
  int64_t *scalar;

  size_t nphi;
  size_t *phiw_off;
  labrador38_polxvec *phi;
} labrador38_comcnst[1];

typedef struct _labrador38_sigmam1cnst{
  size_t off1;
  size_t off2;
  size_t len;
  int mul;
  labrador38_polxvec c;
} labrador38_sigmam1cnst[1];

typedef struct _labrador38_intcnst{
  size_t off;
  size_t rank;
} labrador38_intcnst[1];

typedef struct _labrador38_rqcnstset{
  size_t nsparse;
  size_t sparse_nchal;
  labrador38_sparsecnst *sparse;

  size_t ncom;
  size_t com_nchal;
  labrador38_comcnst *com;
} labrador38_rqcnstset[1];

typedef struct _labrador38_zqcnstset{
  size_t nsparse;
  size_t sparse_nchal;
  labrador38_sparsecnst *sparse;

  size_t nsigmam1;
  size_t sigmam1_nchal;
  labrador38_sigmam1cnst *sigmam1;

  size_t nint;
  size_t int_nchal;
  labrador38_intcnst *intc;

#ifndef NDEBUG
  size_t maxnsparse;
  size_t maxnsigmam1;
#endif
} labrador38_zqcnstset[1];

typedef struct _labrador38_statement{
  size_t r;
  size_t *n;
  uint64_t *normsq;
  uint64_t *normsq_req;
  int *normty;
  labrador38_rqcnstset rqcnst;
  labrador38_zqcnstset zqcnst;
  uint8_t h[16];
#ifndef NDEBUG
  size_t maxr;
#endif
} labrador38_statement[1];

typedef struct _labrador38_dch_proof{
  labrador38_polz *com;
} labrador38_dch_proof[1];

typedef struct _labrador38_dch_params{
  size_t r;
  size_t *n;
  uint64_t *normsq;
  int *normty;

  size_t nexact;
  size_t nexact_merge;
  size_t nbin_merge;
  size_t napprox_merge;
  size_t *exact_map;

  size_t nquad;
  size_t quad_sumranks;
  size_t quad_nterms;
  size_t quad_maxrank;

  size_t base_unif;
  size_t base_liftings;
  size_t base_quad_left;
  size_t digits_unif;
  size_t digits_liftings;
  size_t digits_quad_left;

  size_t nincom;
  size_t *incom_offw;
  size_t *incom_lenw;
  size_t *kappa_inner;
  size_t kappa_middle;
  size_t kappa_outer;
  size_t randlen;

  size_t *off_exact;
  size_t off_liftings;
  size_t off_diff;
  size_t *off_sigma;
  size_t *off_incom;
  size_t off_midcom;
  size_t off_rand;
  size_t off_quad_left;
  size_t off_quad_right;

  size_t *len_exact_merge;
  size_t len_exact_total;
  size_t len_bin_total;
  size_t len_com_inner;
  size_t len_quad;

  size_t *idx_exact;
  size_t *idx_exact_merge;
  size_t *idx_sigma;
  size_t idx_quad;
  size_t *nparts_exact_merge;
  size_t nparts_quad;
} labrador38_dch_params[1];

typedef struct _labrador38_lab_proof{
  labrador38_polz *m[4];
  int32_t p[256];
} labrador38_lab_proof[1];

typedef struct _labrador38_lab_params{
  size_t r_old;
  size_t *rr;
  size_t r;
  size_t *n;
  size_t nn;
  size_t nmax;
  size_t kappa[3];
  size_t randlen;
  size_t bz;
  size_t bu;
  size_t bg;
  size_t fz;
  size_t fu;
  size_t fg;
  uint64_t *normsq;
  uint64_t normsq_global;
  uint64_t normsq_new[4];
  size_t off[14];
  size_t len[14];
  int compressed;
  int tail;
} labrador38_lab_params[1];

typedef struct _labrador38_lnp_proof {
  labrador38_polz *m[5];                 
} labrador38_lnp_proof[1];

typedef struct _labrador38_lnp_params {
  size_t kappa_mlwe;

  size_t kappa_linfmsis;
  uint64_t beta_linfmsis;

  size_t kappa_l2msis1;
  long double beta_l2msis1;

  size_t kappa_l2msis2;
  long double beta_l2msis2;

  size_t k[5];

  size_t silen[5 + 1];        
  size_t slen;                
  size_t stildelen;           
  size_t silen_max;           
  long double sibeta[5 + 1];

  size_t v0ihatlen[5];
  size_t v0hatlen;
  size_t vtildelen;

  long double sdp;
  unsigned int logsdp;
  long double gammap;
  long double capmp;

  long double sd1;
  unsigned int logsd1;
  long double gamma1;
  long double capm1;

  long double sd2;
  unsigned int logsd2;
  long double gamma2;
  long double capm2;

  size_t b1;
  size_t b2;

  size_t rslen;
  size_t rvlen;

  size_t srslen;

  uint64_t z1sbetasq[6];
  uint64_t z1vbetasq;
  uint64_t z2sbetasq;
  uint64_t z2vbetasq;

  size_t off[28];
  size_t len[28];
  size_t xbinlen;
  size_t wtlen;         
  size_t a2soff;
  size_t a2voff;
} labrador38_lnp_params[1];

typedef struct _labrador38_pack_proof{
  size_t np;
  labrador38_lab_proof *p;
  labrador38_lnp_proof *zkp;
  labrador38_witness owt;
} labrador38_pack_proof[1];

typedef struct _labrador38_pack_params{
  size_t np;
  labrador38_lab_params *p;
  labrador38_lnp_params *zkp;
  size_t zkround;
} labrador38_pack_params[1];

typedef struct _labrador38_dch_pack_proof{
  labrador38_dch_proof pi_dch;
  labrador38_pack_proof pi_pack;
} labrador38_dch_pack_proof[1];

typedef struct _labrador38_dch_pack_params{
  labrador38_dch_params pp_dch;
  labrador38_pack_params pp_pack;
} labrador38_dch_pack_params[1];

void labrador38_py_init_witness(labrador38_witness wt, size_t r, size_t n[]);
int labrador38_py_set_witness_vector(labrador38_witness wt, size_t idx, size_t n, size_t deg, const int64_t s[]);
int labrador38_py_print_witness_vector(labrador38_witness wt, size_t idx);
void labrador38_py_init_statement(labrador38_statement st, size_t r, size_t n[], uint64_t normsq[], uint64_t normsq_req[], int normty[], size_t num_rq_cnst, size_t num_zq_cnst, size_t num_int_cnst);
int labrador38_py_append_constraint(labrador38_statement st, size_t nvec, const size_t idx[], const size_t n[], size_t deg, int64_t *phi, int64_t *b, int full);
int labrador38_py_append_quadratic(labrador38_statement st, size_t nlin, size_t nprod, const size_t idx_lin[], const size_t idx_prod1[], const size_t idx_prod2[], const size_t len_phi[], size_t deg, int64_t *a, int64_t *phi, int64_t *b);
int labrador38_py_append_deg0_constraint(labrador38_statement st, size_t idx, size_t deg);
int labrador38_py_gen_params(labrador38_dch_pack_params pp, const labrador38_statement ist, int zk, int debug);
int labrador38_py_simple_verify(const labrador38_statement st, const labrador38_witness wt);
void labrador38_py_prove(labrador38_dch_pack_proof pi, const labrador38_statement ist, const labrador38_witness iwt, const labrador38_dch_pack_params pp);
int labrador38_py_verify(const labrador38_statement ist, const labrador38_dch_pack_params pp, const labrador38_dch_pack_proof pi);
void labrador38_py_free_witness(labrador38_witness wt);
void labrador38_py_free_statement(labrador38_statement st);
void labrador38_py_free_params(labrador38_dch_pack_params pp);
void labrador38_py_free_proof(labrador38_dch_pack_proof pi);


#endif