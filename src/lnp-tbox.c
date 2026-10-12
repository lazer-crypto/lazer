#include "lnp-tbox.h"
#include "lazer.h"
#include "stopwatch.h"

static inline void _expand_R_i (int8_t *Ri, unsigned int ncols, unsigned int i,
                                const uint8_t cseed[32]);
static inline void _expand_Rprime_i (int8_t *Rprimei, unsigned int ncols,
                                     unsigned int i, const uint8_t cseed[32]);
static void __shuffleauto2x2submatssparse (spolymat_t a);
static void __shuffleautovecsparse (spolyvec_t r);
static void __schwartz_zippel_accumulate (
    spolymat_ptr R2i, spolyvec_ptr r1i, poly_ptr r0i, spolymat_ptr Rprime2i[],
    spolyvec_ptr rprime1i[], poly_ptr rprime0i[], unsigned int M,
    const intvec_t v, const lnp_quad_eval_params_t params);
static void __schwartz_zippel_auto (spolymat_ptr R2i, spolyvec_ptr r1i,
                                    poly_ptr r0i, spolymat_ptr R2i2,
                                    spolyvec_ptr r1i2, poly_ptr r0i2,
                                    const lnp_quad_eval_params_t params);
static void __schwartz_zippel_accumulate2 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2primei[], spolyvec_ptr r1primei[], poly_ptr r0primei[],
    unsigned int M, const uint8_t seed[32], uint32_t dom,
    const lnp_quad_eval_params_t params);
static void _lnp_tbox_compute_z34 (uint8_t hash[32], polyvec_t tB,
                                   polyvec_t z3, polyvec_t z4, polyvec_t s1,
                                   polyvec_t m, polyvec_t s2, polymat_t Bprime,
                                   polymat_ptr Es[], polymat_ptr Em[],
                                   polyvec_ptr v[], polymat_t Ps, polymat_t Pm,
                                   polyvec_t f, polymat_t Ds, polymat_t Dm,
                                   polyvec_t u, const uint8_t seed_tbox[32],
                                   const lnp_tbox_params_t params);
static int _lnp_tbox_check_z34 (uint8_t hash[32], polyvec_t z3, polyvec_t z4,
                                polyvec_t tB, polymat_ptr Es[],
                                polymat_ptr Em[], polyvec_ptr v[],
                                polymat_t Ps, polymat_t Pm, polyvec_t f,
                                polymat_t Ds, polymat_t Dm, polyvec_t u,
                                const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_beta3 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, const uint8_t seed[32],
    uint32_t dom, const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_beta4 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, const uint8_t seed[32],
    uint32_t dom, const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_upsilon (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, const uint8_t seed[32],
    uint32_t dom, const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_bin (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, polymat_t Ps,
    polymat_t Pm, polyvec_t f, polymat_t oPs, polymat_t oPm, polyvec_t of,
    const uint8_t seed[32], uint32_t dom, const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_l2 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, polymat_ptr Es[],
    polymat_ptr Em[], polyvec_ptr v[], polymat_ptr oEs[], polymat_ptr oEm[],
    polyvec_ptr ov[], const uint8_t seed[32], uint32_t dom,
    const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_z4 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, polymat_t Ds,
    polymat_t Dm, polyvec_t u, polymat_t oDs, polymat_t oDm, polyvec_t z4,
    const uint8_t seed[32], uint32_t dom, const lnp_tbox_params_t params);
static void __schwartz_zippel_accumulate_z3 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, polymat_ptr Es[],
    polymat_ptr Em[], polyvec_ptr v[], polymat_ptr oEs[], polymat_ptr oEm[],
    polymat_t Ps, polymat_t Pm, polyvec_t f, polymat_t oPs, polymat_t oPm,
    polyvec_t z3, const uint8_t seed[32], uint32_t dom,
    const lnp_tbox_params_t params);

static inline void
__evaleq (poly_ptr res, spolymat_ptr Rprime2, spolyvec_ptr rprime1,
          poly_ptr rprime0, polyvec_ptr s)
{
  polyring_srcptr Rq = rprime0->ring;
  polyvec_t tmp;

  ASSERT_ERR (res != rprime0);

  polyvec_alloc (tmp, Rq, spolymat_get_nrows (Rprime2));

  if (rprime0 != NULL)
    poly_set (res, rprime0);
  else
    poly_set_zero (res);

  if (rprime1 != NULL)
    poly_adddot2 (res, rprime1, s, 0);

  if (Rprime2 != NULL)
    {
      polyvec_mulsparse (tmp, Rprime2, s);
      polyvec_fromcrt (tmp);
      poly_adddot (res, s, tmp, 0);
    }
  poly_fromcrt (res);
  poly_mod (res, res);
  poly_redc (res, res);

  polyvec_free (tmp);
}

#if ASSERT == ASSERT_ENABLED
static inline void
__check_coeff0 (spolymat_ptr Rprime2, spolyvec_ptr rprime1, poly_ptr rprime0,
                polyvec_ptr s, int check)
{
  polyring_srcptr Rq = rprime0->ring;
  const unsigned int d = Rq->d;
  unsigned int i;
  poly_t poly;

  poly_alloc (poly, Rq);
  poly_set_zero (poly);

  __evaleq (poly, Rprime2, rprime1, rprime0, s);

  if (check == 0)
    {
      /* check coeff 0 */
      ASSERT_ERR (int_eqzero (poly_get_coeff (poly, 0)) == 1);
    }
  else if (check == 1)
    {
      /* check coeff 0 and d/2 */
      ASSERT_ERR (int_eqzero (poly_get_coeff (poly, 0)) == 1);
      ASSERT_ERR (int_eqzero (poly_get_coeff (poly, d / 2)) == 1);
    }
  else if (check == 2)
    {
      /* check all coeffs */
      for (i = 0; i < d; i++)
        ASSERT_ERR (int_eqzero (poly_get_coeff (poly, i)) == 1);
    }

  poly_free (poly);
}
#else
static inline void
__check_coeff0 (UNUSED spolymat_ptr Rprime2i[], UNUSED spolyvec_ptr rprime1i[],
                UNUSED poly_ptr rprime0i[], UNUSED polyvec_ptr s,
                UNUSED int check)
{
}
#endif

/*
 * hash hash of tA1, tB
 * s1 = (s1_,upsilon)
 *
 * scratch space:
 * R2,r1,r0 are N+2+lambda/2 arrays
 * R2 is 2*(m1+l)+lambda x 2*(m1+l)+lambda
 */
void
lnp_tbox_prove (uint8_t hash[32], polyvec_t tB, polyvec_t h, poly_t c,
                polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3,
                polyvec_t z4, polyvec_t s1, polyvec_t m, polyvec_t s2,
                polyvec_t tA2, polymat_t A1, polymat_t A2prime,
                polymat_t Bprime, spolymat_ptr R2[], spolyvec_ptr r1[],
                unsigned int N, spolymat_ptr R2prime[], spolyvec_ptr r1prime[],
                poly_ptr r0prime[], unsigned int M, polymat_ptr Es[],
                polymat_ptr Em[], polyvec_ptr v[], polymat_t Ps, polymat_t Pm,
                polyvec_t f, polymat_t Ds, polymat_t Dm, polyvec_t u,
                const uint8_t seed[32], const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  abdlop_params_srcptr quad_eval = params->quad_eval->quad_eval;
  polyring_srcptr Rq = tbox->ring;
  const unsigned int d = polyring_get_deg (Rq);
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int lambda = params->quad_eval->lambda;
  abdlop_params_srcptr quad = params->quad_eval->quad_many;
#if ASSERT == ASSERT_ENABLED
  const unsigned int lext = params->tbox->lext;
#endif
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int m2 = tbox->m2;
  const unsigned int l = tbox->l;
  const unsigned int kmsis = tbox->kmsis;
  const unsigned int nprime = params->nprime;
  const unsigned int nex = params->nex;
  const unsigned int nbin = params->nbin;
  const unsigned int *n = params->n;
  unsigned int i;
  spolymat_ptr R2prime_sz[lambda / 2 + 2 + N], R2primei;
  spolyvec_ptr r1prime_sz[lambda / 2 + 2 + N], r1primei;
  poly_ptr r0prime_sz[lambda / 2 + 2 + N], r0primei;
  spolymat_ptr R2prime_sz2[lambda / 2];
  spolyvec_ptr r1prime_sz2[lambda / 2];
  poly_ptr r0prime_sz2[lambda / 2];
  shake128_state_t hstate;
  coder_state_t cstate;
  uint8_t hash0[32];
  uint8_t expseed[3 * 32];
  const uint8_t *seed_rej34 = expseed;
  const uint8_t *seed_cont = expseed + 32;
  const uint8_t *seed_cont2 = expseed + 64;
  const unsigned int np = 2 * (m1 + Z + quad->l);
  const unsigned int n_ = 2 * (m1 + Z + quad_eval->l);
  polymat_t Bextprime;
  polyvec_t tg, subv, subv2, subv_auto, s, s2_;
  spolymat_t R2t;
  spolyvec_t r1t;
  poly_t r0t;
  size_t outlen;
  /* buff for encoding of tg */
  uint8_t out[CEIL (log2q * d * lambda / 2, 8) + 1];
  poly_ptr poly;
  intvec_ptr coeffs;
  int_ptr coeff;
  INTVEC_T (V, M, Rq->q->nlimbs);
  POLY_T (tmp, Rq);
  const unsigned int loff
      = (nprime > 0 ? 256 / d : 0) + (nex > 0 ? 256 / d : 0);
  const unsigned int ibeta = (m1 + Z + l + loff) * 2;
  polymat_ptr oEs[Z];
  polymat_ptr oEm[Z];
  polyvec_ptr ov[Z];
  polymat_t oPs;
  polymat_t oPm;
  polyvec_t of;
  polymat_t oDs;
  polymat_t oDm;
  polyvec_t ou;

  ASSERT_ERR (nex + nprime
              > 0); /* use quad_eval if no norm proof is needed. */
  ASSERT_ERR (lambda % 2 == 0);
  ASSERT_ERR (polyvec_get_nelems (tB) == l + lext);
  ASSERT_ERR (polyvec_get_nelems (h) == lambda / 2);
  ASSERT_ERR (polyvec_get_nelems (z1) == m1 + Z);
  ASSERT_ERR (polyvec_get_nelems (z21) == m2 - kmsis);
  ASSERT_ERR (polyvec_get_nelems (hint) == kmsis);
  ASSERT_ERR (nex == 0 || polyvec_get_nelems (z3) == 256 / d);
  ASSERT_ERR (nprime == 0 || polyvec_get_nelems (z4) == 256 / d);
  ASSERT_ERR (polyvec_get_nelems (s1) == m1 + Z);
  ASSERT_ERR (polyvec_get_nelems (s2) == m2);
  ASSERT_ERR (polyvec_get_nelems (m) == l + lext);
  ASSERT_ERR (polyvec_get_nelems (tA2) == kmsis);
  ASSERT_ERR (polymat_get_nrows (A1) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A1) == m1 + Z);
  ASSERT_ERR (polymat_get_nrows (A2prime) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A2prime) == m2 - kmsis);
  ASSERT_ERR (polymat_get_nrows (Bprime) == l + lext);
  ASSERT_ERR (polymat_get_ncols (Bprime) == m2 - kmsis);
#if ASSERT == ASSERT_ENABLED
  for (i = 0; i < N; i++)
    {
      ASSERT_ERR (i >= N || spolymat_is_upperdiag (R2[i]));
      ASSERT_ERR (R2[i] == NULL
                  || spolymat_get_nrows (R2[i]) == 2 * (m1 + Z + quad->l));
      ASSERT_ERR (R2[i] == NULL
                  || spolymat_get_ncols (R2[i]) == 2 * (m1 + Z + quad->l));
      ASSERT_ERR (r1[i] == NULL
                  || r1[i]->nelems_max == 2 * (m1 + Z + quad->l));
    }
  for (i = 0; i < M; i++)
    {
      ASSERT_ERR (spolymat_is_upperdiag (R2prime[i]));
      ASSERT_ERR (R2prime[i] == NULL
                  || spolymat_get_nrows (R2prime[i])
                         == 2 * (m1 + Z + quad_eval->l));
      ASSERT_ERR (R2prime[i] == NULL
                  || spolymat_get_ncols (R2prime[i])
                         == 2 * (m1 + Z + quad_eval->l));
      ASSERT_ERR (r1prime[i] == NULL
                  || r1prime[i]->nelems_max == 2 * (m1 + Z + quad_eval->l));
    }
#endif

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s", __func__);
  STOPWATCH_START (stopwatch_lnp_tbox_prove, "lnp_tbox_prove");

  polyvec_alloc (s, Rq, 2 * (m1 + Z + quad->l));

  /*
   * Expand input seed into two seeds: one for rejection sampling on z3, z4
   * and one for continuing the protocol.
   */
  shake128_init (hstate);
  shake128_absorb (hstate, seed, 32);
  shake128_squeeze (hstate, expseed, sizeof (expseed));
  shake128_clear (hstate);

  STOPWATCH_START (stopwatch_lnp_tbox_prove_auto, "lnp_tbox_prove_auto");
  /*
   * precompute automorphisms. do this first, since autos are comuted in coeff
   * dom, and inputs are still in coeff dom here.
   */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "precompute automorphisms");
  for (i = 0; i < Z; i++)
    {
      if (Es[i] != NULL)
        {
          oEs[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (oEs[i], Rq, n[i], m1);
          polymat_auto (oEs[i], Es[i]);
        }

      if (l > 0 && Em[i] != NULL)
        {
          oEm[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (oEm[i], Rq, n[i], l);
          polymat_auto (oEm[i], Em[i]);
        }

      if (v != NULL && v[i] != NULL)
        {
          ov[i] = _alloc (sizeof (polyvec_t));
          polyvec_alloc (ov[i], Rq, n[i]);
          polyvec_auto (ov[i], v[i]);
        }
    }
  if (Ds != NULL)
    {
      polymat_alloc (oDs, Rq, nprime, m1);
      polymat_auto (oDs, Ds);
    }
  if (l > 0 && Dm != NULL)
    {
      polymat_alloc (oDm, Rq, nprime, l);
      polymat_auto (oDm, Dm);
    }
  if (u != NULL)
    {
      polyvec_alloc (ou, Rq, nprime);
      polyvec_auto (ou, u);
    }
  if (Ps != NULL)
    {
      polymat_alloc (oPs, Rq, nbin, m1);
      polymat_auto (oPs, Ps);
    }
  if (l > 0 && Pm != NULL)
    {
      polymat_alloc (oPm, Rq, nbin, l);
      polymat_auto (oPm, Pm);
    }
  if (f != NULL)
    {
      polyvec_alloc (of, Rq, nbin);
      polyvec_auto (of, f);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_auto);

  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "compute z3, z4");
  /* compute proof parts z3=y3+beta3*R*s3, z4=y4+beta4*Rprime*s4 */
  STOPWATCH_START (stopwatch_lnp_tbox_prove_z34, "lnp_tbox_prove_z34");
  _lnp_tbox_compute_z34 (hash, tB, z3, z4, s1, m, s2, Bprime, Es, Em, v, Ps,
                         Pm, f, Ds, Dm, u, seed_rej34, params);
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_z34);
  memcpy (hash0, hash, 32); // save this level of FS hash for later

  /* tB = (tB_,tg,t) */

  polyvec_get_subvec (tg, tB, quad_eval->l, lambda / 2, 1);

  /* Bprime = (Bprime_,Bext,bext) */

  polymat_get_submat (Bextprime, Bprime, quad_eval->l, 0, lambda / 2,
                      m2 - kmsis, 1, 1);

  /* s = (<s1>,<v>,<m>,<y3>,<y4>,<beta>) */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "construct s");

  polyvec_get_subvec (subv, s, 0, m1 + Z, 2);
  polyvec_get_subvec (subv_auto, s, 1, m1 + Z, 2);
  polyvec_set (subv, s1);
  polyvec_auto (subv_auto, s1);

  if (l > 0)
    {
      polyvec_get_subvec (subv, s, (m1 + Z) * 2, l, 2);
      polyvec_get_subvec (subv_auto, s, (m1 + Z) * 2 + 1, l, 2);
      polyvec_get_subvec (subv2, m, 0, l, 1);
      polyvec_set (subv, subv2);
      polyvec_auto (subv_auto, subv2);
    }

  polyvec_get_subvec (subv, s, (m1 + Z + l) * 2, loff + 1, 2);
  polyvec_get_subvec (subv_auto, s, (m1 + Z + l) * 2 + 1, loff + 1, 2);
  polyvec_get_subvec (subv2, m, l, loff + 1, 1);

  polyvec_set (subv, subv2);
  polyvec_auto (subv_auto, subv2);

  STOPWATCH_START (stopwatch_lnp_tbox_prove_tg, "lnp_tbox_prove_tg");
  /* generate uniformly random h=g with coeffs 0 and d/2 == 0 */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "sample g");

  for (i = 0; i < lambda / 2; i++)
    {
      poly = polyvec_get_elem (h, i);
      coeffs = poly_get_coeffvec (poly);

      intvec_urandom (coeffs, q, log2q, seed_cont, i);
      intvec_set_elem_i64 (coeffs, 0, 0);
      intvec_set_elem_i64 (coeffs, d / 2, 0);
    }

  /* append g to message m */
  polyvec_get_subvec (subv, m, quad_eval->l, lambda / 2, 1);
  polyvec_set (subv, h);

  /* tg = Bexptprime*s2 + g */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "compute tg");

  polyvec_set (tg, h);
  polyvec_get_subvec (s2_, s2, 0, m2 - kmsis, 1);
  polyvec_addmul (tg, Bextprime, s2_, 0);

  /* encode and hash tg */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "encode and hash tg");

  polyvec_mod (tg, tg);
  polyvec_redp (tg, tg);

  coder_enc_begin (cstate, out);
  coder_enc_urandom3 (cstate, tg, q, log2q);
  coder_enc_end (cstate);

  outlen = coder_get_offset (cstate);
  ASSERT_ERR (outlen % 8 == 0);
  ASSERT_ERR (outlen / 8 <= CEIL (log2q * d * lambda / 2, 8) + 1);
  outlen >>= 3; /* nbits to nbytes */

  shake128_init (hstate);
  shake128_absorb (hstate, hash, 32);
  shake128_absorb (hstate, out, outlen);
  shake128_squeeze (hstate, hash, 32);
  shake128_clear (hstate);
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_tg);

/* check that input evaleqs have 0 const. coeff. */
#if ASSERT == ASSERT_ENABLED
  polyvec_get_subvec (subv, s, 0, (m1 + Z + l) * 2, 1);
  for (i = 0; i < M; i++)
    __check_coeff0 (R2prime[i], r1prime[i], r0prime[i], subv, 0);
#endif

  /* allocate tmp space for 1 quadrativ eq */
  spolymat_alloc (R2t, Rq, n_, n_, NELEMS_DIAG (n_));
  spolymat_set_empty (R2t);

  spolyvec_alloc (r1t, Rq, n_, n_);
  spolyvec_set_empty (r1t);

  poly_alloc (r0t, Rq);
  poly_set_zero (r0t);

  /* allocate lambda/2 eqs (schwarz-zippel accumulators) */
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = _alloc (sizeof (spolymat_t));
      spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
      R2prime_sz[i] = R2primei;
      spolymat_set_empty (R2prime_sz[i]);

      R2prime_sz[i]->nrows = n_;
      R2prime_sz[i]->ncols = n_;
      R2prime_sz[i]->nelems_max = NELEMS_DIAG (n_);

      r1primei = _alloc (sizeof (spolyvec_t));
      spolyvec_alloc (r1primei, Rq, np, np);
      r1prime_sz[i] = r1primei;
      spolyvec_set_empty (r1prime_sz[i]);

      r1prime_sz[i]->nelems_max = n_;

      r0primei = _alloc (sizeof (poly_t));
      poly_alloc (r0primei, Rq);
      r0prime_sz[i] = r0primei;
      poly_set_zero (r0prime_sz[i]);
    }
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = _alloc (sizeof (spolymat_t));
      spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
      R2prime_sz2[i] = R2primei;
      spolymat_set_empty (R2prime_sz2[i]);

      R2prime_sz2[i]->nrows = n_;
      R2prime_sz2[i]->ncols = n_;
      R2prime_sz2[i]->nelems_max = NELEMS_DIAG (n_);

      r1primei = _alloc (sizeof (spolyvec_t));
      spolyvec_alloc (r1primei, Rq, np, np);
      r1prime_sz2[i] = r1primei;
      spolyvec_set_empty (r1prime_sz2[i]);

      r1prime_sz[i]->nelems_max = n_;

      r0primei = _alloc (sizeof (poly_t));
      poly_alloc (r0primei, Rq);
      r0prime_sz2[i] = r0primei;
      poly_set_zero (r0prime_sz2[i]);
    }

  /* set up quad eqs for lower level protocol */
  // allocate 2 eqs in beta,o(beta):
  // prove beta3^2-1=0 over Rq -> (i2*beta+i2*o(beta))^2 - 1 = i4*beta^2 +
  // i2*beta*o(beta) + i4*o(beta)^2 - 1 == 0 terms: R2: 3, r1: 0, r0: 1 | * 1
  // prove beta4^2-1=0 over Rq -> (-i2*x^(d/2)*beta+i2*x^(d/2)*o(beta))^2 =
  // -i4*beta^2 + i2*beta*o(beta) -i4*o(beta)^2 - 1 == 0 terms: R2: 3, r1: 0,
  // r0: 1 | * 1
  i = lambda / 2;

  R2primei = _alloc (sizeof (spolymat_t));
  spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
  R2prime_sz[i] = R2primei;
  spolymat_set_empty (R2prime_sz[i]);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, params->inv4);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, Rq->inv2);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta + 1, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, params->inv4);
  R2prime_sz[i]->sorted = 1;

  r1prime_sz[i] = NULL;

  r0primei = _alloc (sizeof (poly_t));
  poly_alloc (r0primei, Rq);
  r0prime_sz[i] = r0primei;
  poly_set_zero (r0prime_sz[i]);
  coeff = poly_get_coeff (r0prime_sz[i], 0);
  int_set_i64 (coeff, -1);

  i = lambda / 2 + 1;

  R2primei = _alloc (sizeof (spolymat_t));
  spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
  R2prime_sz[i] = R2primei;
  spolymat_set_empty (R2prime_sz[i]);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_neg (coeff, params->inv4);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, Rq->inv2);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta + 1, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_neg (coeff, params->inv4);
  R2prime_sz[i]->sorted = 1;

  r1prime_sz[i] = NULL;

  r0primei = _alloc (sizeof (poly_t));
  poly_alloc (r0primei, Rq);
  r0prime_sz[i] = r0primei;
  poly_set_zero (r0prime_sz[i]);
  coeff = poly_get_coeff (r0prime_sz[i], 0);
  int_set_i64 (coeff, -1);

  /* accumulate schwarz-zippel .. */

  /* ... first add the additional input equations */
  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel M evalqs");
  if (M > 0)
    {
      __schwartz_zippel_accumulate2 (R2prime_sz, r1prime_sz, r0prime_sz,
                                     R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                     R2prime, r1prime, r0prime, M, hash, 0,
                                     params->quad_eval);
    }
  /* .. then add the internal equations resulting from the norm proofs .. */
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_beta3,
                   "lnp_tbox_prove_sz_beta3");
  if (nex > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel beta3 evalqs");
      __schwartz_zippel_accumulate_beta3 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_beta3);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_beta4,
                   "lnp_tbox_prove_sz_beta4");
  if (nprime > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel beta4 evalqs");
      __schwartz_zippel_accumulate_beta4 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M + d - 1, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_beta4);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_upsilon,
                   "lnp_tbox_prove_sz_upsilon");
  if (Z > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel upsilon evalqs");
      __schwartz_zippel_accumulate_upsilon (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M + 2 * (d - 1), params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_upsilon);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_bin, "lnp_tbox_prove_sz_bin");
  if (nbin > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel bin evalqs");
      __schwartz_zippel_accumulate_bin (R2prime_sz, r1prime_sz, r0prime_sz,
                                        R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                        R2t, r1t, r0t, Ps, Pm, f, oPs, oPm, of,
                                        hash, M + 2 * (d - 1) + 1, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_bin);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_l2, "lnp_tbox_prove_sz_l2");
  if (Z > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel l2 evalqs");
      __schwartz_zippel_accumulate_l2 (R2prime_sz, r1prime_sz, r0prime_sz,
                                       R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                       R2t, r1t, r0t, Es, Em, v, oEs, oEm, ov,
                                       hash, M + 2 * (d - 1) + 2, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_l2);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_z4, "lnp_tbox_prove_sz_z4");
  if (nprime > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel z4 evalqs");
      __schwartz_zippel_accumulate_z4 (R2prime_sz, r1prime_sz, r0prime_sz,
                                       R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                       R2t, r1t, r0t, Ds, Dm, u, oDs, oDm, z4,
                                       hash0, M + 2 * (d - 1) + 2 + Z, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_z4);
  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_z3, "lnp_tbox_prove_sz_z3");
  if (nex > 0)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "schwarz-zippel z3 evalqs");
      __schwartz_zippel_accumulate_z3 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, Es, Em, v, oEs, oEm, Ps, Pm, f, oPs, oPm,
          z3, hash0, M + 2 * (d - 1) + 2 + Z + 256, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_z3);

  STOPWATCH_START (stopwatch_lnp_tbox_prove_sz_auto, "lnp_tbox_prove_sz_auto");
  for (i = 0; i < lambda / 2; i++)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "schwarz-zippel merge accumulators %u",
                    i);
      __schwartz_zippel_auto (R2prime_sz[i], r1prime_sz[i], r0prime_sz[i],
                              R2prime_sz2[i], r1prime_sz2[i], r0prime_sz2[i],
                              params->quad_eval);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_sz_auto);

  /* compute/output hi and set up quadeqs for lower level protocol */
  STOPWATCH_START (stopwatch_lnp_tbox_prove_hi, "lnp_tbox_prove_hi");
  for (i = 0; i < lambda / 2; i++)
    {
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "compute h%u", i);
      polyvec_get_subvec (subv, s, 0, n_, 1);
#if ASSERT == ASSERT_ENABLED
      /* check that sz evaleqs evaleqs have coeff 0 and d/2 == 0 */
      __check_coeff0 (R2prime_sz[i], r1prime_sz[i], r0prime_sz[i], subv, 1);
#endif
      __evaleq (tmp, R2prime_sz[i], r1prime_sz[i], r0prime_sz[i], subv);
      poly = polyvec_get_elem (h, i); /* gi */
      poly_add (poly, poly, tmp, 0);  /* hi = gi + schwarz zippel */

      /* check that sz evaleqs plus garbage term have coeff 0 and d/2 == 0 */
      ASSERT_ERR (int_eqzero (poly_get_coeff (poly, 0)) == 1);
      ASSERT_ERR (int_eqzero (poly_get_coeff (poly, d / 2)) == 1);

      /* build quadeqs */
      DEBUG_PRINTF (DEBUG_LEVEL >= 2, "set up quadeq %u", i);

      /* r0 */
      poly_sub (r0prime_sz[i], r0prime_sz[i], poly, 0); /* r0i -= -hi */

      /* r1 */
      r1prime_sz[i]->nelems_max = np;
      poly = spolyvec_insert_elem (r1prime_sz[i],
                                   2 * (quad_eval->m1 + quad_eval->l + i));
      poly_set_one (poly);
      r1prime_sz[i]->sorted = 1; /* above appends */

      /* R2 only grows by lambda/2 zero rows/cols */
      R2prime_sz[i]->nrows = np;
      R2prime_sz[i]->ncols = np;
      R2prime_sz[i]->nelems_max = NELEMS_DIAG (np);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_prove_hi);

#if ASSERT == ASSERT_ENABLED
  /* check that quadeqs evaluate to zero */
  /* s = (<s1>,<v>,<m>,<y3>,<y4>,<beta>,<g>) */

  polyvec_get_subvec (subv, s, (m1 + Z + l + loff + 1) * 2, lambda / 2, 2);
  polyvec_get_subvec (subv_auto, s, (m1 + Z + l + loff + 1) * 2 + 1,
                      lambda / 2, 2);
  polyvec_get_subvec (subv2, m, l + loff + 1, lambda / 2, 1);

  polyvec_set (subv, subv2);
  polyvec_auto (subv_auto, subv2);

  // printf ("s:\n");
  // polyvec_dump (s);

  for (i = 0; i < lambda / 2; i++)
    __check_coeff0 (R2prime_sz[i], r1prime_sz[i], r0prime_sz[i], s, 2);

#endif

  /* append list of input quadeqs */
  const unsigned int off = lambda / 2 + 2;
  for (i = lambda / 2 + 2; i < lambda / 2 + 2 + N; i++)
    {
      R2prime_sz[i] = R2[i - off];
      if (R2prime_sz[i] != NULL)
        {
          R2prime_sz[i]->nrows = np;
          R2prime_sz[i]->ncols = np;
          R2prime_sz[i]->nelems_max = NELEMS_DIAG (np);
        }
      r1prime_sz[i] = r1[i - off];
      if (r1prime_sz[i] != NULL)
        r1prime_sz[i]->nelems_max = np;
      r0prime_sz[i] = NULL;
    }

  DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "call many_prove");
  lnp_quad_many_prove (hash, tB, c, z1, z21, hint, s1, m, s2, tA2, A1, A2prime,
                       Bprime, R2prime_sz, r1prime_sz, lambda / 2 + 2 + N,
                       seed_cont2, quad);

  /* free schwarz-zippel accumulators and the 2 other eqs */
  for (i = 0; i < lambda / 2 + 2; i++)
    {
      R2primei = R2prime_sz[i];
      spolymat_free (R2primei);
      _free (R2primei, sizeof (spolymat_t));
      R2prime_sz[i] = NULL;

      r1primei = r1prime_sz[i];
      spolyvec_free (r1primei);
      _free (r1primei, sizeof (spolyvec_t));
      r1prime_sz[i] = NULL;

      r0primei = r0prime_sz[i];
      poly_free (r0primei);
      _free (r0primei, sizeof (poly_t));
      r0prime_sz[i] = NULL;
    }
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = R2prime_sz2[i];
      spolymat_free (R2primei);
      _free (R2primei, sizeof (spolymat_t));
      R2prime_sz2[i] = NULL;

      r1primei = r1prime_sz2[i];
      spolyvec_free (r1primei);
      _free (r1primei, sizeof (spolyvec_t));
      r1prime_sz2[i] = NULL;

      r0primei = r0prime_sz2[i];
      poly_free (r0primei);
      _free (r0primei, sizeof (poly_t));
      r0prime_sz2[i] = NULL;
    }

  polyvec_free (s);
  spolymat_free (R2t);
  spolyvec_free (r1t);
  poly_free (r0t);

  for (i = 0; i < Z; i++)
    {
      if (Es[i] != NULL)
        {
          polymat_free (oEs[i]);
          _free (oEs[i], sizeof (polymat_t));
        }

      if (l > 0 && Em[i] != NULL)
        {
          polymat_free (oEm[i]);
          _free (oEm[i], sizeof (polymat_t));
        }

      if (v != NULL && v[i] != NULL)
        {
          polyvec_free (ov[i]);
          _free (ov[i], sizeof (polyvec_t));
        }
    }
  if (Ds != NULL)
    polymat_free (oDs);
  if (l > 0 && Dm != NULL)
    polymat_free (oDm);
  if (u != NULL)
    polyvec_free (ou);
  if (Ps != NULL)
    polymat_free (oPs);
  if (l > 0 && Pm != NULL)
    polymat_free (oPm);
  if (f != NULL)
    polyvec_free (of);

  STOPWATCH_STOP (stopwatch_lnp_tbox_prove);

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s", "lnp_tbox_prove end");
}

int
lnp_tbox_verify (uint8_t hash[32], polyvec_t h, poly_t c, polyvec_t z1,
                 polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
                 polyvec_t tA1, polyvec_t tB, polymat_t A1, polymat_t A2prime,
                 polymat_t Bprime, spolymat_ptr R2[], spolyvec_ptr r1[],
                 poly_ptr r0[], unsigned int N, spolymat_ptr R2prime[],
                 spolyvec_ptr r1prime[], poly_ptr r0prime[], unsigned int M,
                 polymat_ptr Es[], polymat_ptr Em[], polyvec_ptr v[],
                 polymat_t Ps, polymat_t Pm, polyvec_t f, polymat_t Ds,
                 polymat_t Dm, polyvec_t u, const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  abdlop_params_srcptr quad_eval = params->quad_eval->quad_eval;
  const unsigned int Z = params->Z;
  polyring_srcptr Rq = tbox->ring;
  const unsigned int d = polyring_get_deg (Rq);
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int lambda = params->quad_eval->lambda;
#if ASSERT == ASSERT_ENABLED
  const unsigned int lext = params->tbox->lext;
  const unsigned int kmsis = params->tbox->kmsis;
  const unsigned int m2 = params->tbox->m2;
#endif
  abdlop_params_srcptr quad = params->quad_eval->quad_many;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int nex = params->nex;
  const unsigned int l = tbox->l;
  const unsigned int nprime = params->nprime;
  const unsigned int nbin = params->nbin;
  const unsigned int *n = params->n;
  spolymat_ptr R2prime_sz[lambda / 2 + 2 + N], R2primei;
  spolyvec_ptr r1prime_sz[lambda / 2 + 2 + N], r1primei;
  poly_ptr r0prime_sz[lambda / 2 + 2 + N], r0primei;
  const unsigned int np = 2 * (m1 + Z + quad->l);
  const unsigned int n_ = 2 * (m1 + Z + quad_eval->l);
  spolymat_ptr R2prime_sz2[lambda / 2];
  spolyvec_ptr r1prime_sz2[lambda / 2];
  poly_ptr r0prime_sz2[lambda / 2];
  unsigned int i;
  int b;
  shake128_state_t hstate;
  coder_state_t cstate;
  size_t outlen;
  /* buff for encoding of tg */
  uint8_t out[CEIL (log2q * d * lambda / 2, 8) + 1];
  INTVEC_T (V, M, Rq->q->nlimbs);
  polyvec_t tg;
  poly_ptr poly;
  int_ptr coeff;
  const unsigned int loff
      = (nprime > 0 ? 256 / d : 0) + (nex > 0 ? 256 / d : 0);
  const unsigned int ibeta = (m1 + Z + l + loff) * 2;
  spolymat_t R2t;
  spolyvec_t r1t;
  poly_t r0t;
  uint8_t hash0[32];
  polymat_ptr oEs[Z];
  polymat_ptr oEm[Z];
  polyvec_ptr ov[Z];
  polymat_t oPs;
  polymat_t oPm;
  polyvec_t of;
  polymat_t oDs;
  polymat_t oDm;
  polyvec_t ou;

  ASSERT_ERR (lambda % 2 == 0);
  ASSERT_ERR (polyvec_get_nelems (tB) == l + lext);
  ASSERT_ERR (polyvec_get_nelems (h) == lambda / 2);
  ASSERT_ERR (polyvec_get_nelems (z1) == m1 + Z);
  ASSERT_ERR (polyvec_get_nelems (z21) == m2 - kmsis);
  ASSERT_ERR (polyvec_get_nelems (hint) == kmsis);
  ASSERT_ERR (nex == 0 || polyvec_get_nelems (z3) == 256 / d);
  ASSERT_ERR (nprime == 0 || polyvec_get_nelems (z4) == 256 / d);
  ASSERT_ERR (polyvec_get_nelems (tA1) == kmsis);
  ASSERT_ERR (polymat_get_nrows (A1) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A1) == m1 + Z);
  ASSERT_ERR (polymat_get_nrows (A2prime) == kmsis);
  ASSERT_ERR (polymat_get_ncols (A2prime) == m2 - kmsis);
  ASSERT_ERR (polymat_get_nrows (Bprime) == l + lext);
  ASSERT_ERR (polymat_get_ncols (Bprime) == m2 - kmsis);
#if ASSERT == ASSERT_ENABLED
  for (i = 0; i < N; i++)
    {
      ASSERT_ERR (i >= N || spolymat_is_upperdiag (R2[i]));
      ASSERT_ERR (R2[i] == NULL
                  || spolymat_get_nrows (R2[i]) == 2 * (m1 + Z + quad->l));
      ASSERT_ERR (R2[i] == NULL
                  || spolymat_get_ncols (R2[i]) == 2 * (m1 + Z + quad->l));
      ASSERT_ERR (r1[i] == NULL
                  || r1[i]->nelems_max == 2 * (m1 + Z + quad->l));
    }
  for (i = 0; i < M; i++)
    {
      ASSERT_ERR (spolymat_is_upperdiag (R2prime[i]));
      ASSERT_ERR (R2prime[i] == NULL
                  || spolymat_get_nrows (R2prime[i])
                         == 2 * (m1 + Z + quad_eval->l));
      ASSERT_ERR (R2prime[i] == NULL
                  || spolymat_get_ncols (R2prime[i])
                         == 2 * (m1 + Z + quad_eval->l));
      ASSERT_ERR (r1prime[i] == NULL
                  || r1prime[i]->nelems_max == 2 * (m1 + Z + quad_eval->l));
    }
#endif

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s", __func__);
  STOPWATCH_START (stopwatch_lnp_tbox_verify, "lnp_tbox_verify");

  /* allocate tmp space for 1 quadrativ eq */
  spolymat_alloc (R2t, Rq, n_, n_, NELEMS_DIAG (n_));
  spolymat_set_empty (R2t);

  spolyvec_alloc (r1t, Rq, n_, n_);
  spolyvec_set_empty (r1t);

  poly_alloc (r0t, Rq);
  poly_set_zero (r0t);

  /* allocate schwarz zippel accumulators */
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = _alloc (sizeof (spolymat_t));
      spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
      R2prime_sz[i] = R2primei;
      spolymat_set_empty (R2prime_sz[i]);

      R2prime_sz[i]->nrows = n_;
      R2prime_sz[i]->ncols = n_;
      R2prime_sz[i]->nelems_max = NELEMS_DIAG (n_);

      r1primei = _alloc (sizeof (spolyvec_t));
      spolyvec_alloc (r1primei, Rq, np, np);
      r1prime_sz[i] = r1primei;
      spolyvec_set_empty (r1prime_sz[i]);

      r1prime_sz[i]->nelems_max = n_;

      r0primei = _alloc (sizeof (poly_t));
      poly_alloc (r0primei, Rq);
      r0prime_sz[i] = r0primei;
      poly_set_zero (r0prime_sz[i]);
    }
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = _alloc (sizeof (spolymat_t));
      spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
      R2prime_sz2[i] = R2primei;
      spolymat_set_empty (R2prime_sz2[i]);

      R2prime_sz2[i]->nrows = n_;
      R2prime_sz2[i]->ncols = n_;
      R2prime_sz2[i]->nelems_max = NELEMS_DIAG (n_);

      r1primei = _alloc (sizeof (spolyvec_t));
      spolyvec_alloc (r1primei, Rq, np, np);
      r1prime_sz2[i] = r1primei;
      spolyvec_set_empty (r1prime_sz2[i]);

      r1prime_sz[i]->nelems_max = n_;

      r0primei = _alloc (sizeof (poly_t));
      poly_alloc (r0primei, Rq);
      r0prime_sz2[i] = r0primei;
      poly_set_zero (r0prime_sz2[i]);
    }

  /* precompute automorphisms */
  for (i = 0; i < Z; i++)
    {
      if (Es[i] != NULL)
        {
          oEs[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (oEs[i], Rq, n[i], m1);
          polymat_auto (oEs[i], Es[i]);
        }

      if (l > 0 && Em[i] != NULL)
        {
          oEm[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (oEm[i], Rq, n[i], l);
          polymat_auto (oEm[i], Em[i]);
        }

      if (v != NULL && v[i] != NULL)
        {
          ov[i] = _alloc (sizeof (polyvec_t));
          polyvec_alloc (ov[i], Rq, n[i]);
          polyvec_auto (ov[i], v[i]);
        }
    }
  if (Ds != NULL)
    {
      polymat_alloc (oDs, Rq, nprime, m1);
      polymat_auto (oDs, Ds);
    }
  if (l > 0 && Dm != NULL)
    {
      polymat_alloc (oDm, Rq, nprime, l);
      polymat_auto (oDm, Dm);
    }
  if (u != NULL)
    {
      polyvec_alloc (ou, Rq, nprime);
      polyvec_auto (ou, u);
    }
  if (Ps != NULL)
    {
      polymat_alloc (oPs, Rq, nbin, m1);
      polymat_auto (oPs, Ps);
    }
  if (l > 0 && Pm != NULL)
    {
      polymat_alloc (oPm, Rq, nbin, l);
      polymat_auto (oPm, Pm);
    }
  if (f != NULL)
    {
      polyvec_alloc (of, Rq, nbin);
      polyvec_auto (of, f);
    }

  // allocate 2 eqs in beta,o(beta):
  // prove beta3^2-1=0 over Rq -> (i2*beta+i2*o(beta))^2 - 1 = i4*beta^2 +
  // i2*beta*o(beta) + i4*o(beta)^2 - 1 == 0 terms: R2: 3, r1: 0, r0: 1 | * 1
  // prove beta4^2-1=0 over Rq -> (-i2*x^(d/2)*beta+i2*x^(d/2)*o(beta))^2 =
  // -i4*beta^2 + i2*beta*o(beta) -i4*o(beta)^2 - 1 == 0 terms: R2: 3, r1: 0,
  // r0: 1 | * 1
  i = lambda / 2;

  R2primei = _alloc (sizeof (spolymat_t));
  spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
  R2prime_sz[i] = R2primei;
  spolymat_set_empty (R2prime_sz[i]);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, params->inv4);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, Rq->inv2);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta + 1, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, params->inv4);
  R2prime_sz[i]->sorted = 1;

  r1prime_sz[i] = NULL;

  r0primei = _alloc (sizeof (poly_t));
  poly_alloc (r0primei, Rq);
  r0prime_sz[i] = r0primei;
  poly_set_zero (r0prime_sz[i]);
  coeff = poly_get_coeff (r0prime_sz[i], 0);
  int_set_i64 (coeff, -1);

  i = lambda / 2 + 1;

  R2primei = _alloc (sizeof (spolymat_t));
  spolymat_alloc (R2primei, Rq, np, np, NELEMS_DIAG (np));
  R2prime_sz[i] = R2primei;
  spolymat_set_empty (R2prime_sz[i]);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_neg (coeff, params->inv4);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_set (coeff, Rq->inv2);
  poly = spolymat_insert_elem (R2prime_sz[i], ibeta + 1, ibeta + 1);
  poly_set_zero (poly);
  coeff = poly_get_coeff (poly, 0);
  int_neg (coeff, params->inv4);
  R2prime_sz[i]->sorted = 1;

  r1prime_sz[i] = NULL;

  r0primei = _alloc (sizeof (poly_t));
  poly_alloc (r0primei, Rq);
  r0prime_sz[i] = r0primei;
  poly_set_zero (r0prime_sz[i]);
  coeff = poly_get_coeff (r0prime_sz[i], 0);
  int_set_i64 (coeff, -1);

  /* check norm bounds on z3, z4 */
  b = _lnp_tbox_check_z34 (hash, z3, z4, tB, Es, Em, v, Ps, Pm, f, Ds, Dm, u,
                           params);
  if (b != 1)
    goto ret;
  memcpy (hash0, hash, 32); // save this level of FS hash for later

  /* check if h's coeffs 0 and d/2 are zero. */
  b = 0;
  for (i = 0; i < lambda / 2; i++)
    {
      poly = polyvec_get_elem (h, i);

      coeff = poly_get_coeff (poly, 0);
      if (int_eqzero (coeff) != 1)
        goto ret;
      coeff = poly_get_coeff (poly, d / 2);
      if (int_eqzero (coeff) != 1)
        goto ret;
    }

  /* tB = (tB_,tg,t) */
  polyvec_get_subvec (tg, tB, quad_eval->l, lambda / 2, 1);

  /* encode and hash tg */

  polyvec_mod (tg, tg);
  polyvec_redp (tg, tg);

  coder_enc_begin (cstate, out);
  coder_enc_urandom3 (cstate, tg, q, log2q);
  coder_enc_end (cstate);

  outlen = coder_get_offset (cstate);
  ASSERT_ERR (outlen % 8 == 0);
  ASSERT_ERR (outlen / 8 <= CEIL (log2q * d * lambda / 2, 8) + 1);
  outlen >>= 3; /* nbits to nbytes */

  shake128_init (hstate);
  shake128_absorb (hstate, hash, 32);
  shake128_absorb (hstate, out, outlen);
  shake128_squeeze (hstate, hash, 32);
  shake128_clear (hstate);

  /* ... first add the additional input equations .. */
  if (M > 0)
    {
      __schwartz_zippel_accumulate2 (R2prime_sz, r1prime_sz, r0prime_sz,
                                     R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                     R2prime, r1prime, r0prime, M, hash, 0,
                                     params->quad_eval);
    }

  /* .. then add the internal equations resulting from the norm proofs .. */
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_beta3,
                   "lnp_tbox_verify_sz_beta3");
  if (nex > 0)
    {
      __schwartz_zippel_accumulate_beta3 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_beta3);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_beta4,
                   "lnp_tbox_verify_sz_beta4");
  if (nprime > 0)
    {
      __schwartz_zippel_accumulate_beta4 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M + d - 1, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_beta4);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_upsilon,
                   "lnp_tbox_verify_sz_upsilon");
  if (Z > 0)
    {
      __schwartz_zippel_accumulate_upsilon (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, hash, M + 2 * (d - 1), params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_upsilon);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_bin, "lnp_tbox_verify_sz_bin");
  if (nbin > 0)
    {
      __schwartz_zippel_accumulate_bin (R2prime_sz, r1prime_sz, r0prime_sz,
                                        R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                        R2t, r1t, r0t, Ps, Pm, f, oPs, oPm, of,
                                        hash, M + 2 * (d - 1) + 1, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_bin);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_l2, "lnp_tbox_verify_sz_l2");
  if (Z > 0)
    {
      __schwartz_zippel_accumulate_l2 (R2prime_sz, r1prime_sz, r0prime_sz,
                                       R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                       R2t, r1t, r0t, Es, Em, v, oEs, oEm, ov,
                                       hash, M + 2 * (d - 1) + 2, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_l2);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_z4, "lnp_tbox_verify_sz_z4");
  if (nprime > 0)
    {
      __schwartz_zippel_accumulate_z4 (R2prime_sz, r1prime_sz, r0prime_sz,
                                       R2prime_sz2, r1prime_sz2, r0prime_sz2,
                                       R2t, r1t, r0t, Ds, Dm, u, oDs, oDm, z4,
                                       hash0, M + 2 * (d - 1) + 2 + Z, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_z4);
  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_z3, "lnp_tbox_verify_sz_z3");
  if (nex > 0)
    {
      __schwartz_zippel_accumulate_z3 (
          R2prime_sz, r1prime_sz, r0prime_sz, R2prime_sz2, r1prime_sz2,
          r0prime_sz2, R2t, r1t, r0t, Es, Em, v, oEs, oEm, Ps, Pm, f, oPs, oPm,
          z3, hash0, M + 2 * (d - 1) + 2 + Z + 256, params);
    }
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_z3);

  STOPWATCH_START (stopwatch_lnp_tbox_verify_sz_auto,
                   "lnp_tbox_verify_sz_auto");
  for (i = 0; i < lambda / 2; i++)
    __schwartz_zippel_auto (R2prime_sz[i], r1prime_sz[i], r0prime_sz[i],
                            R2prime_sz2[i], r1prime_sz2[i], r0prime_sz2[i],
                            params->quad_eval);
  STOPWATCH_STOP (stopwatch_lnp_tbox_verify_sz_auto);

  /* build quad eqs */
  for (i = 0; i < lambda / 2; i++)
    {
      /* r0 */
      poly = polyvec_get_elem (h, i);
      poly_sub (r0prime_sz[i], r0prime_sz[i], poly, 0); /* r0i -= -hi */

      /* r1 */
      r1prime_sz[i]->nelems_max = np;
      poly = spolyvec_insert_elem (r1prime_sz[i],
                                   2 * (quad_eval->m1 + quad_eval->l + i));
      poly_set_one (poly);
      r1prime_sz[i]->sorted = 1; /* above appends */

      /* R2 only grows by lambda/2 zero rows/cols */
      R2prime_sz[i]->nrows = np;
      R2prime_sz[i]->ncols = np;
      R2prime_sz[i]->nelems_max = NELEMS_DIAG (np);
    }

  /* append list of input quadeqs */
  const unsigned int off = lambda / 2 + 2;
  for (i = lambda / 2 + 2; i < lambda / 2 + 2 + N; i++)
    {
      R2prime_sz[i] = R2[i - off];
      if (R2prime_sz[i] != NULL)
        {
          R2prime_sz[i]->nrows = np;
          R2prime_sz[i]->ncols = np;
          R2prime_sz[i]->nelems_max = NELEMS_DIAG (np);
        }
      r1prime_sz[i] = r1[i - off];
      if (r1prime_sz[i] != NULL)
        r1prime_sz[i]->nelems_max = np;
      r0prime_sz[i] = r0[i - off];
    }

  b = lnp_quad_many_verify (hash, c, z1, z21, hint, tA1, tB, A1, A2prime,
                            Bprime, R2prime_sz, r1prime_sz, r0prime_sz,
                            lambda / 2 + 2 + N, quad);
  if (b != 1)
    goto ret;

  b = 1;
ret:
  /* free schwarz zippel accumulators and the 2 other qs */
  for (i = 0; i < lambda / 2 + 2; i++)
    {
      R2primei = R2prime_sz[i];
      spolymat_free (R2primei);
      _free (R2primei, sizeof (spolymat_t));
      R2prime_sz[i] = NULL;

      r1primei = r1prime_sz[i];
      spolyvec_free (r1primei);
      _free (r1primei, sizeof (spolyvec_t));
      r1prime_sz[i] = NULL;

      r0primei = r0prime_sz[i];
      poly_free (r0primei);
      _free (r0primei, sizeof (poly_t));
      r0prime_sz[i] = NULL;
    }
  for (i = 0; i < lambda / 2; i++)
    {
      R2primei = R2prime_sz2[i];
      spolymat_free (R2primei);
      _free (R2primei, sizeof (spolymat_t));
      R2prime_sz2[i] = NULL;

      r1primei = r1prime_sz2[i];
      spolyvec_free (r1primei);
      _free (r1primei, sizeof (spolyvec_t));
      r1prime_sz2[i] = NULL;

      r0primei = r0prime_sz2[i];
      poly_free (r0primei);
      _free (r0primei, sizeof (poly_t));
      r0prime_sz2[i] = NULL;
    }
  spolymat_free (R2t);
  spolyvec_free (r1t);
  poly_free (r0t);

  for (i = 0; i < Z; i++)
    {
      if (Es[i] != NULL)
        {
          polymat_free (oEs[i]);
          _free (oEs[i], sizeof (polymat_t));
        }

      if (l > 0 && Em[i] != NULL)
        {
          polymat_free (oEm[i]);
          _free (oEm[i], sizeof (polymat_t));
        }

      if (v != NULL && v[i] != NULL)
        {
          polyvec_free (ov[i]);
          _free (ov[i], sizeof (polyvec_t));
        }
    }
  if (Ds != NULL)
    polymat_free (oDs);
  if (l > 0 && Dm != NULL)
    polymat_free (oDm);
  if (u != NULL)
    polyvec_free (ou);
  if (Ps != NULL)
    polymat_free (oPs);
  if (l > 0 && Pm != NULL)
    polymat_free (oPm);
  if (f != NULL)
    polyvec_free (of);

  STOPWATCH_STOP (stopwatch_lnp_tbox_verify);
  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
  return b;
}

static void
_lnp_tbox_compute_z34 (uint8_t hash[32], polyvec_t tB, polyvec_t z3,
                       polyvec_t z4, polyvec_t s1, polyvec_t m, polyvec_t s2,
                       polymat_t Bprime, polymat_ptr Es[], polymat_ptr Em[],
                       polyvec_ptr v[], polymat_t Ps, polymat_t Pm,
                       polyvec_t f, polymat_t Ds, polymat_t Dm, polyvec_t u,
                       const uint8_t seed_tbox[32],
                       const lnp_tbox_params_t params)
{
#if ASSERT == ASSERT_ENABLED
  const unsigned int lext = params->tbox->lext;
  const unsigned int lambda = params->quad_eval->lambda;
#endif
  abdlop_params_srcptr tbox = params->tbox;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int d = polyring_get_deg (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int Z = params->Z;
  const unsigned int nprime = params->nprime;
  const unsigned int nex = params->nex;
  const unsigned int nbin = params->nbin;
  const unsigned int *ni = params->n;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int m2 = tbox->m2;
  const unsigned int l = tbox->l;
  const unsigned int kmsis = tbox->kmsis;
  unsigned int i, j;
  INTVEC_T (s3coeffs, nex * d, int_get_nlimbs (q));
  INTVEC_T (s4coeffs, nprime * d, int_get_nlimbs (q));
  INTVEC_T (y3coeffs, 256, int_get_nlimbs (q));
  INTVEC_T (y4coeffs, 256, int_get_nlimbs (q));
  INTVEC_T (z3coeffs, 256, int_get_nlimbs (q));
  INTVEC_T (z4coeffs, 256, int_get_nlimbs (q));
  polyvec_t tmp_polyvec, subv, s1_, m_, s21, y3_, y4_, ty3, ty4, tbeta, beta,
      upsilon, s3, s4, y3, y4, z3_, z4_;
  intvec_ptr coeffs;
  polymat_t By3, By4, Bbeta;
  shake128_state_t hstate;
  coder_state_t cstate;
  rng_state_t rstate_signs;
  rng_state_t rstate_rej;
  uint32_t dom = 0;
  uint8_t rbits;
  unsigned int nrbits, outlen, loff, off;
  uint8_t out[CEIL (256 * 2 * log2q + d * log2q, 8) + 1];
  uint8_t cseed[32]; /* seed for challenge */
  poly_ptr poly;
  int beta3 = 0, beta4 = 0;
  int rej;

  memset (out, 0, CEIL (256 * 2 * log2q + d * log2q, 8) + 1); // XXX

  polyvec_alloc (s3, Rq, nex);
  polyvec_alloc (s4, Rq, nprime);
  polyvec_alloc (y3, Rq, 256 / d);
  polyvec_alloc (y4, Rq, 256 / d);
  polyvec_alloc (z3_, Rq, 256 / d);
  polyvec_alloc (z4_, Rq, 256 / d);
  polyvec_alloc (tmp_polyvec, Rq, MAX (nex, nprime));

  /* s1 = s1_,upsilon, m = m_,y3_,y4_,beta */
  polyvec_get_subvec (s1_, s1, 0, m1, 1);
  if (l > 0)
    polyvec_get_subvec (m_, m, 0, l, 1);
  polyvec_get_subvec (beta, m, l + (256 / d) * 2, 1, 1);
  polyvec_set_zero (beta);

  polyvec_get_subvec (s21, s2, 0, m2 - kmsis, 1);

  /* tB = tB_,ty,tbeta */
  loff = 0;
  if (nex > 0)
    {
      ASSERT_ERR (Ps == NULL || polymat_get_nrows (Ps) == nbin);
      ASSERT_ERR (Ps == NULL || polymat_get_ncols (Ps) == m1);
      ASSERT_ERR (Pm == NULL || polymat_get_nrows (Pm) == nbin);
      ASSERT_ERR (Pm == NULL || polymat_get_ncols (Pm) == l);
      ASSERT_ERR (f == NULL || polyvec_get_nelems (f) == nbin);
      for (i = 0; i < Z; i++)
        {
          ASSERT_ERR (Es == NULL || Es[i] == NULL
                      || polymat_get_nrows (Es[i]) == ni[i]);
          ASSERT_ERR (Es == NULL || Es[i] == NULL
                      || polymat_get_ncols (Es[i]) == m1);
          ASSERT_ERR (Em == NULL || Em[i] == NULL
                      || polymat_get_nrows (Em[i]) == ni[i]);
          ASSERT_ERR (Em == NULL || Em[i] == NULL
                      || polymat_get_ncols (Em[i]) == l);
          ASSERT_ERR (v == NULL || v[i] == NULL
                      || polyvec_get_nelems (v[i]) == ni[i]);
        }

      polyvec_get_subvec (upsilon, s1, m1, Z, 1);
      polyvec_get_subvec (y3_, m, l + loff, 256 / d, 1);
      polyvec_get_subvec (ty3, tB, l + loff, 256 / d, 1);
      polymat_get_submat (By3, Bprime, l + loff, 0, 256 / d, m2 - kmsis, 1, 1);

      // printf ("upsilon:\n");
      // polyvec_dump (upsilon);

      polyvec_set_coeffvec2 (s3, s3coeffs);
      polyvec_set_coeffvec2 (y3, y3coeffs);
      polyvec_set_coeffvec2 (z3_, z3coeffs);

      /* s3 */
      off = 0;
      if (nbin > 0)
        {
          polyvec_get_subvec (subv, s3, 0, nbin, 1);
          off += nbin;

          if (f != NULL)
            {
              polyvec_set (subv, f);
              polyvec_fromcrt (subv);
              polyvec_mod (subv, subv);
              polyvec_redc (subv, subv);
            }
          else
            {
              polyvec_set_zero (subv);
            }
          if (Ps != NULL)
            {
              polyvec_addmul (subv, Ps, s1_, 0);
              polyvec_fromcrt (subv);
            }
          if (Pm != NULL)
            {
              polyvec_addmul (subv, Pm, m_, 0);
              polyvec_fromcrt (subv);
            }
        }
      if (Z > 0)
        {
          for (i = 0; i < Z; i++)
            {
              polyvec_get_subvec (subv, s3, off, ni[i], 1);
              off += ni[i];

              if (v != NULL && v[i] != NULL)
                {
                  polyvec_set (subv, v[i]);
                  polyvec_fromcrt (subv);
                  polyvec_mod (subv, subv);
                  polyvec_redc (subv, subv);
                }
              else
                {
                  polyvec_set_zero (subv);
                }
              if (Es != NULL && Es[i] != NULL)
                {
                  polyvec_addmul (subv, Es[i], s1_, 0);
                  polyvec_fromcrt (subv);
                }
              if (Em != NULL && Em[i] != NULL)
                {
                  polyvec_addmul (subv, Em[i], m_, 0);
                }
              polyvec_fromcrt (subv);
            }

          polyvec_get_subvec (subv, s3, off, Z, 1);
          polyvec_set (subv, upsilon);
        }

      loff += 256 / d;
    }
  /* s4 */
  if (nprime > 0)
    {
      ASSERT_ERR (Ds == NULL || polymat_get_nrows (Ds) == nprime);
      ASSERT_ERR (Ds == NULL || polymat_get_ncols (Ds) == m1);
      ASSERT_ERR (Dm == NULL || polymat_get_nrows (Dm) == nprime);
      ASSERT_ERR (Dm == NULL || polymat_get_ncols (Dm) == l);
      ASSERT_ERR (u == NULL || polyvec_get_nelems (u) == nprime);

      polyvec_get_subvec (y4_, m, l + loff, 256 / d, 1);
      polyvec_get_subvec (ty4, tB, l + loff, 256 / d, 1);
      polymat_get_submat (By4, Bprime, l + loff, 0, 256 / d, m2 - kmsis, 1, 1);

      polyvec_set_coeffvec2 (s4, s4coeffs);
      polyvec_set_coeffvec2 (y4, y4coeffs);
      polyvec_set_coeffvec2 (z4_, z4coeffs);

      if (u != NULL)
        {
          polyvec_set (s4, u);
          polyvec_fromcrt (s4);
          polyvec_mod (s4, s4);
          polyvec_redc (s4, s4);
        }
      else
        {
          polyvec_set_zero (s4);
        }
      if (Ds != NULL)
        {
          polyvec_addmul (s4, Ds, s1_, 0);
          polyvec_fromcrt (s4);
        }
      if (Dm != NULL)
        {
          polyvec_addmul (s4, Dm, m_, 0);
          polyvec_fromcrt (s4);
        }

      loff += 256 / d;
    }

  // printf ("s1_:\n");
  // polyvec_dump (s1_);
  // printf ("m_:\n");
  // polyvec_dump (m_);
  // printf ("s4:\n");
  // polyvec_dump (s4);

  ASSERT_ERR (lext == (loff + 1) + (lambda / 2 + 1));
  polyvec_get_subvec (tbeta, tB, l + loff, 1, 1);
  polymat_get_submat (Bbeta, Bprime, l + loff, 0, 1, m2 - kmsis, 1, 1);

  nrbits = 0;
  rng_init (rstate_rej, seed_tbox, dom++);
  rng_init (rstate_signs, seed_tbox, dom++);

  while (1)
    {
      /* sample signs */
      if (nrbits == 0)
        {
          rng_urandom (rstate_signs, &rbits, 1);
          nrbits = 8;
        }

      if (nex > 0)
        {
          /* y3, append to m  */
          polyvec_grandom (y3, params->log2stdev3, seed_tbox, dom++);
          polyvec_set (y3_, y3);

          /* ty3 */
          polyvec_set (ty3, y3);
          polyvec_addmul (ty3, By3, s21, 0);
          polyvec_mod (ty3, ty3);
          polyvec_redp (ty3, ty3);

          /* beta3  */
          beta3 = (rbits & (1 << (8 - nrbits))) >> (8 - nrbits);
          beta3 = 1 - 2 * beta3; /* {0,1} -> {1,-1} */
          // printf ("beta3 %d\n", beta3);
          nrbits -= 1;
        }

      if (nprime > 0)
        {
          /* y4, append to m  */
          polyvec_grandom (y4, params->log2stdev4, seed_tbox, dom++);
          polyvec_set (y4_, y4);

          // printf ("y4:\n");
          // polyvec_dump (y4);

          /* ty4 */
          polyvec_set (ty4, y4);
          polyvec_addmul (ty4, By4, s21, 0);
          polyvec_mod (ty4, ty4);
          polyvec_redp (ty4, ty4);

          beta4 = (rbits & (1 << (8 - nrbits + 1))) >> (8 - nrbits + 1);
          beta4 = 1 - 2 * beta4; /* {0,1} -> {1,-1} */

          // printf ("beta4 %d\n", beta4);
          nrbits -= 1;
        }

      /* tbeta */
      poly = polyvec_get_elem (beta, 0);
      coeffs = poly_get_coeffvec (poly);
      if (nex > 0)
        intvec_set_elem_i64 (coeffs, 0, beta3);
      if (nprime > 0)
        intvec_set_elem_i64 (coeffs, d / 2, beta4);
      polyvec_set (tbeta, beta);
      polyvec_addmul (tbeta, Bbeta, s21, 0);
      polyvec_mod (tbeta, tbeta);
      polyvec_redp (tbeta, tbeta);

      /* encode ty, tbeta, hash of encoding is seed for challenges */

      coder_enc_begin (cstate, out);
      if (nex > 0)
        coder_enc_urandom3 (cstate, ty3, q, log2q);
      if (nprime > 0)
        coder_enc_urandom3 (cstate, ty4, q, log2q);
      coder_enc_urandom3 (cstate, tbeta, q, log2q);
      coder_enc_end (cstate);

      outlen = coder_get_offset (cstate);
      ASSERT_ERR (outlen % 8 == 0);
      ASSERT_ERR (outlen / 8 <= CEIL (256 * 2 * log2q + d * log2q, 8) + 1);
      outlen >>= 3; /* nbits to nbytes */

      shake128_init (hstate);
      shake128_absorb (hstate, hash, 32);
      shake128_absorb (hstate, out, outlen);
      shake128_squeeze (hstate, cseed, 32);

      if (nex > 0)
        {
          INT_T (beta3Rijs3j, int_get_nlimbs (q));
          int8_t Ri[nex * d];
          int_ptr s3coeff, Rs3coeff;

          polyvec_fromcrt (s3);
          polyvec_fromcrt (y3);

          polyvec_set (z3_, y3);
          intvec_set_zero (y3coeffs);

          for (i = 0; i < 256; i++)
            {
              Rs3coeff = intvec_get_elem (y3coeffs, i);

              _expand_R_i (Ri, nex * d, i, cseed);

              for (j = 0; j < nex * d; j++)
                {
                  if (Ri[j] == 0)
                    {
                    }
                  else
                    {
                      ASSERT_ERR (Ri[j] == 1 || Ri[j] == -1);

                      s3coeff = intvec_get_elem (s3coeffs, j);

                      int_set (beta3Rijs3j, s3coeff);
                      int_mul_sgn_self (beta3Rijs3j, Ri[j]);
                      int_add (Rs3coeff, Rs3coeff, beta3Rijs3j);
                    }
                }
            }
          intvec_mul_sgn_self (y3coeffs, beta3);
          intvec_add (z3coeffs, z3coeffs, y3coeffs);
        }

      if (nprime > 0)
        {
          INT_T (beta4Rprimeijs4j, int_get_nlimbs (q));
          int8_t Rprimei[nprime * d];
          int_ptr s4coeff, Rs4coeff;

          polyvec_fromcrt (s4);
          polyvec_fromcrt (y4);

          polyvec_set (z4_, y4);
          intvec_set_zero (y4coeffs);

          for (i = 0; i < 256; i++)
            {
              Rs4coeff = intvec_get_elem (y4coeffs, i);

              _expand_Rprime_i (Rprimei, nprime * d, i, cseed);

              for (j = 0; j < nprime * d; j++)
                {
                  if (Rprimei[j] == 0)
                    {
                    }
                  else
                    {
                      ASSERT_ERR (Rprimei[j] == 1 || Rprimei[j] == -1);

                      s4coeff = intvec_get_elem (s4coeffs, j);

                      int_set (beta4Rprimeijs4j, s4coeff);
                      int_mul_sgn_self (beta4Rprimeijs4j, Rprimei[j]);
                      int_add (Rs4coeff, Rs4coeff, beta4Rprimeijs4j);
                    }
                }
            }
          intvec_mul_sgn_self (y4coeffs, beta4);
          intvec_add (z4coeffs, z4coeffs, y4coeffs);
        }

      /* rejection sampling */

      ASSERT_ERR (params->rej3 == 0 || params->rej3 == 2);
      if (nex > 0 && params->rej3)
        {
          intvec_mul_sgn_self (y3coeffs, beta3); /* revert mul by beta3 */

          rej = rej_bimodal (rstate_rej, z3coeffs, y3coeffs, params->scM3,
                             params->stdev3sqr);
          if (rej)
            {
              DEBUG_PRINTF (DEBUG_PRINT_REJ, "%s", "reject s3");
              continue;
            }
        }
      ASSERT_ERR (params->rej4 == 0 || params->rej4 == 2);
      if (nprime > 0 && params->rej4)
        {
          intvec_mul_sgn_self (y4coeffs, beta4); /* revert mul by beta4 */

          rej = rej_bimodal (rstate_rej, z4coeffs, y4coeffs, params->scM4,
                             params->stdev4sqr);
          if (rej)
            {
              DEBUG_PRINTF (DEBUG_PRINT_REJ, "%s", "reject s3");
              continue;
            }
        }

      break;
    }

  /* update fiat-shamir hash */
  memcpy (hash, cseed, 32);

  /* output proof (h,c,z1,z21,hint,z3,z4) */
  polyvec_set (z3, z3_);
  polyvec_set (z4, z4_);

  /* cleanup */
  rng_clear (rstate_signs);
  rng_clear (rstate_rej);
  polyvec_free (s3);
  polyvec_free (s4);
  polyvec_free (y3);
  polyvec_free (y4);
  polyvec_free (z3_);
  polyvec_free (z4_);
}

static int
_lnp_tbox_check_z34 (uint8_t hash[32], polyvec_t z3, polyvec_t z4,
                     polyvec_t tB, UNUSED polymat_ptr Es[],
                     UNUSED polymat_ptr Em[], UNUSED polyvec_ptr v[],
                     UNUSED polymat_t Ps, UNUSED polymat_t Pm,
                     UNUSED polyvec_t f, UNUSED polymat_t Ds,
                     UNUSED polymat_t Dm, UNUSED polyvec_t u,
                     const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  const unsigned int Z = params->Z;
#if ASSERT == ASSERT_ENABLED
  const unsigned int lambda = params->quad_eval->lambda;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int lext = params->tbox->lext;
  const unsigned int *ni = params->n;
#endif
  const unsigned int nbin = params->nbin;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int d = polyring_get_deg (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int nex = params->nex;
  const unsigned int nprime = params->nprime;
  const unsigned int l = tbox->l;
  INT_T (linf, int_get_nlimbs (q));
  INT_T (l2sqr, 2 * int_get_nlimbs (q));
  INTVEC_T (z3coeffs, 256, int_get_nlimbs (q));
  INTVEC_T (z4coeffs, 256, int_get_nlimbs (q));
  unsigned int i;
  polyvec_t tmp_polyvec, ty3, ty4, tbeta;
  intvec_t isubv;
  poly_ptr poly;
  intvec_ptr coeffs;
  shake128_state_t hstate;
  coder_state_t cstate;
  unsigned int outlen, loff;
  uint8_t out[CEIL (256 * 2 * log2q + d * log2q, 8) + 1];
  uint8_t cseed[32]; /* seed for challenge */
  int b = 0;

  memset (out, 0, CEIL (256 * 2 * log2q + d * log2q, 8) + 1); // XXX

  loff = 0;
  if (nex > 0)
    {
      ASSERT_ERR (Ps == NULL || polymat_get_nrows (Ps) == nbin);
      ASSERT_ERR (Ps == NULL || polymat_get_ncols (Ps) == m1);
      ASSERT_ERR (Pm == NULL || polymat_get_nrows (Pm) == nbin);
      ASSERT_ERR (Pm == NULL || polymat_get_ncols (Pm) == l);
      ASSERT_ERR (f == NULL || polyvec_get_nelems (f) == nbin);

      polyvec_get_subvec (ty3, tB, l + loff, 256 / d, 1);
      polyvec_mod (ty3, ty3);
      polyvec_redp (ty3, ty3);

      loff += 256 / d;
    }
  if (nprime > 0)
    {
      ASSERT_ERR (Ds == NULL || polymat_get_nrows (Ds) == nprime);
      ASSERT_ERR (Ds == NULL || polymat_get_ncols (Ds) == m1);
      ASSERT_ERR (Dm == NULL || polymat_get_nrows (Dm) == nprime);
      ASSERT_ERR (Dm == NULL || polymat_get_ncols (Dm) == l);
      ASSERT_ERR (u == NULL || polyvec_get_nelems (u) == nprime);
      for (i = 0; i < Z; i++)
        {
          ASSERT_ERR (Es[i] == NULL || polymat_get_nrows (Es[i]) == ni[i]);
          ASSERT_ERR (Es[i] == NULL || polymat_get_ncols (Es[i]) == m1);
          ASSERT_ERR (Em[i] == NULL || polymat_get_nrows (Em[i]) == ni[i]);
          ASSERT_ERR (Em[i] == NULL || polymat_get_ncols (Em[i]) == l);
          ASSERT_ERR (v[i] == NULL || polyvec_get_nelems (v[i]) == ni[i]);
        }

      polyvec_get_subvec (ty4, tB, l + loff, 256 / d, 1);
      polyvec_mod (ty4, ty4);
      polyvec_redp (ty4, ty4);

      loff += 256 / d;
    }
  ASSERT_ERR (lext == (loff + 1) + (lambda / 2 + 1));

  polyvec_alloc (tmp_polyvec, Rq, MAX (nbin, MAX (nex, nprime)));

  polyvec_get_subvec (tbeta, tB, l + loff, 1, 1);
  polyvec_mod (tbeta, tbeta);
  polyvec_redp (tbeta, tbeta);

  /* check  bounds */

  if (nex > 0)
    {
      polyvec_fromcrt (z3);
      polyvec_l2sqr (l2sqr, z3);
      if (int_gt (l2sqr, params->Bz3sqr))
        goto ret;
    }
  if (nprime > 0)
    {
      polyvec_fromcrt (z4);
      polyvec_linf (linf, z4);
      if (int_gt (linf, params->Bz4))
        goto ret;
    }

  /* encode ty, tbeta, hash of encoding is seed for challenges */

  coder_enc_begin (cstate, out);
  if (nex > 0)
    coder_enc_urandom3 (cstate, ty3, q, log2q);
  if (nprime > 0)
    coder_enc_urandom3 (cstate, ty4, q, log2q);
  coder_enc_urandom3 (cstate, tbeta, q, log2q);
  coder_enc_end (cstate);

  outlen = coder_get_offset (cstate);
  ASSERT_ERR (outlen % 8 == 0);
  ASSERT_ERR (outlen / 8 <= CEIL (256 * 2 * log2q + d * log2q, 8) + 1);
  outlen >>= 3; /* nbits to nbytes */

  /* recover challenge */
  shake128_init (hstate);
  shake128_absorb (hstate, hash, 32);
  shake128_absorb (hstate, out, outlen);
  shake128_squeeze (hstate, cseed, 32);
  shake128_clear (hstate);

  /* get z3 and z4 coefficient vectors */
  for (i = 0; i < 256 / d; i++)
    {
      intvec_get_subvec (isubv, z3coeffs, i * d, d, 1);
      poly = polyvec_get_elem (z3, i);
      coeffs = poly_get_coeffvec (poly);
      intvec_set (isubv, coeffs);

      intvec_get_subvec (isubv, z4coeffs, i * d, d, 1);
      poly = polyvec_get_elem (z4, i);
      coeffs = poly_get_coeffvec (poly);
      intvec_set (isubv, coeffs);
    }

  /* update fiat-shamir hash */
  memcpy (hash, cseed, 32);

  b = 1;
ret:
  /* cleanup */
  polyvec_free (tmp_polyvec);
  return b;
}

/* expand i-th row of R from cseed and i */
static inline void
_expand_R_i (int8_t *Ri, unsigned int ncols, unsigned int i,
             const uint8_t cseed[32])
{
  _brandom (Ri, ncols, 1, cseed, i);
}

/* expand i-th row of Rprime from cseed and 256 + i */
static inline void
_expand_Rprime_i (int8_t *Rprimei, unsigned int ncols, unsigned int i,
                  const uint8_t cseed[32])
{
  _brandom (Rprimei, ncols, 1, cseed, 256 + i);
}

/*
 * r = U^T*auto(a) = U*auto(a)
 * for each dim 2 subvec:
 * (a,b) -> auto((b,a))
 */
static void
__shuffleautovecsparse (spolyvec_t r)
{
  poly_ptr rp;
  unsigned int i, elem;

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  _SVEC_FOREACH_ELEM (r, i)
  {
    rp = spolyvec_get_elem (r, i);
    elem = spolyvec_get_elem_ (r, i);

    poly_auto_self (rp);
    spolyvec_set_elem_ (r, i, elem % 2 == 0 ? elem + 1 : elem - 1);
  }

  r->sorted = 0; // XXX simpler sort possible
  spolyvec_sort (r);

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

/*
 *
 * r = U^T*auto(a)*U = U*auto(a)*U
 * for each 2x2 submat on or above the main diagonal:
 * [[a,b],[c,d]] -> auto([[d,c],[b,a]])
 * r != a
 */
static void
__shuffleauto2x2submatssparse (spolymat_t a)
{
  poly_ptr ap;
  unsigned int i, arow, acol;

  ASSERT_ERR (spolymat_get_nrows (a) % 2 == 0);
  ASSERT_ERR (spolymat_get_ncols (a) % 2 == 0);
  ASSERT_ERR (spolymat_is_upperdiag (a));

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  _SMAT_FOREACH_ELEM (a, i)
  {
    ap = spolymat_get_elem (a, i);
    arow = spolymat_get_row (a, i);
    acol = spolymat_get_col (a, i);

    if (arow % 2 == 0 && acol % 2 == 0)
      {
        spolymat_set_row (a, i, arow + 1);
        spolymat_set_col (a, i, acol + 1);
        poly_auto_self (ap);
      }
    else if (arow % 2 == 1 && acol % 2 == 1)
      {
        spolymat_set_row (a, i, arow - 1);
        spolymat_set_col (a, i, acol - 1);
        poly_auto_self (ap);
      }
    else if (arow % 2 == 1 && acol % 2 == 0)
      {
        spolymat_set_row (a, i, arow - 1);
        spolymat_set_col (a, i, acol + 1);
        poly_auto_self (ap);
      }
    else
      {
        /*
         * arow % 2 == 0 && acol % 2 == 1
         * This element's automorphism may land in the subdiagonal -1
         * if the 2x2 submat is on the main diagonal.
         * Check for this case and keep the matrix upper diagonal.
         */
        if (arow + 1 > acol - 1)
          {
            poly_auto_self (ap);
          }
        else
          {
            spolymat_set_row (a, i, arow + 1);
            spolymat_set_col (a, i, acol - 1);
            poly_auto_self (ap);
          }
      }
  }
  a->sorted = 0;
  spolymat_sort (a);
  ASSERT_ERR (spolymat_is_upperdiag (a));

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

static void
__schwartz_zippel_accumulate (spolymat_ptr R2i, spolyvec_ptr r1i, poly_ptr r0i,
                              spolymat_ptr Rprime2i[], spolyvec_ptr rprime1i[],
                              poly_ptr rprime0i[], unsigned int M,
                              const intvec_t v,
                              const lnp_quad_eval_params_t params)
{
  abdlop_params_srcptr quad_eval = params->quad_eval;
  polyring_srcptr Rq = quad_eval->ring;
  const unsigned int m1 = quad_eval->m1;
  const unsigned int l = quad_eval->l;
  const unsigned int n = 2 * (m1 + l);
  spolyvec_t u0, u1, u2;
  spolymat_t t0, t1, t2;
  unsigned int j;

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  spolyvec_alloc (u0, Rq, n, n);
  spolyvec_alloc (u1, Rq, n, n);
  spolyvec_alloc (u2, Rq, n, n);
  spolymat_alloc (t0, Rq, n, n, (n * n - n) / 2 + n);
  spolymat_alloc (t1, Rq, n, n, (n * n - n) / 2 + n);
  spolymat_alloc (t2, Rq, n, n, (n * n - n) / 2 + n);

  /* R2i */

  spolymat_set (t0, R2i);
  for (j = 0; j < M; j++)
    {
      if (Rprime2i[j] == NULL)
        continue;

      spolymat_fromcrt (Rprime2i[j]);

      spolymat_scale (t1, intvec_get_elem (v, j), Rprime2i[j]);
      spolymat_add (t2, t0, t1, 0);
      spolymat_set (t0, t2);
    }
  spolymat_mod (R2i, t0);

  /* r1i */

  spolyvec_set (u0, r1i);
  for (j = 0; j < M; j++)
    {
      if (rprime1i[j] == NULL)
        continue;

      spolyvec_fromcrt (rprime1i[j]);

      spolyvec_scale (u1, intvec_get_elem (v, j), rprime1i[j]);
      spolyvec_add (u2, u0, u1, 0);
      spolyvec_set (u0, u2);
    }
  spolyvec_mod (r1i, u0);

  if (r0i != NULL)
    {
      for (j = 0; j < M; j++)
        {
          if (rprime0i[j] == NULL)
            continue;

          poly_fromcrt (rprime0i[j]);
          poly_addscale (r0i, intvec_get_elem (v, j), rprime0i[j], 0);
        }
      poly_mod (r0i, r0i);
    }

  spolyvec_free (u0);
  spolyvec_free (u1);
  spolyvec_free (u2);
  spolymat_free (t0);
  spolymat_free (t1);
  spolymat_free (t2);

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

/* just add equations that have already been multiplied by a challenge. */
static void
__schwartz_zippel_accumulate_ (spolymat_ptr R2i, spolyvec_ptr r1i,
                               poly_ptr r0i, spolymat_ptr Rprime2i[],
                               spolyvec_ptr rprime1i[], poly_ptr rprime0i[],
                               unsigned int M,
                               const lnp_quad_eval_params_t params)
{
  abdlop_params_srcptr quad_eval = params->quad_eval;
  polyring_srcptr Rq = quad_eval->ring;
  const unsigned int m1 = quad_eval->m1;
  const unsigned int l = quad_eval->l;
  const unsigned int n = 2 * (m1 + l);
  spolyvec_t u0, u2;
  spolymat_t t0, t2;
  unsigned int j;

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  spolyvec_alloc (u0, Rq, n, n);
  spolyvec_alloc (u2, Rq, n, n);
  spolymat_alloc (t0, Rq, n, n, (n * n - n) / 2 + n);
  spolymat_alloc (t2, Rq, n, n, (n * n - n) / 2 + n);

  /* R2i */

  spolymat_set (t0, R2i);
  for (j = 0; j < M; j++)
    {
      if (Rprime2i[j] == NULL)
        continue;

      spolymat_fromcrt (Rprime2i[j]);

      spolymat_add (t2, t0, Rprime2i[j], 0);
      spolymat_set (t0, t2);
    }
  spolymat_mod (R2i, t0);

  /* r1i */

  spolyvec_set (u0, r1i);
  for (j = 0; j < M; j++)
    {
      if (rprime1i[j] == NULL)
        continue;

      spolyvec_fromcrt (rprime1i[j]);

      spolyvec_add (u2, u0, rprime1i[j], 0);
      spolyvec_set (u0, u2);
    }
  spolyvec_mod (r1i, u0);

  if (r0i != NULL)
    {
      for (j = 0; j < M; j++)
        {
          if (rprime0i[j] == NULL)
            continue;

          poly_fromcrt (rprime0i[j]);
          poly_add (r0i, r0i, rprime0i[j], 0);
        }
      poly_mod (r0i, r0i);
    }

  spolyvec_free (u0);
  spolyvec_free (u2);
  spolymat_free (t0);
  spolymat_free (t2);

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

static void
__schwartz_zippel_auto (spolymat_ptr R2i, spolyvec_ptr r1i, poly_ptr r0i,
                        spolymat_ptr R2i2, spolyvec_ptr r1i2, poly_ptr r0i2,
                        const lnp_quad_eval_params_t params)
{
  abdlop_params_srcptr quad_eval = params->quad_eval;
  polyring_srcptr Rq = quad_eval->ring;
  const unsigned int d = polyring_get_deg (Rq);
  const unsigned int m1 = quad_eval->m1;
  const unsigned int l = quad_eval->l;
  const unsigned int n = 2 * (m1 + l);
  spolyvec_t u0, u1, u2;
  spolymat_t t0, t1, t2;
  poly_t tpoly;

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  poly_alloc (tpoly, Rq);

  spolyvec_alloc (u0, Rq, n, n);
  spolyvec_alloc (u1, Rq, n, n);
  spolyvec_alloc (u2, Rq, n, n);
  spolymat_alloc (t0, Rq, n, n, (n * n - n) / 2 + n);
  spolymat_alloc (t1, Rq, n, n, (n * n - n) / 2 + n);
  spolymat_alloc (t2, Rq, n, n, (n * n - n) / 2 + n);

  /* R2i */

  spolymat_fromcrt (R2i);
  spolymat_fromcrt (R2i2);

  spolymat_set (t0, R2i);
  __shuffleauto2x2submatssparse (t0);

  spolymat_add (t1, R2i, t0, 0); // t1 = R2i + Uo(R2i)U

  spolymat_set (t0, R2i2);
  spolymat_lrot (t2, t0, d / 2);

  spolymat_add (R2i, t1, t2, 0); // R2i = R2i + Uo(R2i)U + R2i2X^(d/2)

  spolymat_set (t0, R2i2);
  __shuffleauto2x2submatssparse (t0);
  spolymat_lrot (t1, t0, d / 2);
  spolymat_add (t0, R2i, t1,
                0); // t0 = R2i + Uo(R2i)U + R2i2X^(d/2) +  Uo(R2i2)UX^(d/2)

  spolymat_scale (R2i, Rq->inv2, t0);

  /* r1i */

  spolyvec_fromcrt (r1i);
  spolyvec_fromcrt (r1i2);

  spolyvec_set (u0, r1i);
  __shuffleautovecsparse (u0);

  spolyvec_add (u1, r1i, u0, 0); // u1 = r1i + Uo(r1i)U

  spolyvec_set (u0, r1i2);
  spolyvec_lrot (u2, u0, d / 2);

  spolyvec_add (r1i, u1, u2, 0); // r1i = r1i + Uo(r1i)U + r1i2X^(d/2)

  spolyvec_set (u0, r1i2);
  __shuffleautovecsparse (u0);
  spolyvec_lrot (u1, u0, d / 2);
  spolyvec_add (u0, r1i, u1,
                0); // t0 = r1i + Uo(r1i)U + r1i2X^(d/2) +  Uo(r1i2)UX^(d/2)

  spolyvec_scale (r1i, Rq->inv2, u0);

  /* r0i */
  if (r0i != NULL)
    {
      poly_fromcrt (r0i);
      poly_fromcrt (r0i2);

      poly_auto (tpoly, r0i);
      poly_add (r0i, r0i, tpoly, 0); // r0i = r0i + o(r0i)

      poly_lrot (tpoly, r0i2, d / 2);
      poly_add (r0i, r0i, tpoly, 0); // r0i = r0i + o(r0i) + r0i2X^(d/2)

      poly_auto (tpoly, r0i2);
      poly_lrot (tpoly, tpoly, d / 2);
      poly_add (r0i, r0i, tpoly,
                0); // r0i = r0i + o(r0i) + r0i2X^(d/2) + o(r0i2)X^(d/2)

      poly_scale (r0i, Rq->inv2, r0i);
    }

  spolyvec_free (u0);
  spolyvec_free (u1);
  spolyvec_free (u2);
  spolymat_free (t0);
  spolymat_free (t1);
  spolymat_free (t2);
  poly_free (tpoly);

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

/*
 * R2i, r1i, r0i: first accumulator (lambda/2 eqs)
 * R2i2, r1i2, r0i2: second accumulator (lambda/2 eqs)
 * R2primei r1primei, r0primei: input eqs (M eqs)
 * Result is in first accumulator.
 */
static void
__schwartz_zippel_accumulate2 (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                               poly_ptr r0i[], spolymat_ptr R2i2[],
                               spolyvec_ptr r1i2[], poly_ptr r0i2[],
                               spolymat_ptr R2primei[],
                               spolyvec_ptr r1primei[], poly_ptr r0primei[],
                               unsigned int M, const uint8_t seed[32],
                               uint32_t dom,
                               const lnp_quad_eval_params_t params)
{
  abdlop_params_srcptr quad_eval = params->quad_eval;
  const unsigned int lambda = params->lambda;
  polyring_srcptr Rq = quad_eval->ring;
  int_srcptr q = polyring_get_mod (Rq);
  const unsigned int log2q = polyring_get_log2q (Rq);
  INTVEC_T (V, 2 * M, Rq->q->nlimbs);
  intvec_t subv1, subv2;
  unsigned int i;

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_ENTRY, "%s begin", __func__);

  intvec_get_subvec (subv1, V, 0, M, 1);
  intvec_get_subvec (subv2, V, M, M, 1);
  intvec_urandom (V, q, log2q, seed, dom);

  for (i = 0; i < lambda / 2; i++)
    {
      __schwartz_zippel_accumulate (R2i[i], r1i[i], r0i[i], R2primei, r1primei,
                                    r0primei, M, subv1, params);
      __schwartz_zippel_accumulate (R2i2[i], r1i2[i], r0i2[i], R2primei,
                                    r1primei, r0primei, M, subv2, params);
    }

  DEBUG_PRINTF (DEBUG_PRINT_FUNCTION_RETURN, "%s end", __func__);
}

static void
__schwartz_zippel_accumulate_beta3 (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                    poly_ptr r0i[], spolymat_ptr R2i2[],
                                    spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                    UNUSED spolymat_ptr R2t, spolyvec_ptr r1t,
                                    UNUSED poly_ptr r0t,
                                    const uint8_t seed[32], uint32_t dom,
                                    const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  const unsigned int Z = params->Z;
  polyring_srcptr Rq = params->tbox->ring;
  const unsigned int d = polyring_get_deg (Rq);
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int nex = params->nex;
  const unsigned int l = tbox->l;
  const unsigned int nprime = params->nprime;
  const unsigned int loff
      = (nprime > 0 ? 256 / d : 0) + (nex > 0 ? 256 / d : 0);
  const unsigned int ibeta = (m1 + Z + l + loff) * 2;
  poly_ptr poly;
  int_ptr coeff;
  unsigned int i;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];

  // d-1 eval eqs in beta,o(beta), for i=1,...,d-1:
  // prove const coeff of X^i * beta3 = 0 -> i2*x^i*beta + i2*x^i*o(beta) = 0
  // terms: R2: 0, r1: 2, r0: 0 | * (d-1)
  for (i = 1; i < d; i++)
    {
      R2tptr[0] = NULL;

      spolyvec_set_empty (r1t);
      poly = spolyvec_insert_elem (r1t, ibeta);
      poly_set_zero (poly);
      coeff = poly_get_coeff (poly, i);
      int_set (coeff, Rq->inv2);
      poly = spolyvec_insert_elem (r1t, ibeta + 1);
      poly_set_zero (poly);
      coeff = poly_get_coeff (poly, i);
      int_set (coeff, Rq->inv2);
      r1t->sorted = 1;
      r1tptr[0] = r1t;

      r0tptr[0] = NULL;

      __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                     r1tptr, r0tptr, 1, seed, dom + i,
                                     params->quad_eval);
    }
}

static void
__schwartz_zippel_accumulate_beta4 (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                    poly_ptr r0i[], spolymat_ptr R2i2[],
                                    spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                    UNUSED spolymat_ptr R2t, spolyvec_ptr r1t,
                                    UNUSED poly_ptr r0t,
                                    const uint8_t seed[32], uint32_t dom,
                                    const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  const unsigned int Z = params->Z;
  polyring_srcptr Rq = params->tbox->ring;
  const unsigned int d = polyring_get_deg (Rq);
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int nex = params->nex;
  const unsigned int l = tbox->l;
  const unsigned int nprime = params->nprime;
  const unsigned int loff
      = (nprime > 0 ? 256 / d : 0) + (nex > 0 ? 256 / d : 0);
  const unsigned int ibeta = (m1 + Z + l + loff) * 2;
  poly_ptr poly;
  int_ptr coeff;
  unsigned int i;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];

  // d-1 eval eqs in beta,o(beta), for i=1,...,d-1:
  // prove const coeff of X^i * beta4 = 0 -> -i2*x^i*x^(d/2)*beta +
  // i2*x^i*x^(d/2)*o(beta) = 0 terms: R2: 0, r1: 2, r0: 0 | * (d-1)
  for (i = 1; i < d; i++)
    {
      R2tptr[0] = NULL;

      spolyvec_set_empty (r1t);
      poly = spolyvec_insert_elem (r1t, ibeta);
      poly_set_zero (poly);
      if (i < d / 2)
        {
          coeff = poly_get_coeff (poly, i + d / 2);
          int_neg (coeff, Rq->inv2);
        }
      else
        {
          coeff = poly_get_coeff (poly, i + d / 2 - d);
          int_set (coeff, Rq->inv2);
        }
      poly = spolyvec_insert_elem (r1t, ibeta + 1);
      poly_set_zero (poly);
      if (i < d / 2)
        {
          coeff = poly_get_coeff (poly, i + d / 2);
          int_set (coeff, Rq->inv2);
        }
      else
        {
          coeff = poly_get_coeff (poly, i + d / 2 - d);
          int_neg (coeff, Rq->inv2);
        }
      r1t->sorted = 1;
      r1tptr[0] = r1t;

      r0tptr[0] = NULL;

      __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                     r1tptr, r0tptr, 1, seed, dom + i,
                                     params->quad_eval);
    }
}

static void
__schwartz_zippel_accumulate_upsilon (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                      poly_ptr r0i[], spolymat_ptr R2i2[],
                                      spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                      UNUSED spolymat_ptr R2t,
                                      spolyvec_ptr r1t, UNUSED poly_ptr r0t,
                                      const uint8_t seed[32], uint32_t dom,
                                      const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  poly_ptr poly;
  unsigned int j;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];
  intvec_ptr coeffs;

  // eval eq in upsilon, o(upsilon)
  // directly prove upsilon is binary i.e.: prove <upsilon,upsilon-ones>=0 over
  // ints
  // terms: R2: Z, r1: Z, r0: 0 | * 1

  spolymat_set_empty (R2t);
  spolyvec_set_empty (r1t);

  for (j = 0; j < Z; j++)
    {
      const unsigned int iupsilonj = (m1 + j) * 2;

      poly = spolymat_insert_elem (R2t, iupsilonj, iupsilonj + 1);
      poly_set_one (poly);

      poly = spolyvec_insert_elem (r1t, iupsilonj + 1);
      coeffs = poly_get_coeffvec (poly);
      intvec_set_ones (coeffs);
      intvec_neg_self (coeffs);
    }

  R2t->sorted = 1;
  R2tptr[0] = R2t;

  r1t->sorted = 1;
  r1tptr[0] = r1t;

  r0tptr[0] = NULL;

  __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                 r1tptr, r0tptr, 1, seed, dom,
                                 params->quad_eval);
}

/* swap row and col iff row > col */
static inline void
_diag (unsigned int *row, unsigned int *col, unsigned int r, unsigned int c)
{
  if (r > c)
    {
      *row = c;
      *col = r;
    }
  else
    {
      *row = r;
      *col = c;
    }
}

static void
__schwartz_zippel_accumulate_bin (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                  poly_ptr r0i[], spolymat_ptr R2i2[],
                                  spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                  spolymat_ptr R2t, spolyvec_ptr r1t,
                                  poly_ptr r0t, polymat_t Ps, polymat_t Pm,
                                  polyvec_t f, polymat_t oPs, polymat_t oPm,
                                  polyvec_t of, const uint8_t seed[32],
                                  uint32_t dom, const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int d = Rq->d;
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int l = tbox->l;
  const unsigned int nbin = params->nbin;
  INT_T (a_, int_get_nlimbs (q));
  INT_T (a, 2 * int_get_nlimbs (q));
  INT_T (at, 2 * int_get_nlimbs (q));
  polyvec_t subv, subv2;
  polyvec_ptr f_;
  intvec_ptr coeffs, coeffs2;
  unsigned int i, j, k, row, col;
  int_ptr coeff;
  poly_ptr poly, poly2;
  polyvec_t tmp_polyvec;
  polyvec_t tmp_polyvec2;
  polyvec_t tmp_polyvec3;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];

  polyvec_alloc (tmp_polyvec, Rq, nbin);
  polyvec_alloc (tmp_polyvec2, Rq, nbin);
  polyvec_alloc (tmp_polyvec3, Rq, MAX (m1, l));

  // 4 eval eq in s1,o(s1),m,o(m)
  // prove s*s1+Pm*m+f is binary i.e.:
  // prove <Ps*s1+Pm*m+f,Ps*s1+Pm*m+f-ones>=0 over ints
  // terms: R2: (m1+l)^2, r1: 2(m1+l), r0: 1 | * 1

  f_ = tmp_polyvec;

  /* r0' */
  poly_set_zero (r0t);

  for (j = 0; j < nbin; j++)
    {
      poly = polyvec_get_elem (f_, j);
      for (i = 0; i < d; i++)
        {
          coeff = poly_get_coeff (poly, i);
          int_set_one (coeff);
          int_neg_self (coeff);
        }
    }

  if (f != NULL)
    {
      polyvec_add (f_, f_, f, 0);
      polyvec_redc (f_, f_);

      int_set_zero (a);
      for (j = 0; j < nbin; j++)
        {
          poly = polyvec_get_elem (f_, j);
          poly2 = polyvec_get_elem (f, j);
          coeffs = poly_get_coeffvec (poly);
          coeffs2 = poly_get_coeffvec (poly2);

          intvec_dot (at, coeffs, coeffs2);
          int_add (a, a, at);
        }
      int_mod (a_, a, q);
      int_redc (a_, a_, q);
      coeff = poly_get_coeff (r0t, 0);
      int_set (coeff, a_);
    }

  /* R2', r1' */
  spolymat_set_empty (R2t);
  spolyvec_set_empty (r1t);

  if (Ps != NULL)
    {
      for (k = 0; k < m1; k++)
        {
          polymat_get_col (subv2, oPs, k);
          // XXXpolymat_get_col (subv, Ps, k);
          // XXXpolyvec_auto (tmp_polyvec2, subv);

          /* o(s1)^T*o(Ps)^T*Ps*s1 */
          for (j = 0; j < m1; j++)
            {
              polymat_get_col (subv, Ps, j);
              _diag (&row, &col, 2 * k + 1, 2 * j);
              poly = spolymat_insert_elem (R2t, row, col);
              polyvec_dot (poly, subv2, subv);
            }

          /* o(s1)^T*o(Ps)^T*Pm*m */
          if (Pm != NULL)
            {
              for (j = 0; j < l; j++)
                {
                  polymat_get_col (subv, Pm, j);
                  _diag (&row, &col, 2 * k + 1, 2 * (m1 + Z + j));
                  poly = spolymat_insert_elem (R2t, row, col);
                  polyvec_dot (poly, subv2, subv);
                }
            }

          /* o(s1)^T*o(Ps)^T*(f-1) */
          poly = spolyvec_insert_elem (r1t, 2 * k + 1);
          polyvec_dot (poly, subv2, f_);
        }
    }
  if (Pm != NULL)
    {
      for (k = 0; k < l; k++)
        {
          polymat_get_col (subv2, oPm, k);
          // XXXpolymat_get_col (subv, Pm, k);
          // XXXpolyvec_auto (tmp_polyvec2, subv);

          /* o(m)^T*o(Pm)^T*Ps*s1 */
          if (Ps != NULL)
            {
              for (j = 0; j < m1; j++)
                {
                  polymat_get_col (subv, Ps, j);
                  _diag (&row, &col, 2 * (m1 + Z + k) + 1, 2 * j);
                  poly = spolymat_insert_elem (R2t, row, col);
                  polyvec_dot (poly, subv2, subv);
                }
            }

          /* o(m)^T*o(Pm)^T*Pm*m */
          for (j = 0; j < l; j++)
            {
              polymat_get_col (subv, Pm, j);
              _diag (&row, &col, 2 * (m1 + Z + k) + 1, 2 * (m1 + Z + j));
              poly = spolymat_insert_elem (R2t, row, col);
              polyvec_dot (poly, subv2, subv);
            }

          /* o(m)^T*o(Pm)^T*(f-1) */
          poly = spolyvec_insert_elem (r1t, 2 * (m1 + Z + k) + 1);
          polyvec_dot (poly, subv2, f_);
        }
    }

  if (f != NULL)
    {
      // XXXpolyvec_auto (f_, f);

      /* o(f)^T*Ps*s1 */
      if (Ps != NULL)
        {
          polyvec_get_subvec (subv, tmp_polyvec3, 0, m1, 1);
          polyvec_mul2 (subv, of, Ps);

          _VEC_FOREACH_ELEM (subv, i)
          {
            poly = polyvec_get_elem (tmp_polyvec3, i);
            poly2 = spolyvec_insert_elem (r1t, 0 + 2 * i);
            poly_set (poly2, poly);
          }
        }

      /* o(f)^T*Pm*m */
      if (Pm != NULL)
        {
          polyvec_get_subvec (subv, tmp_polyvec3, 0, l, 1);
          polyvec_mul2 (subv, of, Pm);

          _VEC_FOREACH_ELEM (subv, i)
          {
            poly = polyvec_get_elem (tmp_polyvec3, i);
            poly2 = spolyvec_insert_elem (r1t, 2 * (m1 + Z) + 2 * i);
            poly_set (poly2, poly);
          }
        }
    }

  // XXXspolyvec_fromcrt (r1t);
  spolyvec_sort (r1t); // compute already sorted ?
  // XXXspolymat_fromcrt (R2t);
  spolymat_sort (R2t); // compute already sorted ?
  ASSERT_ERR (spolymat_is_upperdiag (R2t));

  R2tptr[0] = R2t;
  r1tptr[0] = r1t;
  r0tptr[0] = r0t;

  polyvec_free (tmp_polyvec);
  polyvec_free (tmp_polyvec2);
  polyvec_free (tmp_polyvec3);

  __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                 r1tptr, r0tptr, 1, seed, dom,
                                 params->quad_eval);
}

#define MAX(x, y) ((x) >= (y) ? (x) : (y))

static void
__schwartz_zippel_accumulate_l2 (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                 poly_ptr r0i[], spolymat_ptr R2i2[],
                                 spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                 spolymat_ptr R2t, spolyvec_ptr r1t,
                                 poly_ptr r0t, polymat_ptr Es[],
                                 polymat_ptr Em[], polyvec_ptr v[],
                                 polymat_ptr oEs[], polymat_ptr oEm[],
                                 polyvec_ptr ov[], const uint8_t seed[32],
                                 uint32_t dom, const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int l = tbox->l;
  const unsigned int *ni = params->n;
  INT_T (a_, int_get_nlimbs (q));
  INT_T (a, 2 * int_get_nlimbs (q));
  INT_T (at, 2 * int_get_nlimbs (q));
  unsigned int i, j, k, row, col;
  polyvec_t subv2, subv, tmp_polyvec, tmp_polyvec3;
  unsigned int nelems;
  intvec_ptr coeffs;
  int_ptr coeff;
  poly_ptr poly, poly2;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];

  nelems = 0;
  for (i = 0; i < Z; i++)
    nelems = MAX (nelems, ni[i]);

  polyvec_alloc (tmp_polyvec, Rq, nelems);
  polyvec_alloc (tmp_polyvec3, Rq, MAX (m1, l));

  // eval eqs in s1,o(s1),m,o(m),upsilon,o(upsilon)
  // for i in 0,..,Z-1
  // prove <pwrs2,upsilon[i]> = B[i]^2 - l2(Es[i]*s1+Em[i]*m+v[i])^2
  // i.e., <pwrs2,upsilon[i]> - B[i]^2 + <Es[i]*s1+Em[i]*m+v[i],
  //                                      Es[i]*s1+Em[i]*m+v[i]> = 0
  // equivalently,
  // constcoeff <pwrs2,upsilon[i]> - B[i]^2 +
  // o(Es[i]*s1+Em[i]*m+v[i])^T*(Es[i]*s1+Em[i]*m+v[i]) = 0
  // =
  // o(s1)^T*o(Es[i])^T*Es[i]*s1 + o(m)^T*o(Em[i])^T*Es[i]*s1 + o(v)^T*Es[i]*s1
  // + o(s1)^T*o(Es[i])^T*Em[i]*m  + o(m)^T*o(Em[i])^T*Em[i]*m  +
  // o(v)^T*Em[i]*m
  // + o(s1)^T*o(Es[i])^T*(v) + o(m)^T*o(Em[i])^T*(v) + o(v)^T*(v) +
  // o(pwrs2)*upsilon[i] - B[i]^2
  // terms: R2: (m1+l)^2, r1: 2*(m1+l)+1, r0: 1 | * Z

  for (i = 0; i < Z; i++)
    {
      polyvec_get_subvec (subv2, tmp_polyvec, 0, ni[i], 1);

      /* r0' */
      poly_set_zero (r0t);

      if (v != NULL)
        {
          int_set_zero (a);
          for (j = 0; j < ni[i]; j++)
            {
              if (v[i] == NULL)
                continue;

              poly = polyvec_get_elem (v[i], j);
              coeffs = poly_get_coeffvec (poly);

              intvec_dot (at, coeffs, coeffs);
              int_add (a, a, at);
            }

          int_mod (a_, a, q);
          int_redc (a_, a_, q);
        }
      else
        {
          int_set_zero (a_);
        }

      int_sub (a_, a_, params->l2Bsqr[i]);
      int_redc (a_, a_, q);
      coeff = poly_get_coeff (r0t, 0);
      int_set (coeff, a_); /* <v,v> - Bi^2 */

      /* R2', r1' */
      spolymat_set_empty (R2t);
      R2t->sorted = 0;
      spolyvec_set_empty (r1t);
      r1t->sorted = 0;

      if (Es != NULL && Es[i] != NULL)
        {
          for (k = 0; k < m1; k++)
            {
              polymat_get_col (subv, Es[i], k);
              polymat_get_col (subv2, oEs[i], k);
              // XXXpolyvec_auto (subv2, subv);

              /* o(s1)^T*o(Es)^T*Es*s1 */
              for (j = 0; j < m1; j++)
                {
                  polymat_get_col (subv, Es[i], j);
                  _diag (&row, &col, 2 * k + 1, 2 * j);
                  poly = spolymat_insert_elem (R2t, row, col);
                  polyvec_dot (poly, subv2, subv);
                }

              /* o(s1)^T*o(Es)^T*Em*m */
              if (Em != NULL && Em[i] != NULL)
                {
                  for (j = 0; j < l; j++)
                    {
                      polymat_get_col (subv, Em[i], j);
                      _diag (&row, &col, 2 * k + 1, 2 * (m1 + Z + j));
                      poly = spolymat_insert_elem (R2t, row, col);
                      polyvec_dot (poly, subv2, subv);
                    }
                }

              /* o(s1)^T*o(Es)^T*v */
              if (v != NULL && v[i] != NULL)
                {
                  poly = spolyvec_insert_elem (r1t, 2 * k + 1);
                  polyvec_dot (poly, subv2, v[i]);
                }
            }
        }

      if (Em != NULL && Em[i] != NULL)
        {
          for (k = 0; k < l; k++)
            {
              polymat_get_col (subv, Em[i], k);
              polymat_get_col (subv2, oEm[i], k);
              // XXXpolyvec_auto (subv2, subv);

              if (Es != NULL && Es[i] != NULL)
                {
                  /* o(m)^T*o(Em)^T*Es*s1 */
                  for (j = 0; j < m1; j++)
                    {
                      polymat_get_col (subv, Es[i], j);
                      _diag (&row, &col, 2 * (m1 + Z + k) + 1, 2 * j);
                      poly = spolymat_insert_elem (R2t, row, col);
                      polyvec_dot (poly, subv2, subv);
                    }
                }

              /* o(m)^T*o(Em)^T*Em*m */
              for (j = 0; j < l; j++)
                {
                  polymat_get_col (subv, Em[i], j);
                  _diag (&row, &col, 2 * (m1 + Z + k) + 1, 2 * (m1 + Z + j));
                  poly = spolymat_insert_elem (R2t, row, col);
                  polyvec_dot (poly, subv2, subv);
                }

              /* o(m)^T*o(Em)^T*v */
              if (v != NULL && v[i] != NULL)
                {
                  poly = spolyvec_insert_elem (r1t, 2 * (m1 + Z + k) + 1);
                  polyvec_dot (poly, subv2, v[i]);
                }
            }
        }

      if (v != NULL && v[i] != NULL)
        {
          // XXXpolyvec_auto (subv2, v[i]);

          if (Es != NULL && Es[i] != NULL)
            {
              /* o(v)^T*Es*s1 */
              polyvec_get_subvec (subv, tmp_polyvec3, 0, m1, 1);
              polyvec_mul2 (subv, ov[i], Es[i]);
              // XXXpolyvec_mul2 (subv, subv2, Es[i]);

              _VEC_FOREACH_ELEM (subv, j)
              {
                poly = polyvec_get_elem (subv, j);
                poly2 = spolyvec_insert_elem (r1t, 0 + 2 * j);
                poly_set (poly2, poly);
              }
            }

          if (Em != NULL && Em[i] != NULL)
            {
              /* o(v)^T*Em*m */
              polyvec_get_subvec (subv, tmp_polyvec3, 0, l, 1);
              polyvec_mul2 (subv, ov[i], Em[i]);
              // XXXpolyvec_mul2 (subv, subv2, Em[i]);

              _VEC_FOREACH_ELEM (subv, j)
              {
                poly = polyvec_get_elem (subv, j);
                poly2 = spolyvec_insert_elem (r1t, 2 * (m1 + Z) + 2 * j);
                poly_set (poly2, poly);
              }
            }
        }

      /* o(bin(Bi^2))*upsiloni */
      poly = spolyvec_insert_elem (r1t, 2 * (m1 + i));
      int_binexp (NULL, poly, params->l2Bsqr[i]);
      poly_auto_self (poly);

      // XXXspolyvec_fromcrt (r1t);
      spolyvec_sort (r1t); // compute already sorted
      // XXXspolymat_fromcrt (R2t);
      spolymat_sort (R2t); // compute already sorted
      ASSERT_ERR (spolymat_is_upperdiag (R2t));

      R2tptr[0] = R2t;
      r1tptr[0] = r1t;
      r0tptr[0] = r0t;

      __schwartz_zippel_accumulate2 (R2i, r1i, r0i, R2i2, r1i2, r0i2, R2tptr,
                                     r1tptr, r0tptr, 1, seed, dom,
                                     params->quad_eval);
    }

  polyvec_free (tmp_polyvec);
  polyvec_free (tmp_polyvec3);
}

static void
__schwartz_zippel_accumulate_z4 (spolymat_ptr R2i[], spolyvec_ptr r1i[],
                                 poly_ptr r0i[], spolymat_ptr R2i2[],
                                 spolyvec_ptr r1i2[], poly_ptr r0i2[],
                                 spolymat_ptr R2t, spolyvec_ptr r1t,
                                 poly_ptr r0t, polymat_t Ds, polymat_t Dm,
                                 polyvec_t u, polymat_t oDs, polymat_t oDm,
                                 polyvec_t z4, const uint8_t seed[32],
                                 uint32_t dom, const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int d = Rq->d;
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int l = tbox->l;
  const unsigned int nex = params->nex;
  const unsigned int nprime = params->nprime;
  const unsigned int loff3 = (nex > 0 ? 256 / d : 0);
  const unsigned int loff4 = (nprime > 0 ? 256 / d : 0);
  const unsigned int loff = loff3 + loff4;
  const unsigned int ibeta = (m1 + Z + l + loff) * 2; // XXX correct
  const unsigned int is1 = 0;
  const unsigned int im = (m1 + Z) * 2;
  const unsigned int iy4 = (m1 + Z + l + loff3) * 2; // XXX correct
  unsigned int i, j, k;
  int8_t Rprimei[nprime * d];
  const unsigned int lambda = params->quad_eval->lambda;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];
  int_ptr chal, acc;
  polymat_t vRDs, vRDm, vRpol;
  polyvec_t subv1, subv2;
  int_ptr coeff1, coeff2;
  poly_ptr poly, poly2, poly3;
  int_srcptr inv2 = Rq->inv2;
  intvec_t row1;

  INT_T (tmp, 2 * Rq->q->nlimbs);
  INTVEC_T (u_, nprime * d, Rq->q->nlimbs);
  INTVEC_T (z4_, 256, Rq->q->nlimbs);
  INTMAT_T (V, lambda, 256, Rq->q->nlimbs);
  INTMAT_T (vR_, lambda, nprime * d, Rq->q->nlimbs);
  INTMAT_T (vR, lambda, nprime * d, 2 * Rq->q->nlimbs);
  INTVEC_T (vRu, lambda, 2 * Rq->q->nlimbs);
  intmat_urandom (V, q, log2q, seed, dom);

  polymat_alloc (vRpol, Rq, lambda, nprime);
  polymat_alloc (vRDs, Rq, lambda, m1);
  if (l > 0)
    polymat_alloc (vRDm, Rq, lambda, l);

  // eval eqs in s1,o(s1),m,o(m),y4,o(y4),beta,o(beta) (approx. range proof
  // inf) prove z4 = y4 + beta4*Rprime*s4 over int vec of dim 256
  //       y4 - z4 + beta4*Rprime*s4 = 0
  //       y4 - z4 + beta4*Rprime*(Ds*s1+Dm*m+u) = 0  # view Ds resp Dm as int
  //       rotation matrices in Z^(d*nprimexd*m1) resp Z^(d*nprimexd*l)
  //   (Ds*s1+Dm*m+u is small, but Ds*s1, Dm*m, u do not need to be ..., so the
  //   below holds mod q)
  //       y4 - z4 + beta4*(Rprime*Ds)*s1 + beta4*(Rprime*Dm)*m +
  //       beta4*(Rprime*u) = 0
  // for i in 0,...,255
  //       y4i - z4i + beta4*(Rprime*Ds)i*s1 + beta4*(Rprime*Dm)i*m +
  //       beta4*(Rprime*u)i = 0
  // terms: R2: 2m1+2l, r1: 3, r0: 1 | * 256

  // compute vR=v*Rprime
  // then vR*Ds, vR*Dm, vR*u

  for (i = 0; i < loff4; i++)
    {
      poly = polyvec_get_elem (z4, i);
      for (j = 0; j < d; j++)
        {
          coeff1 = poly_get_coeff (poly, j);
          coeff2 = intvec_get_elem (z4_, i * d + j);
          int_set (coeff2, coeff1);
        }
    }

  intmat_set_zero (vR);

  for (i = 0; i < 256; i++)
    {
      _expand_Rprime_i (Rprimei, nprime * d, i, seed);

      for (k = 0; k < lambda; k++)
        {
          chal = intmat_get_elem (V, k, i);

          for (j = 0; j < nprime * d; j++)
            {
              if (Rprimei[j] == 0)
                {
                }
              else
                {
                  ASSERT_ERR (Rprimei[j] == 1 || Rprimei[j] == -1);

                  acc = intmat_get_elem (vR, k, j);

                  int_set (tmp, chal);
                  int_mul_sgn_self (tmp, Rprimei[j]);
                  int_add (acc, acc, tmp);
                }
            }
        }
    }

  _MAT_FOREACH_ELEM (vR, i, j)
  {
    coeff1 = intmat_get_elem (vR, i, j);
    coeff2 = intmat_get_elem (vR_, i, j); // XXX correct
    int_mod (coeff2, coeff1, q);
  }

  if (u != NULL)
    {
      for (k = 0; k < nprime; k++)
        {
          intvec_get_subvec (row1, u_, d * k, d, 1);
          poly = polyvec_get_elem (u, k);
          intvec_set (row1, poly_get_coeffvec (poly));
        }
      for (k = 0; k < lambda; k++)
        {
          intmat_get_row (row1, vR_, k);
          coeff1 = intvec_get_elem (vRu, k); // XXX correct
          intvec_dot (coeff1, row1, u_);
        }
    }
#if 0
  int32_t RPRIME[nprime * d * 256];
  INTMAT_T (Rprime, 256, nprime * d, 1);
  for (i = 0; i < 256; i++)
    {
      _expand_Rprime_i (Rprimei, nprime * d, i, seed);
      for (j = 0; j < nprime * d; j++)
        RPRIME[i * (nprime * d) + j] = Rprimei[j];
    }
  intmat_set_i32 (Rprime, RPRIME);
  intmat_dump (Rprime);
  //intmat_dump (V);
  //intmat_dump (vR);
#endif

  for (k = 0; k < lambda; k++)
    {
      for (i = 0; i < nprime; i++)
        {
          poly = polymat_get_elem (vRpol, k, i);
          for (j = 0; j < d; j++)
            {
              coeff1 = intmat_get_elem (vR_, k, i * d + j);
              coeff2 = poly_get_coeff (poly, j);

              int_set (coeff2, coeff1);
            }
        }
    }

  if (Ds != NULL)
    {
      // XXXpolymat_get_submat (subm, mat, 0, 0, nprime, m1, 1, 1);
      // XXXpolymat_auto (subm, Ds);

      for (k = 0; k < lambda; k++)
        {
          polymat_get_row (subv1, vRpol, k);
          polymat_get_row (subv2, vRDs, k); // correct

          polyvec_mul2 (subv2, subv1, oDs);
        }

      polymat_lrot (vRDs, vRDs, d / 2); // * X^(d/2)  XXX correct
    }

  if (l > 0 && Dm != NULL)
    {
      // XXXpolymat_get_submat (subm, mat, 0, 0, nprime, l, 1, 1);
      // XXXpolymat_auto (subm, Dm);

      for (k = 0; k < lambda; k++)
        {
          polymat_get_row (subv1, vRpol, k);
          polymat_get_row (subv2, vRDm, k); // correct

          polyvec_mul2 (subv2, subv1, oDm);
        }

      polymat_lrot (vRDm, vRDm, d / 2); // * X^(d/2)  XXX correct
    }

  for (k = 0; k < lambda; k++)
    {

      spolymat_set_empty (R2t);
      spolyvec_set_empty (r1t);
      poly_set_zero (r0t);

      R2tptr[0] = R2t;

      if (Ds != NULL)
        {
          for (i = 0; i < m1; i++)
            {
              poly = spolymat_insert_elem (R2t, is1 + 1 + 2 * i, ibeta);
              poly2 = spolymat_insert_elem (R2t, is1 + 1 + 2 * i, ibeta + 1);

              poly3 = polymat_get_elem (vRDs, k, i);
              poly_scale (poly2, inv2, poly3);
              poly_neg (poly, poly2);
              poly_redc (poly, poly);
            }
        }
      if (l > 0 && Dm != NULL)
        {
          for (i = 0; i < l; i++)
            {
              poly = spolymat_insert_elem (R2t, im + 1 + 2 * i, ibeta);
              poly2 = spolymat_insert_elem (R2t, im + 1 + 2 * i, ibeta + 1);

              poly3 = polymat_get_elem (vRDm, k, i);
              poly_scale (poly2, inv2, poly3);
              poly_neg (poly, poly2);
              poly_redc (poly, poly);
            }
        }

      R2t->sorted = 1;

      r1tptr[0] = r1t;

      for (i = 0; i < loff4; i++)
        {
          poly = spolyvec_insert_elem (r1t, iy4 + 1 + 2 * i);
          for (j = 0; j < d; j++)
            {
              coeff1 = poly_get_coeff (poly, j);
              coeff2 = intmat_get_elem (V, k, i * d + j);
              int_set (coeff1, coeff2);
              int_redc (coeff1, coeff1, q);
            }
        }

      if (u != NULL)
        {
          poly = spolyvec_insert_elem (r1t, ibeta);
          poly2 = spolyvec_insert_elem (r1t, ibeta + 1);

          poly_set_zero (poly2);
          coeff1 = poly_get_coeff (poly2, d / 2);
          coeff2 = intvec_get_elem (vRu, k);
          int_mod (coeff1, coeff2, q);
          int_mul (tmp, inv2, coeff1);
          int_mod (coeff1, tmp, q);
          int_redc (coeff1, coeff1, q);

          poly_set_zero (poly);
          coeff2 = poly_get_coeff (poly, d / 2);
          int_neg (coeff2, coeff1);
          int_redc (coeff2, coeff2, q);
        }

      r1t->sorted = 1;

      r0tptr[0] = r0t;

      poly_set_zero (r0t); // correct

      intmat_get_row (row1, V, k);
      intvec_dot (tmp, z4_, row1);
      coeff1 = poly_get_coeff (r0t, 0);
      int_mod (coeff1, tmp, q);
      int_neg_self (coeff1);
      int_redc (coeff1, coeff1, q);

      if (k % 2 == 0)
        __schwartz_zippel_accumulate_ (R2i[k / 2], r1i[k / 2], r0i[k / 2],
                                       R2tptr, r1tptr, r0tptr, 1,
                                       params->quad_eval);
      else
        __schwartz_zippel_accumulate_ (R2i2[k / 2], r1i2[k / 2], r0i2[k / 2],
                                       R2tptr, r1tptr, r0tptr, 1,
                                       params->quad_eval);
    }

  polymat_free (vRDs);
  if (l > 0)
    polymat_free (vRDm);
  polymat_free (vRpol);
}

static void
__schwartz_zippel_accumulate_z3 (
    spolymat_ptr R2i[], spolyvec_ptr r1i[], poly_ptr r0i[],
    spolymat_ptr R2i2[], spolyvec_ptr r1i2[], poly_ptr r0i2[],
    spolymat_ptr R2t, spolyvec_ptr r1t, poly_ptr r0t, polymat_ptr Es[],
    polymat_ptr Em[], polyvec_ptr v[], polymat_ptr oEs[], polymat_ptr oEm[],
    polymat_t Ps, polymat_t Pm, polyvec_t f, polymat_t oPs, polymat_t oPm,
    polyvec_t z3, const uint8_t seed[32], uint32_t dom,
    const lnp_tbox_params_t params)
{
  abdlop_params_srcptr tbox = params->tbox;
  polyring_srcptr Rq = tbox->ring;
  int_srcptr q = Rq->q;
  const unsigned int log2q = polyring_get_log2q (Rq);
  const unsigned int d = Rq->d;
  const unsigned int Z = params->Z;
  const unsigned int m1 = tbox->m1 - Z;
  const unsigned int l = tbox->l;
  const unsigned int *ni = params->n;
  const unsigned int nex = params->nex;
  const unsigned int nprime = params->nprime;
  const unsigned int nbin = params->nbin;
  const unsigned int loff3 = (nex > 0 ? 256 / d : 0);
  const unsigned int loff4 = (nprime > 0 ? 256 / d : 0);
  const unsigned int loff = loff3 + loff4;
  const unsigned int iupsilon = (m1) * 2;
  const unsigned int ibeta = (m1 + Z + l + loff) * 2; // XXX correct
  const unsigned int is1 = 0;
  const unsigned int im = (m1 + Z) * 2;
  const unsigned int iy3 = (m1 + Z + l) * 2;
  unsigned int i, j, k, off;
  int8_t Ri[nex * d];
  const unsigned int lambda = params->quad_eval->lambda;
  spolymat_ptr R2tptr[1];
  spolyvec_ptr r1tptr[1];
  poly_ptr r0tptr[1];
  int_ptr chal, acc;
  polymat_t vRPs, vRPm, vRpol;
  polyvec_t subv1, subv2;
  int_ptr coeff1, coeff2;
  poly_ptr poly, poly2, poly3;
  int_srcptr inv2 = Rq->inv2;
  intvec_t row1, row2;
  polymat_ptr vREsi[Z];
  polymat_ptr vREmi[Z];
  intvec_ptr vRvi[Z];
  intvec_ptr vi_[Z];

  // printf ("u:\n");
  // polyvec_dump (u);
  // printf ("z3:\n");
  // polyvec_dump (z3);

  INT_T (tmp0, Rq->q->nlimbs);
  INT_T (tmp, 2 * Rq->q->nlimbs);
  INT_T (acc_, 2 * Rq->q->nlimbs);
  INTVEC_T (f_, nbin * d, Rq->q->nlimbs);
  INTVEC_T (z3_, 256, Rq->q->nlimbs);
  INTMAT_T (V, lambda, 256, Rq->q->nlimbs);
  INTMAT_T (vR_, lambda, nex * d, Rq->q->nlimbs);
  INTMAT_T (vR, lambda, nex * d, 2 * Rq->q->nlimbs);
  INTVEC_T (vRf, lambda, 2 * Rq->q->nlimbs);
  intmat_urandom (V, q, log2q, seed, dom);

  // printf ("V:\n");
  // intmat_dump (V);

  polymat_alloc (vRpol, Rq, lambda, nex);
  polymat_alloc (vRPs, Rq, lambda, m1);
  if (l > 0)
    polymat_alloc (vRPm, Rq, lambda, l);

  for (i = 0; i < Z; i++)
    {
      if (Es != NULL && Es[i] != NULL)
        {
          vREsi[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (vREsi[i], Rq, lambda, m1);
        }
      if (l > 0 && Em != NULL && Em[i] != NULL)
        {
          vREmi[i] = _alloc (sizeof (polymat_t));
          polymat_alloc (vREmi[i], Rq, lambda, l);
        }
      if (v != NULL && v[i] != NULL)
        {
          vRvi[i] = _alloc (sizeof (intvec_t));
          intvec_alloc (vRvi[i], lambda, 2 * Rq->q->nlimbs);
          vi_[i] = _alloc (sizeof (intvec_t));
          intvec_alloc (vi_[i], ni[i] * d, Rq->q->nlimbs);
        }
    }

  // eval eqs in s1,o(s1),m,o(m),y3,o(y3),beta,o(beta) (approx. range proof l2)
  // terms: R2: 2s1+2l+2Z, r1: 3, r0: 1 | * 256

  for (i = 0; i < loff3; i++)
    {
      poly = polyvec_get_elem (z3, i);
      for (j = 0; j < d; j++)
        {
          coeff1 = poly_get_coeff (poly, j);
          coeff2 = intvec_get_elem (z3_, i * d + j);
          int_set (coeff2, coeff1);
        }
    }

  intmat_set_zero (vR);

  for (i = 0; i < 256; i++)
    {
      _expand_R_i (Ri, nex * d, i, seed);

      for (k = 0; k < lambda; k++)
        {
          chal = intmat_get_elem (V, k, i);

          for (j = 0; j < nex * d; j++)
            {
              if (Ri[j] == 0)
                {
                }
              else
                {
                  ASSERT_ERR (Ri[j] == 1 || Ri[j] == -1);

                  acc = intmat_get_elem (vR, k, j);

                  int_set (tmp, chal);
                  int_mul_sgn_self (tmp, Ri[j]);
                  int_add (acc, acc, tmp);
                }
            }
        }
    }

  _MAT_FOREACH_ELEM (vR, i, j)
  {
    coeff1 = intmat_get_elem (vR, i, j);
    coeff2 = intmat_get_elem (vR_, i, j); // XXX correct
    int_mod (coeff2, coeff1, q);
  }

  if (f != NULL)
    {
      for (k = 0; k < nbin; k++)
        {
          intvec_get_subvec (row1, f_, d * k, d, 1);
          poly = polyvec_get_elem (f, k);
          intvec_set (row1, poly_get_coeffvec (poly));
        }
    }
  for (i = 0; i < Z; i++)
    {
      if (v != NULL && v[i] != NULL)
        {
          for (k = 0; k < ni[i]; k++)
            {
              intvec_get_subvec (row1, vi_[i], d * k, d, 1);
              poly = polyvec_get_elem (v[i], k);
              intvec_set (row1, poly_get_coeffvec (poly));
            }
        }
    }

  for (k = 0; k < lambda; k++)
    {
      intmat_get_row (row1, vR_, k);
      off = 0;

      if (f != NULL)
        {
          intvec_get_subvec (row2, row1, off, nbin * d, 1);
          coeff1 = intvec_get_elem (vRf, k); // XXX correct
          intvec_dot (coeff1, row2, f_);
        }
      off += nbin * d;

      for (i = 0; i < Z; i++)
        {
          if (v != NULL && v[i] != NULL)
            {
              intvec_get_subvec (row2, row1, off, ni[i] * d, 1);
              coeff1 = intvec_get_elem (vRvi[i], k);
              intvec_dot (coeff1, row2, vi_[i]);
            }
          off += ni[i] * d;
        }
    }

#if 0
  int32_t RPRIME[nex * d * 256];
  INTMAT_T (Rprime, 256, nex * d, 1);
  for (i = 0; i < 256; i++)
    {
      _expand_i (Rprimei, nex * d, i, seed);
      for (j = 0; j < nex * d; j++)
        RPRIME[i * (nex * d) + j] = Rprimei[j];
    }
  intmat_set_i32 (Rprime, RPRIME);
  intmat_dump (Rprime);
  //intmat_dump (V);
  //intmat_dump (vR);
#endif

  for (k = 0; k < lambda; k++)
    {
      for (i = 0; i < nex; i++)
        {
          poly = polymat_get_elem (vRpol, k, i);
          for (j = 0; j < d; j++)
            {
              coeff1 = intmat_get_elem (vR_, k, i * d + j);
              coeff2 = poly_get_coeff (poly, j);

              int_set (coeff2, coeff1);
            }
        }
    }

  if (Ps != NULL)
    {
      // XXXpolymat_get_submat (subm, mat, 0, 0, nbin, m1, 1, 1);
      // XXXpolymat_auto (subm, Ps);

      for (k = 0; k < lambda; k++)
        {
          polymat_get_row (subv1, vRpol, k);
          polyvec_get_subvec (subv1, subv1, 0, nbin, 1);
          polymat_get_row (subv2, vRPs, k); // correct

          polyvec_mul2 (subv2, subv1, oPs);
        }
    }

  if (l > 0 && Pm != NULL)
    {
      // XXXpolymat_get_submat (subm, mat, 0, 0, nbin, l, 1, 1);
      // XXXpolymat_auto (subm, Pm);

      for (k = 0; k < lambda; k++)
        {
          polymat_get_row (subv1, vRpol, k);
          polyvec_get_subvec (subv1, subv1, 0, nbin, 1);
          polymat_get_row (subv2, vRPm, k); // correct

          polyvec_mul2 (subv2, subv1, oPm);
        }
    }

  off = nbin;
  for (i = 0; i < Z; i++)
    {
      if (Es != NULL && Es[i] != NULL)
        {
          // XXXpolymat_get_submat (subm, mat, 0, 0, ni[i], m1, 1, 1);
          // XXXpolymat_auto (subm, Es[i]);

          for (k = 0; k < lambda; k++)
            {
              polymat_get_row (subv1, vRpol, k);
              polyvec_get_subvec (subv1, subv1, off, ni[i], 1);
              polymat_get_row (subv2, vREsi[i], k);

              // XXXpolyvec_mul2 (subv2, subv1, subm);
              polyvec_mul2 (subv2, subv1, oEs[i]);
            }
        }
      off += ni[i];
    }

  off = nbin;
  for (i = 0; i < Z; i++)
    {
      if (l > 0 && Em != NULL && Em[i] != NULL)
        {
          // XXXpolymat_get_submat (subm, mat, 0, 0, ni[i], l, 1, 1);
          // XXXpolymat_auto (subm, Em[i]);

          for (k = 0; k < lambda; k++)
            {
              polymat_get_row (subv1, vRpol, k);
              polyvec_get_subvec (subv1, subv1, off, ni[i], 1);
              polymat_get_row (subv2, vREmi[i], k);

              // XXXpolyvec_mul2 (subv2, subv1, subm);
              polyvec_mul2 (subv2, subv1, oEm[i]);
            }
        }
      off += ni[i];
    }

  // printf ("vRPs:\n");
  // polymat_dump (vRPs);
  // printf ("vRPm:\n");
  // polymat_dump (vRPm);

  for (k = 0; k < lambda; k++)
    {

      spolymat_set_empty (R2t);
      spolyvec_set_empty (r1t);
      poly_set_zero (r0t);

      R2tptr[0] = R2t;

      for (i = 0; i < m1; i++)
        {
          poly = spolymat_insert_elem (R2t, is1 + 1 + 2 * i, ibeta);
          poly2 = spolymat_insert_elem (R2t, is1 + 1 + 2 * i, ibeta + 1);

          if (Ps != NULL)
            {
              poly3 = polymat_get_elem (vRPs, k, i);
              poly_set (poly2, poly3);
            }
          else
            {
              poly_set_zero (poly2);
            }
          for (j = 0; j < Z; j++)
            {
              if (Es != NULL && Es[j] != NULL)
                {
                  poly3 = polymat_get_elem (vREsi[j], k, i);
                  poly_add (poly2, poly2, poly3, 0);
                }
            }

          poly_scale (poly2, inv2, poly2);
          poly_set (poly, poly2);
        }

      for (i = 0; i < Z; i++)
        {
          poly = spolymat_insert_elem (R2t, iupsilon + 1 + 2 * i, ibeta);
          poly2 = spolymat_insert_elem (R2t, iupsilon + 1 + 2 * i, ibeta + 1);

          poly3 = polymat_get_elem (vRpol, k, nex - Z + i);
          poly_scale (poly2, inv2, poly3);
          poly_set (poly, poly2);
        }

      for (i = 0; i < l; i++)
        {
          poly = spolymat_insert_elem (R2t, im + 1 + 2 * i, ibeta);
          poly2 = spolymat_insert_elem (R2t, im + 1 + 2 * i, ibeta + 1);

          if (l > 0 && Pm != NULL)
            {
              poly3 = polymat_get_elem (vRPm, k, i);
              poly_set (poly2, poly3);
            }
          else
            {
              poly_set_zero (poly2);
            }
          for (j = 0; j < Z; j++)
            {
              if (l > 0 && Em != NULL && Em[j] != NULL)
                {
                  poly3 = polymat_get_elem (vREmi[j], k, i);
                  poly_add (poly2, poly2, poly3, 0);
                }
            }

          poly_scale (poly2, inv2, poly2);
          poly_set (poly, poly2);
        }

      R2t->sorted = 1;

      // printf ("R2:\n");
      // spolymat_dump (R2t);

      r1tptr[0] = r1t;

      for (i = 0; i < loff4; i++)
        {
          poly = spolyvec_insert_elem (r1t, iy3 + 1 + 2 * i);
          for (j = 0; j < d; j++)
            {
              coeff1 = poly_get_coeff (poly, j);
              coeff2 = intmat_get_elem (V, k, i * d + j);
              int_set (coeff1, coeff2);
              int_redc (coeff1, coeff1, q);
            }
        }

      poly = spolyvec_insert_elem (r1t, ibeta);
      poly2 = spolyvec_insert_elem (r1t, ibeta + 1);
      poly_set_zero (poly2);
      poly_set_zero (poly);

      int_set_zero (acc_);

      if (f != NULL)
        {
          coeff2 = intvec_get_elem (vRf, k);
          int_mod (tmp0, coeff2, q);
          int_set (tmp, tmp0);
          int_add (acc_, acc_, tmp);
        }

      for (i = 0; i < Z; i++)
        {
          if (v != NULL && v[i] != NULL)
            {
              coeff2 = intvec_get_elem (vRvi[i], k);
              int_mod (tmp0, coeff2, q);
              int_set (tmp, tmp0);
              int_add (acc_, acc_, tmp);
            }
        }

      int_mod (tmp0, acc_, q);
      int_mul (tmp, inv2, tmp0);
      int_mod (tmp0, tmp, q);
      int_redc (tmp0, tmp0, q);
      coeff1 = poly_get_coeff (poly2, 0);
      coeff2 = poly_get_coeff (poly, 0);
      int_set (coeff1, tmp0);
      int_set (coeff2, tmp0);

      // printf ("r1:\n");
      // spolyvec_dump (r1t);

      r1t->sorted = 1;

      r0tptr[0] = r0t;

      poly_set_zero (r0t); // correct

      intmat_get_row (row1, V, k);
      intvec_dot (tmp, z3_, row1);
      coeff1 = poly_get_coeff (r0t, 0);
      int_mod (coeff1, tmp, q);
      int_neg_self (coeff1);
      int_redc (coeff1, coeff1, q);

      // printf ("r0:\n");
      // poly_dump (r0t);

#if 1
      if (k % 2 == 0)
        __schwartz_zippel_accumulate_ (R2i[k / 2], r1i[k / 2], r0i[k / 2],
                                       R2tptr, r1tptr, r0tptr, 1,
                                       params->quad_eval);
      else
        __schwartz_zippel_accumulate_ (R2i2[k / 2], r1i2[k / 2], r0i2[k / 2],
                                       R2tptr, r1tptr, r0tptr, 1,
                                       params->quad_eval);
#endif
    }

  polymat_free (vRPs);
  if (l > 0)
    polymat_free (vRPm);
  polymat_free (vRpol);
  for (i = 0; i < Z; i++)
    {
      if (Es != NULL && Es[i] != NULL)
        {
          polymat_free (vREsi[i]);
          _free (vREsi[i], sizeof (polymat_t));
        }
      if (l > 0 && Em != NULL && Em[i] != NULL)
        {
          polymat_free (vREmi[i]);
          _free (vREmi[i], sizeof (polymat_t));
        }
      if (v != NULL && v[i] != NULL)
        {
          intvec_free (vRvi[i]);
          _free (vRvi[i], sizeof (intvec_t));
          intvec_free (vi_[i]);
          _free (vi_[i], sizeof (intvec_t));
        }
    }
}
