#include "brandom.h"
#include "grandom.h"
#include "lazer.h"
#include "memory.h"
#include "urandom.h"

#include <gmp.h>
#include <string.h>

void
int_alloc (int_ptr r, unsigned int nlimbs)
{
  void *mem;

  mem = _alloc (_sizeof_int_data (nlimbs));

  _int_init (r, nlimbs, mem);
}

void
int_free (int_ptr r)
{
  if (r == NULL)
    return;

  _free (r->limbs, _sizeof_int_data (r->nlimbs));
}

void
int_mul (int_t r, const int_t a, const int_t b)
{
  limb_t scratch[mpn_sec_mul_itch (a->nlimbs, b->nlimbs)];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  mpn_sec_mul (r->limbs, a->limbs, a->nlimbs, b->limbs, b->nlimbs, scratch);
  r->neg = a->neg ^ b->neg;
}

void
int_sqr (int_t r, const int_t a)
{
  limb_t scratch[mpn_sec_sqr_itch (a->nlimbs)];

  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  mpn_sec_sqr (r->limbs, a->limbs, a->nlimbs, scratch);
  r->neg = 0;
}

void
int_addmul (int_t r, const int_t a, const int_t b)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_mul (tmp, a, b);
  int_add (r, r, tmp);
}

void
int_submul (int_t r, const int_t a, const int_t b)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_mul (tmp, a, b);
  int_sub (r, r, tmp);
}

void
int_addsqr (int_t r, const int_t a)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_sqr (tmp, a);
  int_add (r, r, tmp);
}

void
int_subsqr (int_t r, const int_t a)
{
  INT_T (tmp, r->nlimbs);

  ASSERT_ERR (r->nlimbs == 2 * a->nlimbs);

  int_sqr (tmp, a);
  int_sub (r, r, tmp);
}

/* divisor non-secret */
void
int_div (int_t rq, int_t rr, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], r;
  unsigned int bnlimbs;

  for (bnlimbs = b->nlimbs; b->limbs[bnlimbs - 1] == 0; bnlimbs--)
    ;

  ASSERT_ERR (bnlimbs >= 1);
  ASSERT_ERR (a->nlimbs >= bnlimbs);
  ASSERT_ERR (rr->nlimbs == bnlimbs);
  ASSERT_ERR (rq->nlimbs == a->nlimbs - bnlimbs + 1);

  limbs_cpy (_a, a->limbs, a->nlimbs);
  {
    limb_t scratch[mpn_sec_div_qr_itch (a->nlimbs, bnlimbs)];

    r = mpn_sec_div_qr (rq->limbs, _a, a->nlimbs, b->limbs, bnlimbs, scratch);
  }
  rq->limbs[rq->nlimbs - 1] = r;
  limbs_cpy (rr->limbs, _a, bnlimbs);

  rq->neg = a->neg ^ b->neg;
  rr->neg = rq->neg;
}

/* [-(m-1),...,(m-1)] -> [0,...,m-1] */
void
int_redp (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_cpy (r->limbs, a->limbs, a->nlimbs);
  limbs_sub (tmp, m->limbs, a->limbs, 0, a->nlimbs);

  b = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs)); /* neg.zero! */
  limbs_cnd_select (r->limbs, r->limbs, tmp, r->nlimbs, b);
  r->neg = 0;
}

/* result in [-(m-1),...,m-1] */
void
int_mod (int_t r, const int_t a, const int_t m)
{
  ASSERT_ERR (r->nlimbs == m->nlimbs);
  ASSERT_ERR (m->limbs);

  if (m->nlimbs == 1)
    {
      const crtcoeff_t mod = (crtcoeff_t)m->limbs[0];
      crtcoeff_t x = int_mod_XXX (a, mod);
      int_set_i64 (r, x);
    }
  else
    {
      /* mpn_sec_div_r needs the divisor's most significant limb to be
       * non-zero: drop m's leading zero limbs (m may be stored with more
       * limbs than it needs, e.g. with those of q). */
      unsigned int dn = m->nlimbs;
      while (dn > 1 && m->limbs[dn - 1] == 0)
        dn--;
      limb_t scratch[mpn_sec_div_r_itch (a->nlimbs, dn)];
      limb_t tmp[a->nlimbs];

      limbs_cpy (tmp, a->limbs, a->nlimbs);
      mpn_sec_div_r (tmp, a->nlimbs, m->limbs, dn, scratch);
      memset (r->limbs, 0, r->nlimbs * sizeof (limb_t));
      limbs_cpy (r->limbs, tmp, dn);
      r->neg = a->neg;
    }
}

/* result in [-(m-1),...,m-1] */
void
int_invmod (int_t r, const int_t a, const int_t m)
{
  const size_t itchlen = mpn_sec_invert_itch (r->nlimbs);
  limb_t itch[itchlen], _a[a->nlimbs];

  ASSERT_ERR (r->nlimbs == m->nlimbs);
  ASSERT_ERR (a->nlimbs == m->nlimbs);

  /* mpn_sec_invert destroys second operand. */
  limbs_cpy (_a, a->limbs, a->nlimbs);

  mpn_sec_invert (r->limbs, _a, m->limbs, r->nlimbs,
                  2 * r->nlimbs * GMP_NUMB_BITS, itch);
  r->neg = a->neg;
}

/* binomial distribution */
void
int_brandom (int_t r, unsigned int k, const uint8_t seed[32],
             const uint32_t dom)
{
  int8_t z;

  _brandom (&z, 1, k, seed, dom);
  int_set_i64 (r, z);
}

/* discrete gaussian distribution */
void
int_grandom (int_t r, unsigned int log2o, const uint8_t seed[32], uint32_t dom)
{
  int32_t sample;

  if (LIKELY (log2o < 24))
    { /* XXX single precision sampler limit */
      _grandom_sample_i32 (&sample, 1, log2o, seed, dom);
      int_set_i64 (r, sample);
    }
  else
    {
      _grandom_sample (r, log2o, seed, dom);
    }
}

void
int_urandom (int_t r, const int_t mod, unsigned int log2mod,
             const uint8_t seed[32], uint32_t dom)
{
  INTVEC_T (tmp, 1, r->nlimbs);

  _urandom (tmp, mod, log2mod, seed, dom);
  int_set (r, intvec_get_elem_src (tmp, 0));
}

void
int_urandom_bnd (int_t r, const int_t lo, const int_t hi,
                 const uint8_t seed[32], uint32_t dom)

{
  INTVEC_T (tmp, 1, r->nlimbs);

  _urandom_bnd (tmp, lo, hi, seed, dom);
  int_set (r, intvec_get_elem_src (tmp, 0));
}

void
int_binexp (poly_t upsilon, poly_t powB, int_srcptr B)
{
  polyring_srcptr Rq;

  ASSERT_ERR (upsilon != NULL || powB != NULL);

  if (upsilon != NULL)
    Rq = upsilon->ring;
  else
    Rq = powB->ring;

  INT_T (pow2, Rq->q->nlimbs);
  INT_T (B_, Rq->q->nlimbs);
  int i;

  int_set (B_, B);
  if (upsilon != NULL)
    poly_set_zero (upsilon);
  if (powB != NULL)
    poly_set_zero (powB);

  for (i = Rq->log2q - 1; i >= 0; i--)
    {
      int_set_one (pow2);
      int_lshift (pow2, pow2, i);

      if (powB != NULL && int_le (pow2, B))
        int_set (poly_get_coeff (powB, i), pow2);

      if (upsilon != NULL && int_ge (B_, pow2))
        {
          int_sub (B_, B_, pow2);
          int_set_one (poly_get_coeff (upsilon, i));
        }
    }
}

void
int_clear (int_t r)
{
  const size_t nbytes = r->nlimbs * sizeof (limb_t);

  explicit_bzero (r->limbs, nbytes);
  memset (r, 0, sizeof (int_t));
}

size_t
int_out_str (FILE *stream, int base, const int_t a)
{
  int nlimbs, sign;
  mpz_t _a;

  nlimbs = int_eqzero (a) ? 0 : (int)a->nlimbs;
  sign = _neg2sign (a->neg);

  return mpz_out_str (stream, base,
                      mpz_roinit_n (_a, a->limbs, nlimbs * sign));
}

void
int_dump (int_t z)
{
  int_out_str (stdout, 10, z);
  fprintf (stdout, "\n");
  fflush (stdout);
}

size_t
int_inp_str (UNUSED int_t r, UNUSED FILE *stream, UNUSED int base)
{
  return 0;
}

/* import export twos complement ? XXX */
void
int_import (int_t r, const uint8_t *bytes, size_t nbytes)
{
  const mp_limb_t *ptr;
  size_t i;
  mpz_t z;

  mpz_init2 (z, 8 * (sizeof (mp_limb_t) + nbytes));
  mpz_import (z, nbytes, -1, 1, -1, 0, bytes);

  ptr = mpz_limbs_read (z);
  for (i = 0; i < MIN (mpz_size (z), r->nlimbs); i++)
    r->limbs[i] = ptr[i];
  r->neg = 0;

  mpz_clear (z);
}

void
int_export (uint8_t *bytes, size_t *nbytes, const int_t a)
{
  mpz_t _a;

  mpz_roinit_n (_a, a->limbs, a->nlimbs);
  mpz_export (bytes, nbytes, -1, 1, -1, 0, _a);
}
