#include "grandom.h"
#include "lazer.h"
#include "rng.h"

#include <math.h>
#include <stdint.h>

typedef struct
{
  uint64_t hi, lo;
} z128;

static const z128 CDF155[]
    = { { 10894764499197476522ULL, 10804844707381617341ULL },
        { 4761708367981796450ULL, 6209732027000382074ULL },
        { 1476784279527800432ULL, 14108379346150813303ULL },
        { 316388870594767345ULL, 17827298407763885637ULL },
        { 46043503515468600ULL, 18385899657892021654ULL },
        { 4503729779335039ULL, 3860889375818664979ULL },
        { 294122444862326ULL, 13947176349836216550ULL },
        { 12769598070895ULL, 14321894682751135119ULL },
        { 367552986472ULL, 10286761328368440884ULL },
        { 7001273393ULL, 2287787188970898528ULL },
        { 88153536ULL, 17843977990435837663ULL },
        { 733119ULL, 12174894787802692461ULL },
        { 4024ULL, 18067426722645776197ULL },
        { 14ULL, 10764017821655913055ULL },
        { 0ULL, 643125733022530080ULL },
        { 0ULL, 1014291014134832ULL },
        { 0ULL, 1055215183460ULL },
        { 0ULL, 724109373ULL },
        { 0ULL, 327744ULL },
        { 0ULL, 98ULL },
        { 0ULL, 0ULL } };

/*
 * Compute exp(x) for x in [-ln 2, 0]  
 *
 * The algorithm used below is derived from the public domain
 * library fdlibm (http://www.netlib.org/fdlibm/e_exp.c).
 *
 */
static inline double
exp_small (double x)
{
#define C1 ( 1.66666666666666657415e-01)
#define C2 (-2.77777777777722060387e-03)
#define C3 ( 6.61375660702744565646e-05)
#define C4 (-1.65343769616898187644e-06)
#define C5 ( 4.17431906195525278958e-08)
#define C6 (-1.02842107821646284274e-09)

  double t, d, y;

  t = x * x;
  t = x - t * (C1 + t * (C2 + t * (C3 + t * (C4 + t * (C5 + t * C6))))); // R1

  /* 1/(t - 2) via Newton (y <- y*(2 - d*y)) */
  d = t - 2.0;
  y = -0.4193;
  y *= 2.0 - d * y;
  y *= 2.0 - d * y;
  y *= 2.0 - d * y;
  y *= 2.0 - d * y;
  y *= 2.0 - d * y;
  t = 1.0 - (x * t * y - x); // == 1.0 - ((x * t) / (t - 2.0) - x)
  return t;

#undef C1
#undef C2
#undef C3
#undef C4
#undef C5
#undef C6
}

static inline unsigned int
cdfsampler (rng_state_t state, const z128 CDF[], unsigned int len)
{
  uint64_t buf[2], hi, lo, d;
  unsigned int z, i;
  int b0, b1, b2;

  rng_urandom (state, (unsigned char *)buf, 16);
  hi = buf[0];
  lo = buf[1];

  z = 0;
  for (i = 0; i < len; i++)
    {
      b0 = __builtin_sub_overflow (lo, CDF[i].lo, &d); // b0 = (lo < CDF[i].lo)
      b1 = __builtin_sub_overflow (hi, CDF[i].hi, &d); // b1 = (hi < CDF[i].hi) 
      b2 = __builtin_sub_overflow (d, (uint64_t)b0, &d); // d = 0 if (hi = CDF[i].hi). then, if b0 = 1, b2 = 1
      z += (unsigned int)(b1 | b2); 
    }

  return z;
}

static inline unsigned int
BerExp (rng_state_t state, double x)
{
  unsigned int b;
  uint64_t w[2], t, u;

  rng_urandom (state, (unsigned char *)w, 16);

  t = w[0];
  u = x * (1 / log (2));
  x -= log (2) * u;
  u ^= (u ^ 63) & ((int64_t)(63 - u) >> 63); /* if(u > 63) u = 63; */
  t ^= (t >> u) << u;                        /* u random bits */
  b = 1 - ((t | -t) >> 63);                  /* 1 with probability 2^-u */

  t = w[1];
  t &= (1ULL << 53) - 1;
  u = exp_small (-x) * pow (2, 53);
  b &= (t - u) >> 63; /* t < u with probability u/2^56 = e^-x */

  return b;
}

static inline int
gaussian155 (rng_state_t state, double c)
{
  static int pos = 64;
  static uint64_t bits;
  int k, b;
  double x;
  const double dss = 1 / (2 * 1.55 * 1.55);

  do
    {
      if (pos >= 64)
        {
          rng_urandom (state, (unsigned char *)&bits, 8);
          pos = 0;
        }
      b = bits & 1;
      bits >>= 1;
      pos += 1;
      k = cdfsampler (state, CDF155, sizeof (CDF155) / sizeof (CDF155[0]));
      k = (-b & (2 * k)) - k + b; // bimodal Gaussian
      x = ((k - c) * (k - c) - (k - b) * (k - b)) * dss;
    }
  while (!BerExp (state, x));

  return k;
}

#ifdef XXX
/*
 * sample centered discrete gaussian with sigma = 1.55 * 2^log2o
 */
static int64_t
_grandom_sample_i64 (unsigned int log2o, const uint8_t seed[32],
                    uint64_t dom)
{
  rng_state_t state;
  double c;
  int k;
  int64_t urandom = 0;
  const unsigned int nbytes = CEIL (log2o, 8);
  const uint8_t mask = 0xff >> ((nbytes * 8) - log2o);
  uint8_t *urandom_ptr = (uint8_t *)&urandom;

  _rng_init (state, seed, dom);

  _rng_urandom (state, urandom_ptr, nbytes);
  urandom_ptr[nbytes - 1] &= mask;
  urandom = le64toh (urandom);

  c = (double)urandom / (1 << log2o);
  k = gaussian155 (state, c);

  _rng_clear (state);

  return ((int64_t)k << log2o) - urandom;
}
#endif

/*
 * sample centered discrete gaussian with sigma = 1.55 * 2^log2o
 */
static void
_grandom_sample_i32 (int32_t *ret, unsigned int nelems, unsigned int log2o,
                    const uint8_t seed[32], uint64_t dom)
{
  rng_state_t state;

  unsigned int i, j;
  unsigned int outlen = CEIL (log2o * nelems, 8);
  uint8_t out[outlen];
  uint32_t urand;
  int32_t k;
  double c;

  _rng_init (state, seed, dom);
  _rng_urandom (state, out, outlen);

  for (i = 0; i < nelems; i++)
    {
      urand = 0;
      for (j = 0; j < log2o; j++)
        {
          const unsigned int q = (i * log2o + j) >> 3;
          const unsigned int r = (i * log2o + j) - (q << 3);

          urand |= (((out[q] & (1 << r)) >> r) << j);
        }

      c = (double)urand / (1 << log2o);
      k = gaussian155 (state, c);

      ret[i] = ((int32_t)k << log2o) - urand;
    }

  _rng_clear (state);
}

/*
 * sample centered discrete gaussian with sigma = 1.55 * 2^log2o
 */
static void
_grandom_sample (int_t z, unsigned int log2o, const uint8_t seed[32],
                uint64_t dom)
{
  INT_T (z1, z->nlimbs);
  rng_state_t state;
  double c;
  unsigned int i, m;
  int k;
  int64_t urandom = 0;
  const unsigned int nbytes = CEIL (log2o, 8);
  const uint8_t mask = 0xff >> ((nbytes * 8) - log2o);
  uint8_t *urandom_ptr = (uint8_t *)z->limbs;

  ASSERT_ERR (nbytes <= z->nlimbs * sizeof (*(z->limbs)));

  int_set_i64 (z, 0);

  _rng_init (state, seed, dom);

  _rng_urandom (state, urandom_ptr, nbytes);
  urandom_ptr[nbytes - 1] &= mask;

  /* most significant bits to double */
  urandom = 0;
  m = MIN (nbytes, 6);
  for (i = 1; i <= m; i++)
    urandom |= ((uint64_t)(urandom_ptr[nbytes - i]) << (8 * (m - i)));

  c = (double)urandom / ((uint64_t)1 << (log2o - (nbytes - m) * 8));
  k = gaussian155 (state, c);

  _rng_clear (state);

  z->neg = 1; /* substract */

  int_set_i64 (z1, k);
  int_lshift (z1, z1, log2o);
  int_add (z, z, z1);
}
