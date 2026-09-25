#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "falcon.h"
#include "inner.h"

#define FALCON1024_Q 12289
#define FALCON1024_LOGN 10
#define FALCON1024_DEG 1024
#define FALCON1024_PUBKEYLEN FALCON_PUBKEY_SIZE (FALCON1024_LOGN)
#define FALCON1024_PRIVKEYLEN FALCON_PRIVKEY_SIZE (FALCON1024_LOGN)
#define FALCON1024_TMPKGLEN FALCON_TMPSIZE_KEYGEN (FALCON1024_LOGN)

void
falcon1024_redc (int16_t c[FALCON1024_DEG])
{
  unsigned int i;

  for (i = 0; i < FALCON1024_DEG; i++)
    {
      if (c[i] > (FALCON1024_Q - 1) / 2)
        c[i] -= FALCON1024_Q;
      else if (c[i] < -(FALCON1024_Q - 1) / 2)
        c[i] += FALCON1024_Q;
    }
}

void
falcon1024_add (int16_t c[FALCON1024_DEG], const int16_t a[FALCON1024_DEG],
                const int16_t b[FALCON1024_DEG])
{
  unsigned int i;

  for (i = 0; i < FALCON1024_DEG; i++)
    c[i] = (a[i] + b[i]) % FALCON1024_Q;
}

void
falcon1024_mul (int16_t c[FALCON1024_DEG], const int16_t a[FALCON1024_DEG],
                const int16_t b[FALCON1024_DEG])
{
  int32_t t[2 * FALCON1024_DEG] = { 0 };
  unsigned int i, j;

  for (i = 0; i < FALCON1024_DEG; i++)
    for (j = 0; j < FALCON1024_DEG; j++)
      t[i + j] += (int32_t)a[i] * b[j] % FALCON1024_Q;

  for (i = 0; i < FALCON1024_DEG; i++)
    c[i] = (t[i] - t[FALCON1024_DEG + i]) % FALCON1024_Q;
}

/* generate compressed secret and public key. */
void
falcon1024_keygen (uint8_t sk[FALCON1024_PRIVKEYLEN],
                   uint8_t pk[FALCON1024_PUBKEYLEN])
{
  shake256_context rng;
  uint8_t tmpkg[FALCON1024_TMPKGLEN];
  int r;

  shake256_init_prng_from_system (&rng);

  r = falcon_keygen_make (&rng, FALCON1024_LOGN, (void *)sk,
                          FALCON1024_PRIVKEYLEN, (void *)pk,
                          FALCON1024_PUBKEYLEN, tmpkg, FALCON1024_TMPKGLEN);
  if (r != 0)
    {
      fprintf (stderr, "falcon1024 keygen failed: %d.\n", r);
      exit (EXIT_FAILURE);
    }
}

/* compressed public key to coefficient representation */
void
falcon1024_decode_pubkey (int16_t h[FALCON1024_DEG],
                          const uint8_t pk[FALCON1024_PUBKEYLEN])
{
  if (Zf (modq_decode) ((uint16_t *)h, FALCON1024_LOGN, pk + 1,
                        FALCON1024_PUBKEYLEN - 1)
      != FALCON1024_PUBKEYLEN - 1)
    {
      fprintf (stderr, "falcon1024 decoding of pubkey failed.\n");
      exit (EXIT_FAILURE);
    }
}

/* find (s1,s2) s.t.: (1,h) * (s1,s2)^T = t*/
void
falcon1024_preimage_sample (int16_t s1[FALCON1024_DEG],
                            int16_t s2[FALCON1024_DEG],
                            const int16_t t[FALCON1024_DEG],
                            const uint8_t sk[FALCON1024_PRIVKEYLEN])
{
  __attribute__ ((aligned (8))) uint8_t tmp[72 * FALCON1024_DEG];
  int8_t f[FALCON1024_DEG], g[FALCON1024_DEG], F[FALCON1024_DEG],
      G[FALCON1024_DEG];
  uint16_t h[FALCON1024_DEG], tu[FALCON1024_DEG];
  shake256_context rng;
  unsigned oldcw;
  int u, v;

  shake256_init_prng_from_system (&rng);

  /* decode private key elements */
  u = 1;
  v = Zf (trim_i8_decode) (f, FALCON1024_LOGN,
                           Zf (max_fg_bits)[FALCON1024_LOGN], sk + u,
                           FALCON1024_PRIVKEYLEN - u);
  if (v == 0)
    goto err;

  u += v;
  v = Zf (trim_i8_decode) (g, FALCON1024_LOGN,
                           Zf (max_fg_bits)[FALCON1024_LOGN], sk + u,
                           FALCON1024_PRIVKEYLEN - u);
  if (v == 0)
    goto err;

  u += v;
  v = Zf (trim_i8_decode) (F, FALCON1024_LOGN,
                           Zf (max_FG_bits)[FALCON1024_LOGN], sk + u,
                           FALCON1024_PRIVKEYLEN - u);
  if (v == 0)
    goto err;

  u += v;
  if (u != FALCON1024_PRIVKEYLEN)
    goto err;

  /* complete private key */
  if (!Zf (complete_private) (G, f, g, F, FALCON1024_LOGN, tmp))
    goto err;

  for (u = 0; u < FALCON1024_DEG; u++)
    tu[u] = (uint16_t)((t[u] % FALCON1024_Q + FALCON1024_Q) % FALCON1024_Q);

  oldcw = set_fpu_cw (2);
  Zf (sign_dyn) (s2, (inner_shake256_context *)&rng, f, g, F, G, tu,
                 FALCON1024_LOGN, tmp);
  set_fpu_cw (oldcw);

  Zf (compute_public) (h, f, g, FALCON1024_LOGN, tmp);
  Zf (to_ntt_monty) (h, FALCON1024_LOGN);
  if (!Zf (reconstruct_s1) (s1, tu, s2, h, FALCON1024_LOGN, tmp))
    goto err;

  return;
err:
  fprintf (stderr, "falcon1024 preimage sampling failed.\n");
  exit (EXIT_FAILURE);
}
