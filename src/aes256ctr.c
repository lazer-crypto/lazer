#include "aes256ctr.h"
#include "lazer.h"

#include <stdlib.h>
#include <string.h>

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_GENERIC

#if defined(__ARM_FEATURE_AES)
#include <arm_neon.h>
#endif

static inline void
incbe (uint8_t n[16])
{
  unsigned int c = 1;
  int i;

  for (i = 15; i >= 0; i--)
    {
      c += n[i];
      n[i] = c & 0xff;
      c >>= 8;
    }
}

static unsigned char
multiply (unsigned int c, unsigned int d)
{
  unsigned char f[8];
  unsigned char g[8];
  unsigned char h[15];
  unsigned char result;
  int i;
  int j;

  for (i = 0; i < 8; ++i)
    f[i] = 1 & (c >> i);
  for (i = 0; i < 8; ++i)
    g[i] = 1 & (d >> i);
  for (i = 0; i < 15; ++i)
    h[i] = 0;
  for (i = 0; i < 8; ++i)
    for (j = 0; j < 8; ++j)
      h[i + j] ^= f[i] & g[j];

  for (i = 6; i >= 0; --i)
    {
      h[i + 0] ^= h[i + 8];
      h[i + 1] ^= h[i + 8];
      h[i + 3] ^= h[i + 8];
      h[i + 4] ^= h[i + 8];
      h[i + 8] ^= h[i + 8];
    }

  result = 0;
  for (i = 0; i < 8; ++i)
    result |= h[i] << i;
  return result;
}

static unsigned char
square (unsigned char c)
{
  return multiply (c, c);
}

static unsigned char
xtime (unsigned char c)
{
  return multiply (c, 2);
}

static unsigned char
bytesub (unsigned char c)
{
#if defined(__ARM_FEATURE_AES)
  /* vaeseq with a zero key on a splatted byte is SubBytes (ShiftRows
     is a no-op on equal bytes). */
  return vgetq_lane_u8 (vaeseq_u8 (vdupq_n_u8 (c), vdupq_n_u8 (0)), 0);
#else
  unsigned char c3 = multiply (square (c), c);
  unsigned char c7 = multiply (square (c3), c);
  unsigned char c63 = multiply (square (square (square (c7))), c7);
  unsigned char c127 = multiply (square (c63), c);
  unsigned char c254 = square (c127);
  unsigned char f[8];
  unsigned char h[8];
  unsigned char result;
  int i;

  for (i = 0; i < 8; ++i)
    f[i] = 1 & (c254 >> i);
  h[0] = f[0] ^ f[4] ^ f[5] ^ f[6] ^ f[7] ^ 1;
  h[1] = f[1] ^ f[5] ^ f[6] ^ f[7] ^ f[0] ^ 1;
  h[2] = f[2] ^ f[6] ^ f[7] ^ f[0] ^ f[1];
  h[3] = f[3] ^ f[7] ^ f[0] ^ f[1] ^ f[2];
  h[4] = f[4] ^ f[0] ^ f[1] ^ f[2] ^ f[3];
  h[5] = f[5] ^ f[1] ^ f[2] ^ f[3] ^ f[4] ^ 1;
  h[6] = f[6] ^ f[2] ^ f[3] ^ f[4] ^ f[5] ^ 1;
  h[7] = f[7] ^ f[3] ^ f[4] ^ f[5] ^ f[6];
  result = 0;
  for (i = 0; i < 8; ++i)
    result |= h[i] << i;
  return result;
#endif
}

static void
aes256 (aes256ctr_state_t state, unsigned char *out, const unsigned char *in)
{
#if defined(__ARM_FEATURE_AES)
  /* ARMv8 crypto extensions: vaeseq is AddRoundKey+SubBytes+ShiftRows,
     vaesmcq is MixColumns. */
  uint8x16_t b = vld1q_u8 (in);
  int r;

  for (r = 0; r < 13; ++r)
    b = vaesmcq_u8 (vaeseq_u8 (b, vld1q_u8 (state->rkeys[r])));
  b = vaeseq_u8 (b, vld1q_u8 (state->rkeys[13]));
  b = veorq_u8 (b, vld1q_u8 (state->rkeys[14]));
  vst1q_u8 (out, b);
#else
  unsigned char _state[4][4];
  unsigned char new_state[4][4];
  int i, j, r;

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      _state[i][j] = in[j * 4 + i] ^ state->expanded[i][j];

  for (r = 0; r < 14; ++r)
    {
      for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
          new_state[i][j] = bytesub (_state[i][j]);
      for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
          _state[i][j] = new_state[i][(j + i) % 4];
      if (r < 13)
        for (j = 0; j < 4; ++j)
          {
            unsigned char a0 = _state[0][j];
            unsigned char a1 = _state[1][j];
            unsigned char a2 = _state[2][j];
            unsigned char a3 = _state[3][j];
            _state[0][j] = xtime (a0 ^ a1) ^ a1 ^ a2 ^ a3;
            _state[1][j] = xtime (a1 ^ a2) ^ a2 ^ a3 ^ a0;
            _state[2][j] = xtime (a2 ^ a3) ^ a3 ^ a0 ^ a1;
            _state[3][j] = xtime (a3 ^ a0) ^ a0 ^ a1 ^ a2;
          }
      for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
          _state[i][j] ^= state->expanded[i][r * 4 + 4 + j];
    }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      out[j * 4 + i] = _state[i][j];
#endif
}

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                 const uint8_t nonce[16])
{
  unsigned char roundconstant;
  int i, j;

  state->cache_ptr = NULL;
  state->nbytes = 0;
  memcpy (state->nonce, nonce, 16);

  for (j = 0; j < 8; ++j)
    for (i = 0; i < 4; ++i)
      state->expanded[i][j] = key[j * 4 + i];

  roundconstant = 1;
  for (j = 8; j < 60; ++j)
    {
      unsigned char temp[4];
      if (j % 4)
        for (i = 0; i < 4; ++i)
          temp[i] = state->expanded[i][j - 1];
      else if (j % 8)
        for (i = 0; i < 4; ++i)
          temp[i] = bytesub (state->expanded[i][j - 1]);
      else
        {
          for (i = 0; i < 4; ++i)
            temp[i] = bytesub (state->expanded[(i + 1) % 4][j - 1]);
          temp[0] ^= roundconstant;
          roundconstant = xtime (roundconstant);
        }
      for (i = 0; i < 4; ++i)
        state->expanded[i][j] = temp[i] ^ state->expanded[i][j - 8];
    }

  /* round keys in AES byte order */
  for (j = 0; j < 60; ++j)
    for (i = 0; i < 4; ++i)
      state->rkeys[j / 4][(j % 4) * 4 + i] = state->expanded[i][j];
}

static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  size_t len;

  len = MIN (outlen, state->nbytes);
  memcpy (out, state->cache_ptr, len);

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

  while (outlen >= 16)
    {
      aes256 (state, out, state->nonce);
      incbe (state->nonce);

      out += 16;
      outlen -= 16;
    }
  if (outlen > 0)
    {
      aes256 (state, state->cache, state->nonce);
      incbe (state->nonce);

      memcpy (out, state->cache, outlen);

      state->cache_ptr = state->cache + outlen;
      state->nbytes = 16 - outlen;
    }
}

#endif

static void
_aes256ctr_clear (aes256ctr_state_t state)
{
  explicit_bzero (state, sizeof (aes256ctr_state_struct));
}

#endif
