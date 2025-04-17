#ifndef SHAKE128_H
#define SHAKE128_H

// Self-contained SHAKE128 (FIPS 202) extendable-output function.
// Header-only, public-domain reference style. Assumes a little-endian host
// (which is the case for x86_64 / aarch64 on the platforms this project
// targets). Used by generate_data.c so anyone can re-derive MATRIX_A and
// SHIFTS from the published seed string with any standard SHAKE128
// implementation (e.g. OpenSSL EVP_shake128, Python hashlib.shake_128).

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHAKE128_RATE 168

typedef struct {
    union {
        uint8_t  b[200];
        uint64_t q[25];
    } st;
    size_t pt;
} shake128_ctx;

static const uint64_t shake128_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int shake128_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int shake128_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static inline uint64_t shake128_rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

static void shake128_keccakf(uint64_t st[25])
{
    uint64_t bc[5], t;
    for (int r = 0; r < 24; ++r) {
        for (int i = 0; i < 5; ++i)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ shake128_rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = shake128_piln[i];
            bc[0] = st[j];
            st[j] = shake128_rotl64(t, shake128_rotc[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; ++i)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= shake128_rc[r];
    }
}

static void shake128_init(shake128_ctx *c)
{
    memset(c, 0, sizeof(*c));
}

static void shake128_absorb(shake128_ctx *c, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        c->st.b[c->pt++] ^= data[i];
        if (c->pt == SHAKE128_RATE) {
            shake128_keccakf(c->st.q);
            c->pt = 0;
        }
    }
}

// Apply SHAKE domain separator (0x1F) and pad10*1 trailing bit (0x80), then
// permute and switch the context into squeezing mode.
static void shake128_finalize(shake128_ctx *c)
{
    c->st.b[c->pt]              ^= 0x1F;
    c->st.b[SHAKE128_RATE - 1]  ^= 0x80;
    shake128_keccakf(c->st.q);
    c->pt = 0;
}

static void shake128_squeeze(shake128_ctx *c, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (c->pt == SHAKE128_RATE) {
            shake128_keccakf(c->st.q);
            c->pt = 0;
        }
        out[i] = c->st.b[c->pt++];
    }
}

#endif // SHAKE128_H
