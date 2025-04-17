#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <immintrin.h>

#include "hash.h"
#include "data.h"

extern uint64_t inv_mod(uint64_t a, uint64_t modulus);
extern void ntt_forward_in_place(
    uint64_t* operand,
    size_t n,
    uint64_t modulus
);

extern void ntt_inverse_in_place(
    uint64_t* operand,
    size_t n,
    uint64_t modulus
);

extern void ntt_forward(
    uint64_t* operand1,
    uint64_t* operand2,
    size_t n,
    uint64_t modulus
);

extern void ntt_inverse(
    uint64_t* operand1,
    uint64_t* operand2,
    size_t n,
    uint64_t modulus
);

extern void eltwise_add_mod(
    uint64_t* result,
    const uint64_t* operand1,
    const uint64_t* operand2,
    size_t n,
    uint64_t modulus
);

extern void eltwise_mult_mod(
    uint64_t* result,
    const uint64_t* operand1,
    const uint64_t* operand2,
    size_t n,
    uint64_t modulus
);

extern void eltwise_reduce_mod(
    uint64_t* result,
    const uint64_t* operand,
    size_t n,
    uint64_t modulus
);

extern uint64_t multiply_mod(
    uint64_t a,
    uint64_t b,
    uint64_t modulus
);

// Precomputed Shoup constant for the fixed multiplier INV_257_MOD_PRIME:
//   INV_257_SHOUP = floor(INV_257_MOD_PRIME * 2^64 / PRIME).
// Initialized at library load time.
static uint64_t INV_257_SHOUP;

__attribute__((constructor))
static void init_shoup_constants(void) {
    INV_257_SHOUP = (uint64_t)(((__uint128_t)INV_257_MOD_PRIME << 64) / PRIME);
}

// Shoup multiplication: computes x * W mod PRIME assuming x, W < PRIME and
// W_shoup is the precomputed floor(W * 2^64 / PRIME). Produces result in [0, PRIME).
static inline uint64_t shoup_mul_prime(uint64_t x, uint64_t W, uint64_t W_shoup) {
    uint64_t q_hat = (uint64_t)(((__uint128_t)x * W_shoup) >> 64);
    uint64_t r = x * W - q_hat * PRIME;
    if (r >= PRIME) r -= PRIME;
    return r;
}

// AVX-512: split 8 polynomials' low byte into 8 separate bit-plane polynomials.
// Destroys 'image'.
static inline void decompose_bits_8_avx512(poly512 image_decomposed[8], poly512 image) {
    const __m512i one = _mm512_set1_epi64(1);
    for (int j = 0; j < DEGREE; j += 8) {
        __m512i v = _mm512_loadu_si512((const __m512i*)&image[j]);
        _mm512_storeu_si512((__m512i*)&image_decomposed[0][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[1][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[2][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[3][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[4][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[5][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[6][j], _mm512_and_si512(v, one));
        v = _mm512_srli_epi64(v, 1);
        _mm512_storeu_si512((__m512i*)&image_decomposed[7][j], _mm512_and_si512(v, one));
    }
}

// AVX-512 center-lift + split into (quotient = signed >> 8, remainder = signed & 0xFF).
static inline void center_lift_split_8bit_avx512(poly512 image, signed_poly512 cutoff, const poly512 output) {
    const __m512i vprime = _mm512_set1_epi64((int64_t)PRIME);
    const __m512i vhalf = _mm512_set1_epi64((int64_t)(PRIME / 2));
    const __m512i vmask = _mm512_set1_epi64(0xFF);
    for (int i = 0; i < DEGREE; i += 8) {
        __m512i v = _mm512_loadu_si512((const __m512i*)&output[i]);
        __mmask8 gt = _mm512_cmpgt_epi64_mask(v, vhalf);
        __m512i s = _mm512_mask_sub_epi64(v, gt, v, vprime);
        __m512i q = _mm512_srai_epi64(s, 8);
        __m512i r = _mm512_and_si512(s, vmask);
        _mm512_storeu_si512((__m512i*)&image[i], r);
        _mm512_storeu_si512((__m512i*)&cutoff[i], q);
    }
}

// Compute output += sum(MATRIX_A_NTT[offset+i] * input[i]) for i in [0, count),
// where all multiplications are polynomial multiplications via NTT.
static void ntt_multiply_accumulate(poly512 output, poly512 input[], int count, int offset) {
    poly512 tmp;
    for (int i = 0; i < count; ++i) {
        ntt_forward(tmp, input[i], DEGREE, PRIME);
        eltwise_mult_mod(tmp, tmp, MATRIX_A_NTT[offset + i], DEGREE, PRIME);
        eltwise_add_mod(output, tmp, output, DEGREE, PRIME);
    }
}

// Center-lift: convert from [0, PRIME) to (-PRIME/2, PRIME/2].
static inline int64_t center_lift(uint64_t coeff) {
    int64_t s = (int64_t)coeff;
    if (s > (int64_t)PRIME / 2) {
        s -= (int64_t)PRIME;
    }
    return s;
}

// Efficiently compute x mod 257 using byte-wise processing
// Input: 64-bit integer x
// Output: x mod 257 (in range 0..256)
// 
uint64_t mod257_bytes_u64(uint64_t x) {
    uint64_t r = 0;      // always kept in 0..256
    uint64_t add = 1;    // 1 = add, 0 = subtract

    while (x) {
        uint64_t b = x & 0xFFu;

        if (add) {
            // r = r + b; if r >= 257, r -= 257
            uint64_t t = r + b;
            uint64_t mask = 0u - (uint64_t)(t >= 257u);
            r = t - (mask & 257u);
        } else {
            // r = r - b; if underflow, add 257
            uint64_t t = r - b;                  // wraps if r < b
            uint64_t mask = 0u - (uint64_t)(r < b);
            r = t + (mask & 257u);
        }

        x >>= 8;
        add ^= 1;  // flip add/sub
    }
    return r;  // 0..256
}

// Compress two blocks of 8 polynomials each into one block of 8 polynomials
// using a fixed random matrix A.
// Each polynomial has degree 512 and coefficients mod PRIME.
//
// Computes output = A * (left_input || right_input) in the polynomial ring.
// Optionally adds SHIFTS[shift_index] to avoid during mixing that an all-
// zero input produces a zero output.
//
// The output polynomial coefficients are split into remainder and quotient
// of the division by 256:
//   - the lower 8 bits go to 'image_decomposed' (as 8 polynomials of bits),
//   - the higher bits go to 'cutoff' (as one polynomial).
static void compress_internal(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 left_input[8], poly512 right_input[], int right_count, int shift_index) {

    poly512 output;
    poly512 image;
    memset(output, 0, sizeof(output));

    ntt_multiply_accumulate(output, left_input, 8, 0);
    if (right_count > 0) {
        ntt_multiply_accumulate(output, right_input, right_count, 8);
    }

    ntt_inverse_in_place(output, DEGREE, PRIME);

    // Add a shift vector to prevent the matrix-vector product from being
    // trivially zero (which would be problematic in the mixing rounds).
    if (shift_index != NO_SHIFT) {
        for (int i = 0; i < DEGREE; ++i) {
            output[i] += SHIFTS[shift_index][i];
        }
    }

    center_lift_split_8bit_avx512(image, cutoff, output);
    decompose_bits_8_avx512(image_decomposed, image);
}

// Public API: compress without any shift (shift_index = NO_SHIFT).
void absorb(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 left_input[8], poly512 right_input[8]) {
    compress_internal(image_decomposed, cutoff, left_input, right_input, right_input ? 8 : 0, NO_SHIFT);
}

void mix_256(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 input[9], int shift_index) {
    compress_internal(image_decomposed, cutoff, input, input + 8, 1, shift_index);
}

void mix_257(poly512 image_decomposed[9], signed_poly512 cutoff, poly512 input[8]) {
    poly512 output;
    poly512 image;
    memset(output, 0, sizeof(output));

    ntt_multiply_accumulate(output, input, 8, 0);

    ntt_inverse_in_place(output, DEGREE, PRIME);
    for (int i = 0; i < DEGREE; ++i) {
        int64_t signed_coeff = center_lift(output[i]);
        int negative = signed_coeff < 0;
        uint64_t unsigned_coeff = (uint64_t)(negative ? -signed_coeff : signed_coeff);
        // unsigned_coeff < PRIME < 2^30, so `% 257` compiles to reciprocal
        // multiplication — much faster than the byte-wise loop.
        uint64_t remainder = unsigned_coeff % 257u;
        // Inline Shoup multiplication for the fixed constant INV_257_MOD_PRIME
        // avoids a cross-library call per coefficient (1024 calls per pipeline).
        int64_t signed_quotient = (int64_t) shoup_mul_prime(unsigned_coeff - remainder, INV_257_MOD_PRIME, INV_257_SHOUP);

        if (negative) {
            signed_quotient = -signed_quotient;
            if (remainder > 0) {
                remainder = 257 - remainder;
                signed_quotient -= 1;
            }
        }
        image[i] = (uint64_t)remainder;
        cutoff[i] = signed_quotient;
    }
    // Decompose 9 bit-planes (values in [0, 256], bit 8 can be set) with AVX-512.
    {
        const __m512i one = _mm512_set1_epi64(1);
        for (int j = 0; j < DEGREE; j += 8) {
            __m512i v = _mm512_loadu_si512((const __m512i*)&image[j]);
            for (int i = 0; i < 9; ++i) {
                _mm512_storeu_si512((__m512i*)&image_decomposed[i][j], _mm512_and_si512(v, one));
                v = _mm512_srli_epi64(v, 1);
            }
        }
    }
}

// Squeeze function based on Learning with Rounding.
//
// Computes output = a_1 * s_1 + a_2 * s_2, where a_1, a_2 are the first two
// rows of MATRIX_A / MATRIX_A_NTT and s_1, s_2 are input[0], input[1].
//
// The result is written as remainder and quotient of the division by 256. 
// The coefficients of the remainder are represented as integers in [-2, 253]
// and binary decomposed with weights (1, -2, 4, 8, ..., 128): 
// x = x0 - 2*x1 + 4*x2 + ... + 128*x7.
// In the rounding the 2 least significant bits, x0, x1, are dropped.
//    
//   1. The binary decomposition of the remainder becomes image_decomposed.
//   2. The quotient becomes cutoff.
void squeeze(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 input[2]) {
    poly512 output;
    poly512 image;
    memset(output, 0, sizeof(output));

    ntt_multiply_accumulate(output, input, 2, 0);

    ntt_inverse_in_place(output, DEGREE, PRIME);

    // AVX-512 center-lift + split into (quotient, remainder).
    // remainder is in [0, 255] but the balanced representation needs [-2, 253].
    // For remainder in {254, 255}, the balanced value is {-2, -1}, which
    // belongs to the next quotient block, so we bump the quotient by 1.
    {
        const __m512i vprime = _mm512_set1_epi64((int64_t)PRIME);
        const __m512i vhalf = _mm512_set1_epi64((int64_t)(PRIME / 2));
        const __m512i vmask = _mm512_set1_epi64(0xFF);
        const __m512i v253 = _mm512_set1_epi64(253);
        const __m512i vone = _mm512_set1_epi64(1);
        for (int i = 0; i < DEGREE; i += 8) {
            __m512i v = _mm512_loadu_si512((const __m512i*)&output[i]);
            __mmask8 gt = _mm512_cmpgt_epi64_mask(v, vhalf);
            __m512i s = _mm512_mask_sub_epi64(v, gt, v, vprime);
            __m512i q = _mm512_srai_epi64(s, 8);
            __m512i r = _mm512_and_si512(s, vmask);
            __mmask8 bump = _mm512_cmpgt_epi64_mask(r, v253);
            q = _mm512_mask_add_epi64(q, bump, q, vone);
            _mm512_storeu_si512((__m512i*)&image[i], r);
            _mm512_storeu_si512((__m512i*)&cutoff[i], q);
        }
    }

    // Standard binary decomposition of image[j] (in [0, 255]) into 8 bit-planes.
    decompose_bits_8_avx512(image_decomposed, image);

    // Convert from standard binary (weights 1, 2, 4, ..., 128) to balanced
    // binary (weights 1, -2, 4, ..., 128).
    //
    // Standard:  x = x0 + 2*x1 + 4*x2 + ... + 128*x7   (range [0, 255])
    // Balanced:  x = x0 - 2*x1 + 4*x2 + ... + 128*x7   (range [-2, 253])
    //
    // When x1 == 0, the representations are equal. When x1 == 1, 2*x1 can be
    // written as -2*x1 + 4*x1, hence we keep x1 = 1 and increment (x2, ..., x7).
    // The loop below performs this binary increment with carry propagation:
    //   - each bit that is already 1 becomes 0 (carry continues),
    //   - the first 0 bit becomes 1 (carry absorbed, done).
    //
    // Example: x = 6 = (x0=0, x1=1, x2=1, x3=0, ...) in standard binary.
    //   x1==1 so increment (x2,...): x2: 1->0 carry, x3: 0->1 done.
    //   Balanced bits: (0, 1, 0, 1, 0, ...) -> 0 - 2 + 0 + 8 = 6. 
    for (int i = 0; i < DEGREE; ++i) {
        if (image_decomposed[1][i] == 1) {
            int j = 2;
            while (j < 8 && image_decomposed[j][i] == 1) {
                image_decomposed[j][i] = 0;
                j++;
            }
            if (j < 8) {
                image_decomposed[j][i] = 1;
            }
        }
    }
}


// Balanced binary decomposition by a power of 2.
// Currently only loops == 2 is supported.
void decomposition_binary_power(signed_poly512 output[2], signed_poly512 input, int exp, int loops){
    assert(loops == 2 && "Error: only loops = 2 supported.");
    int64_t half = (int64_t)1 << (exp - 1);
    int64_t base = (int64_t)1 << exp;
    int64_t mask = base - 1;
    for (int i = 0; i < DEGREE; ++i) {
        int64_t signed_coeff = input[i];
        for (int j = 0; j < loops; ++j) {
            output[j][i] = signed_coeff & mask;
            if (output[j][i] > half) {
                output[j][i] -= base;
            }
            signed_coeff = (signed_coeff - output[j][i]) >> exp;
        }
    }
}


void compute_cutoff_parent_node(signed_poly512 cutoff, poly512 child_node[8], poly512 sibling[8], int path, signed_poly512 delta, poly512 parent_node[8]) {
    poly512 output;
    memset(output, 0, sizeof(output));

    ntt_multiply_accumulate(output, child_node, 8, 0);
    ntt_multiply_accumulate(output, sibling, 8, 8);

    ntt_inverse_in_place(output, DEGREE, PRIME);

    for (int i = 0; i < DEGREE; ++i) {
        int64_t signed_coeff = center_lift(output[i]);
        for (int j = 0; j < 8; ++j) {
            if (parent_node[j][i] == 1) {
                signed_coeff -= (int64_t)1 << j; // - G_2 * v_{i-1}
            }
        }
        if (path == 1) {
            signed_coeff += delta[i];
        }
        cutoff[i] = signed_coeff >> 8;
    }
}


void compute_delta(signed_poly512 image, signed_poly512 cutoff, poly512 left_input[8], poly512 right_input[8]) {
    poly512 output1;
    memset(output1, 0, sizeof(output1));

    ntt_multiply_accumulate(output1, left_input, 8, 0);
    ntt_multiply_accumulate(output1, right_input, 8, 8);

    ntt_inverse_in_place(output1, DEGREE, PRIME);

    poly512 output2;
    memset(output2, 0, sizeof(output2));

    ntt_multiply_accumulate(output2, right_input, 8, 0);
    ntt_multiply_accumulate(output2, left_input, 8, 8);

    ntt_inverse_in_place(output2, DEGREE, PRIME);

    signed_poly512 output;
    for (int i = 0; i < DEGREE; ++i) {
        output[i] = center_lift(output2[i]) - center_lift(output1[i]);
    }

    for (int i = 0; i < DEGREE; ++i) {
        int64_t quotient = output[i] >> 8;
        int64_t remainder = output[i] & 0xFF;
        if (remainder > 127) {
            remainder -= 256;
            quotient += 1;
        }
        image[i] = remainder;
        cutoff[i] = quotient;
    }
}
