#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "shake128.h"

// Public domain string used to seed the matrix-and-shifts XOF. Anyone can
// re-derive MATRIX_A / SHIFTS by absorbing exactly these bytes (no NUL
// terminator) into SHAKE128, finalizing, and squeezing first MATRIX_BYTES
// then SHIFTS_BYTES bytes (one byte per coefficient, mapped via x - 128).
//
// Cross-check (Python):
//     import hashlib
//     x = hashlib.shake_128(b"LatHash v1").digest(MATRIX_BYTES + SHIFTS_BYTES)
static const char DOMAIN_SEED[] = "LatHash v1";

extern void ntt_forward(
    uint64_t* operand1,
    uint64_t* operand2,
    size_t n,
    uint64_t modulus
);

#define MATRIX_ROWS 16
#define NUMBER_SHIFTS 5
#define OUTPUT_PATH "src/data.h"

// FIPS 202 known-answer test for SHAKE128(""). Detects a broken Keccak
// permutation before any data.h is written.
static void shake128_self_test(void)
{
    static const uint8_t expected[32] = {
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26
    };
    shake128_ctx ctx;
    uint8_t got[32];
    shake128_init(&ctx);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, got, sizeof(got));
    if (memcmp(got, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "shake128 self-test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void fill_signed_from_xof(shake128_ctx *xof, int64_t *coeffs, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        uint8_t byte;
        shake128_squeeze(xof, &byte, 1);
        coeffs[i] = (int64_t)byte - 128;
    }
}

static void generate_matrix(shake128_ctx *xof, signed_poly512 matrix[MATRIX_ROWS])
{
    for (size_t row = 0; row < MATRIX_ROWS; ++row) {
        fill_signed_from_xof(xof, matrix[row], DEGREE);
    }
}

static void compute_ntt_matrix(poly512 result[MATRIX_ROWS], const signed_poly512 input[MATRIX_ROWS])
{
    for (size_t row = 0; row < MATRIX_ROWS; ++row) {
        poly512 input_mod;
        for (size_t col = 0; col < DEGREE; ++col) {
            int64_t coeff = input[row][col];
            if (coeff < 0) {
                input_mod[col] = PRIME - (uint64_t)(-coeff);
            } else {
                input_mod[col] = (uint64_t)coeff;
            }
        }
        ntt_forward(result[row], input_mod, DEGREE, PRIME);
    }
}

static void generate_shifts(shake128_ctx *xof, signed_poly512 vector[NUMBER_SHIFTS])
{
    for (size_t row = 0; row < NUMBER_SHIFTS; ++row) {
        fill_signed_from_xof(xof, vector[row], DEGREE);
    }
}

static void write_poly(FILE* output, const poly512 poly)
{
    fprintf(output, "    { ");
    for (size_t col = 0; col < DEGREE; ++col) {
        fprintf(output, "%llu", (unsigned long long)poly[col]);
        if (col + 1 < DEGREE) {
            fprintf(output, ", ");
            if ((col + 1) % 16 == 0) {
                fprintf(output, "\n      ");
            }
        }
    }
    fprintf(output, " }");
}

static void write_signed_poly(FILE* output, const signed_poly512 poly)
{
    fprintf(output, "    { ");
    for (size_t col = 0; col < DEGREE; ++col) {
        fprintf(output, "%lld", (long long)poly[col]);
        if (col + 1 < DEGREE) {
            fprintf(output, ", ");
            if ((col + 1) % 16 == 0) {
                fprintf(output, "\n      ");
            }
        }
    }
    fprintf(output, " }");
}

static void write_matrix(FILE* output, const char* name, const poly512 matrix[MATRIX_ROWS])
{
    fprintf(output, "static const poly512 %s[%d] = {\n", name, MATRIX_ROWS);
    for (size_t row = 0; row < MATRIX_ROWS; ++row) {
        write_poly(output, matrix[row]);
        fprintf(output, "%s\n", (row + 1 < MATRIX_ROWS) ? "," : "");
    }
    fprintf(output, "};\n\n");
}

static void write_signed_matrix(FILE* output, const char* name, const signed_poly512 matrix[MATRIX_ROWS])
{
    fprintf(output, "static const signed_poly512 %s[%d] = {\n", name, MATRIX_ROWS);
    for (size_t row = 0; row < MATRIX_ROWS; ++row) {
        write_signed_poly(output, matrix[row]);
        fprintf(output, "%s\n", (row + 1 < MATRIX_ROWS) ? "," : "");
    }
    fprintf(output, "};\n\n");
}

static void write_shifts(FILE* output, const char* name, const signed_poly512 vector[NUMBER_SHIFTS])
{
    fprintf(output, "static const signed_poly512 %s[%d] = {\n", name, NUMBER_SHIFTS);
    for (size_t row = 0; row < NUMBER_SHIFTS; ++row) {
        write_signed_poly(output, vector[row]);
        fprintf(output, "%s\n", (row + 1 < NUMBER_SHIFTS) ? "," : "");
    }
    fprintf(output, "};\n\n");
}


int main(void)
{
    signed_poly512 matrix[MATRIX_ROWS];
    poly512 matrix_ntt[MATRIX_ROWS];
    signed_poly512 shifts[NUMBER_SHIFTS];

    shake128_self_test();

    shake128_ctx xof;
    shake128_init(&xof);
    shake128_absorb(&xof, (const uint8_t*)DOMAIN_SEED, strlen(DOMAIN_SEED));
    shake128_finalize(&xof);

    generate_matrix(&xof, matrix);
    compute_ntt_matrix(matrix_ntt, matrix);
    generate_shifts(&xof, shifts);

    FILE* output = fopen(OUTPUT_PATH, "w");
    if (!output) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(output, "#ifndef DATA_H\n");
    fprintf(output, "#define DATA_H\n\n");
    fprintf(output, "#include \"hash.h\"\n\n");
    fprintf(output, "// Generated by generate_data.c. Do not edit manually.\n");
    fprintf(output, "// MATRIX_A and SHIFTS coefficients are derived deterministically by\n");
    fprintf(output, "// squeezing SHAKE128(\"%s\") and mapping each output byte b to b - 128.\n",
            DOMAIN_SEED);
    fprintf(output, "// MATRIX_A_NTT is the row-wise forward NTT of MATRIX_A mod PRIME.\n\n");

    write_signed_matrix(output, "MATRIX_A", matrix);
    write_matrix(output, "MATRIX_A_NTT", matrix_ntt);
    write_shifts(output, "SHIFTS", shifts);

    fprintf(output, "#endif // DATA_H\n");

    if (fclose(output) != 0) {
        perror("fclose");
        return EXIT_FAILURE;
    }

    printf("Generated %s with %d polynomials of degree %d.\n",
           OUTPUT_PATH,
           MATRIX_ROWS,
           DEGREE);

    return EXIT_SUCCESS;
}
