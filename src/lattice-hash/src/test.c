#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "hash.h"
#include "data.h"

static void print_poly_blocks(const char* name,
                              const uint64_t blocks[][DEGREE],
                              size_t count)
{
    printf("%s = [\n", name);
    for (size_t i = 0; i < count; ++i) {
        printf("  [");
        for (size_t j = 0; j < DEGREE; ++j) {
            printf("%llu", (unsigned long long)blocks[i][j]);
            if (j + 1 < DEGREE) {
                printf(", ");
            }
        }
        if (i + 1 < count) {
            printf("],");
        } else {
            printf("]");
        }
    }
    printf("\n];\n");
}

static void print_signed_poly(const char* name, const int64_t poly[DEGREE])
{
    printf("%s = [", name);
    for (size_t j = 0; j < DEGREE; ++j) {
        printf("%lld", (long long)poly[j]);
        if (j + 1 < DEGREE) {
            printf(", ");
        }
    }
    printf("];\n");
}

static void read_random_bytes(void* buffer, size_t length)
{
    uint8_t* out = (uint8_t*)buffer;
    while (length > 0) {
        ssize_t received = getrandom(out, length, 0);
        if (received < 0) {
            perror("getrandom");
            exit(EXIT_FAILURE);
        }
        out += received;
        length -= (size_t)received;
    }
}

static void fill_random_poly(poly512 poly)
{
    uint8_t bytes[DEGREE];
    read_random_bytes(bytes, sizeof(bytes));
    for (size_t coeff = 0; coeff < DEGREE; ++coeff) {
        poly[coeff] = (uint64_t)(bytes[coeff] & 1U);
    }
}

static void fill_random_input(poly512 input[8])
{
    for (size_t block = 0; block < 8; ++block) {
        fill_random_poly(input[block]);
    }
}

int main(void)
{
    poly512 input_1[8];
    poly512 input_2[8];
    poly512 input_3[8];

    fill_random_input(input_1);
    fill_random_input(input_2);
    fill_random_input(input_3);

    poly512 image_bits_after_compress_1[8];
    signed_poly512 cutoff_after_compress_1;
    poly512 image_bits_after_compress_2[8];
    signed_poly512 cutoff_after_compress_2;

    poly512 image_bits_after_mix_1[9];
    signed_poly512 cutoff_after_mix_1;
    poly512 image_bits_after_mix_2[8];
    signed_poly512 cutoff_after_mix_2;
    poly512 image_bits_after_mix_3[9];
    signed_poly512 cutoff_after_mix_3;


    poly512 squeeze_output_1[8];
    signed_poly512 cutoff_after_squeeze_1;
    poly512 squeeze_output_2[8];
    signed_poly512 cutoff_after_squeeze_2;
    poly512 squeeze_output_3[8];
    signed_poly512 cutoff_after_squeeze_3;

    struct timespec start_time;
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);


    absorb(image_bits_after_compress_1, cutoff_after_compress_1, input_1, input_2);
    absorb(image_bits_after_compress_2, cutoff_after_compress_2, image_bits_after_compress_1, input_3);
    mix_257(image_bits_after_mix_1, cutoff_after_mix_1, image_bits_after_compress_2);
    // mix_256(image_bits_after_mix_2, cutoff_after_mix_2, image_bits_after_compress_2);
    mix_257(image_bits_after_mix_3, cutoff_after_mix_3, image_bits_after_mix_2);
    squeeze(squeeze_output_1, cutoff_after_squeeze_1, image_bits_after_mix_3);
    squeeze(squeeze_output_2, cutoff_after_squeeze_2, squeeze_output_1);
    squeeze(squeeze_output_3, cutoff_after_squeeze_3, squeeze_output_2);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    uint64_t elapsed_ns = (uint64_t)(end_time.tv_sec - start_time.tv_sec) * 1000000000ULL +
                          (uint64_t)(end_time.tv_nsec - start_time.tv_nsec);





    printf("matrix_a = [\n");
    for (size_t i = 0; i < 16; ++i) {
        printf("  [");
        for (size_t j = 0; j < DEGREE; ++j) {
            printf("%lld", (long long)MATRIX_A[i][j]);
            if (j + 1 < DEGREE) {
                printf(", ");
            }
        }
        printf("]");
        if (i + 1 < 16) {
            printf(",\n");
        }
    }
    printf("\n];\n");

    print_poly_blocks("input_1", input_1, 8);
    print_poly_blocks("input_2", input_2, 8);
    print_poly_blocks("input_3", input_3, 8);

    print_poly_blocks("image_bits_after_compress_1", image_bits_after_compress_1, 8);
    print_signed_poly("cutoff_after_compress_1", cutoff_after_compress_1);
    print_poly_blocks("image_bits_after_compress_2", image_bits_after_compress_2, 8);
    print_signed_poly("cutoff_after_compress_2", cutoff_after_compress_2);

    print_poly_blocks("image_bits_after_mix_1", image_bits_after_mix_1, 9);
    print_signed_poly("cutoff_after_mix_1", cutoff_after_mix_1);
    print_poly_blocks("image_bits_after_mix_2", image_bits_after_mix_2, 8);
    print_signed_poly("cutoff_after_mix_2", cutoff_after_mix_2);
    print_poly_blocks("image_bits_after_mix_3", image_bits_after_mix_3, 9);
    print_signed_poly("cutoff_after_mix_3", cutoff_after_mix_3);

    print_poly_blocks("squeeze_output_1", squeeze_output_1, 8);
    print_signed_poly("cutoff_after_squeeze_1", cutoff_after_squeeze_1);
    print_poly_blocks("squeeze_output_2", squeeze_output_2, 8);
    print_signed_poly("cutoff_after_squeeze_2", cutoff_after_squeeze_2);
    print_poly_blocks("squeeze_output_3", squeeze_output_3, 8);
    print_signed_poly("cutoff_after_squeeze_3", cutoff_after_squeeze_3);
    printf("pipeline_time_ns = %llu\n", (unsigned long long)elapsed_ns);

    return 0;
}
