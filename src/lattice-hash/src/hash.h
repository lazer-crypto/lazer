#ifndef INCLUDE_H
#define INCLUDE_H

#include <stdint.h>

static const uint64_t PRIME = 536813569;
static const uint64_t INV_257_MOD_PRIME = 528458494; // precomputed value of inv_mod(257, PRIME)
#define DEGREE 512

typedef uint64_t poly512[DEGREE];
typedef int64_t signed_poly512[DEGREE];

// NO_SHIFT means no shift vector is added to the matrix-vector product.
#define NO_SHIFT -1

void absorb(poly512 image[8], signed_poly512 cutoff, poly512 left_input[8], poly512 right_input[8]);
void mix_256(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 input[9], int shift_index);
void mix_257(poly512 image_decomposed[9], signed_poly512 cutoff, poly512 input[8]);
void squeeze(poly512 image_decomposed[8], signed_poly512 cutoff, poly512 input[2]);
void decomposition_binary_power(signed_poly512 output[2], signed_poly512 input, int exp, int loops);
void compute_cutoff_parent_node(signed_poly512 cutoff, poly512 child_node[8], poly512 sibling[8], int path, signed_poly512 delta, poly512 parent_node[8]);
void compute_delta(signed_poly512 image, signed_poly512 cutoff, poly512 left_input[8], poly512 right_input[8]);
#endif // INCLUDE_H
