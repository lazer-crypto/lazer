import sys
sys.path.append('..')   # path to lazer module 
from lazer import *     # import lazer python module
from labrados import *
import hashlib          # for SHAKE128
from math import log2, ceil, sqrt
from numpy import binary_repr
from decomposition import opt_decompose
from urand_matrix import *
from random import randrange
import time

# Hash variables
MODULUS_HASH = 256
MODULUS_MIXING = 257
MODULUS_EXPANSION = 64
MODULUS_PROOF = LAB_RING_38.mod
DEGREE_HASH = 512
SIZE_MODULUS_PROOF = str(ceil(log2(MODULUS_PROOF)))
RING_PROOF = polyring_t(DEGREE_HASH, MODULUS_PROOF)
ONE_IN_RING_PROOF = int_to_poly(1, RING_PROOF)
ZERO_IN_RING_PROOF = poly_t(RING_PROOF)
COMPRESSION_FACTOR = 2 # only option supported
ITERATIONS_MIXING = 4
BITS_MODULUS_HASH = ceil(log2(MODULUS_HASH))
BITS_MODULUS_MIXING = ceil(log2(MODULUS_MIXING))
BITS_MODULUS_EXPANSION = ceil(log2(MODULUS_EXPANSION))
BITS_TO_DISCARD = BITS_MODULUS_HASH - BITS_MODULUS_EXPANSION
BITS_SEED_EXPANSION = 2
BITS_TO_OUTPUT =  BITS_MODULUS_HASH - BITS_SEED_EXPANSION - BITS_TO_DISCARD
NORM_BINARY = 0
BASE_LIFTINGS_COMPRESSION = 64 # only option supported
SQNORM_COMPONENTS_LIFTING_COMPRESSION = BASE_LIFTINGS_COMPRESSION ** 2 * DEGREE_HASH
SQNORM_LIFTING_EXPANSION = round((1.45 * RING_PROOF.deg / sqrt(12) + sqrt(RING_PROOF.deg)) ** 2)

# matrix uniformly random in MODULUS_HASH, used in the hash function
DIMENSION_MATRIX_HASH = BITS_MODULUS_HASH * COMPRESSION_FACTOR # matrix 1 x 16, seen as a vector
URANDOM_MATRIX_HASH = polyvec_t(RING_PROOF, DIMENSION_MATRIX_HASH, list_urandom_matrix_hash)

# constants for mixing
CONSTANTS = [poly_t(RING_PROOF, list_constants[i]) for i in range(ITERATIONS_MIXING + 1)]

# precompute part of statements
COMMON_LEFT_PART_COMPRESSION = [- 2 ** i * ONE_IN_RING_PROOF  for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH] + [- ONE_IN_RING_PROOF * MODULUS_HASH * BASE_LIFTINGS_COMPRESSION]
LEFT_LIST_COMPRESSION = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR)] + COMMON_LEFT_PART_COMPRESSION
LEFT_LIST_FIRST_MIX = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH, - ONE_IN_RING_PROOF * MODULUS_HASH * BASE_LIFTINGS_COMPRESSION]
LEFT_LIST_DECOMP_257 = [ONE_IN_RING_PROOF, ONE_IN_RING_PROOF, - ONE_IN_RING_PROOF]
LEFT_LIST_MIX_257 = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_MIXING)] + [- ONE_IN_RING_PROOF * MODULUS_MIXING, - ONE_IN_RING_PROOF * MODULUS_MIXING * BASE_LIFTINGS_COMPRESSION]
LEFT_LIST_MIX_256 = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_MIXING)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH, - ONE_IN_RING_PROOF * MODULUS_HASH * BASE_LIFTINGS_COMPRESSION]
INDEX_NEGATIVE_POWER = BITS_MODULUS_HASH - BITS_MODULUS_EXPANSION - 1
LEFT_LIST_BINARY_EXPANSION = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_SEED_EXPANSION)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER)] + [2 ** INDEX_NEGATIVE_POWER * ONE_IN_RING_PROOF] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER + 1, BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]


class proof_statement_description:
    ''''''
    def __init__(self, list_degrees = None, list_number_polynomials = None, list_norm_constraints = None, number_constraints = None, num_deg0_constraints = None):
        # assert len(list_degrees) == len(...) == ...
        # maybe other reasonable assert?
        if list_degrees == None:
            self.list_degrees = []
            self.list_number_polynomials = []
            self.list_norm_constraints = []
            self.number_constraints = 0
            self.num_deg0_constraints = 0
        else:
            self.list_degrees = list_degrees
            self.list_number_polynomials = list_number_polynomials
            self.list_norm_constraints = list_norm_constraints
            self.number_constraints = number_constraints
            self.num_deg0_constraints = num_deg0_constraints

    def update_witnesses_description(self, new_degrees: list, new_number_polynomials: list, new_norm_constraints: list):
        # assert ...
        self.list_degrees += new_degrees
        self.list_number_polynomials += new_number_polynomials
        self.list_norm_constraints += new_norm_constraints

    def update_statements_description(self, new_constraints: int):
        # assert new_constraints > 0
        self.number_constraints += new_constraints


# Functions

def convert_array_to_poly_t(array):
    poly = poly_t(RING_PROOF, list(array))
    return poly

def convert_array_to_polyvec_t(array):
    list_coeffs = []
    for i in range(len(array)):
        list_coeffs += list(array[i])
    vec = polyvec_t(RING_PROOF, len(array), list_coeffs)
    return vec

def clib_compression_step(left_input, right_input):
    # assert left_input_vec.dim == BITS_MODULUS_HASH and right_input_vec.dim == BITS_MODULUS_HASH, "left_input and right_input in compression must be of dimension BITS_MODULUS_HASH"

    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.absorb(image, cutoff, left_input, right_input)
    
    return image, cutoff

def clib_mix_256(input, index_iteration):
    # assert input_vec.dim == BITS_MODULUS_MIXING, "input in mix_256 must be of dimension BITS_MODULUS_MIXING"
    
    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.mix_256(image, cutoff, input, index_iteration)

    return image, cutoff

def clib_mix_257(input):
    # assert input_vec.dim == BITS_MODULUS_HASH, "input in mix_257 must be of dimension BITS_MODULUS_HASH"

    image = ffi.new("poly512 []", BITS_MODULUS_MIXING)
    cutoff = ffi.new("signed_poly512")
    lib.mix_257(image, cutoff, input)

    return image, cutoff

def clib_squeeze(input):
    # assert input_vec.dim == BITS_SEED_EXPANSION, "input in squeeze must be of dimension BITS_SEED_EXPANSION"

    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.squeeze(image, cutoff, input)

    return image, cutoff

def clib_decomp_64(input):
    
    output = ffi.new("signed_poly512 [2]")
    lib.decomposition_binary_power(output, input, 6, 2)

    return output

def description_compression(dimension_input, PS_description):
    assert dimension_input < 2 ** DEGREE_HASH, "Maximal dimension allowed 2^DEGREE_HASH"
    dimension_padded_input = ceil((dimension_input + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH # padding with one poly describing the dimension and zero polynomials
    iterations_compression = dimension_padded_input // BITS_MODULUS_HASH
    number_witnesses_compression = (BITS_MODULUS_HASH + 2) * iterations_compression
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_compression
    PS_description.list_number_polynomials += [1] * number_witnesses_compression
    PS_description.list_norm_constraints += ([NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] * 2) * iterations_compression
    PS_description.number_constraints += iterations_compression
    return PS_description

def description_mixing(PS_description):
    number_witnesses_mixing = (BITS_MODULUS_HASH + 2) * (ITERATIONS_MIXING + 1) + (BITS_MODULUS_MIXING + BITS_MODULUS_HASH + 2) * ITERATIONS_MIXING
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_mixing
    PS_description.list_number_polynomials += [1] * number_witnesses_mixing
    PS_description.list_norm_constraints += [NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] * 2  + ([NORM_BINARY] * (BITS_MODULUS_MIXING + BITS_MODULUS_HASH) + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] * 2 + [NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] * 2) * ITERATIONS_MIXING
    PS_description.number_constraints += 1 + ITERATIONS_MIXING * BITS_MODULUS_HASH + 2 * ITERATIONS_MIXING
    return PS_description

def description_binary_expansion(dimension_binary_output, PS_description):
    iterations_binary_expansion = max(1, ceil((dimension_binary_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    number_witnesses_expansion = (BITS_MODULUS_HASH + 1) * iterations_binary_expansion
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_expansion
    PS_description.list_number_polynomials += [1] * number_witnesses_expansion
    PS_description.list_norm_constraints += ([NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_EXPANSION]) * iterations_binary_expansion
    PS_description.number_constraints += iterations_binary_expansion
    return PS_description

def description_hash(dimension_input, dimension_binary_output, PS_description):
    PS_description = description_compression(dimension_input, PS_description)
    PS_description = description_mixing(PS_description)
    PS_description = description_binary_expansion(dimension_binary_output, PS_description)
    return PS_description

def compression(input, initial_vector, PS, indices_input, next_witness):

    # compression
    dimension_padded_input = ceil((len(input) + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH # padding with one poly describing the dimension and zero polynomials
    dimension_input_in_bits = [int(x) for x in list(binary_repr(len(input), DEGREE_HASH))] # can be only the part with the dimension without ", DEGREE_HASH", but need to change in the proof part
    iterations_compression = dimension_padded_input // BITS_MODULUS_HASH
    compressed_input = initial_vector
    for i in range(iterations_compression - 1):
        block_from_padded_input = input + (i * BITS_MODULUS_HASH)
        compressed_input, lifting = clib_compression_step(compressed_input, block_from_padded_input)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness_pointer(ffi.cast("int64_t*", compressed_input[j]), DEGREE_HASH)
            decomposed_lifting = clib_decomp_64(lifting)
            for j in range(2):
                PS.append_witness_pointer(decomposed_lifting[j], DEGREE_HASH)
    block_from_padded_input = ffi.new("poly512[]", BITS_MODULUS_HASH)
    last_block = (iterations_compression - 1) * BITS_MODULUS_HASH
    for poly in range(len(input) - last_block):
        for coeff in range(DEGREE_HASH):
            block_from_padded_input[poly][coeff] = input[last_block + poly][coeff]
    for coeff in range(DEGREE_HASH):
        block_from_padded_input[BITS_MODULUS_HASH - 1][coeff] = dimension_input_in_bits[coeff]
    compressed_input, lifting = clib_compression_step(compressed_input, block_from_padded_input)
    if PS != None:
        for j in range(BITS_MODULUS_HASH):
            PS.append_witness_pointer(ffi.cast("int64_t*", compressed_input[j]), DEGREE_HASH)
        decomposed_lifting = clib_decomp_64(lifting)
        for j in range(2):
            PS.append_witness_pointer(decomposed_lifting[j], DEGREE_HASH)
    if PS == None:
        return compressed_input
    
    # proof compression
    
    # if iterations_compression == 1:
    #     left_list = [URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH + i) for i in range(len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
    #     indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    #     next_witness += BITS_MODULUS_HASH
    #     indices_witness = indices_input + indices_compressed_input + [next_witness + i for i in range(2)]
    #     next_witness += 2
    #     right_pol = ZERO_IN_RING_PROOF.copy()
    #     for i in range(BITS_MODULUS_HASH):
    #         right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * initial_vector.get_elem(i)
    #     right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * convert_array_to_poly_t(dimension_input_in_bits)
    #     PS.append_statement(left_list, indices_witness, right_pol)
    # else:
    #     left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH, BITS_MODULUS_HASH * COMPRESSION_FACTOR)] + COMMON_LEFT_PART_COMPRESSION
    #     indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    #     next_witness += BITS_MODULUS_HASH
    #     indices_witness = indices_input[ : BITS_MODULUS_HASH] + indices_compressed_input + [next_witness + i for i in range(2)]
    #     next_witness += 2
    #     right_pol = ZERO_IN_RING_PROOF.copy()
    #     for i in range(BITS_MODULUS_HASH):
    #         right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * initial_vector.get_elem(i)
    #     PS.append_statement(left_list, indices_witness, right_pol)
    #     if iterations_compression > 2:
    #         left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR)] + COMMON_LEFT_PART_COMPRESSION
    #         for i in range(1, iterations_compression - 1):
    #             indices_witness = indices_compressed_input + [indices_input[i] for i in range(i * BITS_MODULUS_HASH, (i + 1) * BITS_MODULUS_HASH)] + [next_witness + i for i in range(BITS_MODULUS_HASH + 2)]
    #             indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    #             next_witness += BITS_MODULUS_HASH + 2
    #             PS.append_statement(left_list, indices_witness, ZERO_IN_RING_PROOF)
    #     left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR - padded_input.dim + len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
    #     indices_witness = indices_compressed_input + [indices_input[i] for i in range((iterations_compression - 1) * BITS_MODULUS_HASH, len(indices_input))] + [next_witness + i for i in range(BITS_MODULUS_HASH + 2)]
    #     indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    #     next_witness += BITS_MODULUS_HASH + 2
    #     right_pol = ZERO_IN_RING_PROOF.copy()
    #     right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * convert_array_to_poly_t(dimension_input_in_bits)
    #     PS.append_statement(left_list, indices_witness, right_pol)
    
    minim = min(len(indices_input), BITS_MODULUS_HASH)
    left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH, BITS_MODULUS_HASH + minim)] + COMMON_LEFT_PART_COMPRESSION
    indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    next_witness += BITS_MODULUS_HASH
    indices_witness = indices_input[ : minim] + indices_compressed_input + [next_witness + i for i in range(2)]
    next_witness += 2
    right_pol = ZERO_IN_RING_PROOF.copy()
    for i in range(BITS_MODULUS_HASH):
        right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * convert_array_to_poly_t(initial_vector[i])
    if iterations_compression == 1:
        right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * convert_array_to_poly_t(dimension_input_in_bits)
    PS.append_statement(left_list, indices_witness, right_pol)
    for i in range(1, iterations_compression - 1):
        indices_previous_compressed_input = indices_compressed_input
        indices_compressed_input = [next_witness + j for j in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_compressed_input + [indices_input[j] for j in range(i * BITS_MODULUS_HASH, (i + 1) * BITS_MODULUS_HASH)] + indices_compressed_input + [next_witness + j for j in range(2)]
        next_witness += 2
        PS.append_statement(LEFT_LIST_COMPRESSION, indices_witness, ZERO_IN_RING_PROOF)        
    if iterations_compression > 1:
        left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR - dimension_padded_input + len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
        indices_previous_compressed_input = indices_compressed_input
        indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_compressed_input + [indices_input[i] for i in range((iterations_compression - 1) * BITS_MODULUS_HASH, len(indices_input))] + indices_compressed_input + [next_witness + i for i in range(2)]
        next_witness += 2
        right_pol = ZERO_IN_RING_PROOF.copy()
        right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * convert_array_to_poly_t(dimension_input_in_bits)
        PS.append_statement(left_list, indices_witness, right_pol)
    return compressed_input, PS, indices_compressed_input, next_witness

def mixing(compressed_input, PS, indices_compressed_input, next_witness):
    mixed_input, lifting = clib_mix_256(compressed_input, 0)
    if PS != None:
        for i in range(BITS_MODULUS_HASH):
            PS.append_witness_pointer(ffi.cast("int64_t*", mixed_input[i]), DEGREE_HASH)
        decomposed_lifting = clib_decomp_64(lifting)
        for i in range(2):
            PS.append_witness_pointer(decomposed_lifting[i], DEGREE_HASH)
        indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH   
        indices_witness = indices_compressed_input + indices_mixed_input + [next_witness + i for i in range(2)]    
        next_witness += 2
        PS.append_statement(LEFT_LIST_FIRST_MIX, indices_witness, - CONSTANTS[0])
    for i in range(ITERATIONS_MIXING):
        mixed_input, lifting = clib_mix_257(mixed_input)
        if PS != None:
            for j in range(BITS_MODULUS_MIXING):
                PS.append_witness_pointer(ffi.cast("int64_t*", mixed_input[j]), DEGREE_HASH)
            indices_previous_mixed_input = indices_mixed_input
            indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_MIXING)]
            next_witness += BITS_MODULUS_MIXING
            mixed_input_vec = convert_array_to_polyvec_t(mixed_input) #
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness(mixed_input_vec.get_elem(j) + mixed_input_vec.get_elem(BITS_MODULUS_HASH)) #
                indices_witness = [indices_mixed_input[j], indices_mixed_input[BITS_MODULUS_HASH], next_witness + j]
                PS.append_statement(LEFT_LIST_DECOMP_257, indices_witness, ZERO_IN_RING_PROOF)
            next_witness += BITS_MODULUS_HASH
            decomposed_lifting = clib_decomp_64(lifting)
            for j in range(2):
                PS.append_witness_pointer(decomposed_lifting[j], DEGREE_HASH)
            indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness + i for i in range(2)]
            next_witness += 2
            PS.append_statement(LEFT_LIST_MIX_257, indices_witness, ZERO_IN_RING_PROOF)
        mixed_input, lifting = clib_mix_256(mixed_input, i + 1)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness_pointer(ffi.cast("int64_t*", mixed_input[j]), DEGREE_HASH)
            decomposed_lifting = clib_decomp_64(lifting)
            for j in range(2):
                PS.append_witness_pointer(decomposed_lifting[j], DEGREE_HASH)
            indices_previous_mixed_input = indices_mixed_input
            indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness + i for i in range(2)]
            next_witness += 2
            PS.append_statement(LEFT_LIST_MIX_256, indices_witness, - CONSTANTS[i + 1])
    list_coeffs_msb_mixed_input = [list(mixed_input[i]) for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
    msb_mixed_input = ffi.new("poly512 []", list_coeffs_msb_mixed_input) # could do better? would it matter?
    # msb_mixed_input = mixed_input + BITS_MODULUS_HASH - BITS_SEED_EXPANSION
    if PS == None:
        return msb_mixed_input
    indices_msb_mixed_input = [indices_mixed_input[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
    return msb_mixed_input, PS, indices_msb_mixed_input, next_witness

def binary_expansion(seed_expansion, dimension_binary_output, PS, indices_seed_expansion, next_witness):
    iterations_binary_expansion = max(1, ceil((dimension_binary_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    binary_output = polyvec_t(RING_PROOF, dimension_binary_output)
    if PS != None:
        indices_binary_output = []
    for i in range(iterations_binary_expansion - 1):
        mlwr_vector_tmp, lifting = clib_squeeze(seed_expansion)
        seed_expansion = mlwr_vector_tmp + (BITS_MODULUS_HASH - BITS_SEED_EXPANSION)
        for j in range(BITS_TO_OUTPUT): 
            binary_output.set_elem(poly_t(RING_PROOF, list(mlwr_vector_tmp[BITS_TO_DISCARD + j])), BITS_TO_OUTPUT * i + j)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness_pointer(ffi.cast("int64_t*", mlwr_vector_tmp[j]), DEGREE_HASH)
            PS.append_witness_pointer(lifting, DEGREE_HASH)
            indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_lifting = [next_witness]
            next_witness += 1
            indices_witness = indices_seed_expansion + indices_mlwr_vector + indices_lifting
            PS.append_statement(LEFT_LIST_BINARY_EXPANSION, indices_witness, ZERO_IN_RING_PROOF)
            indices_seed_expansion = [indices_mlwr_vector[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
            indices_binary_output += [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + BITS_TO_OUTPUT)]
    mlwr_vector_tmp, lifting = clib_squeeze(seed_expansion)
    rem = min(dimension_binary_output - BITS_TO_OUTPUT * (iterations_binary_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
    for j in range(rem):
        binary_output.set_elem(poly_t(RING_PROOF, list(mlwr_vector_tmp[BITS_TO_DISCARD + j])), BITS_TO_OUTPUT * (iterations_binary_expansion - 1) + j)
    if PS != None:
        for j in range(BITS_MODULUS_HASH):
            PS.append_witness_pointer(ffi.cast("int64_t*", mlwr_vector_tmp[j]), DEGREE_HASH)
        PS.append_witness_pointer(lifting, DEGREE_HASH)
        indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_lifting = [next_witness]
        next_witness += 1
        indices_witness = indices_seed_expansion + indices_mlwr_vector + indices_lifting
        PS.append_statement(LEFT_LIST_BINARY_EXPANSION, indices_witness, ZERO_IN_RING_PROOF)
        indices_seed_expansion = [indices_mlwr_vector[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
        indices_binary_output += [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + rem)]        
    if PS == None:
        return binary_output
    return binary_output, PS, indices_binary_output, next_witness

def hash(input_polyvec_t, initial_vector_polyvec_t, dimension_binary_output, PS = None, indices_input = None, next_witness  = None):
    assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
    assert input_polyvec_t.is_binary(), "Input must be binary."
    input = ffi.new("poly512 []", input_polyvec_t.dim)
    for poly in range(input_polyvec_t.dim):
        for coeff in range(DEGREE_HASH):
            input[poly][coeff] = input_polyvec_t[poly][coeff]
    
    assert initial_vector_polyvec_t.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension BITS_MODULUDS_HASH."
    assert initial_vector_polyvec_t.ring.deg == DEGREE_HASH, "Initial vector must be of ring degree DEGREE_HASH"
    assert initial_vector_polyvec_t.is_binary(), "Initial vector must be binary."
    initial_vector = ffi.new("poly512 []", BITS_MODULUS_HASH)
    for poly in range(BITS_MODULUS_HASH):
        for coeff in range(DEGREE_HASH):
            initial_vector[poly][coeff] = initial_vector_polyvec_t[poly][coeff]

    if PS == None:
        compression_start_time = time.perf_counter()
        compressed_input = compression(input, initial_vector, None, None, None)
        compression_end_time = time.perf_counter()
        print("Compression time:", compression_end_time - compression_start_time)
        list_coeffs_compressed_input = [list(compressed_input[i]) for i in range(BITS_MODULUS_HASH)] + [[0] * DEGREE_HASH]
        compressed_input = ffi.new("poly512 []", list_coeffs_compressed_input)
        mixing_start_time = time.perf_counter()
        seed_expansion = mixing(compressed_input, None, None, None)
        mixing_end_time = time.perf_counter()
        print("Mixing time:", mixing_end_time - mixing_start_time)
        expansion_start_time = time.perf_counter()
        binary_output = binary_expansion(seed_expansion, dimension_binary_output, None, None, None)
        expansion_end_time = time.perf_counter()
        print("Expansion time:", expansion_end_time - expansion_start_time)
        return binary_output
    compression_start_time = time.perf_counter()
    compressed_input, PS, indices_compressed_input, next_witness = compression(input, initial_vector, PS, indices_input, next_witness)
    compression_end_time = time.perf_counter()
    print("Compression time:", compression_end_time - compression_start_time)
    list_coeffs_compressed_input = [list(compressed_input[i]) for i in range(BITS_MODULUS_HASH)] + [[0] * DEGREE_HASH]
    compressed_input = ffi.new("poly512 []", list_coeffs_compressed_input)
    mixing_start_time = time.perf_counter()
    seed_expansion, PS, indices_seed_expansion, next_witness = mixing(compressed_input, PS, indices_compressed_input, next_witness)
    mixing_end_time = time.perf_counter()
    print("Mixing time:", mixing_end_time - mixing_start_time)
    expansion_start_time = time.perf_counter()
    binary_output, PS, indices_binary_output, next_witness = binary_expansion(seed_expansion, dimension_binary_output, PS, indices_seed_expansion, next_witness)
    expansion_end_time = time.perf_counter()
    print("Expansion time:", expansion_end_time - expansion_start_time)
    return binary_output, PS, indices_binary_output, next_witness
    
    
# temp test
if __name__ == "__main__":
    dimension_input, dimension_binary_output = 1000, 1000

    # only hash, no check for correctness
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output = hash(input, initial_vector, dimension_binary_output)

    # hash and proof
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True)
    next_witness = 0
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(input.dim):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output, PS, indices_binary_output, next_witness = hash(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)

    print("Time proof:", proof_end_time - proof_start_time)
