import sys
sys.path.append('..')   # path to lazer module 
from lazer import *     # import lazer python module
from labrados import *
from math import log2, ceil, sqrt
from random import randrange
from numpy import binary_repr
from urand_matrix import *
import time

# Hash variables
DEGREE_HASH = 512
MODULUS_HASH = 256
MODULUS_MIXING = 257
MODULUS_PROOF = LAB_RING_38.mod
SIZE_MODULUS_PROOF = str(ceil(log2(MODULUS_PROOF)))
RING_PROOF = polyring_t(DEGREE_HASH, MODULUS_PROOF)
ITERATIONS_MIXING = 4
BITS_MODULUS_HASH = ceil(log2(MODULUS_HASH))
BITS_MODULUS_MIXING = ceil(log2(MODULUS_MIXING))
BITS_SEED_EXPANSION = 2
BITS_MODULUS_EXPANSION = 6
BITS_TO_DISCARD = BITS_MODULUS_HASH - BITS_MODULUS_EXPANSION
BITS_TO_OUTPUT =  BITS_MODULUS_HASH - BITS_SEED_EXPANSION - BITS_TO_DISCARD
NUMBER_WITNESSES_MIX = (BITS_MODULUS_HASH + 1) * (ITERATIONS_MIXING + 1) + (BITS_MODULUS_MIXING + BITS_MODULUS_HASH + 1) * ITERATIONS_MIXING
NORM_BINARY = 0
SQNORM_LIFTING_COMPRESSION = 2**32
SQNORM_LIFTING_MIXING = 2 ** 30
BOUND_APPROX_COMPRESSION = 2 ** 58
BOUND_APPROX_MIXING = 2 ** 58
BASE_LIFTINGS_COMPRESSION = 64 # only option supported
SQNORM_COMPONENTS_LIFTING_COMPRESSION = BASE_LIFTINGS_COMPRESSION ** 2 * DEGREE_HASH
SQNORM_LIFTING_EXPANSION = round((1.45 * RING_PROOF.deg / sqrt(12) + sqrt(RING_PROOF.deg)) ** 2)
BOUND_APPROX_EXPANSION = 2 ** 60

# matrix uniformly random in MODULUS_HASH, used in the hash function
COMPRESSION_FACTOR = 2 
DIMENSION_MATRIX_HASH = BITS_MODULUS_HASH * COMPRESSION_FACTOR # matrix 1 x 16, seen as a vector
URANDOM_MATRIX_HASH = polyvec_t(RING_PROOF, DIMENSION_MATRIX_HASH, list_urandom_matrix_hash)

# constants for mixing
CONSTANTS = [poly_t(RING_PROOF, list_constants[i]) for i in range(ITERATIONS_MIXING + 1)]

# precompute part of statements
ONE_IN_RING_PROOF = int_to_poly(1, RING_PROOF)
ZERO_IN_RING_PROOF = poly_t(RING_PROOF)
COMMON_LEFT_PART_COMPRESSION = [- 2 ** i * ONE_IN_RING_PROOF  for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH]
LEFT_LIST_COMPRESSION = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR)] + COMMON_LEFT_PART_COMPRESSION
LEFT_LIST_FIRST_MIX = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH]
LEFT_LIST_DECOMP_257 = [ONE_IN_RING_PROOF, ONE_IN_RING_PROOF, - ONE_IN_RING_PROOF]
LEFT_LIST_MIX_257 = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_MIXING)] + [- ONE_IN_RING_PROOF * MODULUS_MIXING]
LEFT_LIST_MIX_256 = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_MIXING)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF * MODULUS_HASH]
INDEX_NEGATIVE_POWER = BITS_MODULUS_HASH - BITS_MODULUS_EXPANSION - 1
LEFT_LIST_BINARY_EXPANSION = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_SEED_EXPANSION)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER)] + [2 ** INDEX_NEGATIVE_POWER * ONE_IN_RING_PROOF] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER + 1, BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]
LEFT_LIST_EXPANSION_PUBLIC_OUTPUT = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_SEED_EXPANSION)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER)] + [2 ** INDEX_NEGATIVE_POWER * ONE_IN_RING_PROOF] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER + BITS_TO_OUTPUT+ 1, BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]


class proof_statement_description:
    def __init__(self, list_degrees = None, list_number_polynomials = None, list_norm_constraints = None, number_constraints = None, num_deg0_constraints = None, approx_norm_list = None):
        if list_degrees == None:
            self.list_degrees = []
            self.list_number_polynomials = []
            self.list_norm_constraints = []
            self.number_constraints = 0
            self.num_deg0_constraints = 0
            self.approx_norm_list = []
        else:
            self.list_degrees = list_degrees
            self.list_number_polynomials = list_number_polynomials
            self.list_norm_constraints = list_norm_constraints
            self.number_constraints = number_constraints
            self.num_deg0_constraints = num_deg0_constraints
            self.approx_norm_list = approx_norm_list


# Functions
def convert_polyvec_to_poly512(input):
    output = ffi.new("poly512 []", input.dim)
    output[0:input.dim] = [input.get_elem(poly).to_list(in64bits=True) for poly in range(input.dim)]
    return output

def convert_poly512_to_poly(input, ring):
    output = poly_t(ring, list(input))
    return output

def convert_poly512_to_polyvec(input, ring):
    output = polyvec_t(ring, len(input))
    for poly in range(len(input)):
        output.set_elem(convert_poly512_to_poly(input[poly], ring), poly)
    return output

def compute_number_witnesses_compress(dimension_input, output_in_witness):
    
    iterations_compression = ceil((dimension_input + 1) / BITS_MODULUS_HASH)
    
    if output_in_witness:
        return (BITS_MODULUS_HASH + 1) * iterations_compression
    
    return (BITS_MODULUS_HASH + 1) * (iterations_compression - 1) + 1

def compute_number_witnesses_expand(dimension_output, output_in_witness):
    
    iterations_expansion = max(1, ceil((dimension_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    
    if output_in_witness:
        return (BITS_MODULUS_HASH + 1) * iterations_expansion
    
    rem = min(dimension_output - BITS_TO_OUTPUT * (iterations_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
    return (BITS_MODULUS_HASH - BITS_TO_OUTPUT + 1) * (iterations_expansion - 1) + (BITS_MODULUS_HASH - rem + 1)

def compress_internal(input, initial_vector, with_proof, output_in_witness = True):
    iterations_compression = ceil((len(input) + 1) / BITS_MODULUS_HASH)
    if with_proof:
        number_witnesses_compress = compute_number_witnesses_compress(len(input), output_in_witness)
        trace_compression = ffi.new("signed_poly512 []", number_witnesses_compress)

    compressed_input = ffi.new("poly512 []", BITS_MODULUS_HASH)
    ffi.memmove(compressed_input, initial_vector, BITS_MODULUS_HASH * ffi.sizeof("poly512"))
    lifting = ffi.new("signed_poly512")
    for i in range(iterations_compression - 1):
        block_from_input = input + (i * BITS_MODULUS_HASH)
        lib.absorb(compressed_input, lifting, compressed_input, block_from_input)
        if with_proof:
            pos_in_trace = (BITS_MODULUS_HASH + 1) * i
            ffi.memmove(trace_compression + pos_in_trace, compressed_input, ffi.sizeof(compressed_input))
            ffi.memmove(trace_compression + pos_in_trace + BITS_MODULUS_HASH, lifting, ffi.sizeof(lifting))
    i = iterations_compression - 1
    block_from_input = ffi.new("poly512 []", BITS_MODULUS_HASH)
    ffi.memmove(block_from_input, input + i * BITS_MODULUS_HASH, (len(input) - i * BITS_MODULUS_HASH) * ffi.sizeof("poly512")) 
    dimension_input_in_bits = [int(x) for x in list(binary_repr(len(input)))]
    block_from_input[BITS_MODULUS_HASH - 1][DEGREE_HASH - len(dimension_input_in_bits) : DEGREE_HASH] = dimension_input_in_bits[:]
    lib.absorb(compressed_input, lifting, compressed_input, block_from_input)
    if with_proof:
        pos_in_trace = (BITS_MODULUS_HASH + 1) * i
        if output_in_witness:
            ffi.memmove(trace_compression + pos_in_trace, compressed_input, ffi.sizeof(compressed_input))
            ffi.memmove(trace_compression + pos_in_trace + BITS_MODULUS_HASH, lifting, ffi.sizeof(lifting))
        else:
            ffi.memmove(trace_compression + pos_in_trace, lifting, ffi.sizeof(lifting))
    if with_proof:
        return compressed_input, trace_compression
    return compressed_input

def mix(input, with_proof):

    if with_proof:
        trace_mixing = ffi.new("signed_poly512 []", NUMBER_WITNESSES_MIX)

    mixed_input_256 = ffi.new("poly512 []", BITS_MODULUS_HASH)
    mixed_input_257 = ffi.new("poly512 []", BITS_MODULUS_MIXING)
    lifting = ffi.new("signed_poly512")
    
    ffi.memmove(mixed_input_257, input, BITS_MODULUS_HASH * ffi.sizeof("poly512"))
    lib.mix_256(mixed_input_256, lifting, mixed_input_257, 0)

    if with_proof:
        ffi.memmove(trace_mixing, mixed_input_256, BITS_MODULUS_HASH * ffi.sizeof("poly512"))
        pos_in_trace = BITS_MODULUS_HASH
        ffi.memmove(trace_mixing + pos_in_trace, lifting, ffi.sizeof(lifting))
        pos_in_trace += 1

    for i in range(ITERATIONS_MIXING):
        lib.mix_257(mixed_input_257, lifting, mixed_input_256)
        if with_proof:
            ffi.memmove(trace_mixing + pos_in_trace, mixed_input_257, BITS_MODULUS_MIXING * ffi.sizeof("poly512"))
            pos_in_trace += BITS_MODULUS_MIXING
            for poly in range(BITS_MODULUS_HASH):
                for coeff in range(DEGREE_HASH):
                    trace_mixing[pos_in_trace + poly][coeff] = mixed_input_257[poly][coeff] + mixed_input_257[BITS_MODULUS_HASH][coeff]
            pos_in_trace += BITS_MODULUS_HASH
            ffi.memmove(trace_mixing + pos_in_trace, lifting, ffi.sizeof(lifting))
            pos_in_trace += 1
        
        lib.mix_256(mixed_input_256, lifting, mixed_input_257, i + 1)
        if with_proof:
            ffi.memmove(trace_mixing + pos_in_trace, mixed_input_256, BITS_MODULUS_HASH * ffi.sizeof("poly512"))
            pos_in_trace += BITS_MODULUS_HASH
            ffi.memmove(trace_mixing + pos_in_trace, lifting, ffi.sizeof(lifting))
            pos_in_trace += 1
           
    mixed_msb = ffi.new("poly512 []", BITS_SEED_EXPANSION)
    ffi.memmove(mixed_msb, mixed_input_256 + BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_SEED_EXPANSION * ffi.sizeof("poly512"))

    if with_proof:
        return mixed_msb, trace_mixing
    return mixed_msb

def expand_internal(seed, dimension_output, with_proof, output_in_witness):

    if with_proof:
        number_witnesses_expand = compute_number_witnesses_expand(dimension_output, output_in_witness)
        trace_expansion = ffi.new("signed_poly512 []", number_witnesses_expand)
    
    output = ffi.new("poly512 []", dimension_output)
    image_squeeze = ffi.new("poly512 []", BITS_MODULUS_HASH)
    lifting = ffi.new("signed_poly512")

    iterations_expansion = max(1, ceil((dimension_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    for i in range(iterations_expansion - 1):
        lib.squeeze(image_squeeze, lifting, seed)
        seed = image_squeeze + BITS_TO_DISCARD + BITS_TO_OUTPUT
        ffi.memmove(output + i * BITS_TO_OUTPUT, image_squeeze + BITS_TO_DISCARD, BITS_TO_OUTPUT * ffi.sizeof("poly512"))
        seed = image_squeeze + BITS_TO_DISCARD + BITS_TO_OUTPUT
        if with_proof:
            if output_in_witness:
                pos_in_trace = (BITS_MODULUS_HASH + 1) * i
                ffi.memmove(trace_expansion + pos_in_trace, image_squeeze, ffi.sizeof(image_squeeze))
                ffi.memmove(trace_expansion + pos_in_trace + BITS_MODULUS_HASH, lifting, ffi.sizeof(lifting))
            else:
                pos_in_trace = (BITS_TO_DISCARD + BITS_SEED_EXPANSION + 1) * i
                ffi.memmove(trace_expansion + pos_in_trace, image_squeeze, BITS_TO_DISCARD * ffi.sizeof("poly512"))
                pos_in_trace += BITS_TO_DISCARD
                ffi.memmove(trace_expansion + pos_in_trace, image_squeeze + BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_SEED_EXPANSION * ffi.sizeof("poly512"))
                pos_in_trace += BITS_SEED_EXPANSION
                ffi.memmove(trace_expansion + pos_in_trace, lifting, ffi.sizeof(lifting))

    i = iterations_expansion - 1
    lib.squeeze(image_squeeze, lifting, seed)
    ffi.memmove(output + i * BITS_TO_OUTPUT, image_squeeze + BITS_TO_DISCARD, (dimension_output - i * BITS_TO_OUTPUT) * ffi.sizeof("poly512"))
    if with_proof:
        if output_in_witness:
            pos_in_trace = (BITS_MODULUS_HASH + 1) * i
            ffi.memmove(trace_expansion + pos_in_trace, image_squeeze, ffi.sizeof(image_squeeze))
            ffi.memmove(trace_expansion + pos_in_trace + BITS_MODULUS_HASH, lifting, ffi.sizeof(lifting))
        else:
            pos_in_trace = (BITS_TO_DISCARD + BITS_SEED_EXPANSION + 1) * i
            ffi.memmove(trace_expansion + pos_in_trace, image_squeeze, BITS_TO_DISCARD * ffi.sizeof("poly512"))
            pos_in_trace += BITS_TO_DISCARD
            rem = min(dimension_output - BITS_TO_OUTPUT * (iterations_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
            ffi.memmove(trace_expansion + pos_in_trace, image_squeeze + BITS_TO_DISCARD + rem, (BITS_MODULUS_HASH - BITS_TO_DISCARD - rem) * ffi.sizeof("poly512"))
            pos_in_trace += BITS_MODULUS_HASH - BITS_TO_DISCARD - rem
            ffi.memmove(trace_expansion + pos_in_trace, lifting, ffi.sizeof(lifting))
    
    if with_proof:
        return output, trace_expansion
    return output

# inputs: the input of the hash function of the initial vector are poly512 []
def compute_hash_internal(input, initial_vector, dimension_output, with_proof, output_in_witness):

    if not with_proof:
        compressed_input = compress_internal(input, initial_vector, with_proof)
        mixed_msb = mix(compressed_input, with_proof)
        output = expand_internal(mixed_msb, dimension_output, with_proof, dimension_output)
        return output
    
    compressed_input, trace_compression = compress_internal(input, initial_vector, with_proof, True)
    mixed_msb, trace_mixing = mix(compressed_input, with_proof)
    output, trace_expansion = expand_internal(mixed_msb, dimension_output, with_proof, output_in_witness)
    trace = [trace_compression, trace_mixing, trace_expansion]
    return output, trace

# inputs: the input of the hash function and the initial vector are polyvec_t
def compress(input_polyvec_t, initial_vector_polyvec_t, with_proof = False, output_in_witness = True):
    
    # input as poly512 []
    assert input_polyvec_t.dim < 2 ** DEGREE_HASH, "Input dimension must be < 2 ** DEGREE_HASH."
    assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
    # assert input_polyvec_t.is_binary(), "Input must be binary."
    input = convert_polyvec_to_poly512(input_polyvec_t)
    
    # initial vector as poly512 []
    assert initial_vector_polyvec_t.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension BITS_MODULUDS_HASH."
    assert initial_vector_polyvec_t.ring.deg == DEGREE_HASH, "Initial vector must be of ring degree DEGREE_HASH"
    assert initial_vector_polyvec_t.is_binary(), "Initial vector must be binary."
    initial_vector = convert_polyvec_to_poly512(initial_vector_polyvec_t)

    if not with_proof:
        output = compress_internal(input, initial_vector, with_proof)
        return convert_poly512_to_polyvec(output, RING_PROOF)
    
    output, trace = compress_internal(input, initial_vector, with_proof, output_in_witness)
    return convert_poly512_to_polyvec(output, RING_PROOF), trace

# inputs: the input of the hash function and the initial vector are polyvec_t
def expand(input_polyvec_t, dimension_output, with_proof = False, output_in_witness = False):
    
    # input as poly512 []
    assert input_polyvec_t.dim == 2, "Input dimension must be 2."
    assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
    # assert input_polyvec_t.is_binary(), "Input must be binary."
    input = convert_polyvec_to_poly512(input_polyvec_t)

    if not with_proof:
        output = expand_internal(input, dimension_output, with_proof, output_in_witness)
        return convert_poly512_to_polyvec(output, RING_PROOF)
    
    output, trace = expand_internal(input, dimension_output, with_proof, output_in_witness)
    return convert_poly512_to_polyvec(output, RING_PROOF), trace

# inputs: the input of the hash function and the initial vector are polyvec_t
def compute_hash(input_polyvec_t, initial_vector_polyvec_t, dimension_output, with_proof = False, output_in_witness = False):
    
    # input as poly512 []
    assert input_polyvec_t.dim < 2 ** DEGREE_HASH, "Input dimension must be < 2 ** DEGREE_HASH."
    assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
    # assert input_polyvec_t.is_binary(), "Input must be binary."
    input = convert_polyvec_to_poly512(input_polyvec_t)
    
    # initial vector as poly512 []
    assert initial_vector_polyvec_t.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension BITS_MODULUDS_HASH."
    assert initial_vector_polyvec_t.ring.deg == DEGREE_HASH, "Initial vector must be of ring degree DEGREE_HASH"
    # assert initial_vector_polyvec_t.is_binary(), "Initial vector must be binary."
    initial_vector = convert_polyvec_to_poly512(initial_vector_polyvec_t)

    if not with_proof:
        output = compute_hash_internal(input, initial_vector, dimension_output, with_proof, output_in_witness)
        return convert_poly512_to_polyvec(output, RING_PROOF)
    
    output, trace = compute_hash_internal(input, initial_vector, dimension_output, with_proof, output_in_witness)
    return convert_poly512_to_polyvec(output, RING_PROOF), trace

def description_knowledge_compression_preimage(PS_description, dimension_input, output_in_witness = True):
    
    iterations_compression = ceil((dimension_input + 1) / BITS_MODULUS_HASH)
    number_witnesses_compression = compute_number_witnesses_compress(dimension_input, output_in_witness)

    if output_in_witness:
        PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_compression
        PS_description.list_number_polynomials += [1] * number_witnesses_compression
        next_norm_constraint = len(PS_description.list_norm_constraints)
        PS_description.list_norm_constraints += ([NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_COMPRESSION]) * iterations_compression
        PS_description.approx_norm_list += [(next_norm_constraint + (BITS_MODULUS_HASH + 1) * i + BITS_MODULUS_HASH, BOUND_APPROX_COMPRESSION) for i in range(iterations_compression)]
        PS_description.number_constraints += iterations_compression
        return PS_description
    
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_compression
    PS_description.list_number_polynomials += [1] * number_witnesses_compression
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += ([NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_COMPRESSION]) * (iterations_compression - 1) + [SQNORM_LIFTING_COMPRESSION]
    PS_description.approx_norm_list += [(next_norm_constraint + (BITS_MODULUS_HASH + 1) * i + BITS_MODULUS_HASH, BOUND_APPROX_COMPRESSION) for i in range(iterations_compression - 1)] + [(next_norm_constraint + (BITS_MODULUS_HASH + 1) * (iterations_compression - 1), BOUND_APPROX_COMPRESSION)]
    PS_description.number_constraints += iterations_compression
    return PS_description

def description_knowledge_mixing_preimage(PS_description):
    
    PS_description.list_degrees += [RING_PROOF.deg] * NUMBER_WITNESSES_MIX
    PS_description.list_number_polynomials += [1] * NUMBER_WITNESSES_MIX
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += [NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_MIXING] + ([NORM_BINARY] * (BITS_MODULUS_MIXING + BITS_MODULUS_HASH) + [SQNORM_LIFTING_MIXING] + [NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_MIXING]) * ITERATIONS_MIXING
    PS_description.approx_norm_list += [(next_norm_constraint + BITS_MODULUS_HASH, BOUND_APPROX_MIXING)]
    next_norm_constraint += BITS_MODULUS_HASH + 1
    for i in range(ITERATIONS_MIXING):
        PS_description.approx_norm_list += [(next_norm_constraint + BITS_MODULUS_HASH + BITS_MODULUS_MIXING, BOUND_APPROX_MIXING)]
        next_norm_constraint += BITS_MODULUS_HASH + BITS_MODULUS_MIXING + 1
        PS_description.approx_norm_list += [(next_norm_constraint + BITS_MODULUS_HASH, BOUND_APPROX_MIXING)]
        next_norm_constraint += BITS_MODULUS_HASH + 1
    PS_description.number_constraints += 1 + ITERATIONS_MIXING * BITS_MODULUS_HASH + 2 * ITERATIONS_MIXING
    return PS_description

def description_knowledge_expansion_preimage(PS_description, dimension_output, output_in_witness = False):
    
    iterations_binary_expansion = max(1, ceil((dimension_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    number_witnesses_expansion = compute_number_witnesses_expand(dimension_output, output_in_witness)
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_expansion
    PS_description.list_number_polynomials += [1] * number_witnesses_expansion
    if output_in_witness:
        next_norm_constraint = len(PS_description.list_norm_constraints)
        PS_description.list_norm_constraints += ([NORM_BINARY] * BITS_MODULUS_HASH + [SQNORM_LIFTING_EXPANSION]) * iterations_binary_expansion
        PS_description.approx_norm_list += [(next_norm_constraint + (BITS_MODULUS_HASH + 1) * i + BITS_MODULUS_HASH, BOUND_APPROX_EXPANSION) for i in range(iterations_binary_expansion)]
    else:
        rem = min(dimension_output - BITS_TO_OUTPUT * (iterations_binary_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
        next_norm_constraint = len(PS_description.list_norm_constraints)
        PS_description.list_norm_constraints += ([NORM_BINARY] * (BITS_TO_DISCARD + BITS_SEED_EXPANSION) + [SQNORM_LIFTING_EXPANSION]) * (iterations_binary_expansion - 1) + [NORM_BINARY] * (BITS_MODULUS_HASH - rem) + [SQNORM_LIFTING_EXPANSION]
        PS_description.approx_norm_list += [(next_norm_constraint + (BITS_TO_DISCARD + BITS_SEED_EXPANSION + 1) * i + BITS_TO_DISCARD + BITS_SEED_EXPANSION, BOUND_APPROX_EXPANSION) for i in range(iterations_binary_expansion - 1)] + [(next_norm_constraint + (BITS_TO_DISCARD + BITS_SEED_EXPANSION + 1) * (iterations_binary_expansion - 1) + (BITS_MODULUS_HASH - rem), BOUND_APPROX_EXPANSION)]
    PS_description.number_constraints += iterations_binary_expansion
    return PS_description

def description_knowledge_hash_preimage(PS_description, dimension_input, dimension_output, output_in_witness = False):
    
    PS_description = description_knowledge_compression_preimage(PS_description, dimension_input, True)
    PS_description = description_knowledge_mixing_preimage(PS_description)
    PS_description = description_knowledge_expansion_preimage(PS_description, dimension_output, output_in_witness)
    return PS_description

def knowledge_compression_preimage(PS, next_witness, indices_input, trace_compression, initial_vector, output_in_witness = True, compressed_input = None):

    number_witnesses_compress = compute_number_witnesses_compress(len(indices_input), output_in_witness)
    for i in range(number_witnesses_compress):
        PS.append_witness_pointer(trace_compression[i], DEGREE_HASH)
    
    iterations_compression = ceil((len(indices_input) + 1) / BITS_MODULUS_HASH)
    dimension_input_in_bits = poly_t(RING_PROOF, [int(x) for x in list(binary_repr(len(indices_input), DEGREE_HASH))])
    minim = min(len(indices_input), BITS_MODULUS_HASH)
    left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH, BITS_MODULUS_HASH + minim)] + COMMON_LEFT_PART_COMPRESSION
    if output_in_witness:
        indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_input[ : minim] + indices_compressed_input + [next_witness]
        next_witness += 1    
        right_pol = ZERO_IN_RING_PROOF.copy()
        for i in range(BITS_MODULUS_HASH):
            right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * initial_vector.get_elem(i)
        if iterations_compression == 1:
            right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
        PS.append_statement(left_list, indices_witness, right_pol)
        for i in range(1, iterations_compression - 1):
            indices_previous_compressed_input = indices_compressed_input
            indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_witness = indices_previous_compressed_input + [indices_input[j] for j in range(i * BITS_MODULUS_HASH, (i + 1) * BITS_MODULUS_HASH)] + indices_compressed_input + [next_witness]
            next_witness += 1
            PS.append_statement(LEFT_LIST_COMPRESSION, indices_witness, ZERO_IN_RING_PROOF)
        if iterations_compression > 1:
            dimension_padded_input = ceil((len(indices_input) + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH #
            left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR - dimension_padded_input + len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
            indices_previous_compressed_input = indices_compressed_input
            indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_witness = indices_previous_compressed_input + [indices_input[i] for i in range((iterations_compression - 1) * BITS_MODULUS_HASH, len(indices_input))] + indices_compressed_input + [next_witness]
            next_witness += 1
            right_pol = ZERO_IN_RING_PROOF.copy()
            right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
            PS.append_statement(left_list, indices_witness, right_pol)
        return PS, next_witness, indices_compressed_input
    
    right_pol = ZERO_IN_RING_PROOF.copy()
    for i in range(BITS_MODULUS_HASH):
        right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * initial_vector.get_elem(i)
    if iterations_compression == 1:
        indices_witness = indices_input[ : minim] + [next_witness]
        next_witness += 1    
        right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
        for i in range(BITS_MODULUS_HASH):
            right_pol += 2 ** i * compressed_input.get_elem(i)
        left_list_output_public = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH, BITS_MODULUS_HASH + minim)] + [- ONE_IN_RING_PROOF * MODULUS_HASH]
        PS.append_statement(left_list_output_public, indices_witness, right_pol)
    else:
        indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_input[ : minim] + indices_compressed_input + [next_witness]
        next_witness += 1    
        PS.append_statement(left_list, indices_witness, right_pol)
    for i in range(1, iterations_compression - 1):
        indices_previous_compressed_input = indices_compressed_input
        indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_compressed_input + [indices_input[j] for j in range(i * BITS_MODULUS_HASH, (i + 1) * BITS_MODULUS_HASH)] + indices_compressed_input + [next_witness]
        next_witness += 1
        PS.append_statement(LEFT_LIST_COMPRESSION, indices_witness, ZERO_IN_RING_PROOF)
    if iterations_compression > 1:
        dimension_padded_input = ceil((len(indices_input) + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH #
        left_list_pu = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR - dimension_padded_input + len(indices_input))] + [- ONE_IN_RING_PROOF * MODULUS_HASH]
        indices_previous_compressed_input = indices_compressed_input
        indices_witness = indices_previous_compressed_input + [indices_input[i] for i in range((iterations_compression - 1) * BITS_MODULUS_HASH, len(indices_input))] + [next_witness]
        next_witness += 1
        right_pol = - URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
        for i in range(BITS_MODULUS_HASH):
            right_pol += 2 ** i * compressed_input.get_elem(i)
        PS.append_statement(left_list_pu, indices_witness, right_pol)
    return PS, next_witness

def knowledge_mixing_preimage(PS, next_witness, indices_compressed_input, trace_mixing):

    for i in range(NUMBER_WITNESSES_MIX):
        PS.append_witness_pointer(trace_mixing[i], DEGREE_HASH)

    indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    next_witness += BITS_MODULUS_HASH   
    indices_witness = indices_compressed_input + indices_mixed_input + [next_witness]    
    next_witness += 1
    PS.append_statement(LEFT_LIST_FIRST_MIX, indices_witness, - CONSTANTS[0])
    for i in range(ITERATIONS_MIXING):
        indices_previous_mixed_input = indices_mixed_input
        indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_MIXING)]
        next_witness += BITS_MODULUS_MIXING
        for j in range(BITS_MODULUS_HASH):
            indices_witness = [indices_mixed_input[j], indices_mixed_input[BITS_MODULUS_HASH], next_witness + j]
            PS.append_statement(LEFT_LIST_DECOMP_257, indices_witness, ZERO_IN_RING_PROOF)
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness]
        next_witness += 1
        PS.append_statement(LEFT_LIST_MIX_257, indices_witness, ZERO_IN_RING_PROOF)
        indices_previous_mixed_input = indices_mixed_input
        indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness]
        next_witness += 1
        PS.append_statement(LEFT_LIST_MIX_256, indices_witness, - CONSTANTS[i + 1])
    indices_mixed_msb = [indices_mixed_input[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
    return PS, next_witness, indices_mixed_msb

def knowledge_expansion_preimage(PS, next_witness, indices_seed, trace_expansion, info_output, output_in_witness = False):

    if output_in_witness:
        dimension_output = info_output
    else:
        output = info_output
        dimension_output = output.dim

    number_witnesses_expand = compute_number_witnesses_expand(dimension_output, output_in_witness)
    for i in range(number_witnesses_expand):
        PS.append_witness_pointer(trace_expansion[i], DEGREE_HASH)

    iterations_expansion = max(1, ceil((dimension_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check

    if output_in_witness:
        indices_output = []
        for i in range(iterations_expansion - 1):
            indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_lifting = [next_witness]
            next_witness += 1
            indices_witness = indices_seed + indices_mlwr_vector + indices_lifting
            PS.append_statement(LEFT_LIST_BINARY_EXPANSION, indices_witness, ZERO_IN_RING_PROOF)
            indices_seed = [indices_mlwr_vector[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
            indices_output += [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + BITS_TO_OUTPUT)]
        rem = min(dimension_output - BITS_TO_OUTPUT * (iterations_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
        indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_lifting = [next_witness]
        next_witness += 1
        indices_witness = indices_seed + indices_mlwr_vector + indices_lifting
        PS.append_statement(LEFT_LIST_BINARY_EXPANSION, indices_witness, ZERO_IN_RING_PROOF)
        indices_output += [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + rem)]        
        return PS, next_witness, indices_output
    
    for i in range(iterations_expansion - 1):
        indices_mlwr_vector = [next_witness + i for i in range(BITS_TO_DISCARD + BITS_SEED_EXPANSION)]
        next_witness += len(indices_mlwr_vector)
        indices_lifting = [next_witness]
        next_witness += 1
        indices_witness = indices_seed + indices_mlwr_vector + indices_lifting
        right_pol = ZERO_IN_RING_PROOF.copy()
        for j in range(BITS_TO_OUTPUT):
            right_pol += 2 ** (BITS_TO_DISCARD + j) * output.get_elem(BITS_TO_OUTPUT * i + j)
        PS.append_statement(LEFT_LIST_EXPANSION_PUBLIC_OUTPUT, indices_witness, right_pol)
        indices_seed = [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + BITS_SEED_EXPANSION)]
    rem = min(dimension_output - BITS_TO_OUTPUT * (iterations_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
    indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH - rem)]
    next_witness += len(indices_mlwr_vector)
    indices_lifting = [next_witness]
    next_witness += 1
    indices_witness = indices_seed + indices_mlwr_vector + indices_lifting
    left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_SEED_EXPANSION)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER)] + [2 ** INDEX_NEGATIVE_POWER * ONE_IN_RING_PROOF] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(INDEX_NEGATIVE_POWER + rem + 1, BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]
    right_pol = ZERO_IN_RING_PROOF.copy()
    for j in range(rem):
        right_pol += 2 ** (BITS_TO_DISCARD + j) * output.get_elem(BITS_TO_OUTPUT * (iterations_expansion - 1) + j)
    PS.append_statement(left_list, indices_witness, right_pol)
    return PS, next_witness

def knowledge_hash_preimage(PS, next_witness, indices_input, trace, initial_vector, info_output, output_in_witness = False):

    trace_compression = trace[0]
    PS, next_witness, indices_compressed_input = knowledge_compression_preimage(PS, next_witness, indices_input, trace_compression, initial_vector, True)

    trace_mixing = trace[1]
    PS, next_witness, indices_mixed_msb = knowledge_mixing_preimage(PS, next_witness, indices_compressed_input, trace_mixing)

    trace_expansion = trace[2]
    if output_in_witness:
        PS, next_witness, indices_output = knowledge_expansion_preimage(PS, next_witness, indices_mixed_msb, trace_expansion, info_output, output_in_witness)
        return PS, next_witness, indices_output
    
    PS, next_witness = knowledge_expansion_preimage(PS, next_witness, indices_mixed_msb, trace_expansion, info_output, output_in_witness)
    return PS, next_witness


def example_hash_only(dimension_input, dimension_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output = compute_hash(input, initial_vector, dimension_output)

    # check against python
    from test_hash import padding_no_pointer, compression_py, mixing_py, binary_expansion_py
    padded_input_py, _ = padding_no_pointer(input)
    compressed_input_py, _ = compression_py(padded_input_py, initial_vector)
    mixed_msb_py, _ = mixing_py(compressed_input_py)
    output_py, _ = binary_expansion_py(mixed_msb_py, dimension_output)
    assert output == output_py, "Output not matching."

def example_hash_and_proof(dimension_input, dimension_output):
    
    # compute output = hash(input)
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output, trace = compute_hash(input, initial_vector, dimension_output, with_proof = True, output_in_witness = True)

    # prove knowledge of hash preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_hash_preimage(PS_description, input.dim, output.dim, True)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness, _ = knowledge_hash_preimage(PS, next_witness, indices_input, trace, initial_vector, dimension_output, True)

    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_hash_and_proof_public_output(dimension_input, dimension_output):
    
    # compute output = hash(input)
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output, trace = compute_hash(input, initial_vector, dimension_output, with_proof = True)

    # prove knowledge of hash preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_hash_preimage(PS_description, input.dim, output.dim)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness = knowledge_hash_preimage(PS, next_witness, indices_input, trace, initial_vector, output)
    
    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_compress_and_proof(dimension_input):
    
    # compute output = compress(input)
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output, trace = compress(input, initial_vector, with_proof = True, output_in_witness = True)

    # prove knowledge of compression preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_compression_preimage(PS_description, input.dim, output_in_witness = True)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness, _ = knowledge_compression_preimage(PS, next_witness, indices_input, trace, initial_vector, output_in_witness = True)

    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_compress_and_proof_public_output(dimension_input):
    
    # compute output = compress(input)
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output, trace = compress(input, initial_vector, with_proof = True, output_in_witness = False)

    # prove knowledge of compression preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_compression_preimage(PS_description, input.dim, output_in_witness = False)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness = knowledge_compression_preimage(PS, next_witness, indices_input, trace, initial_vector, output_in_witness = False, compressed_input = output)

    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_expand_and_proof(dimension_output):
    
    # compute output = expand(input)
    input = polyvec_t(RING_PROOF, BITS_SEED_EXPANSION, [randrange(2) for i in range(DEGREE_HASH * BITS_SEED_EXPANSION)])
    output, trace = expand(input, dimension_output, with_proof = True, output_in_witness = True)

    # prove knowledge of expansion preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_expansion_preimage(PS_description, output.dim, True)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness, _ = knowledge_expansion_preimage(PS, next_witness, indices_input, trace, dimension_output, True)

    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_expand_and_proof_public_output(dimension_output):
    
    # compute output = hash(input)
    input = polyvec_t(RING_PROOF, BITS_SEED_EXPANSION, [randrange(2) for i in range(DEGREE_HASH * BITS_SEED_EXPANSION)])
    output, trace = expand(input, dimension_output, with_proof = True)

    # prove knowledge of expansion preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_expansion_preimage(PS_description, output.dim)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = True, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness = knowledge_expansion_preimage(PS, next_witness, indices_input, trace, output)
    
    PS.smpl_verify()
    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        verif_start_time = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        verif_end_time = time.perf_counter()
        print("Proof time:", proof_end_time - proof_start_time)
        print("Verif time:", verif_end_time - verif_start_time)
    assert successful_verification, "Proof verification failed."

def example_compress_only(dimension_input):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    output = compress(input, initial_vector)

    # check against python
    from test_hash import padding_no_pointer, compression_py, mixing_py, binary_expansion_py
    padded_input_py, _ = padding_no_pointer(input)
    output_py, _ = compression_py(padded_input_py, initial_vector)
    assert output == output_py, "Output not matching."

def example_expand_only(dimension_output):
    input = polyvec_t(RING_PROOF, BITS_SEED_EXPANSION, [randrange(2) for i in range(DEGREE_HASH * BITS_SEED_EXPANSION)])
    output = expand(input, dimension_output)

    # check against python
    from test_hash import padding_no_pointer, compression_py, mixing_py, binary_expansion_py
    output_py, _ = binary_expansion_py(input, dimension_output)
    assert output == output_py, "Output not matching."

def time_hash_internal(dimension_input, dimension_output):
    input = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dimension_input)])
    initial_vector = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)])
    start_time = time.perf_counter()
    output = compute_hash_internal(input, initial_vector, dimension_output, False, False)
    end_time = time.perf_counter()
    print("Time:", end_time - start_time)

def time_hash_trace(dimension_input, dimension_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    start_time = time.perf_counter()
    output = compute_hash(input, initial_vector, dimension_output, False, False)
    end_time = time.perf_counter()
    print("Time hash only:", end_time - start_time)
    start_time = time.perf_counter()
    output, trace = compute_hash(input, initial_vector, dimension_output, True, False)
    end_time = time.perf_counter()
    print("Time hash and trace:", end_time - start_time)
    
if __name__ == "__main__":
    for pair in [(1, 1), (7, 1), (13, 1), (17, 1), (19, 1), (23, 1), (1, 2), (1, 13), (25, 14), (1, 19), (1, 28)]:
        
        # check execution
        example_hash_only(pair[0], pair[1])
        example_hash_and_proof(pair[0], pair[1])
        example_hash_and_proof_public_output(pair[0], pair[1])
        
        # # check execution compression
        # example_compress_only(pair[0])
        # example_compress_and_proof(pair[0])
        # example_compress_and_proof_public_output(pair[0])

        # # check execution
        # example_expand_only(pair[1])
        # example_expand_and_proof(pair[1])
        # example_expand_and_proof_public_output(pair[1])


    # time_hash_internal(10000, 1)
    # time_hash_trace(10000, 1)

