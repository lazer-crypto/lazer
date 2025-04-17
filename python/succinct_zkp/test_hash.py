from splhash import *

# python functions
# - also in blns.py -
# extended euclidean algorithm - from lazer
def _xgcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _xgcd(b % a, a)
        return (g, x - (b // a) * y, y)

# Return inverse of a mod m - from lazer
def invmod(a, m):
    assert m % 2 == 1
    g, x, y = _xgcd(a, m)
    assert g == 1
    res = x % m
    if res > (m-1) / 2:
        res -= m
    return res

def binary_decomposition(x, modulus): # modulus being a power of 2, x positive integer
    length_decomposition = ceil(log2(modulus))
    decomposition = [0] * length_decomposition
    assert x >= 0, "Input must be non negative"
    for i in range(length_decomposition - 1, -1, -1):
        decomposition[i] = x // 2 ** i
        x -= 2 ** i * decomposition[i]
    return decomposition

def polynomial_binary_decomposition(polynomial, modulus): # input polynomial in any ring, binary decomposition in PROOF_RING
    length_decomposition = ceil(log2(modulus))
    polynomial_decomposition = polyvec_t(RING_PROOF, length_decomposition)
    for i in range(DEGREE_HASH):
        coefficient_decomposition = binary_decomposition(polynomial.get_coeff(i), modulus)
        for j in range(length_decomposition):
            polynomial_decomposition.set_elem(coefficient_decomposition[j], j, i)
    return polynomial_decomposition

def reduce_integer(element, modulus):
    element = element % modulus
    return element

def reduce_polynomial(polynomial, modulus):
    polynomial.set_coeffs([reduce_integer(polynomial.get_coeff(i), modulus) for i in range(polynomial.ring.deg)])
    return polynomial

def center_reduce_integer(element, modulus):
    element = element % modulus
    if element >= modulus / 2:
        element = element - modulus
    return element

def center_reduce_polynomial(polynomial, modulus):
    polynomial.set_coeffs([center_reduce_integer(polynomial.get_coeff(i), modulus) for i in range(polynomial.ring.deg)])
    return polynomial

# - only here -
INVERSE_MODULUS_HASH = invmod(MODULUS_HASH, RING_PROOF.mod)
INVERSE_MODULUS_MIXING = invmod(MODULUS_MIXING, RING_PROOF.mod)

# Gadget matrices
gadget_matrix_bin_decomposition = polyvec_t(RING_PROOF, BITS_MODULUS_MIXING)
for i in range(BITS_MODULUS_MIXING):
    gadget_matrix_bin_decomposition.set_elem(2 ** i * ONE_IN_RING_PROOF, i)

gadget_matrix_bin_expansion = polyvec_t(RING_PROOF, BITS_MODULUS_HASH)
index_negative_power = BITS_MODULUS_HASH - BITS_MODULUS_EXPANSION - 1
for i in range(index_negative_power):
    gadget_matrix_bin_expansion.set_elem(2 ** i * ONE_IN_RING_PROOF, i)
gadget_matrix_bin_expansion.set_elem(- 2 ** index_negative_power * ONE_IN_RING_PROOF, index_negative_power)
for i in range(index_negative_power + 1, BITS_MODULUS_HASH):
    gadget_matrix_bin_expansion.set_elem(2 ** i * ONE_IN_RING_PROOF, i)

def lwr_decomposition(x, starting_modulus, ending_modulus): # moduli being powers of 2, use efficient version!
    length_decomposition = ceil(log2(starting_modulus))
    number_discarded_bits = ceil(log2(starting_modulus / ending_modulus))
    decomposition = [0]*length_decomposition
    if x < - 2 ** (number_discarded_bits - 1):
        x += starting_modulus
    for i in range(length_decomposition - 1, number_discarded_bits - 1, -1):
        decomposition[i] = (x + 2 ** (number_discarded_bits - 1)) // 2 ** i
        x -= 2 ** i * decomposition[i]
    if x < 0:
        i = number_discarded_bits - 1
        decomposition[i] = 1
        x += 2 ** i
    for i in range(number_discarded_bits - 2, -1, -1):
        decomposition[i] = x // 2 ** i
        x -= 2 ** i * decomposition[i]
    return decomposition

def rlwr_decomposition(polynomial, starting_modulus, ending_modulus): # use efficient version!
    ring = polynomial.ring
    length_decomposition = ceil(log2(starting_modulus))
    polynomial_decomposition = polyvec_t(ring, length_decomposition)
    for i in range(ring.deg):
        coefficient_decomposition = lwr_decomposition(polynomial.get_coeff(i), starting_modulus, ending_modulus)
        for j in range(length_decomposition):
            polynomial_decomposition.set_elem(coefficient_decomposition[j], j, i)
    return polynomial_decomposition

def compression_py(padded_input, initial_vector):
    trace_compression = []
    compressed_input = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, initial_vector)
    blocks_to_compress = polyvec_t(RING_PROOF, BITS_MODULUS_HASH * COMPRESSION_FACTOR)
    iterations_compression = padded_input.dim // BITS_MODULUS_HASH
    for i in range(iterations_compression):
        for j in range(BITS_MODULUS_HASH):
            blocks_to_compress.set_elem(compressed_input.get_elem(j), j)
            blocks_to_compress.set_elem(padded_input.get_elem(i * BITS_MODULUS_HASH + j), BITS_MODULUS_HASH + j)
        tmp = URANDOM_MATRIX_HASH * blocks_to_compress
        compressed_input = polynomial_binary_decomposition(reduce_polynomial(tmp.copy(), MODULUS_HASH), MODULUS_HASH)
        for j in range(BITS_MODULUS_HASH):
            trace_compression.append(compressed_input.get_elem(j))
        lifting = tmp
        for j in range(BITS_MODULUS_HASH):
            lifting -= compressed_input.get_elem(j) * gadget_matrix_bin_decomposition.get_elem(j)
        lifting *= INVERSE_MODULUS_HASH
        decomposed_lifting = clib_decomp_64_no_pointers(lifting)
        for j in range(2):
            trace_compression.append(decomposed_lifting.get_elem(j))
    return compressed_input, trace_compression

def mixing_py(compressed_input):
    mixed_input = polyvec_t(RING_PROOF, BITS_MODULUS_MIXING)
    for i in range(BITS_MODULUS_HASH):
        mixed_input.set_elem(compressed_input.get_elem(i), i)
    tmp = ZERO_IN_RING_PROOF.copy()
    for i in range(BITS_MODULUS_HASH):
        tmp += URANDOM_MATRIX_HASH.get_elem(i) * mixed_input.get_elem(i)
    tmp += CONSTANTS[0]
    mixed_input = polynomial_binary_decomposition(reduce_polynomial(tmp.copy(), MODULUS_HASH), MODULUS_MIXING)
    trace_mixing = []
    for i in range(BITS_MODULUS_HASH):
        trace_mixing.append(mixed_input.get_elem(i))
    lifting = tmp
    for i in range(BITS_MODULUS_HASH):
        lifting -= mixed_input.get_elem(i) * gadget_matrix_bin_decomposition.get_elem(i)
    lifting *= INVERSE_MODULUS_HASH
    decomposed_lifting = clib_decomp_64_no_pointers(lifting)
    for i in range(2):
        trace_mixing.append(decomposed_lifting.get_elem(i))
    for i in range(ITERATIONS_MIXING):
        tmp = ZERO_IN_RING_PROOF.copy()
        for j in range(BITS_MODULUS_HASH):
            tmp += URANDOM_MATRIX_HASH.get_elem(j) * mixed_input.get_elem(j)
        mixed_input = polynomial_binary_decomposition(reduce_polynomial(tmp.copy(), MODULUS_MIXING), MODULUS_MIXING)
        for j in range(BITS_MODULUS_MIXING):
            trace_mixing.append(mixed_input.get_elem(j))
        for j in range(BITS_MODULUS_HASH):
            trace_mixing.append(mixed_input.get_elem(j) + mixed_input.get_elem(BITS_MODULUS_HASH))
        lifting = tmp
        for j in range(BITS_MODULUS_MIXING):
            lifting -= mixed_input.get_elem(j) * gadget_matrix_bin_decomposition.get_elem(j)
        lifting *= INVERSE_MODULUS_MIXING
        decomposed_lifting = clib_decomp_64_no_pointers(lifting)
        for j in range(2):
            trace_mixing.append(decomposed_lifting.get_elem(j))
        tmp = ZERO_IN_RING_PROOF.copy()
        for j in range(BITS_MODULUS_MIXING):
            tmp += URANDOM_MATRIX_HASH.get_elem(j) * mixed_input.get_elem(j)
        tmp += CONSTANTS[1 + i]
        mixed_input = polynomial_binary_decomposition(reduce_polynomial(tmp.copy(), MODULUS_HASH), MODULUS_HASH)
        for j in range(BITS_MODULUS_HASH):
            trace_mixing.append(mixed_input.get_elem(j))
        lifting = tmp
        for j in range(BITS_MODULUS_HASH):
            lifting -= mixed_input.get_elem(j) * gadget_matrix_bin_decomposition.get_elem(j)
        lifting *= INVERSE_MODULUS_HASH
        decomposed_lifting = clib_decomp_64_no_pointers(lifting)
        for j in range(2):
            trace_mixing.append(decomposed_lifting.get_elem(j))
    msb_mixed_input = polyvec_t(RING_PROOF, BITS_SEED_EXPANSION)
    for j in range(BITS_SEED_EXPANSION):
        msb_mixed_input.set_elem(mixed_input.get_elem(BITS_MODULUS_HASH - BITS_SEED_EXPANSION + j), j)
    return msb_mixed_input, trace_mixing

def binary_expansion_py(seed_expansion, dimension_binary_output):
    iterations_binary_expansion = max(1, ceil((dimension_binary_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    binary_output = polyvec_t(RING_PROOF, dimension_binary_output)
    trace_binary_expansion = []
    for i in range(iterations_binary_expansion):
        tmp = ZERO_IN_RING_PROOF.copy()
        for j in range(BITS_SEED_EXPANSION):
            tmp += URANDOM_MATRIX_HASH.get_elem(j) * seed_expansion.get_elem(j)
        mlwr_vector_tmp = rlwr_decomposition(center_reduce_polynomial(tmp.copy(), MODULUS_HASH), MODULUS_HASH, MODULUS_EXPANSION) # is MODULUS_EXPANSION correct?
        for j in range(BITS_MODULUS_HASH):
            trace_binary_expansion.append(mlwr_vector_tmp.get_elem(j))
        lifting = tmp
        for j in range(BITS_MODULUS_HASH):
            lifting -= mlwr_vector_tmp.get_elem(j) * gadget_matrix_bin_expansion.get_elem(j)
        lifting *= INVERSE_MODULUS_HASH
        trace_binary_expansion.append(lifting)
        for j in range(BITS_SEED_EXPANSION):
            seed_expansion.set_elem(mlwr_vector_tmp.get_elem(BITS_MODULUS_HASH - BITS_SEED_EXPANSION + j), j)
        if i < iterations_binary_expansion - 1: # handle better this if
            for j in range(BITS_TO_OUTPUT): 
                binary_output.set_elem(mlwr_vector_tmp.get_elem(BITS_TO_DISCARD + j), BITS_TO_OUTPUT * i + j)
        else: 
            for j in range(min(dimension_binary_output - BITS_TO_OUTPUT * (iterations_binary_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)):
                binary_output.set_elem(mlwr_vector_tmp.get_elem(BITS_TO_DISCARD + j), BITS_TO_OUTPUT * i + j)
    return binary_output, trace_binary_expansion

def hash_py(input, initial_vector, dimension_binary_output):
    padded_input, pad = padding_no_pointer(input)
    compressed_input, trace_compression = compression_py(padded_input, initial_vector)
    seed_expansion, trace_mixing = mixing_py(compressed_input)
    binary_output, trace_binary_expansion = binary_expansion_py(seed_expansion, dimension_binary_output)
    return binary_output

def _test_with_python_hash(dimension_input, dimension_binary_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output = hash(input, initial_vector, dimension_binary_output)
    binary_output_py = hash_py(input, initial_vector, dimension_binary_output)
    assert binary_output == binary_output_py, "Hash results do not match python implementation for dimension_input = {} and dimension_binary_output = {}.".format(dimension_input, dimension_binary_output)


# c functions, no pointers
def clib_compression_step_no_pointers(left_input_vec, right_input_vec):
    assert left_input_vec.dim == BITS_MODULUS_HASH and right_input_vec.dim == BITS_MODULUS_HASH, "left_input and right_input in compression must be of dimension BITS_MODULUS_HASH"

    list_coeffs_left_input = [[left_input_vec.get_elem(i, j) for j in range(left_input_vec.ring.deg)] for i in range(BITS_MODULUS_HASH)]
    left_input = ffi.new("poly512 []", list_coeffs_left_input)

    list_coeffs_right_input = [[right_input_vec.get_elem(i, j) for j in range(right_input_vec.ring.deg)] for i in range(BITS_MODULUS_HASH)]
    right_input = ffi.new("poly512 []", list_coeffs_right_input)

    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.compress(image, cutoff, left_input, right_input, -1)
    
    image_vec = convert_array_to_polyvec_t(image)
    cutoff_poly = convert_array_to_poly_t(cutoff)

    return image_vec, cutoff_poly

def clib_mix_256_no_pointers(input_vec, index_iteration):
    assert input_vec.dim == BITS_MODULUS_MIXING, "input in mix_256 must be of dimension BITS_MODULUS_MIXING"
    list_coeffs_input = [[input_vec.get_elem(i, j) for j in range(input_vec.ring.deg)] for i in range(BITS_MODULUS_MIXING)]
    input = ffi.new("poly512 []", list_coeffs_input)
    
    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.mix_256(image, cutoff, input, index_iteration)

    image_vec = convert_array_to_polyvec_t(image)
    cutoff_poly = convert_array_to_poly_t(cutoff)
    return image_vec, cutoff_poly

def clib_mix_257_no_pointers(input_vec):
    assert input_vec.dim == BITS_MODULUS_HASH, "input in mix_257 must be of dimension BITS_MODULUS_HASH"

    list_coeffs_input = [[input_vec.get_elem(i, j) for j in range(input_vec.ring.deg)] for i in range(BITS_MODULUS_HASH)]
    input = ffi.new("poly512 []", list_coeffs_input)

    image = ffi.new("poly512 []", BITS_MODULUS_MIXING)
    cutoff = ffi.new("signed_poly512")
    lib.mix_257(image, cutoff, input)

    image_vec = convert_array_to_polyvec_t(image)
    cutoff_poly = convert_array_to_poly_t(cutoff)
    return image_vec, cutoff_poly

def clib_squeeze_no_pointers(input_vec):
    assert input_vec.dim == BITS_SEED_EXPANSION, "input in squeeze must be of dimension BITS_SEED_EXPANSION"

    list_coeffs_input = [[input_vec.get_elem(i, j) for j in range(input_vec.ring.deg)] for i in range(BITS_SEED_EXPANSION)]
    input = ffi.new("poly512 []", list_coeffs_input)

    image = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.squeeze(image, cutoff, input)

    image_vec = convert_array_to_polyvec_t(image)
    cutoff_poly = convert_array_to_poly_t(cutoff)
    return image_vec, cutoff_poly

def clib_decomp_64_no_pointers(input_poly):
    list_coeffs_input = [input_poly.get_coeff(i) for i in range(input_poly.ring.deg)]
    input = ffi.new("signed_poly512", list_coeffs_input)

    output = ffi.new("signed_poly512 [2]")
    lib.decomposition_binary_power(output, input, 6, 2)

    output_vec = convert_array_to_polyvec_t(output)
    return output_vec

def padding_no_pointer(input):
    assert input.ring == RING_PROOF, "Input must be in RING_PROOF"
    assert input.is_binary(), "Input not binary"
    dimension_padded_input = ceil((input.dim + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH
    padded_input = polyvec_t(RING_PROOF, dimension_padded_input)
    for i in range(input.dim):
        padded_input.set_elem(input.get_elem(i), i)
    dimension_input_in_bits = poly_t(RING_PROOF, [int(x) for x in list(binary_repr(input.dim, DEGREE_HASH))])
    padded_input.set_elem(dimension_input_in_bits, padded_input.dim - 1)
    return padded_input, dimension_input_in_bits

def compression_no_pointers(padded_input, dimension_input_in_bits, initial_vector, PS, indices_input, next_witness):
    assert initial_vector.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension 8."
    compressed_input = initial_vector.copy()
    block_from_padded_input = polyvec_t(RING_PROOF, BITS_MODULUS_HASH)
    iterations_compression = padded_input.dim // BITS_MODULUS_HASH
    for i in range(iterations_compression):
        for j in range(BITS_MODULUS_HASH):
            block_from_padded_input.set_elem(padded_input.get_elem(i * BITS_MODULUS_HASH + j), j)
        compressed_input, lifting = clib_compression_step_no_pointers(compressed_input, block_from_padded_input)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness(compressed_input.get_elem(j))
            decomposed_lifting = clib_decomp_64_no_pointers(lifting)
            for j in range(2):
                PS.append_witness(decomposed_lifting.get_elem(j))
    if PS == None:
        return compressed_input
    # if iterations_compression == 1:
    #     left_list = [URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH + i) for i in range(len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
    #     indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    #     next_witness += BITS_MODULUS_HASH
    #     indices_witness = indices_input + indices_compressed_input + [next_witness + i for i in range(2)]
    #     next_witness += 2
    #     right_pol = ZERO_IN_RING_PROOF.copy()
    #     for i in range(BITS_MODULUS_HASH):
    #         right_pol -= URANDOM_MATRIX_HASH.get_elem(i) * initial_vector.get_elem(i)
    #     right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
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
    #     right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
    #     PS.append_statement(left_list, indices_witness, right_pol)
    
    minim = min(len(indices_input), BITS_MODULUS_HASH)
    left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH, BITS_MODULUS_HASH + minim)] + COMMON_LEFT_PART_COMPRESSION
    indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
    next_witness += BITS_MODULUS_HASH
    indices_witness = indices_input[ : minim] + indices_compressed_input + [next_witness + i for i in range(2)]
    next_witness += 2
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
        indices_witness = indices_previous_compressed_input + [indices_input[i] for i in range(i * BITS_MODULUS_HASH, (i + 1) * BITS_MODULUS_HASH)] + indices_compressed_input + [next_witness + i for i in range(2)]
        next_witness += 2
        PS.append_statement(LEFT_LIST_COMPRESSION, indices_witness, ZERO_IN_RING_PROOF)        
    if iterations_compression > 1:
        left_list = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(BITS_MODULUS_HASH * COMPRESSION_FACTOR - padded_input.dim + len(indices_input))] + COMMON_LEFT_PART_COMPRESSION
        indices_previous_compressed_input = indices_compressed_input
        indices_compressed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH
        indices_witness = indices_previous_compressed_input + [indices_input[i] for i in range((iterations_compression - 1) * BITS_MODULUS_HASH, len(indices_input))] + indices_compressed_input + [next_witness + i for i in range(2)]
        next_witness += 2
        right_pol = ZERO_IN_RING_PROOF.copy()
        right_pol -= URANDOM_MATRIX_HASH.get_elem(BITS_MODULUS_HASH * COMPRESSION_FACTOR - 1) * dimension_input_in_bits
        PS.append_statement(left_list, indices_witness, right_pol)
    return compressed_input, PS, indices_compressed_input, next_witness

def mixing_no_pointers(compressed_input, PS, indices_compressed_input, next_witness):
    mixed_input = polyvec_t(RING_PROOF, BITS_MODULUS_MIXING)
    for i in range(BITS_MODULUS_HASH):
        mixed_input.set_elem(compressed_input.get_elem(i), i)
    mixed_input, lifting = clib_mix_256_no_pointers(mixed_input, 0)
    if PS != None:
        for i in range(BITS_MODULUS_HASH):
            PS.append_witness(mixed_input.get_elem(i))
        decomposed_lifting = clib_decomp_64_no_pointers(lifting)
        for i in range(2):
            PS.append_witness(decomposed_lifting.get_elem(i))
        indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH   
        indices_witness = indices_compressed_input + indices_mixed_input + [next_witness + i for i in range(2)]    
        next_witness += 2
        PS.append_statement(LEFT_LIST_FIRST_MIX, indices_witness, - CONSTANTS[0])
    for i in range(ITERATIONS_MIXING):
        mixed_input, lifting = clib_mix_257_no_pointers(mixed_input)
        if PS != None:
            for j in range(BITS_MODULUS_MIXING):
                PS.append_witness(mixed_input.get_elem(j))
            indices_previous_mixed_input = indices_mixed_input
            indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_MIXING)]
            next_witness += BITS_MODULUS_MIXING
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness(mixed_input.get_elem(j) + mixed_input.get_elem(BITS_MODULUS_HASH))
                indices_witness = [indices_mixed_input[j], indices_mixed_input[BITS_MODULUS_HASH], next_witness + j]
                PS.append_statement(LEFT_LIST_DECOMP_257, indices_witness, ZERO_IN_RING_PROOF)
            next_witness += BITS_MODULUS_HASH
            decomposed_lifting = clib_decomp_64_no_pointers(lifting)
            for j in range(2):
                PS.append_witness(decomposed_lifting.get_elem(j))
            indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness + i for i in range(2)]
            next_witness += 2
            PS.append_statement(LEFT_LIST_MIX_257, indices_witness, ZERO_IN_RING_PROOF)
        mixed_input, lifting = clib_mix_256_no_pointers(mixed_input, i + 1)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness(mixed_input.get_elem(j))
            decomposed_lifting = clib_decomp_64_no_pointers(lifting)
            for j in range(2):
                PS.append_witness(decomposed_lifting.get_elem(j))
            indices_previous_mixed_input = indices_mixed_input
            indices_mixed_input = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_witness = indices_previous_mixed_input + indices_mixed_input + [next_witness + i for i in range(2)]
            next_witness += 2
            PS.append_statement(LEFT_LIST_MIX_256, indices_witness, - CONSTANTS[i + 1])    
    msb_mixed_input = polyvec_t(RING_PROOF, BITS_SEED_EXPANSION)
    for j in range(BITS_SEED_EXPANSION):
        msb_mixed_input.set_elem(mixed_input.get_elem(BITS_MODULUS_HASH - BITS_SEED_EXPANSION + j), j)
    if PS == None:
        return msb_mixed_input
    indices_msb_mixed_input = [indices_mixed_input[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
    return msb_mixed_input, PS, indices_msb_mixed_input, next_witness

def binary_expansion_no_pointers(seed_expansion, dimension_binary_output, PS, indices_seed_expansion, next_witness):
    iterations_binary_expansion = max(1, ceil((dimension_binary_output - BITS_SEED_EXPANSION) / BITS_TO_OUTPUT)) # to check
    binary_output = polyvec_t(RING_PROOF, dimension_binary_output)
    if PS != None:
        indices_binary_output = []
    for i in range(iterations_binary_expansion - 1):
        mlwr_vector_tmp, lifting = clib_squeeze_no_pointers(seed_expansion)
        for j in range(BITS_SEED_EXPANSION):
            seed_expansion.set_elem(mlwr_vector_tmp.get_elem(BITS_MODULUS_HASH - BITS_SEED_EXPANSION + j), j)
        for j in range(BITS_TO_OUTPUT): 
            binary_output.set_elem(mlwr_vector_tmp.get_elem(BITS_TO_DISCARD + j), BITS_TO_OUTPUT * i + j)
        if PS != None:
            for j in range(BITS_MODULUS_HASH):
                PS.append_witness(mlwr_vector_tmp.get_elem(j))
            PS.append_witness(lifting)
            indices_mlwr_vector = [next_witness + i for i in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
            indices_lifting = [next_witness]
            next_witness += 1
            indices_witness = indices_seed_expansion + indices_mlwr_vector + indices_lifting
            PS.append_statement(LEFT_LIST_BINARY_EXPANSION, indices_witness, ZERO_IN_RING_PROOF)
            indices_seed_expansion = [indices_mlwr_vector[i] for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
            indices_binary_output += [indices_mlwr_vector[i] for i in range(BITS_TO_DISCARD, BITS_TO_DISCARD + BITS_TO_OUTPUT)]
    mlwr_vector_tmp, lifting = clib_squeeze_no_pointers(seed_expansion)
    for j in range(BITS_SEED_EXPANSION):
        seed_expansion.set_elem(mlwr_vector_tmp.get_elem(BITS_MODULUS_HASH - BITS_SEED_EXPANSION + j), j)
    rem = min(dimension_binary_output - BITS_TO_OUTPUT * (iterations_binary_expansion - 1), BITS_MODULUS_HASH - BITS_TO_DISCARD)
    for j in range(rem):
        binary_output.set_elem(mlwr_vector_tmp.get_elem(BITS_TO_DISCARD + j), BITS_TO_OUTPUT * (iterations_binary_expansion - 1) + j)
    if PS != None:
        for j in range(BITS_MODULUS_HASH):
            PS.append_witness(mlwr_vector_tmp.get_elem(j))
        PS.append_witness(lifting)
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

def hash_no_pointers(input, initial_vector, dimension_binary_output, PS = None, indices_input = None, next_witness  = None):
    padded_input, dimension_input_in_bits = padding_no_pointer(input)
    if PS == None:
        compressed_input = compression_no_pointers(padded_input, dimension_input_in_bits, initial_vector, None, None, None)
        seed_expansion = mixing_no_pointers(compressed_input, None, None, None)
        binary_output = binary_expansion_no_pointers(seed_expansion, dimension_binary_output, None, None, None)
        return binary_output
    compressed_input, PS, indices_compressed_input, next_witness = compression_no_pointers(padded_input, dimension_input_in_bits, initial_vector, PS, indices_input, next_witness)
    seed_expansion, PS, indices_seed_expansion, next_witness = mixing_no_pointers(compressed_input, PS, indices_compressed_input, next_witness)
    binary_output, PS, indices_binary_output, next_witness = binary_expansion_no_pointers(seed_expansion, dimension_binary_output, PS, indices_seed_expansion, next_witness)
    return binary_output, PS, indices_binary_output, next_witness

def _time_hash(dimension_input, dimension_binary_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    start_time = time.perf_counter()
    hash_no_pointers(input, initial_vector, dimension_binary_output)
    end_time = time.perf_counter()
    print("Hash time for input dimension {} and output dimension {}: ".format(dimension_input, dimension_binary_output), end_time - start_time)

def _test_hash_with_proof(dimension_input, dimension_binary_output):
    ## Description
    # initialition
    PS_description = proof_statement_description()
    # input
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    # hash
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    
    ## Execution
    # proof setup
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF)
    next_witness = 0
    # input
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(input.dim):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    # hash
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output, PS, indices_binary_output, next_witness = hash_no_pointers(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)

    statement = PS.output_statement()
    proof = PS.pack_prove()
    if proof[0] == 0:
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
    return successful_verification

def _time_proof(dimension_input, dimension_binary_output):
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    ## Execution
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF)
    next_witness = 0
    # input
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(dimension_input):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    # hash
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])    
    hash_with_proof_start_time = time.perf_counter()
    binary_output, PS, indices_binary_output, next_witness = hash_no_pointers(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)
    hash_with_proof_end_time = time.perf_counter()

    statement = PS.output_statement()
    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    verification_start_time = time.perf_counter()
    if proof[0] == 0:
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
    verification_end_time = time.perf_counter()
    print("Hash with proof time:", hash_with_proof_end_time - hash_with_proof_start_time)
    print("Proof time: ", proof_end_time - proof_start_time)
    print("Verification time:", verification_end_time - verification_start_time)
    return successful_verification

def _tmp_test(dimension_input, dimension_binary_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    padding_start_time = time.perf_counter()
    padded_input, pad = padding_no_pointer(input)
    padding_end_time = time.perf_counter()
    print("Padding time:", padding_end_time - padding_start_time)
    compression_start_time = time.perf_counter()
    compressed_input = compression_no_pointers(padded_input, pad, initial_vector, None, None, None)    
    compression_end_time = time.perf_counter()
    print("Compression time:", compression_end_time - compression_start_time)
    mixing_start_time = time.perf_counter()
    seed_expansion = mixing_no_pointers(compressed_input, None, None, None)
    mixing_end_time = time.perf_counter()
    print("Mixing time:", mixing_end_time - mixing_start_time)
    expansion_start_time = time.perf_counter()
    binary_output = binary_expansion_no_pointers(seed_expansion, dimension_binary_output, None, None, None)
    expansion_end_time = time.perf_counter()
    print("Expansion time:", expansion_end_time - expansion_start_time, "\n")

def _time_only_proof(dimension_input, dimension_binary_output):
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    ## Execution
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF)
    next_witness = 0
    # input
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(dimension_input):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    # hash
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])    
    hash_with_proof_start_time = time.perf_counter()
    binary_output, PS, indices_binary_output, next_witness = hash_no_pointers(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)
    hash_with_proof_end_time = time.perf_counter()
    print("Hash with proof time:", hash_with_proof_end_time - hash_with_proof_start_time)

def _time_hash_pointer(dimension_input, dimension_binary_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    start_time = time.perf_counter()
    hash(input, initial_vector, dimension_binary_output)
    end_time = time.perf_counter()
    print("Hash time for input dimension {} and output dimension {}: ".format(dimension_input, dimension_binary_output), end_time - start_time)

def _test_with_python_hash_pointer(dimension_input, dimension_binary_output):
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output = hash(input, initial_vector, dimension_binary_output)
    binary_output_py = hash_py(input, initial_vector, dimension_binary_output)
    assert binary_output == binary_output_py, "Hash results do not match python implementation for dimension_input = {} and dimension_binary_output = {}.".format(dimension_input, dimension_binary_output)

def _test_hash_with_proof_pointer(dimension_input, dimension_binary_output):
    ## Description
    # initialition
    PS_description = proof_statement_description()
    # input
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    # hash
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    
    ## Execution
    # proof setup
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF)
    next_witness = 0
    # input
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(input.dim):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    # hash
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    binary_output, PS, indices_binary_output, next_witness = hash(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)

    statement = PS.output_statement()
    proof = PS.pack_prove()
    if proof[0] == 0:
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
    return successful_verification

def _time_only_proof_pointer(dimension_input, dimension_binary_output):
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * dimension_input
    PS_description.list_number_polynomials += [1] * dimension_input
    PS_description.list_norm_constraints += [NORM_BINARY] * dimension_input
    PS_description = description_hash(dimension_input, dimension_binary_output, PS_description)
    ## Execution
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF)
    next_witness = 0
    # input
    input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
    indices_input = list(range(input.dim))
    for i in range(dimension_input):
        PS.append_witness(input.get_elem(i))
    next_witness += input.dim
    # hash
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])    
    hash_with_proof_start_time = time.perf_counter()
    binary_output, PS, indices_binary_output, next_witness = hash(input, initial_vector, dimension_binary_output, PS, indices_input, next_witness)
    hash_with_proof_end_time = time.perf_counter()
    print("Hash with proof time:", hash_with_proof_end_time - hash_with_proof_start_time)


# # TEMPPP
# def check_compr(input_polyvec_t, initial_vector_polyvec_t):

#     assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
#     assert input_polyvec_t.is_binary(), "Input must be binary."
#     input = ffi.new("poly512 []", input_polyvec_t.dim)
#     for poly in range(input_polyvec_t.dim):
#         for coeff in range(DEGREE_HASH):
#             input[poly][coeff] = input_polyvec_t[poly][coeff]
    
#     assert initial_vector_polyvec_t.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension BITS_MODULUDS_HASH."
#     assert initial_vector_polyvec_t.ring.deg == DEGREE_HASH, "Initial vector must be of ring degree DEGREE_HASH"
#     assert initial_vector_polyvec_t.is_binary(), "Initial vector must be binary."
#     initial_vector = ffi.new("poly512 []", BITS_MODULUS_HASH)
#     for poly in range(BITS_MODULUS_HASH):
#         for coeff in range(DEGREE_HASH):
#             initial_vector[poly][coeff] = initial_vector_polyvec_t[poly][coeff]

#     dimension_padded_input = ceil((len(input) + 1) / BITS_MODULUS_HASH) * BITS_MODULUS_HASH # padding with one poly describing the dimension and zero polynomials
#     dimension_input_in_bits = [int(x) for x in list(binary_repr(len(input), DEGREE_HASH))] # can be only the part with the dimension without ", DEGREE_HASH", but need to change in the proof part
#     iterations_compression = dimension_padded_input // BITS_MODULUS_HASH
#     trace_compression = []
#     compressed_input = initial_vector
#     for i in range(iterations_compression - 1):
#         block_from_padded_input = input + (i * BITS_MODULUS_HASH)
#         compressed_input, lifting = clib_compression_step(compressed_input, block_from_padded_input)
#         for j in range(BITS_MODULUS_HASH):
#             trace_compression.append(convert_array_to_poly_t(compressed_input[j]))
#         decomposed_lifting = clib_decomp_64(lifting)
#         for j in range(2):
#             trace_compression.append(convert_array_to_poly_t(decomposed_lifting[j]))
    
#     block_from_padded_input = ffi.new("poly512[]", BITS_MODULUS_HASH)
#     last_block = (iterations_compression - 1) * BITS_MODULUS_HASH
#     for poly in range(len(input) - last_block):
#         for coeff in range(DEGREE_HASH):
#             block_from_padded_input[poly][coeff] = input[last_block + poly][coeff]
#     for coeff in range(DEGREE_HASH):
#         block_from_padded_input[BITS_MODULUS_HASH - 1][coeff] = dimension_input_in_bits[coeff]
#     compressed_input, lifting = clib_compression_step(compressed_input, block_from_padded_input)
#     for j in range(BITS_MODULUS_HASH):
#         trace_compression.append(convert_array_to_poly_t(compressed_input[j]))
#     decomposed_lifting = clib_decomp_64(lifting)
#     for j in range(2):
#         trace_compression.append(convert_array_to_poly_t(decomposed_lifting[j]))
    
#     correct_compressed_input = compressed_input
#     correct_trace_compression = trace_compression


#     assert input_polyvec_t.ring.deg == DEGREE_HASH, "Input must be of ring degree DEGREE_HASH."
#     assert input_polyvec_t.is_binary(), "Input must be binary."
#     input = ffi.new("poly512 []", input_polyvec_t.dim)
#     for poly in range(input_polyvec_t.dim):
#         for coeff in range(DEGREE_HASH):
#             input[poly][coeff] = input_polyvec_t[poly][coeff]
    
#     assert initial_vector_polyvec_t.dim == BITS_MODULUS_HASH, "Initial vector must be of dimension BITS_MODULUDS_HASH."
#     assert initial_vector_polyvec_t.ring.deg == DEGREE_HASH, "Initial vector must be of ring degree DEGREE_HASH"
#     assert initial_vector_polyvec_t.is_binary(), "Initial vector must be binary."
#     initial_vector = ffi.new("poly512 []", BITS_MODULUS_HASH)
#     for poly in range(BITS_MODULUS_HASH):
#         for coeff in range(DEGREE_HASH):
#             initial_vector[poly][coeff] = initial_vector_polyvec_t[poly][coeff]

#     # compression
#     iterations_compression = ceil((len(input) + 1) / BITS_MODULUS_HASH)
#     number_witnesses_compression = (BITS_MODULUS_HASH + 2) * iterations_compression
#     compressed_input = ffi.new("poly512 []", BITS_MODULUS_HASH)
#     trace_compression = ffi.new("signed_poly512 []", number_witnesses_compression)
#     lib.compression(compressed_input, trace_compression, input, initial_vector, iterations_compression, len(input))

#     tentative_compressed_input = compressed_input
#     tentative_trace_compression = trace_compression

#     assert convert_array_to_polyvec_t(tentative_compressed_input) == convert_array_to_polyvec_t(correct_compressed_input), "Compressed input not matching for dimension_input {}.".format(input_polyvec_t.dim)
#     assert [convert_array_to_poly_t(x) for x in tentative_trace_compression] == correct_trace_compression, "Trace compression not matching for dimension_input {}.".format(input_polyvec_t.dim)

#     return correct_compressed_input

# def check_mixing(input):
#     trace_mixing = []
    
#     mixed_input, lifting = clib_mix_256(input, 0)
#     for i in range(BITS_MODULUS_HASH):
#         trace_mixing.append(convert_array_to_poly_t(mixed_input[i]))
#     decomposed_lifting = clib_decomp_64(lifting)
#     for i in range(2):
#         trace_mixing.append(convert_array_to_poly_t(decomposed_lifting[i]))
#     for i in range(ITERATIONS_MIXING):
#         mixed_input, lifting = clib_mix_257(mixed_input)
#         for j in range(BITS_MODULUS_MIXING):
#             trace_mixing.append(convert_array_to_poly_t(mixed_input[j]))
#         mixed_input_vec = convert_array_to_polyvec_t(mixed_input)
#         for j in range(BITS_MODULUS_HASH):
#             trace_mixing.append(mixed_input_vec.get_elem(j) + mixed_input_vec.get_elem(BITS_MODULUS_HASH))
#         decomposed_lifting = clib_decomp_64(lifting)
#         for j in range(2):
#             trace_mixing.append(convert_array_to_poly_t(decomposed_lifting[j]))
#         mixed_input, lifting = clib_mix_256(mixed_input, i + 1)
#         for j in range(BITS_MODULUS_HASH):
#             trace_mixing.append(convert_array_to_poly_t(mixed_input[j]))
#         decomposed_lifting = clib_decomp_64(lifting)
#         for j in range(2):
#             trace_mixing.append(convert_array_to_poly_t(decomposed_lifting[j]))
#     list_coeffs_msb_mixed_input = [list(mixed_input[i]) for i in range(BITS_MODULUS_HASH - BITS_SEED_EXPANSION, BITS_MODULUS_HASH)]
#     msb_mixed_input = ffi.new("poly512 []", list_coeffs_msb_mixed_input)

#     correct_msb_mixed_input = msb_mixed_input
#     correct_trace_mixing = trace_mixing
    

#     number_witnesses_mixing = (BITS_MODULUS_HASH + 2) * (ITERATIONS_MIXING + 1) + (BITS_MODULUS_MIXING + BITS_MODULUS_HASH + 2) * ITERATIONS_MIXING
#     msb_mixed_input = ffi.new("poly512 []", BITS_SEED_EXPANSION)
#     trace_mixing = ffi.new("signed_poly512 []", number_witnesses_mixing)
#     lib.mixing(msb_mixed_input, trace_mixing, input, ITERATIONS_MIXING)

#     tentative_msb_mixed_input = msb_mixed_input
#     tentative_trace_mixing = trace_mixing

#     # assert convert_array_to_polyvec_t(tentative_msb_mixed_input) == convert_array_to_polyvec_t(correct_msb_mixed_input), "MSB mixed input not matching."
#     # assert [convert_array_to_poly_t(x) for x in tentative_trace_mixing] == correct_trace_mixing, "Trace mixing not matching."
#     i = 0
#     print(convert_array_to_poly_t(tentative_trace_mixing[i]) == correct_trace_mixing[0])

#     return correct_msb_mixed_input

# if __name__ == "__main__":
#     for dimension_input in [1, 7, 13, 20, 25, 100]:
#     # for dimension_input in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 17, 18, 19, 20, 25, 78, 89, 100]:
#     # for dimension_input in range(1, 100):
#         input = polyvec_t(RING_PROOF, dimension_input, [randrange(2) for i in range(DEGREE_HASH * dimension_input)])
#         initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
#         compressed_input = check_compr(input, initial_vector)
#         msb_mixed_input = check_mixing(compressed_input)
#     print("Very good, very nice!")
#     quit()
# #

if __name__ == "__main__":
    # # test_pairs = [[1, 1], [7, 1], [13, 1], [20, 1], [25, 1], [1, 9], [100, 19]]
    # # for pair in test_pairs:
    # #     _test_with_python_hash(pair[0], pair[1])
    # # print("Hash results match python implementation.")
    
    # # test_pairs = [[1, 1], [7, 1], [13, 1], [20, 1], [25, 1], [1, 9], [100, 19], [1000, 1000]]
    # # for pair in test_pairs:
    # #     assert _test_hash_with_proof(pair[0], pair[1]), "Proof verification False for dimension_input {} and dimension_binary_output {}.".format(pair[0], pair[1])

    # test_pairs = [[1, 1], [100, 100], [10000, 10000]]
    # for pair in test_pairs:
    #     _time_hash(pair[0], pair[1])

    # test_pairs = [[1, 1], [100, 100], [10000, 10000]]
    # for pair in test_pairs:
    #     assert _time_proof(pair[0], pair[1]), "Proof verification False."
    
    # # test_pairs = [[1, 1], [100, 100], [10000, 10000]]
    # # print("\n")
    # # for pair in test_pairs:
    # #     _tmp_test(pair[0], pair[1])


    ## pointers
    # correctness
    test_pairs = [[1, 1], [7, 1], [13, 1], [20, 1], [25, 19]]
    for pair in test_pairs:
        _test_with_python_hash_pointer(pair[0], pair[1])
    print("Hash results match python implementation.")
    
    for pair in test_pairs:
        assert _test_hash_with_proof_pointer(pair[0], pair[1]), "Proof verification False for dimension_input {} and dimension_binary_output {}.".format(pair[0], pair[1])
    quit()

    # time
    test_pairs = [[100, 100]]

    for pair in test_pairs:
        _time_only_proof_pointer(pair[0], pair[1]), "Proof verification False."

    for pair in test_pairs:
        _time_hash(pair[0], pair[1])

    for pair in test_pairs:
        _time_hash_pointer(pair[0], pair[1])

    quit()


    ## tmp
    # correctness
    test_pairs = [[1, 1], [7, 1], [13, 1], [20, 1], [25, 19]]
    for pair in test_pairs:
        assert _test_hash_with_proof(pair[0], pair[1]), "Proof verification False for dimension_input {} and dimension_binary_output {}.".format(pair[0], pair[1])

    # time
    test_pairs = [[100, 100]]
    for pair in test_pairs:
        _time_only_proof(pair[0], pair[1]), "Proof verification False."
