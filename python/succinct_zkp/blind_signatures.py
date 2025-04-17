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

from hash import *
import hashlib          # for SHAKE128
from decomposition import opt_decompose

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("00"))
SEED_RING_PROOF = shake128.digest(32)
index_ring_proof = 0

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

def generate_matrix_transf_to_Falcon_mod(dimension_matrix_modulus_conversion, bound_modulus_falcon, index_ring_proof): # fix this
    matrix_modulus_conversion = polyvec_t(RING_PROOF, dimension_matrix_modulus_conversion)
    for i in range(dimension_matrix_modulus_conversion - 1):
        urandom_poly = poly_t(RING_PROOF)
        urandom_poly.urandom_bnd(- bound_modulus_falcon, bound_modulus_falcon, SEED_RING_PROOF, index_ring_proof)
        index_ring_proof += 1
        matrix_modulus_conversion.set_elem(urandom_poly, i)
    matrix_modulus_conversion.set_elem(ONE_IN_RING_PROOF, dimension_matrix_modulus_conversion - 1)
    return matrix_modulus_conversion, index_ring_proof

def transform_to_Falcon_modulo(binary_vector, matrix_modulus_conversion, dimension_vector_modq, base_decomp_Falcon):
    dimension_vector_modq_decomposed = dimension_vector_modq * 2
    vector_modq_decomposed = polyvec_t(RING_PROOF, dimension_vector_modq_decomposed)
    trace_modulus_transf = []
    for i in range(dimension_vector_modq):
        tmp = ZERO_IN_RING_PROOF.copy()
        for j in range(matrix_modulus_conversion.dim):
            tmp += matrix_modulus_conversion.get_elem(j) * binary_vector.get_elem(i * matrix_modulus_conversion.dim + j)
        decomposed_component = opt_decompose(center_reduce_polynomial(tmp.copy(), RING_FALCON.mod), base_decomp_Falcon, 2)
        for j in range(2):
            vector_modq_decomposed.set_elem(decomposed_component.get_elem(j), 2 * i + j)
            trace_modulus_transf.append(decomposed_component.get_elem(j))
        lifting = (tmp - decomposed_component.get_elem(0) - base_decomp_Falcon * decomposed_component.get_elem(1)) * invmod(RING_FALCON.mod, RING_PROOF.mod)
        trace_modulus_transf.append(lifting)
    return vector_modq_decomposed, trace_modulus_transf

def description_transform_to_Falcon_modulo(dimension_vector_modq, PS_description): # each polynomial of the output is decomposed in 2 parts to support the proof
    dimension_vector_modq_decomposed = dimension_vector_modq * 2
    base_decomp_Falcon = ceil(sqrt(1.85 * RING_FALCON.mod / sqrt(12)))
    PS_description.list_degrees += [RING_PROOF.deg] * (3 * dimension_vector_modq)
    PS_description.list_number_polynomials += [1] * (3 * dimension_vector_modq)
    sqnorm_components_t = RING_PROOF.deg * base_decomp_Falcon ** 2 # // 2
    sqnorm_lifting = 2 ** 18
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += [sqnorm_components_t, sqnorm_components_t, sqnorm_lifting] * dimension_vector_modq
    PS_description.approx_norm_list += [(next_norm_constraint, 2 ** 68), (next_norm_constraint + 1, 2 ** 58), (next_norm_constraint + 2, 2 ** 46)] * dimension_vector_modq
    PS_description.number_constraints += dimension_vector_modq
    return PS_description

def knowledge_transform_to_Falcon_modulo(PS, next_witness, indices_binary_vector, trace_modulus_transf, dimension_vector_modq, matrix_modulus_conversion, base_decomp_Falcon):
    statements_modulus_transf = []
    indices_vector_modq = []
    left_list = [matrix_modulus_conversion.get_elem(i) for i in range(matrix_modulus_conversion.dim)] + [- ONE_IN_RING_PROOF, - ONE_IN_RING_PROOF * base_decomp_Falcon, - ONE_IN_RING_PROOF * RING_FALCON.mod]
    right_pol = poly_t(RING_FALCON)
    for i in range(dimension_vector_modq):
        indices_witness = [indices_binary_vector[i * matrix_modulus_conversion.dim + j] for j in range(matrix_modulus_conversion.dim)] + [next_witness + j for j in range(3)]
        indices_vector_modq += [next_witness + j for j in range(2)]
        next_witness += 3
        statements_modulus_transf.append([left_list, indices_witness, right_pol])
    for witness in trace_modulus_transf:
        PS.append_witness(witness)
    for statement in statements_modulus_transf:
        PS.append_statement(statement[0], statement[1], statement[2])
    return PS, next_witness, indices_vector_modq

def compute_binary_randomness(randomness, dimension_binary_randomness, bound_rand, bits_coefficients_rand):
    binary_randomness = polyvec_t(RING_PROOF, dimension_binary_randomness)
    trace_binary_decomp_rand = []
    for i in range(randomness.dim):
        decomposed_component = polynomial_binary_decomposition(reduce_polynomial(randomness.get_elem(i).copy(), 2 * bound_rand + 1), 2 ** bits_coefficients_rand) # directly how many bits for decompositions instead of modulus
        for j in range(bits_coefficients_rand):
            binary_randomness.set_elem(decomposed_component.get_elem(j), bits_coefficients_rand * i + j)
        lifting = randomness.get_elem(i)
        for j in range(bits_coefficients_rand):
            lifting -= decomposed_component.get_elem(j) * 2 ** j
            trace_binary_decomp_rand.append(decomposed_component.get_elem(j))
        lifting *= invmod(2 * bound_rand + 1, MODULUS_PROOF)
        trace_binary_decomp_rand.append(lifting)
    return binary_randomness, trace_binary_decomp_rand

def description_compute_binary_randomness(PS_description, dimension_randomness, bits_coefficients_rand):
    number_witnesses_bin_decomp_rand = (bits_coefficients_rand + 1) * dimension_randomness
    PS_description.list_degrees += [RING_PROOF.deg] * number_witnesses_bin_decomp_rand
    PS_description.list_number_polynomials += [1] * number_witnesses_bin_decomp_rand
    sqnorm_lifting_bin_rand = RING_PROOF.deg # to recompute
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += ([NORM_BINARY] * bits_coefficients_rand + [sqnorm_lifting_bin_rand]) * dimension_randomness
    PS_description.approx_norm_list += [(next_norm_constraint + (bits_coefficients_rand + 1) * i + bits_coefficients_rand, 2 ** 60) for i in range(dimension_randomness)]
    PS_description.number_constraints += dimension_randomness
    return PS_description

def proof_binary_randomness(PS, next_witness, indices_randomness, trace_binary_decomp_rand, dimension_randomness, bits_coefficients_rand, bound_rand):
    indices_binary_randomness = [next_witness + (bits_coefficients_rand + 1) * i + j for i in range(dimension_randomness) for j in range(bits_coefficients_rand)]
    statements_binary_decomposition_randomness = []
    left_list_decomp = [ONE_IN_RING_PROOF, 2 * ONE_IN_RING_PROOF, 4 * ONE_IN_RING_PROOF, (2 * bound_rand + 1) * ONE_IN_RING_PROOF, - ONE_IN_RING_PROOF]
    for i in range(dimension_randomness):
        ind = next_witness + (bits_coefficients_rand + 1) * i
        indices_witness = [ind + j for j in range(bits_coefficients_rand + 1)] + [indices_randomness[i]]
        statements_binary_decomposition_randomness.append([left_list_decomp, indices_witness, ZERO_IN_RING_PROOF])
    next_witness += (bits_coefficients_rand + 1) * dimension_randomness
    for witness in trace_binary_decomp_rand:
        PS.append_witness(witness)
    for statement in statements_binary_decomposition_randomness:
        PS.append_statement(statement[0], statement[1], statement[2])
    return PS, next_witness, indices_binary_randomness


## Public

# description randomness, r
dimension_randomness, modulus_randomness = 2, RING_FALCON.mod
bound_rand, bits_coefficients_rand, variance_rand = 2, 3, 2 # uniform in [-2, 2]: 5 = 2 * 2 + 1, 3 = ceil(log2(5)), 2 = (5 ** 2 - 1) / 12
sqnorm_polynomials_randomness = round(1.35 ** 2 * variance_rand * dimension_randomness * RING_PROOF.deg) # uniform in [-2,2]

# generation commitment matrix, B
commitment_matrix = polyvec_t(RING_PROOF, dimension_randomness) # matrix 1 x 2, seen as a vector
bound_modulus_falcon = modulus_randomness // 2
for i in range(dimension_randomness):
    urandom_poly = poly_t(RING_PROOF)
    urandom_poly.urandom_bnd(- bound_modulus_falcon, bound_modulus_falcon, SEED_RING_PROOF, index_ring_proof)
    index_ring_proof += 1
    commitment_matrix.set_elem(urandom_poly, i)

# binary randomness (input of hash must be binary)
dimension_binary_randomness = dimension_randomness * bits_coefficients_rand

# description hash(bin(r))
dimension_binary_hashed_randomness = 1

# hash(rho) in mod q (Falcon modulus), h, decomposed as h(0) + b * h(1)
dimension_hashed_rho_modq, modulus_hashed_rho = 1, RING_FALCON.mod
dimension_matrix_modulus_conversion = ceil(log2(modulus_hashed_rho)) + 1
dimension_binary_hashed_rho = dimension_hashed_rho_modq * dimension_matrix_modulus_conversion
matrix_modulus_conversion, index_ring_proof = generate_matrix_transf_to_Falcon_mod(dimension_matrix_modulus_conversion, bound_modulus_falcon, index_ring_proof)

# 
base_decomp_Falcon = ceil(sqrt(1.85 * RING_FALCON.mod / sqrt(12)))

# public commitment c = Br + h mod q
dimension_commitment, modulus_commitment = dimension_hashed_rho_modq, modulus_hashed_rho

# initial vectors hash
initial_vector_rand = polyvec_t(RING_PROOF, BITS_MODULUS_HASH)
initial_vector_rho = polyvec_t(RING_PROOF, BITS_MODULUS_HASH)

def compute_commitment(message):

    # randomness
    shake128 = hashlib.shake_128(bytes.fromhex("01"))
    SEED_USER = shake128.digest(32)
    index_seed_user = 0
    randomness = polyvec_t(RING_PROOF, dimension_randomness)
    for i in range(dimension_randomness):
        urandom_poly = poly_t(RING_PROOF)
        urandom_poly.urandom_bnd(- bound_rand, bound_rand, SEED_USER, index_seed_user)
        index_seed_user += 1
        randomness.set_elem(urandom_poly, i)
    sqnorm_randomness = sum([randomness.get_elem(i).l2sq() for i in range(dimension_randomness)])
    while sqnorm_randomness > dimension_randomness * sqnorm_polynomials_randomness: # if norm randomness > beta_r, resample
        for i in range(dimension_randomness):
            urandom_poly = poly_t(RING_PROOF)
            urandom_poly.urandom_bnd(- bound_rand, bound_rand, SEED_USER, index_seed_user) # different seeds?
            index_seed_user += 1
            randomness.set_elem(urandom_poly, i)
        sqnorm_randomness = sum([randomness.get_elem(i).l2sq() for i in range(dimension_randomness)])

    # binary randomness
    binary_randomness, trace_binary_decomp_rand = compute_binary_randomness(randomness, dimension_binary_randomness, bound_rand, bits_coefficients_rand)

    # binary input hash, rho = hash(r) || nu
    binary_hashed_randomness, trace_hashed_randomness = compute_hash(binary_randomness, initial_vector_rand, dimension_binary_hashed_randomness, with_proof = True, output_in_witness = True)

    # rho
    dimension_input_hash_rho = dimension_binary_hashed_randomness + message.dim
    input_hash_rho = polyvec_t(RING_PROOF, dimension_input_hash_rho)
    for i in range(dimension_binary_hashed_randomness):
        input_hash_rho.set_elem(binary_hashed_randomness.get_elem(i), i)
    for i in range(message.dim):
        input_hash_rho.set_elem(message.get_elem(i), dimension_binary_hashed_randomness + i)

    # binary hash(rho)
    binary_hashed_rho, trace_hashed_rho = compute_hash(input_hash_rho, initial_vector_rho, dimension_binary_hashed_rho, with_proof = True, output_in_witness = True)

    # hash(rho) mod q, h = h(0) + b * h(1)
    # add witnesses and statements from modulus transformation of hashed_rho
    hashed_rho_modq_decomposed, trace_hashed_rho_modq = transform_to_Falcon_modulo(binary_hashed_rho, matrix_modulus_conversion, dimension_hashed_rho_modq, base_decomp_Falcon)

    # c = Br + h
    tmp = ZERO_IN_RING_PROOF.copy()
    for i in range(dimension_randomness):
        tmp += commitment_matrix.get_elem(i) * randomness.get_elem(i)
    tmp += hashed_rho_modq_decomposed.get_elem(0) + base_decomp_Falcon * hashed_rho_modq_decomposed.get_elem(1)
    commitment = center_reduce_polynomial(tmp.copy(), modulus_commitment)
    lifting = (tmp - commitment) * invmod(modulus_commitment, RING_PROOF.mod) # _invmod(modulus_commitment, RING_PROOF.mod) computed also above

    trace_commitment = [randomness, trace_binary_decomp_rand, trace_hashed_randomness, trace_hashed_rho, trace_hashed_rho_modq, lifting] # make better
    return commitment, trace_commitment, randomness, hashed_rho_modq_decomposed

def knowledge_preimage_commitment(message, commitment, trace_commitment, zk = True):

    # setup proof 
    PS_description = proof_statement_description()

    # update description witnesses for message
    PS_description.list_degrees += [RING_PROOF.deg] * message.dim
    PS_description.list_number_polynomials += [1] * message.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * message.dim

    # update description witnesses for randomness
    PS_description.list_degrees += [RING_PROOF.deg] * dimension_randomness
    PS_description.list_number_polynomials += [1] * dimension_randomness
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += [sqnorm_polynomials_randomness] * dimension_randomness
    PS_description.approx_norm_list += [(next_norm_constraint + i, 2 ** 40) for i in range(dimension_randomness)]

    # add description witnesses and statements for binary decomposition of randomness
    PS_description = description_compute_binary_randomness(PS_description, dimension_randomness, bits_coefficients_rand)

    #
    PS_description = description_knowledge_hash_preimage(PS_description, dimension_binary_randomness, dimension_binary_hashed_randomness, True)

    #
    dimension_input_hash_rho = dimension_binary_hashed_randomness + message.dim
    PS_description = description_knowledge_hash_preimage(PS_description, dimension_input_hash_rho, dimension_binary_hashed_rho, True)

    # add description witnesses and statements for hashed rho mod q, h
    PS_description = description_transform_to_Falcon_modulo(dimension_hashed_rho_modq, PS_description)
        
    # add description witnesses and statements for c = Br + h mod q -> c = Br + h - kq
    PS_description.list_degrees += [RING_PROOF.deg]
    PS_description.list_number_polynomials += [1]
    sqnorm_lifting_commitment = 2 ** 17 # round((1.45 * (sqrt(RING_PROOF.deg) + 1)) ** 2 * RING_PROOF.deg / 3)
    next_norm_constraint = len(PS_description.list_norm_constraints)
    PS_description.list_norm_constraints += [sqnorm_lifting_commitment]
    PS_description.approx_norm_list += [(next_norm_constraint, 2 ** 46)]
    PS_description.number_constraints += 1

    # proof setup
    PS_commitment = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = zk, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    # - to change
    randomness, trace_binary_decomp_rand, trace_hashed_randomness, trace_hashed_rho, trace_hashed_rho_modq, lifting = trace_commitment[0], trace_commitment[1], trace_commitment[2], trace_commitment[3], trace_commitment[4], trace_commitment[5]

    # add witnesses message to proof
    for i in range(message.dim):
        PS_commitment.append_witness(message.get_elem(i))
    indices_msg = [next_witness + i for i in range(message.dim)]
    next_witness += message.dim

    # add witnesses randomness
    for i in range(randomness.dim):
        PS_commitment.append_witness(randomness.get_elem(i))
    indices_randomness = [next_witness + i for i in range(randomness.dim)]
    next_witness += randomness.dim

    # witnesses and statements computation binary randomness
    PS_commitment, next_witness, indices_binary_randomness = proof_binary_randomness(PS_commitment, next_witness, indices_randomness, trace_binary_decomp_rand, randomness.dim, bits_coefficients_rand, bound_rand)

    # 
    PS_commitment, next_witness, indices_binary_hashed_rand = knowledge_hash_preimage(PS_commitment, next_witness, indices_binary_randomness, trace_hashed_randomness, initial_vector_rand, dimension_binary_hashed_randomness, True)

    #
    indices_input_hash_rho = indices_binary_hashed_rand + indices_msg
    PS_commitment, next_witness, indices_binary_hashed_rho = knowledge_hash_preimage(PS_commitment, next_witness, indices_input_hash_rho, trace_hashed_rho, initial_vector_rho, dimension_binary_hashed_rho, True)

    #
    PS_commitment, next_witness, indices_hashed_rho_modq = knowledge_transform_to_Falcon_modulo(PS_commitment, next_witness, indices_binary_hashed_rho, trace_hashed_rho_modq, dimension_hashed_rho_modq, matrix_modulus_conversion, base_decomp_Falcon)

    # add witnesses and statement for proving c = Br + h
    PS_commitment.append_witness(lifting)
    indices_lifting_commitment = [next_witness]
    next_witness += 1
    left_list = [commitment_matrix.get_elem(i) for i in range(dimension_randomness)] + [ONE_IN_RING_PROOF, ONE_IN_RING_PROOF * base_decomp_Falcon, - modulus_hashed_rho * ONE_IN_RING_PROOF]
    indices_witness = indices_randomness + indices_hashed_rho_modq + indices_lifting_commitment
    PS_commitment.append_statement(left_list, indices_witness, commitment)

    return PS_commitment


## Message generation
dimension_msg = 1
message = polyvec_t(RING_PROOF, dimension_msg, [randrange(2) for i in range(dimension_msg * RING_PROOF.deg)])

# computation commitment to message
commitment, trace_commitment, randomness, hashed_rho_modq_decomposed = compute_commitment(message)

# proof of correct computation of the commitment
PS_commitment = knowledge_preimage_commitment(message, commitment, trace_commitment)


# Proof
statement = PS_commitment.output_statement()
proof = PS_commitment.pack_prove()

# Signer
# verify the proof 
verification_start_time = time.perf_counter()
if proof[0] == 0:
    successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF) # if False should abort itself # nope
assert successful_verification, "Proof verification failed."
verification_end_time = time.perf_counter()


# sample A, T (before this point)
skenc, pkenc, pkpol = falcon_keygen()
lifted_pkpol = pkpol.lift(RING_PROOF)

# compute preimage of the commitment
# check that coefficient of c are in Rq, write it as a Falcon polynomial to use "falcon_preimage_sample"
assert commitment.linf() <= RING_FALCON.mod // 2, "Coefficients of the commitment must be mod Falcon modulus"
commitment_in_Falcon_ring = poly_t(RING_FALCON, commitment)
sd_s = 287.58 # ???
sqnorm_polynomials_s = round(RING_PROOF.deg * sd_s ** 2)
s_in_Falcon_ring = falcon_preimage_sample(skenc, commitment_in_Falcon_ring)
dimension_s = len(s_in_Falcon_ring)

sqnorm_s = 0
for i in range(len(s_in_Falcon_ring)):
    sqnorm_s += s_in_Falcon_ring[i].l2sq()
while sqnorm_s > len(s_in_Falcon_ring) * sqnorm_polynomials_s:
    s_in_Falcon_ring = falcon_preimage_sample(skenc, commitment_in_Falcon_ring) # different or the same as before?
    sqnorm_s = 0
    for i in range(len(s_in_Falcon_ring)):
        sqnorm_s += s_in_Falcon_ring[i].l2sq()    

# Signature
assert center_reduce_polynomial(pkpol * s_in_Falcon_ring[1] + s_in_Falcon_ring[0], RING_FALCON.mod) == commitment
# compute As = Br + h mod q
h_decomp = polyvec_t(RING_FALCON, hashed_rho_modq_decomposed.dim, hashed_rho_modq_decomposed)
h = polyvec_t(RING_FALCON, 1, [h_decomp.get_elem(0) + h_decomp.get_elem(1) * base_decomp_Falcon])

seed = b'\0' * 32
from _blns_params_cffi import lib
prover = lin_prover_state_t(seed, lib.get_params("blns_param"))
verifier = lin_verifier_state_t(seed, lib.get_params("blns_param"))
matrix = polymat_t(RING_FALCON, 1, dimension_s + dimension_randomness)
matrix.set_elem(- ONE_IN_RING_PROOF, 0, 0)
matrix.set_elem(- pkpol, 0, 1)
matrix.set_elem(commitment_matrix.get_elem(0), 0, 2)
matrix.set_elem(commitment_matrix.get_elem(1), 0, 3)

prover.set_statement(matrix, h)
wit = polyvec_t(RING_FALCON, dimension_s + dimension_randomness)
for i in range(dimension_s):
    wit.set_elem(s_in_Falcon_ring[i], i)
for i in range(dimension_randomness):
    wit.set_elem(randomness.get_elem(i), dimension_s + i)
prover.set_witness(wit)

proof = prover.prove()
print_stopwatch_lnp_prover_prove(0)

verifier.set_statement(matrix, h)
try:
    verifier.verify(proof)
except VerificationError:
    print("reject")
    bool_commitment = False
else:
    print("accept")
    bool_commitment = True
print_stopwatch_lnp_verifier_verify(0)
assert bool_commitment