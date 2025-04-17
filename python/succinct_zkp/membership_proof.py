import sys
sys.path.append('..')   # path to lazer module 
from lazer import *     # import lazer python module
from labrados import *
from merkle_tree import *

lifting_decomposed_mt = False

SQNORM_DELTA = 2 ** 23
SQNORM_LIFTING_DELTA = 2 ** 32 # should be 2 ** 32
SQNORM_LIFTING_PARENT = 2 **32 # should be 2 ** 32


if lifting_decomposed_mt:
    LEFT_LIST_DELTA = [URANDOM_MATRIX_HASH.get_elem(poly) - URANDOM_MATRIX_HASH.get_elem(poly + BITS_MODULUS_HASH) for poly in range(BITS_MODULUS_HASH)] + [URANDOM_MATRIX_HASH.get_elem(poly + BITS_MODULUS_HASH) - URANDOM_MATRIX_HASH.get_elem(poly) for poly in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF, - MODULUS_HASH * ONE_IN_RING_PROOF, - MODULUS_HASH * BASE_LIFTINGS_COMPRESSION * ONE_IN_RING_PROOF]
    STAT_LIN = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(2 * BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF, - MODULUS_HASH * BASE_LIFTINGS_COMPRESSION * ONE_IN_RING_PROOF]
    STAT_LIN_ROOT = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(2 * BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF, - MODULUS_HASH * BASE_LIFTINGS_COMPRESSION * ONE_IN_RING_PROOF]
else:
    LEFT_LIST_DELTA = [URANDOM_MATRIX_HASH.get_elem(poly) - URANDOM_MATRIX_HASH.get_elem(poly + BITS_MODULUS_HASH) for poly in range(BITS_MODULUS_HASH)] + [URANDOM_MATRIX_HASH.get_elem(poly + BITS_MODULUS_HASH) - URANDOM_MATRIX_HASH.get_elem(poly) for poly in range(BITS_MODULUS_HASH)] + [- ONE_IN_RING_PROOF, - MODULUS_HASH * ONE_IN_RING_PROOF]
    STAT_LIN = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(2 * BITS_MODULUS_HASH)] + [- 2 ** i * ONE_IN_RING_PROOF for i in range(BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]
    STAT_LIN_ROOT = [URANDOM_MATRIX_HASH.get_elem(i) for i in range(2 * BITS_MODULUS_HASH)] + [- MODULUS_HASH * ONE_IN_RING_PROOF]

def compute_delta(path_node, sibling):
    delta = ffi.new("signed_poly512")
    lifting = ffi.new("signed_poly512")
    lib.compute_delta(delta, lifting, path_node, sibling)

    return delta, lifting

def clib_compute_lifting_parent_node(child_path_node, sibling, path_selector, delta, parent_path_node):
    lifting_parent_node = ffi.new("signed_poly512")
    lib.compute_cutoff_parent_node(lifting_parent_node, child_path_node, sibling, path_selector, delta, parent_path_node)

    return lifting_parent_node

def description_knowledge_path(dim_binary_pk, height_tree, PS_description):
    PS_description = description_knowledge_compression_preimage(PS_description, dim_binary_pk)
    if lifting_decomposed_mt:
        approx_norms_delta = []
        approx_norms_lifting_delta_high = []
        approx_norms_lifting_delta_low = []
        approx_norms_lifting_parent_high = []
        approx_norms_lifting_parent_low = []
    else:
        approx_norms_delta = []
        approx_norms_lifting_delta = []
        approx_norms_lifting_parent = []
    for depth in reversed(range(height_tree)):
        # append witnesses for sibling node
        PS_description.list_degrees += [DEGREE_HASH] * BITS_MODULUS_HASH
        PS_description.list_number_polynomials += [1] * BITS_MODULUS_HASH
        PS_description.list_norm_constraints += [NORM_BINARY] * BITS_MODULUS_HASH
        # append witness for delta and decomposed lifting, append statement for delta being well-formed
        next_norm_constraint = len(PS_description.list_degrees)
        if lifting_decomposed_mt:
            PS_description.list_degrees += [DEGREE_HASH] * 3
            PS_description.list_number_polynomials += [1] * 3
            PS_description.list_norm_constraints += [2**23] + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] # recompute first with smart way, compute last # first one should be around 2**16
            approx_norms_delta += [(next_norm_constraint, 2**70)]
            approx_norms_lifting_delta_high += [(next_norm_constraint + 1, 2**46)]
            approx_norms_lifting_delta_low += [(next_norm_constraint + 2, 2**54)]
        else:
            PS_description.list_degrees += [DEGREE_HASH] * 2
            PS_description.list_number_polynomials += [1] * 2
            PS_description.list_norm_constraints += [SQNORM_DELTA] + [SQNORM_LIFTING_DELTA]
            approx_norms_delta += [(next_norm_constraint, 2**72)]
            approx_norms_lifting_delta += [(next_norm_constraint + 1, 2**58)]
        PS_description.number_constraints += 1
        # append witness for bit representing the path
        PS_description.list_degrees += [DEGREE_HASH]
        PS_description.list_number_polynomials += [1]
        PS_description.list_norm_constraints += [NORM_BINARY]
        PS_description.num_deg0_constraints += 1
        # append witnesses for sibling node
        if depth > 0:
            PS_description.list_degrees += [DEGREE_HASH] * BITS_MODULUS_HASH
            PS_description.list_number_polynomials += [1] * BITS_MODULUS_HASH
            PS_description.list_norm_constraints += [NORM_BINARY] * BITS_MODULUS_HASH
        #lifting, append statement for correct computation of parent node
        next_norm_constraint = len(PS_description.list_degrees)
        if lifting_decomposed_mt:
            PS_description.list_degrees += [DEGREE_HASH] * 2
            PS_description.list_number_polynomials += [1] * 2
            PS_description.list_norm_constraints += [SQNORM_COMPONENTS_LIFTING_COMPRESSION] + [SQNORM_COMPONENTS_LIFTING_COMPRESSION] # compute last
            approx_norms_lifting_parent_high += [(next_norm_constraint, 2**46)]
            approx_norms_lifting_parent_low += [(next_norm_constraint + 1, 2**54)]    
        else:
            PS_description.list_degrees += [DEGREE_HASH]
            PS_description.list_number_polynomials += [1]
            PS_description.list_norm_constraints += [SQNORM_LIFTING_PARENT]
            approx_norms_lifting_parent += [(next_norm_constraint, 2**58)]
        PS_description.number_constraints += 1    
    if lifting_decomposed_mt:
        PS_description.approx_norm_list += approx_norms_delta + approx_norms_lifting_delta_high + approx_norms_lifting_delta_low + approx_norms_lifting_parent_high + approx_norms_lifting_parent_low
    else:
        PS_description.approx_norm_list += approx_norms_delta + approx_norms_lifting_delta + approx_norms_lifting_parent
    return PS_description

def clib_decomp_64(input):
    
    output = ffi.new("signed_poly512 [2]")
    lib.decomposition_binary_power(output, input, 6, 2)
    return output

# input binary_pk must be of type poly512[] and binary
def knowledge_path(binary_pk, siblings, path, height_tree, PS, indices_pk, next_witness, root):
    assert len(siblings) == height_tree and len(path) == height_tree, "Inconsistent path."

    # compress pk to obtain leaf with proof
    compressed_pk, trace_compression = compress_internal(binary_pk, INITIAL_VECTOR, True)
    PS, next_witness, indices_compressed_pk = knowledge_compression_preimage(PS, next_witness, indices_pk, trace_compression, convert_poly512_to_polyvec(INITIAL_VECTOR, RING_PROOF))
    path_node, indices_path_node = compressed_pk, indices_compressed_pk

    # proof knowledge of path
    for depth in reversed(range(height_tree)):
        # witness for sibling node
        for poly in range(BITS_MODULUS_HASH):
            PS.append_witness_pointer(ffi.cast("int64_t*", siblings[depth][poly]), DEGREE_HASH)
        indices_sibling = [next_witness + poly for poly in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH

        # witness delta and lifting, well-formness delta
        delta, lifting_delta = compute_delta(path_node, siblings[depth])
        PS.append_witness_pointer(delta, DEGREE_HASH)
        indices_delta = [next_witness]
        if lifting_decomposed_mt:
            lifting_delta_decomposed = clib_decomp_64(lifting_delta)
            for poly in range(2):
                PS.append_witness_pointer(lifting_delta_decomposed[poly], DEGREE_HASH)
            indices_witness = indices_sibling + indices_path_node + indices_delta + [next_witness + 1 + poly for poly in range(2)]
        else:
            PS.append_witness_pointer(lifting_delta, DEGREE_HASH)
            indices_witness = indices_sibling + indices_path_node + indices_delta + [next_witness + 1]
        PS.append_statement(LEFT_LIST_DELTA, indices_witness, ZERO_IN_RING_PROOF)
        if lifting_decomposed_mt:
            next_witness += 3
        else:
            next_witness += 2

        # witness path selector
        if path[depth] == 0:
            PS.append_witness(ZERO_IN_RING_PROOF)
        else:
            PS.append_witness(ONE_IN_RING_PROOF)
        indices_path_direction = [next_witness]
        next_witness += 1

        # path selector is an integer
        PS.append_deg0_statement(indices_path_direction[0])

        # compute parent node
        if path[depth] == 0:
            left_child = path_node
            right_child = siblings[depth]
        else:
            left_child = siblings[depth]
            right_child = path_node
        child_path_node = path_node
        path_node = compute_parent_node(left_child, right_child)

        if depth > 0:
            # witness parent node
            for poly in range(BITS_MODULUS_HASH):
                PS.append_witness_pointer(ffi.cast("int64_t*", path_node[poly]), DEGREE_HASH)
            indices_child_path_node = indices_path_node
            indices_path_node = [next_witness + poly for poly in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH
        
        # compute lifting correct computation parent node
        lifting_parent_node = clib_compute_lifting_parent_node(child_path_node, siblings[depth], path[depth], delta, path_node)

        # correct computation parent node
        if lifting_decomposed_mt:
            lifting_parent_node_decomposed = clib_decomp_64(lifting_parent_node)
            for poly in range(2):
                PS.append_witness_pointer(lifting_parent_node_decomposed[poly], DEGREE_HASH)
            indices_lifting_parent = [next_witness + i for i in range(2)]
            next_witness += 2
        else:
            PS.append_witness_pointer(lifting_parent_node, DEGREE_HASH)
            indices_lifting_parent = [next_witness]
            next_witness += 1
        if depth > 0:
            wit_lin = indices_child_path_node + indices_sibling + indices_path_node + indices_lifting_parent
            PS.append_quadratic_statement(STAT_LIN, wit_lin, [1], indices_path_direction, indices_delta, ZERO_IN_RING_PROOF)
        else:
            wit_lin = indices_path_node + indices_sibling + indices_lifting_parent
            PS.append_quadratic_statement(STAT_LIN_ROOT, wit_lin, [1], indices_path_direction, indices_delta, root)

    return PS, next_witness

def compute_number_witnesses_tree(height_tree):
    if lifting_decomposed_mt:
        return height_tree * (2 * BITS_MODULUS_HASH + 6) - BITS_MODULUS_HASH
    return height_tree * (2 * BITS_MODULUS_HASH + 4) - BITS_MODULUS_HASH

# compute path trace
def compute_path_trace(binary_pk, siblings, path, height_tree):
    assert len(siblings) == height_tree and len(path) == height_tree, "Inconsistent path."

    # compress pk to obtain leaf with proof
    compressed_pk, trace_compression = compress_internal(binary_pk, INITIAL_VECTOR, True)
    path_node = compressed_pk

    trace_tree = ffi.new("signed_poly512 []", compute_number_witnesses_tree(height_tree))
    pos_in_trace = 0
    
    # path
    for depth in reversed(range(height_tree)):

        # witness for sibling node
        ffi.memmove(trace_tree + pos_in_trace, siblings[depth], BITS_MODULUS_HASH * ffi.sizeof("poly512"))
        pos_in_trace += BITS_MODULUS_HASH

        # witness delta and lifting, well-formness delta
        delta, lifting_delta = compute_delta(path_node, siblings[depth])
        ffi.memmove(trace_tree + pos_in_trace, delta, ffi.sizeof(delta))
        pos_in_trace += 1
        if lifting_decomposed_mt:
            lifting_delta_decomposed = clib_decomp_64(lifting_delta)
            ffi.memmove(trace_tree + pos_in_trace, lifting_delta_decomposed, 2 * ffi.sizeof("signed_poly512"))
            pos_in_trace += 2
        else:
            ffi.memmove(trace_tree + pos_in_trace, lifting_delta, ffi.sizeof(lifting_delta))
            pos_in_trace += 1
        
        # witness path selector
        trace_tree[pos_in_trace] = [0]*DEGREE_HASH
        if path[depth] == 1:
            trace_tree[pos_in_trace][0] = 1
        pos_in_trace += 1
        
        # compute parent node # (in the if depth > 0, for 0 is root)
        if path[depth] == 0:
            left_child = path_node
            right_child = siblings[depth]
        else:
            left_child = siblings[depth]
            right_child = path_node
        child_path_node = path_node
        path_node = compute_parent_node(left_child, right_child)

        # witness parent node
        if depth > 0:
            ffi.memmove(trace_tree + pos_in_trace, path_node, BITS_MODULUS_HASH * ffi.sizeof("poly512"))
            pos_in_trace += BITS_MODULUS_HASH

        
        # compute lifting correct computation parent node
        lifting_parent_node = clib_compute_lifting_parent_node(child_path_node, siblings[depth], path[depth], delta, path_node)

        # correct computation parent node
        if lifting_decomposed_mt:
            lifting_parent_node_decomposed = clib_decomp_64(lifting_parent_node)
            ffi.memmove(trace_tree + pos_in_trace, lifting_parent_node_decomposed, 2 * ffi.sizeof("signed_poly512"))
            pos_in_trace += 2
        else:
            ffi.memmove(trace_tree + pos_in_trace, lifting_parent_node, ffi.sizeof(lifting_parent_node))
            pos_in_trace += 1
    return [trace_compression, trace_tree]

# prove path knowledge
def knowledge_path_only(PS, next_witness, indices_pk, trace_path, root, height_tree):

    # compress pk
    PS, next_witness, indices_compressed_pk = knowledge_compression_preimage(PS, next_witness, indices_pk, trace_path[0], convert_poly512_to_polyvec(INITIAL_VECTOR, RING_PROOF))
    indices_path_node = indices_compressed_pk
    
    # witnesses path
    for poly in range(len(trace_path[1])):
        PS.append_witness_pointer(trace_path[1][poly], DEGREE_HASH)
    
    # path
    for depth in reversed(range(height_tree)):

        # witness for sibling node
        indices_sibling = [next_witness + poly for poly in range(BITS_MODULUS_HASH)]
        next_witness += BITS_MODULUS_HASH

        # witness delta and lifting, well-formness delta
        indices_delta = [next_witness]
        if lifting_decomposed_mt:
            indices_witness = indices_sibling + indices_path_node + indices_delta + [next_witness + 1 + poly for poly in range(2)]
            next_witness += 3
        else:
            indices_witness = indices_sibling + indices_path_node + indices_delta + [next_witness + 1]
            next_witness += 2
        PS.append_statement(LEFT_LIST_DELTA, indices_witness, ZERO_IN_RING_PROOF)

        # witness path selector
        indices_path_direction = [next_witness]
        next_witness += 1

        # path selector is an integer
        PS.append_deg0_statement(indices_path_direction[0])

        # witness parent node
        if depth > 0:    
            indices_child_path_node = indices_path_node
            indices_path_node = [next_witness + poly for poly in range(BITS_MODULUS_HASH)]
            next_witness += BITS_MODULUS_HASH

        # correct computation parent node
        if lifting_decomposed_mt:
            indices_lifting_parent = [next_witness + i for i in range(2)]
            next_witness += 2
        else:
            indices_lifting_parent = [next_witness]
            next_witness += 1
        if depth > 0:
            wit_lin = indices_child_path_node + indices_sibling + indices_path_node + indices_lifting_parent
            PS.append_quadratic_statement(STAT_LIN, wit_lin, [1], indices_path_direction, indices_delta, ZERO_IN_RING_PROOF)
        else:
            wit_lin = indices_path_node + indices_sibling + indices_lifting_parent
            PS.append_quadratic_statement(STAT_LIN_ROOT, wit_lin, [1], indices_path_direction, indices_delta, root)

    return PS, next_witness

def knowledge_path_separate(binary_pk, siblings, path, height_tree, PS, indices_pk, next_witness, root):
    trace_path = compute_path_trace(binary_pk, siblings, path, height_tree)
    PS, next_witness = knowledge_path_only(PS, next_witness, indices_pk, trace_path, root, height_tree)
    return PS, next_witness

def prove_knowledge_path(height_tree, binary_pk, root, siblings, path, time_proof = False):
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * len(binary_pk)
    PS_description.list_number_polynomials += [1] * len(binary_pk)
    PS_description.list_norm_constraints += [NORM_BINARY] * len(binary_pk)
    PS_description = description_knowledge_path(len(binary_pk), height_tree, PS_description)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, num_deg0_constraints = PS_description.num_deg0_constraints, zk = True, approx_norm_list = PS_description.approx_norm_list)

    next_witness = 0
    for i in range(len(binary_pk)):
        PS.append_witness_pointer(ffi.cast("int64_t*", binary_pk[i]), DEGREE_HASH)
    next_witness += len(binary_pk)
    indices_pk = list(range(len(binary_pk)))

    # PS, next_witness = knowledge_path(binary_pk, siblings, path, height_tree, PS, indices_pk, next_witness, root)
    PS, next_witness = knowledge_path_separate(binary_pk, siblings, path, height_tree, PS, indices_pk, next_witness, root)
    statement = PS.output_statement()

    proof_start_time = time.perf_counter()
    proof = PS.pack_prove()
    proof_end_time = time.perf_counter()
    if proof[0] == 0:
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
    assert successful_verification, "Proof verification failed."

    if time_proof:
        return proof_end_time - proof_start_time
    
def compute_root_from_path(height_tree, binary_pk, siblings, path):

    # compress pk to obtain leaf with proof
    compressed_pk = compress_internal(binary_pk, INITIAL_VECTOR, False)
    path_node = compressed_pk
    for depth in reversed(range(height_tree)):
        
        # compute parent node
        if path[depth] == 0:
            left_child = path_node
            right_child = siblings[depth]
        else:
            left_child = siblings[depth]
            right_child = path_node
        path_node = compute_parent_node(left_child, right_child)

    # re-compose root
    root = ZERO_IN_RING_PROOF.copy()
    for poly in range(BITS_MODULUS_HASH):
        root += 2 ** poly * convert_poly512_to_polyvec(path_node, RING_PROOF).get_elem(poly)
        
    return root


if __name__ == "__main__":

    # compute Merkle tree
    height_tree = 7

    dim_binary_pk = ceil(log2(RING_FALCON.mod))
    pks = [] # create list of binary pks, number must be a power of 2
    for i in range(2**height_tree):
        pks += [ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])]

    tree = MerkleTree(pks)

    # get path 
    user_index = 2
    path,siblings = tree.get_path(user_index)
    binary_pk = pks[user_index]

    # root 
    binary_root = convert_poly512_to_polyvec(tree.get_root(), RING_PROOF)
    root = ZERO_IN_RING_PROOF.copy()
    for poly in range(BITS_MODULUS_HASH):
        root += 2 ** poly * binary_root.get_elem(poly)

    # prove knowledge of path
    prove_knowledge_path(height_tree, binary_pk, root, siblings, path)


    ## Proof timing
    list_heights = [8, 16, 32, 64, 128, 256]
    timings = []
    for height_tree in list_heights:

        # create meaningless path
        dim_binary_pk = ceil(log2(RING_FALCON.mod))
        binary_pk = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])
        siblings = [ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)]) for depth in range(height_tree)]
        path = [randrange(2) for depth in range(height_tree)]
        root = compute_root_from_path(height_tree, binary_pk, siblings, path)

        # prove knowledge of path
        timings.append(prove_knowledge_path(height_tree, binary_pk, root, siblings, path, time_proof = True))

    for i in range(len(list_heights)):
        print("Proof time for tree height ", list_heights[i], " = ", timings[i])
