from membership_proof import *
import time
from benchmark_aux import get_statistics
import random

dim_binary_pk = ceil(log2(RING_FALCON.mod))

# path generation
# computation of the Merkle tree and extraction of the user path
# for large tree height, we generate a random path instead (benchmarking of the Merkle tree generation separate)
def generate_path(height_tree):

    if height_tree < 10:

        # generate public keys
        pks = [] # create list of binary pks, number must be a power of 2
        for i in range(2**height_tree):
            pks += [ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])]

        # compute Merkle tree
        tree = MerkleTree(pks)

        # get path 
        user_index = 2 # randrange(2 ** height_tree)
        path,siblings = tree.get_path(user_index)
        binary_pk = pks[user_index]

        # root 
        binary_root = convert_poly512_to_polyvec(tree.get_root(), RING_PROOF)
        root = ZERO_IN_RING_PROOF.copy()
        for poly in range(BITS_MODULUS_HASH):
            root += 2 ** poly * binary_root.get_elem(poly)

    else:

        # generate path
        dim_binary_pk = ceil(log2(RING_FALCON.mod))
        binary_pk = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])
        siblings = [ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)]) for depth in range(height_tree)]
        path = [randrange(2) for depth in range(height_tree)]
        root = compute_root_from_path(height_tree, binary_pk, siblings, path)

    return binary_pk, root, siblings, path
    

def benchmark_membership_proof(height_tree, number_paths, zk): # with ffi

    # proof description
    PS_description = proof_statement_description()

    for _ in range(number_paths):
        PS_description.list_degrees += [DEGREE_HASH] * dim_binary_pk
        PS_description.list_number_polynomials += [1] * dim_binary_pk
        PS_description.list_norm_constraints += [NORM_BINARY] * dim_binary_pk
        PS_description = description_knowledge_path(dim_binary_pk, height_tree, PS_description)

    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, num_deg0_constraints = PS_description.num_deg0_constraints, zk = zk, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    time_trace = 0
    for _ in range(number_paths):

        # generate path
        binary_pk, root, siblings, path = generate_path(height_tree)

        # compute trace path
        start = time.perf_counter()
        trace_path = compute_path_trace(binary_pk, siblings, path, height_tree) # membership_ptoof_trace/ ???
        end = time.perf_counter()
        time_trace += end - start

        for poly in range(len(binary_pk)):
            PS.append_witness_pointer(ffi.cast("int64_t*", binary_pk[poly]), DEGREE_HASH)
        indices_pk = [next_witness + i for i in range(len(binary_pk))]
        next_witness += len(binary_pk)

        PS, next_witness = knowledge_path_only(PS, next_witness, indices_pk, trace_path, root, height_tree)
    
    statement = PS.output_statement()
    start = time.perf_counter()
    proof = PS.pack_prove()
    end = time.perf_counter()
    time_proof = end - start
    
    if proof[0] == 0:
        start = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        end = time.perf_counter()
        time_verif = end - start
    assert successful_verification, "Verification fails"

    return time_trace, time_proof, time_verif


height_tree = 64

for number_paths in [1, 2, 4, 8, 16, 32, 64, 128]:
    for zk in [True, False]:
        time_trace = []
        time_proof = []
        time_verif = []
        
        random.seed(0)
        for _ in range(5):
            t1, t2, t3 = benchmark_membership_proof(height_tree, number_paths, zk)

            time_trace += [t1]
            time_proof += [t2]
            time_verif += [t3]

        print("\n***********\n")

        print("Tree height:", height_tree)
        print("Number of paths:", number_paths)
        print("zk:", zk)
        # print("Time trace:", get_statistics(time_trace))
        print("Time proof:", get_statistics(time_proof))
        print("Time verif:", get_statistics(time_verif))

        print("\n***********\n")