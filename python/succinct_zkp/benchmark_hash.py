from hash import *
import time
from benchmark_aux import get_statistics

def benchmark_hash(nb_hash, dim_input, dim_output, zk):
    
    # prove knowledge of compression preimage
    PS_description = proof_statement_description()

    for _ in range(nb_hash):
        PS_description.list_degrees += [DEGREE_HASH] * dim_input
        PS_description.list_number_polynomials += [1] * dim_input
        PS_description.list_norm_constraints += [NORM_BINARY] * dim_input
        PS_description = description_knowledge_hash_preimage(PS_description, dim_input, dim_output, output_in_witness = False)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = zk, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for _ in range(nb_hash):

        # # generate input and initial_vector (poly512 in ffi)
        # input = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_input)])
        # initial_vector = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)])
        
        # # compress input (compress_internal)
        # start = time.perf_counter()
        # output, trace = compute_hash_internal(input, initial_vector, dim_output, with_proof = True, output_in_witness = False)
        # end = time.perf_counter()
        # time_internal = end - start

        # generate input and initial_vector
        input = polyvec_t(RING_PROOF, dim_input, [randrange(2) for i in range(DEGREE_HASH * dim_input)])
        initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
        
        # compress input
        # start = time.perf_counter()
        output, trace = compute_hash(input, initial_vector, dim_output, with_proof = True, output_in_witness = False)
        # end = time.perf_counter()
        # time_compression = end - start

        # Proof of knowledge
        for poly in range(input.dim):
            PS.append_witness(input.get_elem(poly))
        indices_input = [next_witness + i for i in range(input.dim)]
        next_witness += input.dim
        PS, next_witness = knowledge_hash_preimage(PS, next_witness, indices_input, trace, initial_vector, info_output = output, output_in_witness = False)
        
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

    # return time_internal, time_compression, time_proof, time_verif
    return time_proof, time_verif

zk = True
dim_input = 1
dim_output = 1

for nb_hash in [1000]:
    # time_internal = []
    # time_compression = []
    time_proof = []
    time_verif = []

    for _ in range(10):
        # t1, t2, t3, t4 = benchmark_compression(dim_input, zk)
        t3, t4 = benchmark_hash(nb_hash, dim_input, dim_output, zk)
        # time_internal += [t1]
        # time_compression += [t2]
        time_proof += [t3]
        time_verif += [t4]

    print("\n***********\n")

    print("Input dimension:", dim_input)
    print("zk:", zk)

    # print("Time internal:", get_statistics(time_internal))
    # print("Time compression:", get_statistics(time_compression))
    print("Time proof:", get_statistics(time_proof))
    print("Time verif:", get_statistics(time_verif))

    print("\n***********\n")