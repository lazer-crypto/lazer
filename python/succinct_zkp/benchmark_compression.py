from hash import *
import time
from benchmark_aux import get_statistics
import random

def benchmark_compression(dim_input, zk):
    
    # generate input and initial_vector (poly512 in ffi)
    input = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_input)])
    initial_vector = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)])
    
    # compress input (compress_internal)
    start = time.perf_counter()
    output, trace = compress_internal(input, initial_vector, with_proof = True, output_in_witness = False)
    end = time.perf_counter()
    time_internal = end - start

    # generate input and initial_vector
    input = polyvec_t(RING_PROOF, dim_input, [randrange(2) for i in range(DEGREE_HASH * dim_input)])
    initial_vector = polyvec_t(RING_PROOF, BITS_MODULUS_HASH, [randrange(2) for i in range(DEGREE_HASH * BITS_MODULUS_HASH)])
    
    # compress input
    start = time.perf_counter()
    output, trace = compress(input, initial_vector, with_proof = True, output_in_witness = False)
    end = time.perf_counter()
    time_compression = end - start

    # prove knowledge of compression preimage
    PS_description = proof_statement_description()
    PS_description.list_degrees += [DEGREE_HASH] * input.dim
    PS_description.list_number_polynomials += [1] * input.dim
    PS_description.list_norm_constraints += [NORM_BINARY] * input.dim
    PS_description = description_knowledge_compression_preimage(PS_description, input.dim, output_in_witness = False)
    
    PS = proof_statement(PS_description.list_degrees, PS_description.list_number_polynomials, PS_description.list_norm_constraints, PS_description.number_constraints, SIZE_MODULUS_PROOF, zk = zk, approx_norm_list = PS_description.approx_norm_list)
    next_witness = 0

    for poly in range(input.dim):
        PS.append_witness(input.get_elem(poly))
    indices_input = list(range(input.dim))
    next_witness += input.dim
    PS, next_witness = knowledge_compression_preimage(PS, next_witness, indices_input, trace, initial_vector, output_in_witness = False, compressed_input = output)

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

    return time_internal, time_compression, time_proof, time_verif

for dim_input in [2**6,2**8,2**10,2**12,2**14,2**16]:
    for zk in [True, False]:
        time_internal = []
        time_compression = []
        time_proof = []
        time_verif = []

        random.seed(0)
        for _ in range(5):
            t1, t2, t3, t4 = benchmark_compression(dim_input, zk)
            time_internal += [t1]
            time_compression += [t2]
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
