from hash import *
from blind_signatures import *
import time    
from benchmark_aux import get_statistics
import random

def benchmark_blind_signatures(dimension_msg, zk):
    
    # generation message 
    message = polyvec_t(RING_PROOF, dimension_msg, [randrange(2) for i in range(dimension_msg * RING_PROOF.deg)])

    # computation commitment to message
    start = time.perf_counter()
    commitment, trace_commitment, _, _ = compute_commitment(message)
    end = time.perf_counter()
    time_commitment = end - start

    # proof correct computation commitment
    PS_commitment = knowledge_preimage_commitment(message, commitment, trace_commitment, zk)

    PS_commitment.smpl_verify()

    statement = PS_commitment.output_statement()
    start = time.perf_counter()
    proof = PS_commitment.pack_prove()
    end = time.perf_counter()
    time_proof = end - start


    # verification
    if proof[0] == 0:
        start = time.perf_counter()
        successful_verification = pack_verify(proof[1:3], statement, SIZE_MODULUS_PROOF)
        end = time.perf_counter()
        time_verif = end - start
    assert successful_verification, "Verification fails"

    return time_commitment, time_proof, time_verif


dimension_msg = 10

for zk in [True, False]:
    time_commitment = []
    time_proof= []
    time_verif = []

    random.seed(0)
    for _ in range(10):
        t1, t2, t3 = benchmark_blind_signatures(dimension_msg, zk)

        time_commitment += [t1]
        time_proof += [t2]
        time_verif += [t3]

    print("\n***********\n")

    print("Message dimension:", dimension_msg)
    print("zk:", zk)

    # print("Time commitment:", get_statistics(time_commitment))
    print("Time proof:", get_statistics(time_proof))
    print("Time verif:", get_statistics(time_verif))

    print("\n***********\n")