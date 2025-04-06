import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module
from merkletree import *     # import tree node module

import time
import hashlib          # for SHAKE128

from math import ceil
from math import log2 as lg
from treethings.tree import makeGvec

from ajtaitree_params import deg, mod, mod, B, m, n
from _ajtaitree_params_cffi import lib

d, q = deg, mod
Rq = polyring_t(d, q)

def set_A_matrix(T: MerkleTree) -> Tuple[polymat_t, polymat_t]:
    """
    Construct the matrix A used in the proof system.

    Args:
        T (MerkleTree): The Merkle tree to use for commitment.

    Returns:
        Tuple[polymat_t, polymat_t]: The public proof matrices A0 and A1.
    """
    # initialise the matrices
    A0 = polymat_t(Rq, m, 3 * n)
    A1 = polymat_t(Rq, m, 3 * n)

    # create the binary recomposition gadget madtrix
    G = makeGmat(Rq, m, n)

    # define the submatrices as slices of A0 and A1
    A0.set_submatrix(0, 0, T.L)
    A0.set_submatrix(0, n, T.R)
    A0.set_submatrix(0, 2 * n, -G)

    A1.set_submatrix(0, 0, T.R)
    A1.set_submatrix(0, n, T.L)
    A1.set_submatrix(0, 2 * n, -G)

    return (A0, A1)


def commit(
                COMPP: bytes, T: MerkleTree, µ: List[polyvec_t], 
                test: bool = False
        ) -> Tuple[polyvec_t, polyvec_t]:
    """
    Commit to a list of messages using a Merkle tree.

    Args:
        COMPP (bytes):  Randomness seed.
        T (MerkleTree): The Merkle tree to use for commitment.
        µ (List[polyvec_t]): List of messages to commit to.
        test (bool): Whether to perform a sanity check on the opening.

    Returns:
         Tuple[polyvec_t, polyvec_t]: Commitment to the root of the Merkle tree,
            and the commitment randomness.
    """

    # create the Merkle tree commitment
    print(f"Building the commitment tree for {len(µ)} leaves ...")
    start_time = time.time()
    h = T.commit(µ)
    tree_time = time.time() - start_time
    print(f"[OK] completed in: {tree_time:.3f} s")

    # Ajtai commitment to the Merkle tree root
    x = polyvec_t(Rq, n)
    x.urandom_bnd(0, 1, COMPP, 2 + len(µ))
    _c = T.L * h + T.R * x
    com_time = time.time() - start_time
    print(f"[OK] completed in: +{com_time - tree_time:.3f} s")

    c = bin_decompose_gadget(_c)

    if test:
        # opening sanity check
        op = T.lin_open(0)
        if not T.verify_lin_open(µ[0], op, 0) or T.verify_lin_open(µ[1], op, 0):
            print("[ERR] opening verification failed.")
            sys.exit()
        else: print("[OK] successfully verified linear opening.")

    return c, x

def prove_lin_open(
                    PROOFPP: bytes, A: List[polymat_t], T: MerkleTree, 
                    c: polyvec_t, x: polyvec_t, idx: int = 0
                ) -> List[bytes]:
    """
    Generate a proof of correctness for the commitment.

    Args:
        PROOFPP (bytes): Entropy for pseudorandom generation in the proof system.
        A (List[polymat_t]): List of the public matrices of the proof system.
        T (MerkleTree): The Merkle tree used for commitment.
        c (polyvec_t): The commitment vector.
        x (polyvec_t): Random vector for the commitment.
        idx (int): The idx of the leaf to prove opening of.
    Returns:
        List[bytes]: The generated proofs.
    """
    # initialize an empty list for the proofs
    π = []

    # get the Merkle opening
    op = T.lin_open(idx)

    # ---------------------------------------------------------------
    # WARNING!
    # The proof below is not sound as it proves each individual 
    # node separately. A "no-signaling" property is required for
    # this approach to be made sound. This can be achieved by
    # using PKE to encrypt all the nodes in the opening "to-the-sky".
    # Alternatively, the entire relation can be proven as a single
    # relation Aw = 0
    # ---------------------------------------------------------------

    print("Generating proof ...")
    prove_time = 0.

    # Create the zero vector t once
    t = polyvec_t(Rq, m)

    for i in range(len(op) - 1):
        h1, h2, pos = op[i]
        h3 = op[i + 1][0]
        
        # create witness vector
        w = polyvec_t(Rq, 3 * n, [h1, h2, h3])
        
        # create new prover instance
        prover = lin_prover_state_t(PROOFPP, lib.get_params("param"))
        try:
            # set statement and witness
            prover.set_statement(A[pos], t)
            prover.set_witness(w)

            # generate proof
            start_time = time.time()
            _π = prover.prove()
            prove_time += time.time() - start_time
            π.append(_π)
            print(f"[OK] completed proof {i + 1} of {len(op)} | time elapsed : {prove_time:.3f} s | size: {len(_π) / 1024:.3f} KB")
        finally:
            del prover  # explicitly free prover
    
    # the last node in the opening is the root
    # we must also prove the top level commitment
    h, _, _ = op[-1]
    w = polyvec_t(Rq, 3 * n, [h, x, c])
    prover = lin_prover_state_t(PROOFPP, lib.get_params("param"))
    prover.set_statement(A[0], t)
    prover.set_witness(w)
    start_time = time.time()
    _π = prover.prove()
    prove_time += time.time() - start_time
    print(f"[OK] completed proof {i + 1} of {len(op)} | time elapsed : {prove_time:.3f} s | size: {len(_π) / 1024:.3f} KB")
    π.append(_π)

    print(f"[OK] completed in: {prove_time:.3f} s")

    return π

def verify_lin_open_proof(
        PROOFPP: bytes, A: List[polymat_t], µ: polyvec_t, idx: int, π: List[bytes]
    ) -> bool:
    """
    """
    # create the zero vector t once
    t = polyvec_t(Rq, m)
    # get binary representation, pad with zeros to length lg(B)
    bin_idx = list(format(idx, f'0{int(ceil(lg(B)))}b'))[::-1]
    bin_idx.append('0') # needed for the top level commitment

    print("Verifying proof ... ")
    verify_time = 0.
    for i, _π in enumerate(π):
        pos = int(bin_idx[i])
        verifier = lin_verifier_state_t(PROOFPP, lib.get_params("param"))
        try:
            verifier.set_statement(A[pos], t)
            start_time = time.time()
            verifier.verify(_π)
        except VerificationError:
            return False
        finally:
            del verifier
        verify_time += time.time() - start_time
        print(f"[OK] completed verification {i + 1} of {len(π)} | time elapsed : {verify_time:.3f} s")
    return True

def main():
    # system setup
    shake128 = hashlib.shake_128(bytes.fromhex("00"))
    COMPP = shake128.digest(32)

    shake128 = hashlib.shake_128(bytes.fromhex("02"))
    PROOFPP = shake128.digest(32)

    T = MerkleTree(COMPP)
    A0, A1 = set_A_matrix(T)

    # get B messages
    print(f"Generating {B} messages ...")
    start_time = time.time()
    µ = [ polyvec_t(Rq, n) for _ in range(B) ]
    for i in range(B):
        µ[i].urandom_bnd(0, 1, COMPP, 2 + i) # <-- may need to use bytes here
    msg_time = time.time() - start_time
    print(f"[OK] completed in: {msg_time:.3f} s")

    # a commitment too all messages
    c, x = commit(COMPP, T, µ, test=True)

    # run the zero-knowledge opening proof
    π = prove_lin_open(PROOFPP, [A0, A1], T, c, x)
    print(f"Proof size: {sum(len(_π) for _π in π) / 1024:.3f} KB")

    # verify proof
    if not verify_lin_open_proof(PROOFPP, [A0, A1], µ[0], 0, π):
        print("[ERR] proof verification failed")

if __name__ == "__main__":
    main()

