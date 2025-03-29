import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module

import time
import hashlib          # for SHAKE128
import secrets          # for internal coins

from regev_params import deg, mod, mod, m, n, p, tau
from _regev_params_cffi import lib

from typing import Tuple

d, q = deg, mod
Rq = polyring_t(d, q)

def keygen(ENCPP: bytes) -> Tuple[polymat_t, polymat_t, polymat_t]:
    """
    Generate the public and secret keys for the encryption scheme.

    Args:
        ENCPP (bytes): Entropy for pseudorandom generation.

    Returns:
        tuple: A tuple containing:
            - A1 (polymat_t): Public key matrix.
            - A2 (polymat_t): Derived public key matrix.
            - S1 (polymat_t): Secret key matrix.
    """
    # key generation
    A1 = polymat_t(Rq, n, n)
    A1.urandom(q, ENCPP, 0)

    S1 = polymat_t(Rq, m, n)
    S1.urandom(tau, ENCPP, 1)

    S2 = polymat_t(Rq, m, n)
    S2.urandom(tau, ENCPP, 2)
    A2 = S1 * A1 + 1 * S2
    
    return (A1, A2, S1)

def encrypt(
                ENCPP: bytes, A1: polymat_t, A2: polymat_t, µ: polyvec_t
        ) -> Tuple[polyvec_t, polyvec_t, polyvec_t, polyvec_t, polyvec_t]:
    """
    Encrypt a message using the public key.

    Args:
        ENCPP (bytes): Entropy for pseudorandom generation.
        A1 (polymat_t): Public key matrix.
        A2 (polymat_t): Derived public key matrix.
        µ (polyvec_t): Message to be encrypted.

    Returns:
        tuple: A tuple containing:
            - s (polyvec_t): Random vector.
            - e1 (polyvec_t): Error vector for c1.
            - e2 (polyvec_t): Error vector for c2.
            - c1 (polyvec_t): First ciphertext component.
            - c2 (polyvec_t): Second ciphertext component.
    """
    # encryption
    s = polyvec_t(Rq, n)
    s.urandom_bnd(-tau, tau, ENCPP, 3)
    
    e1 = polyvec_t(Rq, n)
    e1.urandom_bnd(-tau, tau, ENCPP, 4)
    
    e2 = polyvec_t(Rq, m)
    e2.urandom_bnd(-tau, tau, ENCPP, 5)
    
    c1 = A1 * s + e1 * 1
    c2 = A2 * s + e2 + p * µ

    return (s, e1, e2, c1, c2)

def set_A_matrix(A1: polymat_t, A2: polymat_t) -> polymat_t:
    """
    Construct the matrix A used in the proof system.

    Args:
        A1 (polymat_t): Public key matrix.
        A2 (polymat_t): Derived public key matrix.

    Returns:
        polymat_t: The constructed matrix A.
    """
    # create a zero matrix A of appropriate size
    A = polymat_t(Rq, n + m, 2 * (n + m))

    In = polymat_t.identity(Rq, n)
    Im = polymat_t.identity(Rq, m)

    # define submatrices as slices of A
    A.set_submatrix(0, 0, A1)
    A.set_submatrix(0, n, In)
    A.set_submatrix(n, 0, A2)
    A.set_submatrix(n, 2 * n, Im)
    A.set_submatrix(n, 2 * n + m, p * Im)
    
    return A

def prove_enc(
                PROOFPP: bytes, A: polymat_t, c1: polyvec_t, c2: polyvec_t, 
                s: polyvec_t, e1: polyvec_t, e2: polyvec_t, µ: polyvec_t
            ) -> bytes:
    """
    Generate a proof of correctness for the encryption.

    Args:
        PROOFPP (bytes): Entropy for pseudorandom generation in the proof system.
        A (polymat_t): Matrix A used in the proof system.
        c1 (polyvec_t): First ciphertext component.
        c2 (polyvec_t): Second ciphertext component.
        s (polyvec_t): Random vector used in encryption.
        e1 (polyvec_t): Error vector for c1.
        e2 (polyvec_t): Error vector for c2.
        µ (polyvec_t): Original message.

    Returns:
        π (bytes): The generated proof.
    """
    # prove correctness of encryption as A * x + t = 0
    prover = lin_prover_state_t(PROOFPP, lib.get_params("param"))

    x = polyvec_t(Rq, 2 * (n + m), [s, e1, e2, µ])
    t = polyvec_t(Rq, n + m, [-c1, -c2])

    # set the instance and the witness
    prover.set_statement(A, t)
    prover.set_witness(x)

    print("Generating proof ...")
    start_time = time.time()
    π = prover.prove()
    prove_time = time.time() - start_time
    print(f"[OK] completed in: {prove_time:.3f} s")

    return π

def verify_enc_proof(
                        PROOFPP: bytes, A: polymat_t, c1: polyvec_t, 
                        c2: polyvec_t, π: bytes
                    ) -> bool:
    """
    Verify the proof of correctness for the encryption.

    Args:
        PROOFPP (bytes): Entropy for pseudorandom generation in the proof system.
        A (polymat_t): Matrix A used in the proof system.
        c1 (polyvec_t): First ciphertext component.
        c2 (polyvec_t): Second ciphertext component.
        π (bytes): Proof to be verified.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    # verify proof of correctness of encryption
    verifier = lin_verifier_state_t(PROOFPP, lib.get_params("param"))

    # set the instance for verification
    t = polyvec_t(Rq, n + m, [-c1, -c2])
    verifier.set_statement(A, t)

    print("Verifying proof ... ")
    start_time = time.time()
    try:
        verifier.verify(π)
    except VerificationError:
        return False
    else:
        verify_time = time.time() - start_time
        print(f"[OK] completed in: {verify_time:.3f} s")
        return True

def main():
    """
    Main function to demonstrate the encryption, proof generation, and verification process.
    """
    # system setup
    shake128 = hashlib.shake_128(bytes.fromhex("00"))
    ENCPP = shake128.digest(32)

    shake128 = hashlib.shake_128(bytes.fromhex("02"))
    PROOFPP = shake128.digest(32)

    (A1, A2, S2) = keygen(ENCPP)
    A = set_A_matrix(A1, A2)

    µ_raw = bytes.fromhex("0123456789abcdef0123456789abcdef")
    µ = polyvec_t(Rq, m, µ_raw)

    (s, e1, e2, c1, c2) = encrypt(ENCPP, A1, A2, µ)

    π = prove_enc(PROOFPP, A, c1, c2, s, e1, e2, µ)
    print(f"Proof size: {len(π) / 1024:.3f} KB")

    # verify proof
    if not verify_enc_proof(PROOFPP, A, c1, c2, π):
        print("[ERR] proof verification failed")

if __name__ == "__main__":
    main()

