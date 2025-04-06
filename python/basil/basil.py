import sys
sys.path.append('..')       # path to lazer module
import time
import hashlib              # for SHAKE128
import secrets              # for internal coins
from lazer import *         # import lazer python module
from merkletree import *    # import tree node module
from math import log, ceil

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("00"))
COMPP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("01"))
PF1PP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("03"))
SIGPP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("03"))
ENCPP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("04"))
PF2PP = shake128.digest(32)

from _basil_params_cffi import lib
from basil_p1_params import deg, mod, B, m, n, alpha

# constants
d, q = deg, mod
Rq_COM = polyring_t(d, q)
Rq_ENC = polyring_t(d, q)
Rq_ZKP = polyring_t(d, q)
lgB = ceil(log(B, alpha))

# the commitment matrices
L = polymat_t(Rq, m, n)
L.urandom(q, COMPP, 0)

R = polymat_t(Rq, m, n)
R.urandom(q, COMPP, 1)

# the commitment proof matrix
A_COM = [polymat_t(Rq, m, 3 * n) for _ in range(2)]

# create the binary recomposition gadget matrix
G = makeGmat(Rq, m, n)

# define the submatrices as slices of A0 and A1
A_COM[0].set_submatrix(0, 0, L)
A_COM[0].set_submatrix(0, n, R)
A_COM[0].set_submatrix(0, 2 * n, -G)

A_COM[1].set_submatrix(0, 0, R)
A_COM[1].set_submatrix(0, n, L)
A_COM[1].set_submatrix(0, 2 * n, -G)

# the rOM-ISIS polynomial
b = poly_t(Rq)
b.urandom_bnd(-int((q-1)/2), int((q-1)/2), SIGPP, 0)

# the signature proof matrix
A_ZKP = polymat_t(Rq, m, 3 * n)

# the public vector t_COM such that A_COM * w_COM + t_COM = 0
# for our scheme we need t_COM = 0
t_COM = polyvec_t(Rq, m)

class client:
    """
    Class representing the client in the Basil protocol.
    """

    def __init__(self, µ: List[polyvec_t], L: polymat_t, R: polymat_t):
        """
        Initialize the client with a batch of messages.
        
        Args:
            µ (List[polyvec_t]): Batch of messages to commit to.
            L (polymat_t): The left matrix of the Merkle tree.
            R (polymat_t): The right matrix of the Merkle tree.
        """
        self.µ = µ
        self.T = MerkleTree(COMPP, L, R)

        # self.p2_prover = lin_prover_state_t(PF2PP, lib.get_params("p2_param"))

    def client_query(self, precompute: bool = False) -> bytes:
        """
        Commit to a batch of messages using the Ajtai-Merkle tree.

        Args:
            precompute (bool): Whether to precompute the opening proofs.
        Returns:
            bytes: The commitment to the batch as raw bytes.
        """
        # create the Merkle tree commitment
        print(f"Building the commitment tree for {B} leaves ...")
        start_time = time.time()
        self.__h = self.T.commit(self.µ)
        tree_time = time.time() - start_time
        print(f"[OK] completed in: {tree_time:.3f} s")

        # Ajtai commitment to the Merkle tree root
        self.__x = polyvec_t(Rq, n)
        self.__x.urandom_bnd(0, 1, COMPP, 2 + B)
        self.c = self.T.L * self.__h + self.T.R * self.__x
        com_time = time.time() - start_time
        print(f"[OK] completed in: +{com_time - tree_time:.3f} s")

        # encode the commitment
        print("Encoding commitment to raw bytestream ...")
        coder = coder_t()
        coder.enc_begin(22000)
        coder.enc_urandom(mod, self.c)
        c_bytes = coder.enc_end()
        print(f"[OK] Commitment size: {len(c_bytes) / 1024: .3f} KB")

        # precompute the opening proof (for the first message)
        # NOTE: in general, all proofs can be precomputed, but we only show the first one
        if precompute: self._precomute_opening_proofs(0)

        return c_bytes

    def _precomute_opening_proofs(self, idx: int = None):
        """
        Precompute the opening proofs for the batch of messages.

        Args:
            idx (int, optional): The index of the message to prove opening of.
                If None, proofs for all messages are precomputed.
        """
        self.π_COM = [[] for _ in range(B)]
        
        if idx is not None:
            if idx < 0 or idx >= B:
                raise ValueError("Index out of bounds.")
            self.__precompute_opening_proof_idx(idx)
        else:
            raise NotImplementedError("Precomputation for all messages not implemented.")

    def __precompute_opening_proof_idx(self, idx: int) -> None:
        """
        Precompute the opening proof for the i-th message.

        Args:
            idx (int): The index of the message to prove opening of.
        """
        # get the opening proof
        print(f"Precomputing opening proof for leaf {idx} ...")
        start_time = time.time()
        op = self.T.lin_open(idx)
        proof_time = time.time() - start_time
        print(f"[OK] completed in: {proof_time:.3f} s")

        print(f"Generating ZK proof of opening for leaf {idx}...")
        prove_time = 0.
        for i in range(len(op) - 1):
            h1, h2, pos = op[i]
            h3 = op[i + 1][0]
            
            # create witness vector
            w = polyvec_t(Rq_COM, 3 * n, [h1, h2, h3])
            
            # create new prover instance
            p1_prover = lin_prover_state_t(PF1PP, lib.get_params("p1_param"))
            try:
                # set statement and witness
                p1_prover.set_statement(A_COM[pos], t_COM)
                p1_prover.set_witness(w)

                # generate proof
                start_time = time.time()
                _π = p1_prover.prove()
                prove_time += time.time() - start_time
                self.π_COM[idx].append(_π)
                print(f"[OK] completed proof {i + 1} of {len(op) - 1} | time elapsed : {prove_time:.3f} s | size: {len(_π) / 1024:.3f} KB")
            finally:
                del p1_prover  # explicitly free prover
    
    def client_obtain(self, vk: falcon_pkenc, z_bytes: bytes, idx: int) -> bytes:
        """
        Obtain the blind signature on the i-th message.

        Args:
            vk (falcon_pkenc): The public verification key of the issuer.
            z_bytes (bytes): The signature on the batch commitment.
            idx (int): The index of the message to obtain the signature on.

        Returns:
            bytes: The signature on the commitment.
        """
        # decode the signature
        print("Decoding signature from raw bytestream ...")
        try:
            coder = coder_t()
            coder.dec_begin(z_bytes)
            coder.dec_bytes(z_bytes)
            coder.dec_end()
        except DecodingError:
            raise ValueError("[ERR] decoder failed")

        print("[OK] decoded successfully")
        


        return z_bytes

class issuer:
    """
    Class representing the issuer in the Basil protocol.
    """

    def __init__(self):
        # instantiate the FALCON key pair
        self.sk, self.vk, _ = falcon_keygen()
    
    def get_falcon_vk(self) -> falcon_pkenc:
        """
        Returns:
            falcon_pkenc: The public verification key of the issuer.
        """
        return self.vk
    
    def issue(self, c_bytes: bytes) -> bytes:
        """
        Issue a signature for the given commitment.

        Args:
            c (bytes): The commitment to sign with FALCON.

        Returns:
            bytes: The FALCON signature on the client's commitment.
        """
        
        c = polyvec_t(Rq, m)

        # decode the commitment
        print("Decoding commitment from raw bytestream ...")
        try:
            coder = coder_t()
            coder.dec_begin(c_bytes)
            coder.dec_urandom(mod, c)
            coder.dec_end()
        except DecodingError:
            raise ValueError("[ERR] decoder failed")
        
        print("[OK] decoded successfully")
        
        # internal coins
        rho = secrets.token_bytes(64)
        r = poly_t(Rq)

        # sign the commitment
        print("Signing the commitment ...")
        start_time = time.time()
        r.urandom_bnd(0, 1, rho, 0) # the rOM-ISIS randomness
        s1, s2 = falcon_preimage_sample(self.sk, c - b * r)
        sign_time = time.time() - start_time
        print(f"[OK] completed in: {sign_time * 1000:.3f} ms")

        # encode rho, s1, s2
        print("Encoding signature to raw bytestream ...")
        coder = coder_t()
        coder.enc_begin(2000)
        coder.enc_bytes(rho)
        coder.enc_grandom(165, s1)
        coder.enc_grandom(165, s2)
        self.z_bytes = coder.enc_end()
        print(f"[OK] Pre-signature size: {len(self.z_bytes) / 1024: .3f} KB")
        
        return self.z_bytes

class verifier:
    """
    Class representing the verifier in the Basil protocol.
    """
    
    def __init__(self):
        pass
        # self.p1_verifier = lin_verifier_state_t(PF1PP, lib.get_params("p1_param"))
        # self.p2_verifier = lin_verifier_state_t(PF2PP, lib.get_params("p2_param"))
    def verify(self, µ_bytes: bytes, π_bytes: bytes) -> bool:
        """
        Verify the signature and the proof.

        Args:
            µ_bytes (bytes): The commitment to verify.
            π_bytes (bytes): The proof of knowledge.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        
        raise NotImplementedError


def main():
    # create the batch of messages
    µ = [ polyvec_t(Rq, n) for _ in range(B) ]
    for i in range(B):
        µ[i].urandom_bnd(0, 1, COMPP, 2 + i) # <-- may need to use bytes here
    
    # create the client
    cli = client(µ, L, R)

    # create the issuer and get the FALCON verification key
    iss = issuer()
    iss_vk = iss.get_falcon_vk()
    
    # create the client query
    cli_COM = cli.client_query(precompute=True)

    # issue the signature
    iss_sig = iss.issue(cli_COM)

if __name__ == "__main__":
    main()


