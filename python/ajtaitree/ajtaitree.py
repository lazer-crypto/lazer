import sys
sys.path.append('..')   # path to lazer module
from math import log, ceil
from lazer import *     # import lazer python module
from merkletree import *     # import tree node module

import time
import hashlib          # for SHAKE128

from ajtaitree_params import deg, mod, mod, B, m, n
# from _ajtaitree_params_cffi import lib

d, q = deg, mod
Rq = polyring_t(d, q)

# TO DO: break this down into smaller functions

def main():
    # system setup
    shake128 = hashlib.shake_128(bytes.fromhex("00"))
    COMPP = shake128.digest(32)

    shake128 = hashlib.shake_128(bytes.fromhex("02"))
    PROOFPP = shake128.digest(32)

    tree = MerkleTree(COMPP)

    # get B messages
    µ = [ polyvec_t(Rq, n) for _ in range(B) ]

    for i in range(B):
        µ[i].urandom_bnd(0, 1, COMPP, 2 + i) # <-- may need to use bytes here

    # # merkle tree commitment of B messages
    # u = L * µ[0] + R * µ[1]

    # # decompose the commitment
    # h = g_inv(u)

    # create the Merkle tree commitment
    h = tree.commit(µ)

    # create the final Ajtai commitment
    x = polyvec_t(Rq, n)
    x.urandom_bnd(0, 1, COMPP, 2 + B) # <-- doing x \in {0, 1} for the example
    c = L * h + R * x

    # sign the commitment

if __name__ == "__main__":
    main()

