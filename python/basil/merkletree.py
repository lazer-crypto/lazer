import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module

from math import log, ceil
from typing import List, Tuple
from treethings.tree import decompose

from basil_p1_params import deg, mod, mod, B, m, n

d, q = deg, mod
Rq = polyring_t(d, q)

def bin_decompose_gadget(u: polyvec_t) -> polyvec_t:
    """
    Decompose a polynomial vector into its binary representation.

    Args:
        u (polyvec_t): Polynomial vector to decompose.

    Returns:
        polyvec_t: The decomposed polynomial vector.
    """
    
    # initialize empty list to store all decomposed polynomials
    all_decomposed = []
    
    # decompose each polynomial in the input vector
    for i in range(u.dim):
        # get polynomial at idx i
        pol = u.get_elem(i)
        # decompose it into binary representation
        decomposed = decompose(pol, base=2)
        # add all polynomials from decomposition to our list
        for j in range(decomposed.dim):
            all_decomposed.append(decomposed.get_elem(j))
    
    # create a result vector with length = number of all decomposed polynomials
    result = polyvec_t(Rq, len(all_decomposed))
    
    # fill result vector with decomposed polynomials
    for i in range(len(all_decomposed)):
        result.set_elem(all_decomposed[i], i)
    
    return result

def makeGmat(Rq: polyring_t, k: int, l: int) -> polymat_t:
    """
    Create a gadget matrix G such that G * h = u where h is the output of bin_decompose_gadget(u).
    
    Args:
        Rq (polyring_t): The polynomial ring
        k (int): Number of rows in the matrix
        l (int): Number of columns in the matrix
        
    Returns:
        polymat_t: The gadget matrix G
    """
    G = polymat_t(Rq, k, l)
    base = 2  # binary decomposition base
    levels = ceil(log(q, base))  # number of decomposition levels
    
    # fill the matrix with powers of 2
    for i in range(k):
        for j in range(levels):
            col_idx = i * levels + j
            if col_idx < l:
                G[i, col_idx] = poly_t(Rq, {0 : base ** j})
    
    return G

def ajtai_hash(
            L: polymat_t, R: polymat_t, 
            h1: polyvec_t, h2: polyvec_t, test: bool = False
        ) -> polyvec_t:
    """
    Compute the Ajtai hash of a list of matrices and messages.

    Args:
        L, R (polymat_t): Matrices used in the hash computation.
        u, v (polyvec_t): Messages to be hashed together.
        test (bool): Whether to perform a test on the decomposed output.

    Returns:
        polyvec_t: The computed Ajtai hash.
    """
    # initialize empty polynomial vector to store the result
    u = polyvec_t(Rq, m)

    # Merkle tree commitment of a vector pair
    u = L * h1 + R * h2

    # binary decomposition of the result
    h = bin_decompose_gadget(u)

    if test:
        # create a gadget matrix for the decomposition
        G = makeGmat(Rq, m, n)
        # check if G * h = u
        res = G * h
        if res != u:
            raise ValueError("[ERR] Recomposition gadget failed.")

    return h

class MerkleTree:
    def __init__(self, COMPP: bytes, L: polymat_t, R: polymat_t):
        """Initialize Merkle Tree with given leaf values
        
        Args:
            COMPP (bytes): Seed for random matrix generation
            L (polymat_t): Left matrix of the Merkle tree
            R (polymat_t): Right matrix of the Merkle tree
        """
        self.L = L
        self.R = R
        self.leaves = None
        self.root = None

    def commit(self, leaves: List[polyvec_t]) -> polyvec_t:
        """
        Build the Merkle Tree and compute the root hash.

        Args:
            leaves (List[polyvec_t]): List of leaf values as polyvec_t

        Returns:
            polyvec_t: Root hash of the tree
        """
        if not leaves:
            raise ValueError("Must provide at least one leaf value")

        self.leaves = leaves
        current_level = leaves

        # build the tree bottom-up
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = ajtai_hash(self.L, self.R, left, right)
                next_level.append(parent_hash)
            current_level = next_level

        self.root = current_level[0]
        return self.root

    def lin_open(self, leaf_idx: int) -> List[Tuple[polyvec_t, polyvec_t, int]]:
        """
        Generate a linear opening proof for a leaf.

        Args:
            leaf_idx (int): Index of the leaf in the original list

        Returns:
            List[Tuple[polyvec_t, polyvec_t, int]]: List of (path, neighbor, pos) 
                pairs along the path. `pos = 0` if path node is left child and `1` otherwise.
        """
        if leaf_idx < 0 or leaf_idx >= len(self.leaves):
            raise ValueError("Invalid leaf idx")

        op = []
        current_idx = leaf_idx
        current_level = self.leaves
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = ajtai_hash(self.L, self.R, left, right)
                next_level.append(parent_hash)

                # if this is the pair containing our target node
                if i <= current_idx < i + 2:
                    # get the neighbor node (the one not on our path)
                    if current_idx == i:
                        path, neighbor = left, right
                    else: path, neighbor = right, left
                    # record ordered triple (parent, neighbor, pos)
                    op.append((path, neighbor, current_idx % 2))
            
            current_idx //= 2
            current_level = next_level

        # add root as last parent with None as neighbor and position 0
        if len(op) > 0:
            op.append((self.root, None, 0))

        return op

    def verify_lin_open(self, leaf: polyvec_t, op: List[Tuple[polyvec_t, polyvec_t, int]], leaf_idx: int) -> bool:
        """
        Verify a linear opening proof.

        Args:
            leaf (polyvec_t): Original leaf value
            op (List[Tuple[polyvec_t, polyvec_t, int]]): List of (path, neighbor, pos) tuples
            leaf_idx (int): Index of the leaf in the original list

        Returns:
            bool: True if op is valid, False otherwise
        """
        # first path node should be computed from the leaf
        current = leaf
        current_idx = leaf_idx
        
        # check each level except the root
        for path, neighbor, pos in op[:-1]:
            # verify position matches the current_idx's least significant bit
            if pos != (current_idx % 2):
                return False

            # verify current matches the path node
            if current != path:
                return False
                
            # Compute hash for next level
            current = ajtai_hash(self.L, self.R,
                               path if pos == 0 else neighbor,
                               neighbor if pos == 0 else path,
                               test=True)
            current_idx //= 2
            
        # verify final hash matches root
        root, _, _ = op[-1]
        return current == self.root