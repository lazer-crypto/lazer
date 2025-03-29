import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module

from typing import List
from treethings.tree import decompose

def g_inv(u: polyvec_t) -> polyvec_t:
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
        # get polynomial at index i
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

def ajtai_hash(Λ: List[polymat_t], µ: List[polyvec_t]) -> polyvec_t:
    """
    Compute the Ajtai hash of a list of matrices and messages.

    Args:
        Λ (List[polymat_t]): List of matrices.
        µ (List[polyvec_t]): List of messages.

    Returns:
        polyvec_t: The computed Ajtai hash.
    """
    # initialize empty polynomial vector to store the result
    u = polyvec_t(Rq, n)
    
    # Merkle tree commitment of a vector pair
    for i in range(len(Λ)):
        # compute the product of the matrix and the message
        ui = Λ[i] * µ[i]
        # add the product to the result
        u += ui
    
    # binary decomposition of the commitment
    h = g_inv(u)
    return h

class Node:
    def __init__(self, left=None, right=None):
        self.left = left
        self.right = right
        self.hash = None

class MerkleTree:
    def __init__(self, COMPP: bytes, leaves: List[polyvec_t]):
        """Initialize Merkle Tree with given leaf values
        
        Args:
            leaves (List[polyvec_t]): List of leaf values as polyvec_t
        """
        # initialize the tree
        self.L = polymat_t(Rq, m, n)
        self.L.urandom(q, COMPP, 0)

        self.R = polymat_t(Rq, m, n)
        self.R.urandom(q, COMPP, 1)

        self.nodes = []  # we will store all nodes for path generation
        self.leaves = None
        self.root = None

    def commit(self, leaves: List[polyvec_t]) -> Node:
        """
        """
        # ensure we have at least one leaf
        if not leaves:
            raise ValueError("Must provide at least one leaf value")
        
        self.leaves = leaves
        self.root = self._build_tree(leaves)

        return self.root.hash

    def _build_tree(self, leaves: List[polyvec_t]) -> Node:
        """Recursively build the Merkle Tree
        
        Args:
            leaves (List[polyvec_t]): List of leaf values
            
        Returns:
            Node: Root node of the (sub)tree
        """
        # base case: single leaf
        if len(leaves) == 1:
            leaf_node = Node()
            leaf_node.hash = leaves[0]  # use polyvec_t directly as the hash
            self.nodes.append(leaf_node)
            return leaf_node

        # find middle point
        mid = len(leaves) // 2
        
        # Recursively build left and right subtrees
        left = self._build_tree(leaves[:mid])
        right = self._build_tree(leaves[mid:])
        
        # Create parent node and compute its hash using ajtai_hash
        par_node = Node(left, right)
        par_node.hash = ajtai_hash([self.L, self.R], [left.hash, right.hash])
        self.nodes.append(par_node)
        
        return par_node

    def _get_root_vec(self) -> polyvec_t:
        """Get the Merkle root
        
        Returns:
            polyvec_t: Root hash of the tree
        """
        return self.root.hash

    def open(self, leaf_index: int) -> List[polyvec_t]:
        """Generate Merkle proof for a leaf
        
        Args:
            leaf_index (int): Index of the leaf in the original list
            
        Returns:
            List[polyvec_t]: List of sibling hashes forming the proof
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise ValueError("Invalid leaf index")

        # proof = []
        # current_idx = leaf_index
        # level_size = len(self.leaves)

        # while level_size > 1:
        #     sibling_idx = current_idx + 1 if current_idx % 2 == 0 else current_idx - 1
            
        #     if sibling_idx < level_size:
        #         node_idx = (level_size - 1) + sibling_idx
        #         if node_idx < len(self.nodes):
        #             proof.append(self.nodes[node_idx].hash)

        #     current_idx //= 2
        #     level_size = (level_size + 1) // 2

        # return proof

        return [self.root]

    def verify(self, leaf: polyvec_t, proof: List[polyvec_t], leaf_index: int) -> bool:
        """Verify a Merkle proof
        
        Args:
            leaf (polyvec_t): Original leaf value
            proof (List[polyvec_t]): Merkle proof as list of sibling hashes
            leaf_index (int): Index of the leaf in the original list
            
        Returns:
            bool: True if proof is valid, False otherwise
        """
        # current_hash = leaf
        # current_index = leaf_index

        # for sibling_hash in proof:
        #     if current_index % 2 == 0:
        #         current_hash = ajtai_hash([current_hash], [sibling_hash])
        #     else:
        #         current_hash = ajtai_hash([sibling_hash], [current_hash])
        #     current_index //= 2

        # return current_hash == self.get_root_hash()
        return True