from hash import *
import math
import time

INITIAL_VECTOR = ffi.new("poly512 []", BITS_MODULUS_HASH)

# compute parent node
def compute_parent_node(left_child, right_child):

    parent_node = ffi.new("poly512 []", BITS_MODULUS_HASH)
    cutoff = ffi.new("signed_poly512")
    lib.absorb(parent_node, cutoff, left_child, right_child)
    return parent_node

# compute leaf from binary public key
def compute_leaf(binary_pk):

    return compress_internal(binary_pk, INITIAL_VECTOR, False)


class MerkleTreeNode:
    def __init__ (self):
        self.idx = 0
        self.depth = 0
        self.i = 0 # the i-th node at depth
        self.value = 0
        self.parent = 0
        self.sibling = 0
        self.child0 = 0
        self.child1 = 0

    def set_idx (self, idx):
        self.idx = idx
        self.depth = len(idx)
    def set_value (self, value):
        self.value = value
    def set_parent (self, parent):
        self.parent = parent
    def set_sibling (self, sibling):
        self.sibling = sibling
    def set_child0 (self, child0):
        self.child0 = child0
    def set_child1 (self, child1):
        self.child1 = child1
    def get_idx (self):
        return self.idx
    def get_depth (self):
        return self.depth
    def get_value (self):
        return self.value
    def get_parent (self):
        return self.parent
    def get_sibling (self):
        return self.sibling
    def get_child0 (self):
        return self.child0
    def get_child1 (self):
        return self.child1

    def __str__(self):
        s = f"({self.idx})"
        if self.parent != 0:
            s += f",p:({self.parent.idx})"
        if self.sibling != 0:
            s += f",s:({self.sibling.idx})"
        if self.child0 != 0:
            s += f",c0:({self.child0.idx})"
        if self.child1 != 0:
            s += f",c1:({self.child1.idx})"
        return s


class MerkleTree:
    # input: list of public keys
    def __init__ (self, pk):
        assert (len(pk) & (len(pk) - 1)) == 0 # check npks is power of 2

        self.depth = int(math.log2(len(pk)))

        # empty tree: [root, 2 depth1-nodes, ..., 2^depth leaves]
        nodes = [MerkleTreeNode() for _ in range(2**(self.depth+1)-1)]

        # the leaves are the pk hashes
        for i in range(len(pk)):
            depth = self.depth
            pkhash = compute_leaf (pk[i])
            off = 2**depth-1
            nodes[off+i].set_idx (self.__makeidx__(depth,i))
            nodes[off+i].set_value (pkhash)


        for depth in range(self.depth-1,-1,-1):
            off = 2**depth-1 # this depth
            off2 = 2**(depth+1)-1 # children layer
            for i in range(2**depth):
                nodes[off+i].set_idx (self.__makeidx__(depth,i))

                nodes[off+i].set_value (compute_parent_node(nodes[off2+2*i].get_value(), nodes[off2+2*i+1].get_value()))

                nodes[off+i].set_child0 (nodes[off2+2*i])
                nodes[off+i].set_child1 (nodes[off2+2*i+1])

                nodes[off2+2*i].set_parent (nodes[off+i])
                nodes[off2+2*i].set_sibling (nodes[off2+2*i+1])
                nodes[off2+2*i+1].set_parent (nodes[off+i])
                nodes[off2+2*i+1].set_sibling (nodes[off2+2*i])

        self.nodes = nodes

    def __makeidx__ (self, depth, idx):
        if depth == 0:
            return []   # root
        binidx = [int(d) for d in str(bin(idx))[2:]]
        while len(binidx) < depth:
            binidx = [0] + binidx
        return binidx

    def get_node (self, idx):
        assert len(idx) == self.depth

        node = self.nodes[0] # root
        for bit in idx:
            assert bit == 0 or bit == 1
            if bit == 0:
                node = node.get_child0()
            elif bit == 1:
                node = node.get_child1()
        return node

    def get_path (self, pkidx):
        idx = self.__makeidx__ (self.depth,pkidx)
        node = self.get_node (idx)

        siblings = []
        while node.get_idx() != []:
            siblings += [node.get_sibling().get_value()]
            node = node.get_parent()

        siblings = list(reversed(siblings)) # output in reversed order
        return idx, siblings

    def get_root (self):
        root = self.nodes[0]
        return root.get_value()

    def __str__(self):
        s = ""
        for i in self.nodes:
            s += f"{i.__str__()}\n"
        return s




if __name__ == "__main__":

    # example compute_parent_node
    left_child = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)])
    right_child = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(BITS_MODULUS_HASH)])
    parent_node = compute_parent_node(left_child, right_child)
    # parent_node_polyvec_t = convert_array_to_polyvec_t(parent_node)
    # parent_node_polyvec_t.print()

    # example compute_leaf
    dim_binary_pk = ceil(log2(RING_FALCON.mod))
    binary_pk = ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])
    leaf = compute_leaf(binary_pk)
    # leaf_polyvec_t = convert_array_to_polyvec_t(leaf)
    # leaf_polyvec_t.print()

    # example compute tree

    depth = 4

    pks = [] # create list of binary pks, number must be a power of 2
    for i in range(2**depth):
        pks += [ffi.new("poly512 []", [[randrange(2) for coeff in range(DEGREE_HASH)] for poly in range(dim_binary_pk)])]

    tree = MerkleTree(pks)
    print (tree)

    pathbits,siblings = tree.get_path(2)
    print (f"path from root: {pathbits}")
