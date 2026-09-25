import sys
sys.path.append('..')
from lazer import *     # import the lazer python module

print("falcon-1024 signature scheme CFFI exercise")
print("--------------------------------------------\n")

# 1. key generation
print("keygen ... ", end='')
sk, pk_enc, pk_poly = falcon1024_keygen()
print("[OK]")
print("pk (poly_t) linf norm:", pk_poly.linf())

# 2. decode the public key back from its encoded form and check it matches
print("\ndecode_pk ... ", end='')
pk_poly2 = falcon1024_decode_pk(pk_enc)
assert (pk_poly - pk_poly2).linf() == 0
print("[OK] (matches keygen output)")

# 3. falcon1024_pol arithmetic: add, sub, neg, mul, redc
print("\nfalcon1024_pol arithmetic ... ", end='')
a = falcon1024_pol([1] * 1024)
b = falcon1024_pol([2] * 1024)
c = a + b
assert c.to_list() == [3] * 1024
d = c - b
assert d.to_list() == a.to_list()
e = -a
assert e.to_list() == [-1] * 1024
f = a * b  # polynomial multiplication mod (x^1024+1, 12289)
f.redc()
print("[OK]")

# 4. preimage sampling: sample s1, s2 such that pk*s2 + s1 = t (mod falcon-1024 ring)
print("\npreimage_sample on a random target t ... ", end='')
t = poly_t(RING_FALCON1024)
t.urandom(12289, bytes(32), 0)
s1, s2 = falcon1024_preimage_sample(sk, t)

# verify pk*s2 + s1 == t  (all reduced into the falcon-1024 ring)
check = pk_poly * s2 + s1
check.redc()
t_redc = t.copy()
t_redc.redc()
assert check == t_redc
print("[OK] (pk*s2 + s1 == t)")

print("\nsecret key size (bytes):", len(bytes(sk.ptr)))
print("public key size (bytes):", len(bytes(pk_enc.ptr)))
print("s1 linf / l2sq:", s1.linf(), s1.l2sq())
print("s2 linf / l2sq:", s2.linf(), s2.l2sq())

# 5. isoring path: decode pk as a matrix over a smaller ring, and check that
# preimage sampling in that subring is consistent with the matrix relation
# M*aut(s2) + aut(s1) == aut(t)
print("\nisoring path (target ring of degree 64) ... ", end='')
SUBRING = polyring_t(64, 12289)
M = falcon1024_decode_pk(pk_enc, SUBRING)
s1vec, s2vec = falcon1024_preimage_sample(sk, t, SUBRING)
lhs = M * s2vec + s1vec
lhs.redc()
t_vec = t_redc.to_isoring(SUBRING)
assert lhs == t_vec
print("[OK] (M*aut(s2) + aut(s1) == aut(t))")

print("\nall falcon-1024 CFFI functions exercised successfully.")
