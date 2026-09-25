import sys
sys.path.append('..')
from lazer import *     # import the lazer python module

print("falcon signature scheme CFFI exercise")
print("--------------------------------------\n")

# 1. key generation
print("keygen ... ", end='')
sk, pk_enc, pk_poly = falcon_keygen()
print("[OK]")
print("pk (poly_t) linf norm:", pk_poly.linf())

# 2. decode the public key back from its encoded form and check it matches
print("\ndecode_pk ... ", end='')
pk_poly2 = falcon_decode_pk(pk_enc)
assert (pk_poly - pk_poly2).linf() == 0
print("[OK] (matches keygen output)")

# 3. falcon_pol arithmetic: add, sub, neg, mul, redc
print("\nfalcon_pol arithmetic ... ", end='')
a = falcon_pol([1] * 512)
b = falcon_pol([2] * 512)
c = a + b
assert c.to_list() == [3] * 512
d = c - b
assert d.to_list() == a.to_list()
e = -a
assert e.to_list() == [-1] * 512
f = a * b  # polynomial multiplication mod (x^512+1, 12289)
f.redc()
print("[OK]")

# 4. preimage sampling: sample s1, s2 such that pk*s2 + s1 = t (mod falcon ring)
print("\npreimage_sample on a random target t ... ", end='')
t = poly_t(RING_FALCON)
t.urandom(12289, bytes(32), 0)
s1, s2 = falcon_preimage_sample(sk, t)

# verify pk*s2 + s1 == t  (all reduced into the falcon ring)
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

print("\nall falcon CFFI functions exercised successfully.")
