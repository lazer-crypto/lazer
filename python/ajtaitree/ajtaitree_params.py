from math import log2 as lg
from math import sqrt, ceil

# Create a header file with proof system parameters for
# proving knowledge of a witness s in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. s satisfies a linear relation over Rp: As + t = 0
#   2. each element in a partition of s either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound

vname = "param"                 # variable name

deg   = 512                     # ring Rq degree d
mod   = 7213                    # ring Rq modulus q
B     = 2                       # batch size: number of messages
m     = 512                     # dimension of the commited vectors
n     = int(ceil(m * lg(mod)))  # column dimension of L, R
dim   = (1, 2)                  # dimension of A

wpart = [ [0 , 1]          ]  # partition of s
wl2   = [ sqrt(2048)       ]  # l2-norm bounds: l2(s) <= sqrt(2048)
wbin  = [ 0                ]  # binary coeffs
wrej  = [ 0                ]  # rejection sampling

# Optional: some linf-norm bound on x.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
# wlinf = tau
