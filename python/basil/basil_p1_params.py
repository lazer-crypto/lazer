from math import log, ceil

# Create a header file with proof system parameters for
# proving knowledge of a witness s in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. s satisfies a linear relation over Rp: As + t = 0
#   2. each element in a partition of s either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound

vname = "p1_param"                                      # variable name

deg   = 512                                             # ring Rq degree d
mod   = 12289                                           # ring Rq modulus q
B     = 4                                               # batch size: number of messages
alpha = 2                                               # arity of the Merkle tree"
m     = 1                                               # dimension of the commited vectors
n     = ceil(m * log(mod, 2))                           # column dimension of L, R
dim   = (m, 3 * n)                                      # dimension of A

wpart = [   
            list(range(0, n)),                  # partition of w
            list(n + i for i in range(0, n)),
            list(2 * n + i for i in range(0, n)), 
    ]
wl2   = [ 0, 0, 0 ]  # l2-norm bounds
wbin  = [ 1, 1, 1 ]  # binary coeffs
# wrej  = [ 0 ]  # rejection sampling

# Optional: some linf-norm bound on x.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
# wlinf = 1

