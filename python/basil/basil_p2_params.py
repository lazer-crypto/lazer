from math import log, ceil, sqrt

# Create a header file with proof system parameters for
# proving knowledge of a witness s in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. s satisfies a linear relation over Rp: As + t = 0
#   2. each element in a partition of s either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound

vname = "p2_param"                                      # variable name

deg   = 512                                             # ring Rq degree d
mod   = 12289                                           # ring Rq modulus q
m     = 1                                               # dimension of the commited vectors
n     = ceil(m * log(mod, 2))                           # column dimension of L, R
dim   = (1, 2 * n + 3)                                  # dimensions of A

wpart = [ 
            list(range(0, ceil(log(mod, 2)))),          # partition of w
            list(range(ceil(log(mod, 2)), 2 * ceil(log(mod, 2)))),
            [2 * ceil(log(mod, 2)), 2 * ceil(log(mod, 2)) + 1], 
            [2 * ceil(log(mod, 2)) + 2]
    ] 

wl2   = [ 0, 0, sqrt(34034726), 0]                      # l2-norm bounds
wbin  = [ 1, 1, 0, 1 ]                                  # binary coeffs
#wrej  = [0, 0, 0, 1]                                   # rejection sampling: on r only

# Optional: some linf-norm bound on w.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
# wlinf = 5833  # optional linf: some linf-norm bound on w.
