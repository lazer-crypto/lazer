from math import sqrt

# Create a header file with proof system parameters for
# proving knowledge of a witness s in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. s satisfies a linear relation over Rp: As + t = 0
#   2. each element in a partition of s either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound

vname = "p2_param"                 # variable name

deg   = 64                      # ring Rq degree d
mod   = 7213 * 7213             # ring Rq modulus q
p     = 49126
m, n  = (12, 8)                 # dimensions of S1, S2, A2
dim   = (n + m, 2 * (n + m))    # dimension of A
tau    = 3                      # linf-norm on encryption randomness

wpart = [ 
            list(range(0, n)),                  # partition of x
            list(n + i for i in range(0, n)),   # [s, e1, e1, µ]
            list(2 * n + i for i in range(0, m)), 
            list(2 * n + m + i for i in range(0, m))
    ] 
wl2   = [ 
            tau * sqrt(n * deg), tau * sqrt(n * deg),   # l2-norm bounds
            tau * sqrt(m * deg), 0
       ]
wbin  = [ 0, 0, 0, 1 ]  # binary coeffs
# wrej  = [ 0, 0, 0, 0 ]  # rejection sampling

# Optional: some linf-norm bound on x.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
# wlinf = tau
