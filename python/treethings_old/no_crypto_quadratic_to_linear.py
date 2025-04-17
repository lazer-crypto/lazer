import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import everything from the lazer python module
from math import log
SEED=[0]

print(" ")

#================set parameters================

d = 256
q = 12289

Rq = polyring_t(d, q)

N = 2**10 # vector length
m = 2 # reduction factor
l = int(log(N, m)) # rounds

assert m**l == N

#================sample a random instance================

a = polyvec_t(Rq,N)
a.brandom(10, SEED, 0, 1)

b = polyvec_t(Rq,N)
b.brandom(10, SEED, 0, 1)

t = a * b

initial_witness = [a,b]
initial_instance = t # TODO: add commitments to a and b

#================protocol================

current_N = N
current_a = a
current_b = b
current_t = t

V = polymat_t(Rq, l, 2*m-1) # All prover messages from the protocol. Rows are round numbers.
X = polyvec_t(Rq, l) # All verifier challenges from the protocol. Indices are round numbers.

for round_number in range(l):

#======prover message======

    A = polymat_t(Rq, m, current_N // m)
    B = polymat_t(Rq, m, current_N // m)

    for i in range(current_N):
        A[i % m, i // m] = current_a[i]
        B[i % m, i // m] = current_b[i]

    for i in range(m): #quadratic time in m, improve later
        for j in range(m):
            V[round_number, m+i-j-1] += A[i] * B[j]

    # TODO: commit to V[round_number]
    
    assert V[round_number, m-1] == current_t

#======verifier challenge======

    x = poly_t(Rq)
    x.urandom(10, SEED, 0) # TODO: compute as hash
    X[round_number] = x

#======prover computes new vectors======

    current_N = current_N // m

    current_a = A[m-1]
    current_b = B[0]
    for i in range(m-1):
        current_a = x*current_a + A[m-2-i]
        current_b = x*current_b + B[i+1]
        
#======prover and verifier compute new dot product======

    current_t = V[round_number, 2*m-2]
    for i in range(2*m-2):
        current_t = x*current_t + V[round_number, 2*m-3-i]

    assert current_t == current_a * current_b

#================build output instance and witness================

output_a = current_a[0]
output_b = current_b[0]
output_t = current_t

chal_vec_a = polyvec_t(Rq, N)
chal_vec_b = polyvec_t(Rq, N)

for i in range(N): #improve later
    z = poly_t(Rq, {0:1})
    I = i
    for j in range(l):
        digit = I % m
        x = X[j]
        for k in range(digit):
            z *= x
        I = (I - digit) // m
    chal_vec_a[i] = z
    chal_vec_b[N-1-i] = z

witness_v = polyvec_t(Rq, 2*l*(m-1))
chal_vec_v = polyvec_t(Rq, 2*l*(m-1))

for i in range(2*l*(m-1)):
    chal_vec_v[i] = poly_t(Rq, {0:1})

for round_number in range(l):

    x = X[l-1-round_number]
    z = poly_t(Rq, {0:1})

    for i in range(m-1):
        witness_v[(l-1-round_number)*(m-1) + i] = V[round_number, i]
        chal_vec_v[round_number*(m-1)+i] *= z
        z *= x

    for i in range(round_number*(m-1)+m-1,(2*l-2-round_number)*(m-1)+m-1):
        chal_vec_v[i] *= z
    
    z *= x
    
    for i in range(m,2*m-1):
        witness_v[(l-1+round_number)*(m-1) + i-1] = V[round_number, i]
        chal_vec_v[(2*l-2-round_number)*(m-1) + i-1] *= z
        z *= x

z = poly_t(Rq, {0:1})
for round_number in range(l):
    z *= X[round_number]

chal_prod = poly_t(Rq, {0:1})
for j in range(m-1):
    chal_prod *= z

# Prove in Labrador
assert output_a == a * chal_vec_a
assert output_b == b * chal_vec_b
assert output_t == witness_v * chal_vec_v + t * chal_prod

# TODO: prove a and b are inside their respective commitments from the initial instance
# TODO: prove that witness_v is inside the commitments sent during the protocol
