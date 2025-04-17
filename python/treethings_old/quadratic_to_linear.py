import sys
sys.path.append('..')   # path to lazer module
from lazer import *
from labrados import *
from tree import outter_commit, makeGvec, make_falcon_pk_leaves, make_LRhash, BIGMOD_RING

from math import log
import hashlib

SEED=[0]

PRIMESIZE = str(math.ceil(math.log2(BIGMOD_RING.mod)))
Rq = BIGMOD_RING

FALCON_MOD = 12289
COM_MOD = 256 # modulus used for the outer commitments
BASE = 2**7

ID = poly_t(Rq, {0:1})
G = makeGvec(Rq, COM_MOD, 2)
G2 = makeGvec(Rq, 2, math.ceil(math.log2(Rq.mod)))

def prove_scalar_product(N, a, b, t, m, instance_com=poly_t(Rq), PS=None):
    assert a.dim == b.dim and a.dim == N
    assert a*b == t

    l = int(log(N, m))
    assert m**l == N

    current_N = N
    current_a = a
    current_b = b
    current_t = t
  
    U = polymat_t(Rq, l, 2*m-1) # All prover messages from the protocol. Rows are round numbers.
    U_bin = [] # Binary decomposition of elements of U
    X = polyvec_t(Rq, l) # All verifier challenges from the protocol. Indices are round numbers.

    smh = None # aux variable for outter commitments

    for round_number in range(l):

    #======prover message======

        A = polymat_t(Rq, m, current_N // m)
        B = polymat_t(Rq, m, current_N // m)

        for i in range(current_N):
            A[i % m, i // m] = current_a[i]
            B[i % m, i // m] = current_b[i]

        #quadratic time in m, TODO: improve complexity
        for i in range(m):
            for j in range(m):
                U[round_number, m+i-j-1] += A[i] * B[j]

        assert U[round_number, m-1] == current_t

        # Commit to U[round_number], except for U[round_number][m-1]
        u_current_list = U[round_number].to_pol_list()
        u_current_vec = polyvec_t(Rq, 2*m-2, u_current_list[:m-1] + u_current_list[m:])
        u_hash, u_bin_vec, w_dec, smh = outter_commit(u_current_vec, smh)
        U_bin.append(u_bin_vec)
        if PS is not None:
            PS.fresh_statement(smh+[-256*G], u_bin_vec+[w_dec], u_hash)

    #======verifier challenge======

        x = poly_t(Rq)
        x.urandom(10, SEED, 0) # TODO: compute as hash (include instance and u_hash)
        X[round_number] = x

    #======prover computes new vectors======

        current_N = current_N // m

        current_a = A[m-1]
        current_b = B[0]
        for i in range(m-1):
            current_a = x*current_a + A[m-2-i]
            current_b = x*current_b + B[i+1]
            
    #======prover and verifier compute new dot product======

        current_t = U[round_number, 2*m-2]
        for i in range(2*m-2):
            current_t = x*current_t + U[round_number, 2*m-3-i]

        assert current_t == current_a * current_b

    #================build output instance and witness================

    output_a = current_a[0]
    output_b = current_b[0]

    chal_vec_a = polyvec_t(Rq, N)
    chal_vec_b = polyvec_t(Rq, N)

    for i in range(N): # TODO: improve later
        z = ID
        I = i
        for j in range(l):
            digit = I % m
            x = X[j]
            for k in range(digit):
                z *= x
            I = (I - digit) // m
        chal_vec_a[i] = z
        chal_vec_b[N-1-i] = z

    witness_u = [None]*2*l*(m-1)
    chal_vec_u = [None]*2*l*(m-1)

    for i in range(2*l*(m-1)):
        chal_vec_u[i] = ID

    for round_number in range(l):

        x = X[l-1-round_number]
        z = ID

        for i in range(m-1):
            witness_u[(l-1-round_number)*(m-1) + i] = U_bin[round_number][i]
            chal_vec_u[round_number*(m-1)+i] *= z
            z *= x

        for i in range(round_number*(m-1)+m-1,(2*l-2-round_number)*(m-1)+m-1):
            chal_vec_u[i] *= z
        
        z *= x
        
        for i in range(m,2*m-1):
            witness_u[(l-1+round_number)*(m-1) + i-1] = U_bin[round_number][i-1]
            chal_vec_u[(2*l-2-round_number)*(m-1) + i-1] *= z
            z *= x
    
    for i in range(2*l*(m-1)):
        chal_vec_u[i] = G2*chal_vec_u[i]

    z = ID
    for round_number in range(l):
        z *= X[round_number]

    chal_prod = ID
    for j in range(m-1):
        chal_prod *= z

    assert output_a == a * chal_vec_a
    assert output_b == b * chal_vec_b
    assert output_a * output_b == list_inner_product(witness_u, chal_vec_u) + t * chal_prod

    output_prover = (output_a, output_b)
    chal_vecs = (chal_vec_a, chal_vec_b, chal_vec_u, chal_prod)

    return output_prover, witness_u, chal_vecs


def prove_signatures(falcon_pk, falcon_sig, m, instance_com=poly_t(Rq), PS=None, start_index=None):
    """
    Args:
        falcon_pk: falcon public keys, as returned by make_falcon_pk_leaves
        falcon_sig: falcon signatures, as returned by make_falcon_pk_leaves
        m: reduction factor for the scalar product proof. 2*N_sig must be a 
           perfect m-th power, where N_sig = len(falcon_sig)
        instance_com: commitment to the instance (of falcon_pk and falcon_sig)
        PS: labrador proof system
        start_index: witness index in PS where falcon_pk and falcon_sig start
    """

    #======parse input======

    N_sig = len(falcon_sig)

    a_sig_even = polyvec_t(Rq,N_sig)
    a_sig_odd = polyvec_t(Rq,N_sig)
    for i in range(N_sig):
        a_sig_even[i] = falcon_pk[i][0] + BASE * falcon_pk[i][2]
        a_sig_odd[i] = falcon_pk[i][1] + BASE * falcon_pk[i][3]

    S1_sig_even = polyvec_t(Rq,N_sig)
    S1_sig_odd = polyvec_t(Rq,N_sig)
    S2_sig_even = polyvec_t(Rq,N_sig)
    S2_sig_odd = polyvec_t(Rq,N_sig)
    v_sig_even = polyvec_t(Rq,N_sig)
    v_sig_odd = polyvec_t(Rq,N_sig)
    for i in range(N_sig):
        S1_sig_even[i] = falcon_sig[i][0]
        S1_sig_odd[i] = falcon_sig[i][1]
        S2_sig_even[i] = falcon_sig[i][2]
        S2_sig_odd[i] = falcon_sig[i][3]
        v_sig_even[i] = falcon_sig[i][4] + BASE * falcon_sig[i][6]
        v_sig_odd[i] = falcon_sig[i][5] + BASE * falcon_sig[i][7]

    monomial = poly_t(Rq, {1:1})
    t_sig_even = a_sig_even[0]*S2_sig_even[0] + a_sig_odd[0]*monomial*S2_sig_odd[0] + S1_sig_even[0] + FALCON_MOD*v_sig_even[0]
    t_sig_odd = a_sig_even[0]*S2_sig_odd[0] + a_sig_odd[0]*S2_sig_even[0] + S1_sig_odd[0] + FALCON_MOD*v_sig_odd[0]

    for i in range(N_sig):
        assert t_sig_even == a_sig_even[i]*S2_sig_even[i] + a_sig_odd[i]*monomial*S2_sig_odd[i] + S1_sig_even[i] + FALCON_MOD*v_sig_even[i]
        assert t_sig_odd == a_sig_even[i]*S2_sig_odd[i] + a_sig_odd[i]*S2_sig_even[i] + S1_sig_odd[i] + FALCON_MOD*v_sig_odd[i]
    

    #======verifier challenge======

    r = poly_t(Rq)
    r.urandom(10, SEED, 0) # TODO: compute as hash (using instance_com)
    y = poly_t(Rq)
    y.urandom(10, SEED, 0) # TODO: compute as hash (using instance_com)


    #================compute a scalar product instance================

    N = 2*N_sig
    l = int(log(N, m))

    a = polyvec_t(Rq,N)
    z = ID
    for i in range(N_sig):
        a[i] = a_sig_even[i]*z
        a[N_sig+i] = a_sig_odd[i]*z
        z *= y

    b = polyvec_t(Rq,N)
    for i in range(N_sig):
        b[i] = S2_sig_even[i] + r*S2_sig_odd[i]
        b[N_sig+i] = monomial*S2_sig_odd[i] + r*S2_sig_even[i]

    z = ID
    Z = poly_t(Rq)
    chal_vec_y = polyvec_t(Rq,N_sig)
    for i in range(N_sig):
        chal_vec_y[i] = z
        Z += z
        z *= y

    t = (t_sig_even + r*t_sig_odd)*Z - FALCON_MOD*(v_sig_even + r*v_sig_odd)*chal_vec_y - (S1_sig_even + r*S1_sig_odd)*chal_vec_y

    # TODO: use efficient product representation for Z

    assert t == a * b


    #================compute relations for scalar product================

    output_prover, witness_u, chal_vecs = prove_scalar_product(N, a, b, t, m, instance_com, PS)

    output_a, output_b = output_prover
    chal_vec_a, chal_vec_b, chal_vec_u, chal_prod = chal_vecs


    #================compute relations for signatures================

    chal_vec_a_sig = polyvec_t(Rq, N)
    z = ID
    for i in range(N_sig):
        chal_vec_a_sig[i] = chal_vec_a[i]*z
        chal_vec_a_sig[N_sig+i] = chal_vec_a[N_sig+i]*z
        z *= y

    chal_vec_a_sig_decomp = polyvec_t(Rq, 2*N, [chal_vec_a_sig, BASE*chal_vec_a_sig])

    chal_vec_S2_sig = polyvec_t(Rq, N)
    for i in range(N_sig):
        chal_vec_S2_sig[i] = chal_vec_b[i] + r*chal_vec_b[N_sig+i]
        chal_vec_S2_sig[N_sig+i] = r*chal_vec_b[i] + monomial*chal_vec_b[N_sig+i]

    long_chal_vec_y = polyvec_t(Rq, N, [chal_vec_y, r*chal_vec_y])

    chal_vec_S1_sig = - long_chal_vec_y * chal_prod

    chal_vec_v_sig = -FALCON_MOD * long_chal_vec_y * chal_prod
    chal_vec_v_sig_decomp = polyvec_t(Rq, 2*N, [chal_vec_v_sig, BASE*chal_vec_v_sig])


    #================ check relations ================

    a_sig_split_decomp = polyvec_t(Rq, 2*N)
    for i in range(N_sig):
        a_sig_split_decomp[i] = falcon_pk[i][0]
        a_sig_split_decomp[i+N_sig] = falcon_pk[i][1]
        a_sig_split_decomp[i+N] = falcon_pk[i][2]
        a_sig_split_decomp[i+N_sig+N] =falcon_pk[i][3]

    S1_sig_split = polyvec_t(Rq, N)
    for i in range(N_sig):
        S1_sig_split[i] = falcon_sig[i][0]
        S1_sig_split[i+N_sig] = falcon_sig[i][1]

    S2_sig_split = polyvec_t(Rq, N)
    for i in range(N_sig):
        S2_sig_split[i] = falcon_sig[i][2]
        S2_sig_split[i+N_sig] = falcon_sig[i][3]
    
    v_sig_split_decomp = polyvec_t(Rq, 2*N)
    for i in range(N_sig):
        v_sig_split_decomp[i] = falcon_sig[i][4]
        v_sig_split_decomp[i+N_sig] = falcon_sig[i][5]
        v_sig_split_decomp[i+N] = falcon_sig[i][6]
        v_sig_split_decomp[i+N_sig+N] = falcon_sig[i][7]
    
    assert output_a == a_sig_split_decomp * chal_vec_a_sig_decomp
    assert output_b == S2_sig_split * chal_vec_S2_sig
    assert output_a * output_b == list_inner_product(witness_u, chal_vec_u) + (t_sig_even + r*t_sig_odd)*Z*chal_prod + S1_sig_split * chal_vec_S1_sig + v_sig_split_decomp * chal_vec_v_sig_decomp

    #================ input relations into Labrador ================

    if PS is not None:
        a_indices = [start_index + 12*i for i in range(N_sig)] + [start_index + 1 + 12*i for i in range(N_sig)] + [start_index + 2 + 12*i for i in range(N_sig)] + [start_index + 3 + 12*i for i in range(N_sig)]
        PS.append_statement(chal_vec_a_sig_decomp.to_pol_list(), a_indices, output_a)

        S2_indices = [start_index + 6 + 12*i for i in range(N_sig)] + [start_index + 7 + 12*i for i in range(N_sig)]
        PS.append_statement(chal_vec_S2_sig.to_pol_list(), S2_indices, output_b)

        S1_indices = [start_index + 4 + 12*i for i in range(N_sig)] + [start_index + 5 + 12*i for i in range(N_sig)]
        v_indices = [start_index + 8 + 12*i for i in range(N_sig)] + [start_index + 9 + 12*i for i in range(N_sig)] + [start_index + 10 + 12*i for i in range(N_sig)] + [start_index + 11 + 12*i for i in range(N_sig)]
        u_start_index = start_index + 12*N_sig
        u_indices = [None]*(l*2*(m-1))
        for round_number in range(l):
            for i in range(m-1):
                u_indices[(l-1-round_number)*(m-1) + i] = u_start_index + (2*m-1)*round_number + i
            
            for i in range(m,2*m-1):
                u_indices[(l-1+round_number)*(m-1) + i-1] = u_start_index + (2*m-1)*round_number + i - 1

        coefs = chal_vec_S1_sig.to_pol_list() + chal_vec_v_sig_decomp.to_pol_list() + chal_vec_u
        indices = S1_indices + v_indices + u_indices
        target = output_a * output_b - (t_sig_even + r*t_sig_odd)*Z*chal_prod
        PS.append_statement(coefs, indices, target)

def test_scalar():
    N = 2**10
    m = 2
    a = polyvec_t(Rq,N)
    a.brandom(10, SEED, 0, 1)
    b = polyvec_t(Rq,N)
    b.brandom(10, SEED, 0, 1)
    t = a * b

    prove_scalar_product(N, a, b, t, m)

def test_sig():
    NS = 128
    m = 2
    shake128 = hashlib.shake_128(bytes.fromhex("05"))
    seed=shake128.digest(32)
    LRhash=make_LRhash(BIGMOD_RING,4,seed)
    _,falcon_pk,falcon_sig = make_falcon_pk_leaves(NS, LRhash[0])

    prove_signatures(falcon_pk, falcon_sig, m)

def test_sigwPS():
    FALC_SEC_SPLIT_NORM=17017363//2
    V_SPLIT_NORM=round(1248245003*.75)//(2*BASE**2) 
    PK_SPLIT_NORM=256*BASE**2
    SIG_NORM_LIST=[PK_SPLIT_NORM]*4
    SIG_NORM_LIST.extend([FALC_SEC_SPLIT_NORM]*4)
    SIG_NORM_LIST.extend([PK_SPLIT_NORM]*2)
    SIG_NORM_LIST.extend([V_SPLIT_NORM]*2)
    BIN_VEC_DIM = math.ceil(math.log2(Rq.mod))
    W_DEC_DIM=2

    NS = 128
    shake128 = hashlib.shake_128(bytes.fromhex("05"))
    seed=shake128.digest(32)
    LRhash=make_LRhash(BIGMOD_RING,4,seed)
    _,falcon_pk,falcon_sig = make_falcon_pk_leaves(NS, LRhash[0])
    
    m = 2
    rounds = int(log(2*NS, m))

    num_pols_list = [1]*12*NS
    norm_list = SIG_NORM_LIST*NS

    for _ in range(rounds):
        num_pols_list += [BIN_VEC_DIM]*(2*m-2) + [W_DEC_DIM]
        norm_list += [2**13]*(2*m-2) + [W_DEC_DIM*BIGMOD_RING.deg*COM_MOD*COM_MOD]

    num_constraints = rounds + 3
    deg_list = [256]*len(norm_list)

    PS = proof_statement(deg_list, num_pols_list, norm_list, num_constraints, PRIMESIZE)

    for i in range(NS):
        for j in range(4):
            PS.append_witness(falcon_pk[i][j])
        for j in range(8):
            PS.append_witness(falcon_sig[i][j])

    prove_signatures(falcon_pk, falcon_sig, m, PS=PS, start_index=0)

    PS.smpl_verify()

if __name__ == "__main__":
    
    test_scalar()
    test_sig()
    test_sigwPS()
