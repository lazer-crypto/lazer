import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module
from lazer import _invmod
import hashlib      # for SHAKE128
import time
from labrados import *

HASH_DEG=512
HASH_RING=polyring_t(HASH_DEG,LAB_RING_38.mod)
PRIMESIZE=str(math.ceil(math.log2(HASH_RING.mod)))

ZERO=int_to_poly(0,HASH_RING)

HASH_MOD=128
HASH_LOG=7
HASH_ROUNDS=5
W_SPLIT=2
W_BASE=2**6
U_SPLIT=2
U_BASE=2**4
EXPANSION_MOD=4096
EXPANSION_DROP=2**4
EXPANSION_COLS=2
EXPANSION_ROWS=5

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("10"))
APP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("01"))
APP2 = shake128.digest(32)


# expand blindsig public parameters from seeds
# BND = int((mod-1)/2)
HASH_A = polyvec_t.urandom_bnd_static(HASH_RING, HASH_LOG, 0,HASH_MOD-1, APP, 0)

def makeGvec(ring,base,dim):
    """ 

    Args:
        ring (polyring_t)
        base (int)
        dim (int)

    Returns:
        polyvec_t: [1  base   base^2 ... base^{dim-1}]
    
    """

    G=polyvec_t(ring,dim)
    for i in range(dim):
        G[i]=poly_t(ring,{0:base**i})
    return G

HASH_G = makeGvec(HASH_RING,2,HASH_LOG)
W_G = makeGvec(HASH_RING,W_BASE,W_SPLIT)
U_G = makeGvec(HASH_RING,U_BASE,U_SPLIT)

def update_shake128(cur_shake:hashlib.shake_128,to_append):
    if type(to_append) is bytes or type(to_append) is bytearray:
        cur_shake.update(to_append)
    elif type(to_append) is str:
        cur_shake.update(to_append.encode())
    elif type(to_append) is int:
        cur_shake.update(to_append.to_bytes(8,'big'))
    return cur_shake 

EXPANSION_LIST=[]
for i in range(EXPANSION_ROWS):
    update_shake128(shake128,i)
    temp=polyvec_t.urandom_bnd_static(HASH_RING, EXPANSION_COLS, -EXPANSION_MOD//2,(EXPANSION_MOD-1)//2, shake128.digest(32), 0)
    EXPANSION_LIST.append(temp)

def hash_to_bytes(inp: list, salt: str="default"):
    
    shake128 = hashlib.shake_128(str.encode(salt))
    coder=coder_t()
    maxbytes=0
    for elem in inp:
        assert type(elem) is poly_t or type(elem) is polyvec_t
        if type(elem) is poly_t:
            maxbytes+=math.ceil(math.log2(elem.ring.mod))*elem.ring.deg//8
        else:
            maxbytes+=math.ceil(math.log2(elem.ring.mod))*elem.ring.deg*elem.dim//8
    coder.enc_begin(maxbytes)
   
    for elem in inp:
        bound=math.ceil(math.log2(elem.ring.mod))
        coder.enc_urandom(bound,elem)

    res=coder.enc_end()
    shake128.update(res)
    return shake128.digest(32)


def center_mod(a,m):
    a=a % m
    if a>m//2:
        a=a-m
    return a

def flatten_list(a:list):
    """
    Args:
        a (list): list of lists

    Returns:
        list: flattened list
    """
    out = []
    for sublist in a:
        out.extend(sublist)
    return out

def decompose(pol:poly_t,base,loops=0,centered=False):
    """
    
    Args:
        pol (poly_t): the polynomial to be decomposed
        base (int): the decomposition base
        loops: pol=pol_{loops-1}*base^{loops-1} + pol_{loops-2}*base^{loops-2}+ ... + pol_0

    Returns:
        res (polyvec_t): the decomposition of pol
    """

    #pol.redc()
    pol.redp()
    if loops==0:
        loops=math.ceil(math.log(pol.ring.mod,base))
    
    temp_pol=poly_t(pol.ring)
    #cur=ffi.new("int64_t []",pol.ring.deg)
    #top=ffi.new("int64_t []",pol.ring.deg)
    #lib.poly_get_coeffvec_i64(top, pol.ptr)
    top=pol.make_i64array()
    res=polyvec_t(pol.ring,loops)
    for i in range(loops):
        top,cur=armod(top,pol.ring.deg,base,centered)
        #lib.poly_set_coeffvec_i64(temp_pol.ptr,cur)
        temp_pol.set_i64array(cur)
        res[i]=temp_pol
    
    # check to make sure that the top polynomial is 0
    for i in range(pol.ring.deg):
        assert top[i]==0
    return res

def neg_decompose(pol:poly_t,base,loops):
    """Like decompose, but the input can be negative and then the decomposed coefficients can be negative too
    """
    
    pol.redc()
    polar=pol.make_i64array()
    pos_pol=poly_t(pol.ring)
    neg_pol=poly_t(pol.ring)
    negative=ffi.new("int64_t []",pol.ring.deg)
    for i in range(pol.ring.deg):
        if polar[i]<0:
            negative[i]=-1
            polar[i]=-polar[i]
        else:
            negative[i]=1
    
    pos_pol.set_i64array(polar)
    neg_pol.set_i64array(negative)
    dec_vec=decompose(pos_pol,base,loops)
    for i in range(dec_vec.dim):
        dec_vec[i]=neg_pol.component_mul(dec_vec[i])

    G=makeGvec(pol.ring,base,loops)
    assert G*dec_vec==pol
    return dec_vec

def armod(vec_in,deg,mod,center=False):
    """ 
    
    Args:
        vec_in (int64_t []): input vector
        deg (int): size of the vec_in array
        mod (int): modulus
        center (bool): whether the output vector should be centered modulo mod

    Returns:
        top,vec_out (int64_t []): top*mod + vec_out = vec_in

    """
    vec_out=ffi.new("int64_t []",deg)
    top=ffi.new("int64_t []",deg)
    for i in range(deg):
        # TODO switch to shifts later if mod is always a power of 2
        vec_out[i]=vec_in[i] % mod
        if center:
            vec_out[i]=center_mod(vec_in[i],mod)
        top[i]=(vec_in[i]-vec_out[i]) // mod
    return top,vec_out



def one_hash_round(inp: polyvec_t):
    """
    Computes A*inp = G*out+HASH_MOD*w, where out is binary

    """
    assert inp.dim == HASH_A.dim
    temp=HASH_A*inp
    mod_val,w=temp.mod_int(HASH_MOD,True)
    out=decompose(mod_val,2,HASH_LOG)
    return out,w

def multi_hash(inp:polyvec_t):

    assert inp.dim == HASH_A.dim
    inp_list=[inp]
    w_list=[]
    w_split=[]
    for i in range(HASH_ROUNDS):
        inp_new,w_new=one_hash_round(inp_list[i])
        inp_list.append(inp_new)
        w_list.append(w_new)
    for w in w_list:
        w_dec=neg_decompose(w,W_BASE,W_SPLIT)
        w_split.append(w_dec)
    return inp_list,w_split

def expand(inp:polyvec_t):
    assert inp.dim==EXPANSION_COLS
    for i in range(EXPANSION_ROWS):
        temp:poly_t=EXPANSION_LIST[i]*inp
        mod_val,w=temp.mod_int(EXPANSION_MOD,True)
        

def main():
    deg_list=[HASH_DEG]*(2*HASH_ROUNDS+2)
    num_pols_list=[HASH_LOG]*(HASH_ROUNDS+1) 
    num_pols_list.extend([W_SPLIT]*(HASH_ROUNDS+1))
    norm_list=[0]*(HASH_ROUNDS+1) 
    norm_list.extend([W_BASE*W_BASE*W_SPLIT*HASH_DEG]*(HASH_ROUNDS+1))
    num_constraints=HASH_ROUNDS+1

    inp=polyvec_t.urandom_bnd_static(HASH_RING, HASH_LOG, 0, 1, APP2, 0)
    inp_list,w_list=multi_hash(inp)
    temp=HASH_A*inp_list[HASH_ROUNDS]
    final_out,w=temp.mod_int(HASH_MOD,True) #final_out+w*HASH_MOD=temp
    w_dec=neg_decompose(w,W_BASE,W_SPLIT)
    w_list.append(w_dec)

    #for vec in w_list:
    #    print(vec[0])

    #test=HASH_A*inp_list[2]-HASH_G*inp_list[3]-HASH_MOD*W_G*w_list[2]
    #print(test)
    #print(final_out)

    PS=proof_statement(deg_list,num_pols_list,norm_list,num_constraints,PRIMESIZE)
    
    inp_list.extend(w_list)

    for v in inp_list:
        PS.append_witness(v)
        #v.print()
    left=[HASH_A,-HASH_G,-HASH_MOD*W_G]
    for i in range(num_constraints-1):
        PS.append_statement(left,[i,i+1,i+1+HASH_ROUNDS],ZERO)
    PS.append_statement([HASH_A,-HASH_MOD*W_G],[HASH_ROUNDS,1+2*HASH_ROUNDS],final_out)
    #PS.smpl_verify()
    
    stmnt=PS.output_statement()
    proof = PS.pack_prove()
    if proof[0] == 0:
        pack_verify(proof[1:3],stmnt,PRIMESIZE)
    
    print("got here")

    print(HASH_A*inp_list[0])

if __name__ == "__main__":
    main()