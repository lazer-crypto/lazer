import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module
from lazer import _invmod
import hashlib      # for SHAKE128
import time
from labrados import *

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

def center_mod(a,m):
    a=a % m
    if a>m//2:
        a=a-m
    return a

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
    #print(pol)
    if loops==0:
        loops=math.ceil(math.log(pol.ring.mod,base))
    #print(loops)
    
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

def neg_decompose(pol:poly_t,base,loops=0):
    """Like decompose, but the input can be negative and then the decomposed coefficients can be negative too
    """
    if loops==0:
        loops=math.ceil(math.log(pol.ring.mod,base))
    pol.redc()
    #print(pol)
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

    # remove this in the finished protocol -- just for verifying that the decomposition was done right
    G=makeGvec(pol.ring,base,loops)
    assert G*dec_vec==pol
    return dec_vec

def opt_decompose(pol:poly_t,base,loops):
    """
    Args:
        pol (poly_t): the polynomial to be decomposed
        base (int): the decomposition base
        loops: pol=pol_{loops-1}*base^{loops-1} + pol_{loops-2}*base^{loops-2}+ ... + pol_0
            where pol_i in [-base/2),base/2)].  (if loops was set too low, then pol_{loops-1} can be bigger)

    Returns:
        res (polyvec_t): the decomposition of pol
    """
    temp_pol=poly_t(pol.ring)
    pol_ar=pol.make_i64array()
    top_temp, pol_ar=armod(pol_ar,pol.ring.deg,pol.ring.mod,True) # center the original polynomial 
    res=polyvec_t(pol.ring,loops)
    for i in range(loops-1):
        top_temp,bot_temp=armod(pol_ar,pol.ring.deg,base,True)
        temp_pol.set_i64array(bot_temp)
        res[i]=temp_pol
        pol_ar=top_temp
    temp_pol.set_i64array(top_temp)
    res[loops-1]=temp_pol

    G=makeGvec(pol.ring,base,loops)
    assert G*res ==pol
    return res

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
    #print(vec_in)
    vec_out=ffi.new("int64_t []",deg)
    top=ffi.new("int64_t []",deg)
    for i in range(deg):
        #print(i)
        #print(vec_in[i])
        vec_out[i]=vec_in[i] % mod
        if center:
            if vec_out[i]>mod//2:
                vec_out[i]=vec_out[i]-mod
            #vec_out[i]=center_mod(vec_in[i],mod)
        top[i]=(vec_in[i]-vec_out[i]) // mod
    return top,vec_out

