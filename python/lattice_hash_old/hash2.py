import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module
from lazer import _invmod
import hashlib      # for SHAKE128
import time
from labrados import *

shake128 = hashlib.shake_128(bytes.fromhex("1012"))

def makeGvec_lowhigh(ring,base,dim,split_pos=0,plusminus=None):
    if plusminus is None:
        plusminus=[1]*dim     

    G_low=polyvec_t(ring,split_pos)
    G_high=polyvec_t(ring,dim-split_pos)
    for i in range(dim):
        if i<split_pos:
            G_low[i]=poly_t(ring,{0:base**i})
            G_low[i]=G_low[i]*plusminus[i]
        else:
            G_high[i-split_pos]=poly_t(ring,{0:base**i})
            G_high[i-split_pos]=G_high[i-split_pos]*plusminus[i]
    if split_pos==0:
        return G_high
    return G_low,G_high

def decompose_pow2_lowhigh(pol:poly_t,split_pos=0,gvec_plusminus=None):
    assert gvec_plusminus is not None
   
    out_vec_high=polyvec_t(pol.ring,len(gvec_plusminus)-split_pos)
    if split_pos>0:
        out_vec_low=polyvec_t(pol.ring,split_pos)

    a=pol.make_i64array()
    temp=poly_t(pol.ring)
    out=ffi.new("int64_t []",pol.ring.deg)

    for i in range(len(gvec_plusminus)):
        for j in range(pol.ring.deg):
            out[j]=a[j] % 2
            a[j]=(a[j]-out[j]*gvec_plusminus[i]) // 2
        temp.set_i64array(out)
        if i<split_pos:
            out_vec_low[i]=temp
        else:
            out_vec_high[i-split_pos]=temp
    if split_pos==0:
        return out_vec_high
    return out_vec_low,out_vec_high

def decompose_pow2_pol_or_vec(v,split_pos=0,gvec_plusminus=None):

    assert gvec_plusminus is not None 

    low_list=[]
    high_list=[]

    if type(v) is poly_t:
        dim=1
    else: # v is polyvec_t
        dim=v.dim

    for i in range(dim):
        if type(v) is poly_t:
            temp=decompose_pow2_lowhigh(v,split_pos,gvec_plusminus)
        else:
            temp=decompose_pow2_lowhigh(v[i],split_pos,gvec_plusminus)
        if split_pos==0:
            high_list.append(temp)
        else:
            high_list.append(temp[1])
            low_list.append(temp[0])
    if split_pos==0:
        return high_list
    return low_list,high_list

def main():
    R=polyring_t(64,12289)
    g=[1,-1,-1,-1]
    seed=shake128.digest(32)
    pol=poly_t.urandom_bnd_static(R,0,15,seed,0)
    print(pol)
    low,high=decompose_pow2_lowhigh(pol,2,g)
    print("here")
    Glow,Ghigh=makeGvec_lowhigh(R,2,len(g),2,g)
    res=Ghigh*high+Glow*low
    print(res-pol)
    vec=polyvec_t(R,2,[pol,pol])
    ll,hl=decompose_pow2_pol_or_vec(vec,2,g)
    res=Ghigh*hl[1]+Glow*ll[1]
    print(res-pol)

if __name__ == "__main__":
    main()