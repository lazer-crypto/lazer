"""
    Aggregate Falcon signatures. The signatures are decomposed in two parts. 
    The liftings are decomposed in two parts and their norm is proven 
    exactly.
"""
import sys
sys.path.append('..')
from lazer import *
from lazer import _invmod
from labrados import *
from decomposition import *
import hashlib      # for SHAKE128
import time


REJ=0 # counts how many signatures are too big

# Total Signatures
sig_num=2**10

# Falcon parameters
mod=12289
deg=512

# falcon ring
FALCON_RING=polyring_t(deg,mod)
BIGMOD_RING=polyring_t(deg,LAB_RING_38.mod)
PRIMESIZE=str(math.ceil(math.log2(BIGMOD_RING.mod)))

# norms
norm_s_sq=round(34034726)
norm_v_sq=round(1.2*norm_s_sq*deg//12) # 1.2*(||a||*||s||/mod)^2 

LIFT_BASE=100
SIG_BASE=16

lift_norm_high=round(norm_v_sq/(LIFT_BASE*LIFT_BASE))
lift_norm_low=round(1.2*LIFT_BASE*LIFT_BASE*deg//12)

sig_norm_low=round(1.1*2*SIG_BASE*SIG_BASE*deg//12)
sig_norm_high=round(2*norm_s_sq/(SIG_BASE*SIG_BASE))

norms=[sig_norm_high,sig_norm_low,lift_norm_high,lift_norm_low]

# use the same sk/pk falcon key to save time on key generation
# makes no difference for the benchmark
SAME_KEY=1

ID=int_to_poly(1,BIGMOD_RING)

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("00"))
TARGPP = shake128.digest(32)

inv_fal_mod=_invmod(mod,BIGMOD_RING.mod)

deg_list=[deg]*(4*sig_num)
num_pols_list=[2,2,1,1]*sig_num
norm_list=norms*sig_num
num_constraints=sig_num
PS=proof_statement(deg_list,num_pols_list,norm_list,num_constraints,PRIMESIZE)

assert mod//2 * math.sqrt(deg) * (math.sqrt(sig_norm_low) + SIG_BASE*math.sqrt(sig_norm_high)) \
     + mod * (math.sqrt(lift_norm_low) + LIFT_BASE*math.sqrt(lift_norm_high)) \
     + mod//2 < BIGMOD_RING.mod

keytime_start=time.perf_counter()
if SAME_KEY:
    skenc,pkenc,pkpol=falcon_keygen()
    l_pk=pkpol.lift(BIGMOD_RING) 
else:
    sk_list=[]
    pk_list=[]
    for i in range(sig_num):
        skenc,pkenc,pkpol=falcon_keygen()
        l_pk=pkpol.lift(BIGMOD_RING) 
        sk_list+=[skenc]
        pk_list+=[l_pk]
keytime_end=time.perf_counter()

j=0
sig_start=time.perf_counter()
while j<sig_num:
    
    f_t=poly_t.urandom_static(FALCON_RING,FALCON_RING.mod,TARGPP,0)
    l_t=f_t.lift(BIGMOD_RING)
    
    if not SAME_KEY:
        skenc=sk_list[j]
        l_pk=pk_list[j]
    
    l_s1, l_s2 = falcon_preimage_sample(skenc, f_t) # s_1+s_2*pkpol=t, return poly_t 
    
    l_s1=l_s1.lift(BIGMOD_RING)
    l_s2=l_s2.lift(BIGMOD_RING)
    
    v=poly_t(BIGMOD_RING)
    v=(l_t-l_s1-l_pk*l_s2)*inv_fal_mod

    v.redc()

    if (l_s1.l2sq() + l_s2.l2sq()<norm_s_sq) and v.linf()<LIFT_BASE*LIFT_BASE:
        assert l_s1.linf()<2**14 and l_s2.linf()<2**14 and v.linf()<2**14

        v_dec=opt_decompose(v,LIFT_BASE,2) #decomposing the lifting polynomial into 2 parts
        s2_dec=opt_decompose(l_s2,SIG_BASE,2)
        s1_dec=opt_decompose(l_s1,SIG_BASE,2)
        if v_dec[0].l2sq() < lift_norm_low and v_dec[1].l2sq()< lift_norm_high:
            if (s2_dec[0].l2sq() + s1_dec[0].l2sq() < sig_norm_low) and (s2_dec[1].l2sq() + s1_dec[1].l2sq() < sig_norm_high):
                temp_stat_vec1=polyvec_t(BIGMOD_RING,2,[l_pk*SIG_BASE,ID*SIG_BASE])
                
                temp_stat_vec2=polyvec_t(BIGMOD_RING,2,[l_pk,ID])
                temp_wit_vec1=polyvec_t(BIGMOD_RING,2,[s2_dec[1],s1_dec[1]])
                temp_wit_vec2=polyvec_t(BIGMOD_RING,2,[s2_dec[0],s1_dec[0]])
                
                stat_left=[temp_stat_vec1,temp_stat_vec2,ID*mod*LIFT_BASE,ID*mod]
                wit=[temp_wit_vec1,temp_wit_vec2,v_dec[1],v_dec[0]]
                PS.fresh_statement(stat_left,wit,l_t)
                j+=1
            else:   
                print("Low-order (or high-order) signature polynomial too BIG in ",j)
                REJ+=1
        else:
            print("Low-order (or high-order) lifting polynomial too BIG in ",j)
            REJ+=1
    else:
        print("Too BIG in ",j)
        REJ+=1

sig_end=time.perf_counter()

stmnt=PS.output_statement()

PS.smpl_verify()
prove_start=time.perf_counter()
proof = PS.pack_prove()
prove_end=time.perf_counter()
ver_start=time.perf_counter()
if proof[0] == 0:
    pack_verify(proof[1:3],stmnt,PRIMESIZE)
ver_end=time.perf_counter()
print("Key creation: ",keytime_end-keytime_start)
print("Signature creation: ",sig_end-sig_start)
print("Proof Time: ",prove_end-prove_start)
print("Verification Time: ",ver_end-ver_start)
 
