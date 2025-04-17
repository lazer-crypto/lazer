import sys
sys.path.append('..')   # path to lazer module
from lazer import *     # import lazer python module
from lazer import _invmod
import hashlib      # for SHAKE128
import time
from labrados import *

FALCON_RING=polyring_t(512,12289)
BIGFALCON_RING=polyring_t(512,LAB_RING_38.mod)
BIGMOD_RING=polyring_t(256,LAB_RING_38.mod)
PRIMESIZE=str(math.ceil(math.log2(BIGMOD_RING.mod)))
BASE=2**10

# write the public keys and the v polynomials as a0+a1*FALC_SPLIT_BASE
FALC_SPLIT_BASE=2**7

# the falcon secret polynomials gets mapped to half the degree 
FALC_SEC_SPLIT_NORM=17017363//2

# the v polynomial gets mapped to half the degree and written in base FALC_SPLIT_BASE
V_SPLIT_NORM=round(1248245003*.75)//(2*FALC_SPLIT_BASE**2) 

PK_SPLIT_NORM=256*FALC_SPLIT_BASE**2

SIG_NORM_LIST=[PK_SPLIT_NORM]*4
SIG_NORM_LIST.extend([FALC_SEC_SPLIT_NORM]*4)
SIG_NORM_LIST.extend([PK_SPLIT_NORM]*2)
SIG_NORM_LIST.extend([V_SPLIT_NORM]*2)
print(SIG_NORM_LIST)

SMALL_MOD=256 # modulus used for the outer commitments
SMALL_MOD_INV=_invmod(SMALL_MOD,BIGMOD_RING.mod)

def update_shake128(cur_shake:hashlib.shake_128,to_append):
    if type(to_append) is bytes or type(to_append) is bytearray:
        cur_shake.update(to_append)
    elif type(to_append) is str:
        cur_shake.update(to_append.encode())
    elif type(to_append) is int:
        cur_shake.update(to_append.to_bytes(8,'big'))
    return cur_shake 

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

def decompose(pol:poly_t,base,loops=0):
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
        top,cur=armod(top,pol.ring.deg,base)
        #lib.poly_set_coeffvec_i64(temp_pol.ptr,cur)
        temp_pol.set_i64array(cur)
        res[i]=temp_pol
    
    # check to make sure that the top polynomial is 0
    for i in range(pol.ring.deg):
        assert top[i]==0
    return res

# def recompose(polvec:polyvec_t,base):
#     pol=poly_t(polvec.ring)
#     curmul=1
#     for i in range(polvec.dim):
#         pol+=curmul*polvec.get_elem(i)
#         curmul*=base
#     return pol

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

def make_hash_lists(ring:polyring_t, length, seed, height):
    l=[]
    inc=0
    for i in range(height):
        l.append([])
        for j in range(length):
            temp_poly=poly_t.urandom_bnd_static(ring,0,ring.mod-1,seed,inc)
            inc+=1
            l[i].append(temp_poly)
    return l

def make_one_hash_list(ring:polyring_t, length, seed, bound=None):
    l=[]
    inc=0
    for j in range(length):
        if bound==None:
            temp_poly=poly_t.urandom_bnd_static(ring,0,ring.mod-1,seed,inc)
        else:
            if bound%2==0:
                poly_t.urandom_bnd_static(ring,-bound//2+1,bound//2,seed,inc)
            else:
                poly_t.urandom_bnd_static(ring,-bound//2,bound//2,seed,inc)
        inc+=1
        l.append(temp_poly)
    return l

def outter_commit(v:polyvec_t,small_mod_hashes=None):
    
    new_hash=False
    if small_mod_hashes == None: # make a new hash_function
        shake128 = hashlib.shake_128(b"outer_commit") # seed for creating the SMALL_MOD hashes
        small_mod_hashes=[]
        new_hash=True
    
    bin_vec=[] # list of decomposed polynomials from v
    for i in range(v.dim):
        temp=decompose(v[i],2)
        bin_vec.append(temp)
        # make a hash function for each v[i] 
        #make a polyvec hash for each decomposed v[i]
        if new_hash:
            update_shake128(shake128,i) # append i 
            tempseed=shake128.digest(32) #create a seed
            small_mod_hashes.append(polyvec_t.urandom_bnd_static(v.ring,temp.dim,-SMALL_MOD//2+1,SMALL_MOD//2,tempseed,0))
    hash_val=list_inner_product(small_mod_hashes,bin_vec) # hash the decomposition
    mod256,w = hash_val.mod_int(SMALL_MOD,True) #hash_val=mod256+SMALL_MOD*w, mod256 in [0,SMALL_MOD-1)]
    assert w.linf()<SMALL_MOD**2
    w_dec=neg_decompose(w,SMALL_MOD,2) # assuming that all values of w are < 256^2
    
    #verifying that the decomposition was done properly
    G=makeGvec(v.ring,SMALL_MOD,2)
    G2=makeGvec(v.ring,2,math.ceil(math.log2(v.ring.mod)))
    assert SMALL_MOD*G*w_dec + mod256 == hash_val
    for i in range(v.dim):
        assert G2*bin_vec[i]==v[i]
    #<small_mod_hashes,bin_vec> = 256*<G,w_dec> +mod256
    #G2*bin_vec[i] = v[i]
    return mod256, bin_vec, w_dec, small_mod_hashes
    

def falcon_pk_sig_commit(hash_seed, pk_flat:list, sig_flat:list):
    
    #pk_flat=flatten_list(falcon_pk)
    #sig_flat=flatten_list(falcon_sig)
    hash=make_one_hash_list(pk_flat[0].ring,len(pk_flat)+len(sig_flat),hash_seed)

    pklen=len(pk_flat)
    temp_sum=poly_t(pk_flat[0].ring)
    for i in range(len(pk_flat)):
        temp_sum+=hash[i]*pk_flat[i]
    for i in range(len(sig_flat)):
        temp_sum+=hash[pklen+i]*sig_flat[i]
    return hash,temp_sum


def make_LRhash(ring:polyring_t,length,seed):
    Lhash=polyvec_t.urandom_bnd_static(ring,length,0,ring.mod-1,seed,0)
    Rhash=polyvec_t.urandom_bnd_static(ring,length,0,ring.mod-1,seed,1)
    return Lhash,Rhash

def check_path(root:poly_t, node:poly_t, i:int, path:list, dec_base: int, Lhash:polyvec_t, Rhash: polyvec_t):
    temp=poly_t(root.ring)
    count=0
    hash_length=Lhash.dim
    while i != 0:
        if i%2 == 0:
            node=Lhash*decompose(path[count],dec_base,hash_length) + \
                 Rhash*decompose(node,dec_base,hash_length)
        else:
            node=Lhash*decompose(node,dec_base,hash_length) + \
                 Rhash*decompose(path[count],dec_base,hash_length)
        count+=1
        i=(i-1)//2
    return node==root

def make_falcon_pk_leaves(num_leaves:int,Lhash:polyvec_t):
    falcon_pk=[]
    falcon_sig=[]
    leaves=[]
    base=FALC_SPLIT_BASE
    X=poly_t(BIGMOD_RING,{1:1})
    inv_fal_mod=_invmod(12289,BIGFALCON_RING.mod)
    
    shake128 = hashlib.shake_128(bytes.fromhex("44"))
    TARGPP = shake128.digest(32)
    f_t=poly_t.urandom_static(FALCON_RING,FALCON_RING.mod,TARGPP,0)
    l_t=f_t.lift(BIGFALCON_RING)


    i=0

    while i <num_leaves:
        skenc,pkenc,pkpol=falcon_keygen()
        l_s1,l_s2=falcon_preimage_sample(skenc,l_t)
        l_s1=l_s1.lift(BIGFALCON_RING)
        l_s2=l_s2.lift(BIGFALCON_RING)
        l_pk=pkpol.lift(BIGFALCON_RING)
        
        v=poly_t(BIGFALCON_RING)
        v=(l_t-l_s1-l_pk*l_s2)*inv_fal_mod
        var=v.make_i64array()
        var_high,var_low=armod(var,v.ring.deg,base)
        v_high=poly_t(BIGFALCON_RING)
        v_low=poly_t(BIGFALCON_RING)
        v_high.set_i64array(var_high)
        v_low.set_i64array(var_low)
        assert v_low+v_high*base == v
        assert v_low.linf()<base and v_high.linf()<base


        l_pkar=l_pk.make_i64array()
        pkar_high,pkar_low = armod(l_pkar,l_pk.ring.deg,base)
        l_pk_low=poly_t(BIGFALCON_RING)
        l_pk_high=poly_t(BIGFALCON_RING)
        l_pk_low.set_i64array(pkar_low)
        l_pk_high.set_i64array(pkar_high)
        assert l_pk_low+l_pk_high*base == l_pk
        assert (l_pk_low+l_pk_high*base)*l_s2+l_s1 + 12289*(v_low+v_high*base) == l_t 
        assert l_pk_low.linf() < base and l_pk_high.linf()<base

        pk_split_low=l_pk_low.to_isoring(BIGMOD_RING)
        pk_split_high=l_pk_high.to_isoring(BIGMOD_RING)
        v_split_low=v_low.to_isoring(BIGMOD_RING)
        v_split_high=v_high.to_isoring(BIGMOD_RING)
        s1_split=l_s1.to_isoring(BIGMOD_RING)
        s2_split=l_s2.to_isoring(BIGMOD_RING)
        t_split=l_t.to_isoring(BIGMOD_RING)
        
        assert pk_split_low.l2sqr() < PK_SPLIT_NORM and pk_split_high.l2sqr() and v_split_low.l2sqr() < PK_SPLIT_NORM
        if v_split_high[0].l2sq() > V_SPLIT_NORM or v_split_high[1].l2sq() > V_SPLIT_NORM :
            print("V TOO BIG")
            continue
        if s1_split[0].l2sq() > FALC_SEC_SPLIT_NORM or s1_split[1].l2sq() > FALC_SEC_SPLIT_NORM \
            or s2_split[0].l2sq() > FALC_SEC_SPLIT_NORM or s2_split[1].l2sq() > FALC_SEC_SPLIT_NORM:
            #print("S TOO BIG")
            continue
       
        assert (pk_split_low[0]+base*pk_split_high[0])*s2_split[0] + \
            (pk_split_low[1]+base*pk_split_high[1])*s2_split[1]*X + \
            s1_split[0]+12289*(v_split_low[0]+v_split_high[0]*base) == t_split[0]

        assert (pk_split_low[1]+base*pk_split_high[1])*s2_split[0] + \
            (pk_split_low[0]+base*pk_split_high[0])*s2_split[1] + \
            s1_split[1]+12289*(v_split_low[1]+v_split_high[1]*base) == t_split[1]
        
        #falcon_pk.append(polyvec_t(BIGMOD_RING,4,[pk_split_low,pk_split_high]))
        #NEW_CHANGE
        falcon_pk.append([pk_split_low[0],pk_split_low[1],pk_split_high[0],pk_split_high[1]])
        #falcon_sig.append(polyvec_t(BIGMOD_RING,8,[s1_split,s2_split,v_split_low,v_split_high]))
        falcon_sig.append([s1_split[0],s1_split[1],s2_split[0],s2_split[1],v_split_low[0],v_split_low[1],v_split_high[0],v_split_high[1]])
        assert Lhash.dim==4
        #leaves.append(Lhash*falcon_pk[i])
        leaves.append(Lhash[0]*pk_split_low[0]+Lhash[1]*pk_split_low[1]+Lhash[2]*pk_split_high[0]+Lhash[3]*pk_split_high[1])
        i+=1
    return leaves,falcon_pk,falcon_sig


class hash_tree:
    def __init__(self,ring:polyring_t, depth:int, leaves:list, dec_base:int, seed, LRhash=None):
        zpol=poly_t(ring)
        self.tree=[zpol]*(2**(depth+1)-1) # make an empty tree
        self.ring=ring
        self.depth=depth
        self.dec_base=dec_base
        self.hash_length=math.ceil(math.log(ring.mod,dec_base))
        if LRhash == None:
            self.Lhash,self.Rhash = make_LRhash(ring,self.hash_length,seed)
        else:
            self.Lhash,self.Rhash = LRhash
        self.leaves=leaves
        self.leaf_start=2**depth-1
        for i in range(len(leaves)):
            self.tree[self.leaf_start+i]=leaves[i]
        for i in range(2**depth-2,-1,-1):
            self.tree[i]=self.Lhash*decompose(self.tree[2*i+1],dec_base,self.hash_length) + \
                         self.Rhash*decompose(self.tree[2*i+2],dec_base,self.hash_length)
        
    def get_path(self,i):
        path=[]
        while i != 0:
            if i%2==0:
                path.append(self.tree[i-1])
            else:
                path.append(self.tree[i+1])
            i=(i-1)//2
        return path
    
    def decomposed_compath(self,i):
        path=self.get_path(i)
        node=poly_t(self.ring,self.tree[i])
        compath=[]
        pospath=[]
        count=0
        while i != 0:
            if i%2 == 0:
                Ldec=decompose(path[count],self.dec_base,self.hash_length)
                Rdec=decompose(node,self.dec_base,self.hash_length)
                compath.append(Ldec)
                compath.append(Rdec)
                if i>2:
                    node=self.Lhash*Ldec + self.Rhash*Rdec
                if(count>0):
                    pospath.append(1)
            else:
                Ldec=decompose(node,self.dec_base,self.hash_length)
                Rdec=decompose(path[count],self.dec_base,self.hash_length)
                compath.append(Ldec)
                compath.append(Rdec)
                if i>2:
                    node=self.Lhash*Ldec + self.Rhash*Rdec
                if(count>0):
                    pospath.append(0)
            i=(i-1)//2
            count+=1
        #for i in range(len(compath)):
        #    compath[i].redc()
        return compath,pospath

def test_proof():
    small_deg=64
    deg_list=[small_deg]
    num_pols_list=[2]
    norm_list=[2**19]
    num_constraints=1
    PS=proof_statement(deg_list,num_pols_list,norm_list,num_constraints,PRIMESIZE)
    R256=polyring_t(small_deg,LAB_RING_32.mod)
    R512=polyring_t(small_deg*2,LAB_RING_32.mod)
    shake128 = hashlib.shake_128(bytes.fromhex("00"))
    seed=shake128.digest(32)
    hash=polyvec_t.urandom_bnd_static(R256,2,0,10,seed,0)
    pol=poly_t.urandom_static(R512,10,seed,0)
    pol256=polyvec_t(R256,2)
    pol256=pol.to_isoring(R256) # does the same thing as the (commented out) code below
    for i in range(R256.deg):
        pol256.set_elem(pol[2*i],0,i)
        #pol256[0,i]=pol[2*i]
        pol256.set_elem(pol[2*i+1],1,i)
    PS.fresh_statement([hash],[pol],hash*pol256)
    print(pol)
    print(pol256.get_elem(0))
    print(pol256.get_elem(1))
    PS.smpl_verify()

def get_aux_vector(dim,seed):
    """
        Temporary 
    """
    aux_vec=polyvec_t.urandom_bnd_static(BIGMOD_RING,dim,-2**31,2**31,seed,0)
    return aux_vec


def create_proof(HT:hash_tree,node_list:list,falcon_pk=[],falcon_sig=[], hash_seed=None, reduction_factor=None, rounds=None):
    FALC=len(falcon_pk) > 0 and len (falcon_sig) > 0 and hash_seed != None
    AUX=FALC and reduction_factor!=None
    LN=len(node_list)

    W_DEC_DIM=2
    BIN_VEC_DIM=math.ceil(math.log2(BIGMOD_RING.mod))

    for i in range(LN):
        assert node_list[i] > 2**HT.depth-2 and node_list[i]<2**(HT.depth+1)-1
    deg_list=[HT.ring.deg]*((12*FALC+2*HT.depth)*LN+AUX*(2*reduction_factor-1)*rounds)
    num_pols_list=[HT.hash_length]*2*HT.depth*LN
    
    norm_list=[math.ceil(HT.ring.deg*HT.hash_length*(HT.dec_base**2))]*2*HT.depth*LN
    num_constraints=HT.depth*LN
    if FALC:
        num_pols_list.extend([1]*12*LN) # 12 polynomials per falcon signature
        norm_list.extend(SIG_NORM_LIST*LN) # 12 signature polynmials
        #num_constraints+=(3*LN) # 1 for pk hashing and 2 for signature
        num_constraints+=(LN) # 1 per pk hashing. 1 more for the pk/sig hash.  no signature yet 
        num_constraints+=1
    if AUX:
        round_terms = 2*reduction_factor-2
        for j in range(rounds):
            for i in range(round_terms):
                num_pols_list.extend([BIN_VEC_DIM]) #binary decomposition of aux_vec
                norm_list.extend([2**13]) #the coefficients in bin_vec are binary
            num_pols_list.extend([W_DEC_DIM]) # add the decomposition w_dec
            norm_list.extend([W_DEC_DIM*BIGMOD_RING.deg*SMALL_MOD*SMALL_MOD]) # add its l_2sq norm
            num_constraints+=1
        num_constraints += 3


        # for i in range(len(bin_vec)):
        #     num_pols_list.extend([bin_vec[i].dim]) #binary decomposition of aux_vec
        #     # TODO Bug in Labrador -- cannot check binary, using 2**13 for now which is l2sq norm
        #     norm_list.extend([2**13]) #the coefficients in bin_vec are binary
        # num_pols_list.extend([W_DEC_DIM]) # add the decomposition w_dec
        # norm_list.extend([W_DEC_DIM*w_dec.ring.deg*SMALL_MOD*SMALL_MOD]) # add its l_2sq norm
        # num_constraints+=(1+aux_vector.dim) 
        
    print(len(deg_list)," ",len(norm_list)," ",len(num_pols_list))
    PS=proof_statement(deg_list,num_pols_list,norm_list,num_constraints,PRIMESIZE)
    polzero=poly_t(HT.ring)

    negG=-makeGvec(HT.ring,HT.dec_base,HT.hash_length)
    negG.redc()
    cur_start=0
    for i in range(LN):
        print(PS.cur_witness_num)
        compath,pospath=HT.decomposed_compath(node_list[i])
        for j in range(len(compath)):
            PS.append_witness(compath[j])
        count=0
        print("length of compath=",len(compath))
        for j in range(0,len(compath),2):
            if j+2 < len(compath):
                stat_left=[HT.Lhash,HT.Rhash,negG]
                stat_right=polzero
                wit=[cur_start+j,cur_start+j+1,cur_start+j+2+pospath[count]]
            else:
                stat_left=[HT.Lhash,HT.Rhash]
                stat_right=HT.tree[0]
                wit=[cur_start+j,cur_start+j+1]
            
            PS.append_statement(stat_left,wit,stat_right)
            count+=1
        cur_start+=len(compath)
    
    START=2*HT.depth*LN
    if FALC:
        wit_com=[]
        for i in range(LN):
            for j in range(4):
                PS.append_witness(falcon_pk[i][j])
                #PS.append_witness(falcon_pk[i].get_elem(j))
            stat_left=[negG,HT.Lhash[0],HT.Lhash[1],HT.Lhash[2],HT.Lhash[3]]
            #stat_right=HT.tree[node_list[i]]
            stat_right=polzero
            offset = (node_list[i] % 2 == 0)
            wit=[2*HT.depth*i+offset,START+12*i,START+12*i+1,START+12*i+2,START+12*i+3]
            PS.append_statement(stat_left,wit,stat_right)
            for j in range(8):
                PS.append_witness(falcon_sig[i][j])

        # make one big commitment of the public keys and signatures
        pk_flat=flatten_list(falcon_pk)
        sig_flat=flatten_list(falcon_sig)
        # return the hash function and the commitment
        com_hash,com_right=falcon_pk_sig_commit(hash_seed,pk_flat,sig_flat)
        wit_com=[]
        for i in range(LN):
            wit_com+=[START+12*i,START+12*i+1,START+12*i+2,START+12*i+3]
        for i in range(LN):
            wit_com+=[START+12*i+4,START+12*i+5,START+12*i+6,START+12*i+7,START+12*i+8,START+12*i+9,START+12*i+10,START+12*i+11]
        PS.append_statement(com_hash,wit_com,com_right)
    
    if AUX:
        # import here to avoid circular import - TODO: move helper functions to different file
        from quadratic_to_linear import prove_signatures
        prove_signatures(falcon_pk, falcon_sig, reduction_factor, com_right, PS, START)
        
    stmnt=PS.output_statement()
    proof = PS.pack_prove()
    if proof[0]==0:
        pack_verify(proof[1:3],stmnt,PRIMESIZE)
    else:
        print("proof failed with error ",proof[0])
    PS.smpl_verify()
def main():
    
    shake128 = hashlib.shake_128(bytes.fromhex("05"))
    seed=shake128.digest(32)

    lstart=time.perf_counter()
    base=BASE
    loops=math.ceil(math.log(BIGMOD_RING.mod,base))
    leaves=[]
    depth=8
    LRhash=make_LRhash(BIGMOD_RING,4,seed)
    leaves,falcon_pk,falcon_sig = make_falcon_pk_leaves(2**depth,LRhash[0])
    #for i in range(2**depth):
    #    leaves.append(poly_t.urandom_static(BIGMOD_RING,BIGMOD_RING.mod,seed,i))
    HT=hash_tree(BIGMOD_RING,depth,leaves,base,seed,LRhash)
    # for i in range(len(HT.tree)):
    #     print(i)
    #     print(HT.tree[i])
    ind=2**depth-1+3
    path=HT.get_path(ind)
    cp=check_path(HT.tree[0],HT.tree[ind],ind,path,base,HT.Lhash,HT.Rhash)
    print(cp)
    path_start=time.perf_counter()
    compath,pospath=HT.decomposed_compath(ind)
    path_end=time.perf_counter()
    # for i in range(len(compath)):
    #     print(i)
    #     compath[i].print()
    G=makeGvec(BIGMOD_RING,base,loops)
    count=0
    for i in range(0,len(compath),2):
        if i+2<len(compath):
            print("-----")
            #print(HT.Lhash*compath[i]+HT.Rhash*compath[i+1]-G*compath[i+2+pospath[count]])
            print(HT.Lhash*compath[i]+HT.Rhash*compath[i+1]==G*compath[i+2+pospath[count]])
            count+=1
        else:
            print("-----")
            print(HT.Lhash*compath[i]+HT.Rhash*compath[i+1]==HT.tree[0])
    
    proof_start=time.perf_counter()
    index_list=[ind,ind+1,ind+4,ind+5,ind+9,ind+10,ind,ind+1]
    pk_list=[]
    sig_list=[]
    for i in index_list:
        pk_list.append(falcon_pk[i-2**depth+1])
        sig_list.append(falcon_sig[i-2**depth+1])

    N_sig = len(sig_list)
    reduction_factor = 4
    rounds = int(math.log(2*N_sig, reduction_factor))
    assert reduction_factor**rounds == 2*N_sig

    aux_vec=polyvec_t.urandom_bnd_static(BIGMOD_RING,5,-2**31,2**31,seed,0)
    create_proof(HT,index_list,pk_list,sig_list,seed, reduction_factor, rounds)
    proof_end=time.perf_counter()
    # for i in range(len(path)):
    #     print(path[i])
    # for i in range(1000):
    #     pol=poly_t.urandom_static(LAB_RING,LAB_RING.mod,seed,i)
    #     res=decompose(pol,2**8-1)
    #     #pol2=recompose(res,2**8-1)
    #     #print(pol-pol2)
    # lend=time.perf_counter()

    print(path_end-path_start)
    print(proof_end-proof_start)
    #test_proof()
    #make_falcon_pk_leaves(20,HT.Lhash)

    outter_commit(aux_vec)
    out=hash_to_bytes(sig_list[0]+pk_list[0],"hello")
    print(out)

if __name__ == "__main__":
    main()