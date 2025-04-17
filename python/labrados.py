from lazer import *
from decomposition import neg_decompose, makeGvec

LAB_RING_32=polyring_t(64,2**32-99)
LAB_RING_36=polyring_t(64,2**36-243)
LAB_RING_38=polyring_t(64,2**38-107)
LAB_DEGREE=256
MAX_C=2**63-1

def printi64ar(ar,ar_size):
    for i in range(ar_size):
        print(ar[i]," ",end="")
    print()

def l2sq_ar(ar,ar_size):
    l2=0
    for i in range(ar_size):
        l2+=ar[i]*ar[i]
    return l2

def int64_to_type(v,v_size,outtype):
    if outtype=="int64":
        return v
    elif outtype=="size_t":
        s_ar=ffi.new("size_t []",v_size)
    elif outtype=="uint64":
        s_ar=ffi.new("uint64_t []",v_size)
    elif outtype=="int16":
        s_ar=ffi.new("int16_t []",v_size)
    else:
        print("output type unknown")
    for i in range(v_size):
        s_ar[i]=v[i]
    return s_ar

def poly_to_ar(v: poly_t,outtype="int64"):
    pv=ffi.new("int64_t []",v.ring.deg)
    lib.poly_get_coeffvec_i64(pv, v.ptr)
    return int64_to_type(pv,v.ring.deg,outtype)

def polyvec_to_ar(v: polyvec_t,outtype="int64"):
    pvec=ffi.new("int64_t []",v.ring.deg*v.dim)
    for i in range(v.dim):
        temp=poly_to_ar(v.get_elem(i))
        for j in range(v.ring.deg):
            pvec[v.ring.deg*i+j]=temp[j]
    return int64_to_type(pvec,v.ring.deg*v.dim,outtype)

def list_automorphism(pol_coeffs:list):
    """
        Takes a polynomial whose coefficients are in a list and returns a list of coefficients representing
        the automorphism.  e.g. if pol_coeffs=[a,b,c,d], it returns [a,-d,-c,-b]
    """
    coeffs=pol_coeffs.copy()
    deg=len(coeffs)
    coeffs[1:deg]=reversed(coeffs[1:deg])
    coeffs[1:deg]=[-x for x in coeffs[1:deg]]
    return coeffs

def list_iso_split_automorphism(coeffs:list,num_lists:int):
    """
        Takes a coefficient list and splits it into num_lists lists of alternating coefficients,
        computes their auttomorphism using list_automorphism and then collapses the lists
        e.g. if coeffs=[1,2,3,4,5,6,7,8] and num_lists=4, it creates [[1,5],[2,6],[3,7],[4,8]],
        computes the automorphisms [[1,-5],[2,-6],[3,-7],[4,-8]]
        and outputs [1,-5,2,-6,3,-7,4,-8]
    """
    ret=[]
    for i in range(num_lists):
        temp=list_automorphism(coeffs[i::num_lists])
        ret = ret+temp
        #ret=ret+coeffs[i::num_lists]
        #ret.append(coeffs[i::num_lists])
    return ret 

def make_integer_relation_list(coeffs:list,wit_shapes:list,base_degree=LAB_DEGREE):
    cur_coeff=0
    tot_coeffs=0
    for i in range(len(wit_shapes)):
        tot_coeffs+=wit_shapes[i][0]*wit_shapes[i][1]
    assert len(coeffs) == tot_coeffs
    ret=coeffs.copy()
    for i in range(len(wit_shapes)):
        deg=wit_shapes[i][0]
        assert (deg>=base_degree)
        pols=wit_shapes[i][1]
        for j in range(pols):
            ret[cur_coeff:cur_coeff+deg]=list_iso_split_automorphism(ret[cur_coeff:cur_coeff+deg],deg//base_degree)
            cur_coeff+=deg
    return ret

class proof_statement:
    """This is the prover class for the succinct proof system. It collects the statement / witness to be proved and creates a proof. 
    
    Attributes:
        cur_witness_num (int): the current witness number, when creating the witness
        cur_constraint_num (int): the current constraint number, when creating the statements
        cur_int_constraint_num (int): the current integer constraint number
        num_constraints (int): total number of constraints allocated in the statement
        num_int_constraints (int): total number of integer constraints allocated in the statement
        zk (bool): True if the proof is to have zero-knowledge
        witness: the pointer to a C structure holding the witness
        statement: the pointer to a C structure holding the statement
        params: the pointer to a C structure holding the parameters
        proof: the pointer to a C structure holding the proof
        proven (bool): True if there are valid params and proof already computed
    """

    def __init__(self, deg_list:list, num_pols_list:list, norm_list:list, num_constraints:int, 
                 primesize: str, num_int_constraints:int=0, num_deg0_constraints:int=0, 
                 zk:bool=False, approx_norm_list:list=None, debug:bool=False):
        """Initializer function. One should think of the witness vector as a list of either polynomials (poly_t),
        or polynomial vectors (polyvec_t). 
        
        Args:
            deg_list ([int]): a list of the degree of witness i
            num_pols_list ([int]): a list of the number polynomials in witness i
            norm_list: ([int]): a list of l2-squared norm bounds for witness i
            approx_norm_list: ([(int,int)]): a list of pairs of integers, for
                vectors whose norms will only be proven approximately. 
                The first int in the pair is the index of a witness vector, and
                the second is an l2-squared norm bound that the proof has to guarantee.
            num_witness_vectors (int): the  number of witness vectors
            num_constraints (int): the number of equations (over a polynomial ring) in the statement
            num_int_constraints (int): the number of integer equations in the statement
            num_deg0_constraints (int): the number of constraints indicating that a polynomial has degree 0
            primesize (str): either "32","36", or "38".  The prime used in the proof system is ~ 2**primesize
            zk (bool): True if the proof is to have zero-knowledge
            debug (bool): set to True for printing debugging info (parameters)
        """
        assert len(deg_list)==len(num_pols_list)==len(norm_list)
        assert primesize in ["32","36","38"]
        assert all(deg >= LAB_DEGREE for deg in deg_list)
        if approx_norm_list is not None:
            assert all(x < len(deg_list) for (x,_) in approx_norm_list)
            assert all(norm_list[x] != 0 for (x,_) in approx_norm_list)
            assert all(y > 0 for (_,y) in approx_norm_list)

        print("initializing")
        self.cur_witness_num=0
        self.cur_constraint_num=0
        self.cur_int_constraint_num=0
        self.cur_deg0_constraint_num=0
        self.num_witness_vectors=len(deg_list)
        self.num_constraints=num_constraints
        self.num_int_constraints=num_int_constraints
        self.num_deg0_constraints=num_deg0_constraints
        self.zk=zk
        self.debug=debug
        self.proven=False
        self.func_choose_define(primesize)
        
        self.witness=ffi.new("labrador"+primesize+"_witness")
        self.statement=ffi.new("labrador"+primesize+"_statement")
        self.params=ffi.new("labrador"+primesize+"_dch_pack_params")
        self.proof=ffi.new("labrador"+primesize+"_dch_pack_proof")

        # Permute indices to have: approx | bin | exact
        approx_list = [x for (x,_) in approx_norm_list] if approx_norm_list is not None else []
        perm = approx_list.copy()
        bin_list = [i for i in range(len(norm_list)) if norm_list[i]==0]
        perm += bin_list
        exact_list = sorted(list(set(range(self.num_witness_vectors)) - set(perm)))
        perm += exact_list

        deg_list = [deg_list[i] for i in perm]
        num_pols_list = [num_pols_list[i] for i in perm]
        norm_list = [norm_list[i] for i in perm]

        self.deg_list = deg_list.copy()
        self.num_pols_list = num_pols_list.copy()

        # get inverse permutation for appending witness vectors
        self.map = [0]*self.num_witness_vectors
        for i, v in enumerate(perm):
            self.map[v]=i

        dim_ar=ffi.new("size_t []",len(num_pols_list))
        for i in range(len(num_pols_list)):
            dim_ar[i]=num_pols_list[i]*deg_list[i]//LAB_DEGREE
        
        self.init_witness(self.witness,len(num_pols_list),dim_ar)
        self.witness_polys=0 #number of LAB_DEGREE-dimensional ring elements in the witness

        # norm types: 0->L2EXACT, 1->L2APPROX, 2->BIN
        norm_types_list = [1]*len(approx_list) + [2]*len(bin_list) + [0]*len(exact_list)
        norm_types_ar=ffi.new("int []",norm_types_list)

        # add trivial squared l2-norm bound for binary vectors
        norm_list=[dim*deg if norm==0 else norm for (dim,deg,norm) in zip(num_pols_list,deg_list,norm_list)]
        norms_ar=ffi.new("uint64_t []",norm_list)

        # norm requirements for approx vectors
        norm_req_list=[min(y,2**64-1) for (_,y) in approx_norm_list] if approx_norm_list is not None else []
        norm_req_list += [0]*(len(bin_list)+len(exact_list))
        norm_req_ar=ffi.new("uint64_t []",norm_req_list)

        self.init_statement(self.statement,len(num_pols_list),dim_ar,norms_ar,norm_req_ar,norm_types_ar,num_constraints,num_int_constraints,num_deg0_constraints)


    def __del__(self):
        self.free_witness(self.witness)
        self.free_statement(self.statement)
        if self.proven:
          self.free_params(self.params)
          self.free_proof(self.proof)

    def smpl_verify(self):
        """
        A sanity check to make sure that the input statement and witness actually satisfy the linear 
        statement and the norm bounds. May be useful in debugging.
        """
        print("Trying to Simple Verify")
        out=self.simple_verify(self.statement,self.witness)
        print("Simple Verify =",out==1)

    def pack_prove(self):
        """
        Creates the succinct proof.

        Returns:
            self.params (C type): the parameters
            self.proof (C type): the proof
        """
        print("Trying to Pack Prove")
        if self.proven:
            self.free_params(self.params)
            self.free_proof(self.proof)
            self.proven=False
  
        error=self.gen_params(self.params,self.statement,1 if self.zk else 0,1 if self.debug else 0)
        if error==0:
            self.prove(self.proof,self.statement,self.witness,self.params)
            self.proven=True
        # error = 0 means everything is good
        return error,self.params,self.proof

    def append_witness(self,v):
        """ Append a new witness
        
        Args:
            v (poly_t/polyvec_t): a witness to be added to the witness set. it can then be accessed
                later using its witness number, which gets consecutively increased every time a witness
                is added
        
        Returns:
            

        """
        
        if type(v) is poly_t:
            pvec=poly_to_ar(v)
            pols=1
            self.witness_polys+=v.ring.deg//LAB_DEGREE
        elif type(v) is polyvec_t:
            pvec = polyvec_to_ar(v)
            pols=v.dim
            self.witness_polys+=pols*v.ring.deg//LAB_DEGREE

        assert self.cur_witness_num < self.num_witness_vectors
            
        output=self.set_witness_vector(self.witness,self.map[self.cur_witness_num],pols,v.ring.deg//LAB_DEGREE,pvec)

        assert output==0
        # witness coefficients should all be < 16 bits, make sure they're centered
        self.cur_witness_num+=1
        return self.cur_witness_num-1
        
    def append_witness_pointer(self, pv, deg, dim = 1):
        """ Append a new witness
        
        Args:
            v (C pointer for poly_t/polyvec_t): a witness to be added to the witness set. it can then be accessed
                later using its witness number, which gets consecutively increased every time a witness
                is added
        
        Returns:
            

        """
        
        self.witness_polys += dim * deg // LAB_DEGREE

        assert self.cur_witness_num < self.num_witness_vectors
            
        output=self.set_witness_vector(self.witness, self.map[self.cur_witness_num], dim, deg // LAB_DEGREE, pv)

        assert output==0
        # witness coefficients should all be < 16 bits, make sure they're centered
        self.cur_witness_num+=1
        return self.cur_witness_num-1
    
    def append_statement(self,stat_list,witnum_list,right_pol:poly_t):
        """ Adds a linear statement to the proof system.

        Args:
            stat_list (list): a list of poly_t or polyvec_t (or a mix) elements
            witnum_list(list): a list of integers corresponding to the witnesses that were added
                using append_witness() or fresh_statement().  witness i in the witnum_list gets
                multiplied by element i in the stat_list
            right_pol (poly_t): the polynomial t in <ste_list,witnum_list> = t
        
        """


        assert len(stat_list)==len(witnum_list)
        assert self.cur_constraint_num < self.num_constraints
        stat_size=0
        ring=right_pol.ring
        len_ar=ffi.new("size_t []",len(stat_list))
      
        witnum_list = [self.map[x] for x in witnum_list]
        witnum_ar=ffi.new("size_t []",witnum_list)

        for i in range(len(stat_list)):
            if type(stat_list[i]) is poly_t:
                stat_size+=1 #number of polynomials in stat_list increases by 1
                len_ar[i]=1 #number of polynomials 
            elif type(stat_list[i]) is polyvec_t:
                stat_size+=stat_list[i].dim
                len_ar[i]=stat_list[i].dim
            else:
                print("Error")
        
        stat_vec=polyvec_t(ring,stat_size,stat_list) # concatenation of all poly/polyvec in stat_list into one polyvec
        stat_ar=polyvec_to_ar(stat_vec) # convert polyvec to array
        right_ar=poly_to_ar(right_pol)

        output=self.append_constraint(self.statement,len(stat_list),witnum_ar,len_ar,ring.deg//LAB_DEGREE,stat_ar,right_ar,1)
        #print("Set Statement Output",output)
        assert output==0
        # should all be less than q, should centralize everything
        self.cur_constraint_num+=1

    def append_integer_statement(self,coeffs:list,witnum_list,right_int:int):
        """ Adds an integer linear statement to the proof system of the form:
            <coeffs, get_coeff_list(witness)> = t

        Args:
            coeffs (list): a list of integers
            witnum_list(list): a list of integers corresponding to the witnesses that were added
                using append_witness() or fresh_statement().
            right_int (int): the right-hand side of the statement
        
        """

        assert self.cur_int_constraint_num < self.num_int_constraints

        witnum_list_perm=[self.map[x] for x in witnum_list]
        witnum_shape=[(self.deg_list[x], self.num_pols_list[x]) for x in witnum_list_perm]
        len_list=[(deg*npol)//LAB_DEGREE for (deg,npol) in witnum_shape]
        coeffs_list=make_integer_relation_list(coeffs, witnum_shape)

        witnum_ar=ffi.new("size_t []", witnum_list_perm)
        len_ar=ffi.new("size_t []", len_list)
        coeffs_ar=ffi.new("int64_t []", coeffs_list)
        right_ar=ffi.new("int64_t []", [right_int] + [0]*(LAB_DEGREE-1))

        output=self.append_constraint(self.statement,len(witnum_list),witnum_ar,len_ar,1,coeffs_ar,right_ar,0)

        assert output==0
        self.cur_int_constraint_num+=1

    def append_quadratic_statement(self,stat_lin,wit_lin,stat_quad,wit_quad1,wit_quad2,right_pol:poly_t):
        """ Adds a quadratic statement to the proof system
        
        Args:
            stat_lin (list): a list of poly_t or polyvec_t (or a mix) elements
                representing the public elements of the linear part
            wit_lin (list): a list of indices of witness vectors for the linear part.
                witness i in wit_lin is multiplied by element i in the stat_list
            stat_quad (list): a list of integers representing the public coefficients
                multiplying the quadratic terms
            wit_quad1 (list): a list of indices of witness vectors, the left part
                of the quadratics
            wit_quad2 (list): a list of indices of witness vectors, the right part
                of the quadratics
            right_pol (poly_t): the polynomial t in
                <stat_lin,wit_lin> + sum_i stat_quad[i]*<wit_quad1[i],wit_quad2[i]> = t

        """

        assert len(stat_lin) == len(wit_lin)
        assert len(stat_quad) == len(wit_quad1) and len(wit_quad1) == len(wit_quad2)
        assert self.cur_constraint_num < self.num_constraints

        stat_lin_size=0
        ring=right_pol.ring
        len_lin_ar=ffi.new("size_t []", len(stat_lin))

        for i in range(len(stat_lin)):
            if type(stat_lin[i]) is poly_t:
                stat_lin_size+=1
                len_lin_ar[i]=1
            elif type(stat_lin[i]) is polyvec_t:
                stat_lin_size+=stat_lin[i].dim
                len_lin_ar[i]=stat_lin[i].dim
            else:
                print("Error")

        stat_lin_vec=polyvec_t(ring,stat_lin_size,stat_lin)
        stat_lin_ar=polyvec_to_ar(stat_lin_vec)

        wit_lin=[self.map[x] for x in wit_lin]
        wit_lin_ar=ffi.new("size_t []", wit_lin)

        wit_quad1=[self.map[x] for x in wit_quad1]
        wit_quad1_ar=ffi.new("size_t []", wit_quad1)

        wit_quad2=[self.map[x] for x in wit_quad2]
        wit_quad2_ar=ffi.new("size_t []", wit_quad2)

        stat_quad_ar=ffi.new("int64_t []", stat_quad)

        right_ar=poly_to_ar(right_pol)
        
        output=self.append_quadratic(self.statement,len(stat_lin),len(stat_quad),wit_lin_ar,
                                     wit_quad1_ar,wit_quad2_ar,len_lin_ar,ring.deg//LAB_DEGREE,
                                     stat_quad_ar,stat_lin_ar,right_ar)
        assert output==0
        self.cur_constraint_num+=1

    def append_deg0_statement(self,wit:int):
        """ Adds a statement indicating that a witness is a polynomial of deg=0

        Args:
            wit (int): an integer representing the index of the witness with
                degree 0.
        
        """
        assert self.cur_deg0_constraint_num < self.num_deg0_constraints

        wit=self.map[wit]
        deg=self.deg_list[wit]//LAB_DEGREE

        output=self.append_deg0_constraint(self.statement,wit,deg)

        assert output==0
        self.cur_deg0_constraint_num+=1

    def fresh_statement(self,stat_list,wit_list,right_pol:poly_t):
        """ Input a new constraint of the form <a,w>=t over a polynomial ring to the statement 

        Args:
            stat_list ([poly_t/polyvec_t]): a list of poly_t or polyvec_t comprising a
            wit_list ([poly_t/polyvec_t/int]): the list consists of i elements such that the ith element of
                wit_list is multiplied by the ith element of stat_list (make sure they're both either poly_t
                or polyvec_t!). If the ith element of stat_list is to be multiplied by a witness added in a
                prior fresh_statement, then one should enter the witness number of that witness (it will then
                be necessary to keep track of the order in which the witnesses are being entered)
            right_pol (poly_t): the t part of the constraint
        """
        witnum_list=[0]*len(wit_list)
        for i in range(len(wit_list)):
            if type(wit_list[i]) is poly_t or type(wit_list[i]) is polyvec_t:
                witnum_list[i]=self.cur_witness_num
                self.append_witness(wit_list[i])
            else: # type is integer
                assert wit_list[i]<self.cur_witness_num
                witnum_list[i]=wit_list[i]
        self.append_statement(stat_list,witnum_list,right_pol)

    def output_statement(self):
        """Outputs the statement that will be proved
        """
        return self.statement
    
    def print_witness_debug(self,idx:int):
        """Prints witness at an index, mapped to degree 256
        """
        assert idx < self.num_witness_vectors
        self.print_witness_vector(self.witness,self.map[idx])

    #based on the size of the prime, different C functions are used
    def func_choose_define(self,primesize: str):
        if primesize == "32":
            self.init_witness=lib.labrador32_py_init_witness
            self.set_witness_vector=lib.labrador32_py_set_witness_vector
            self.print_witness_vector=lib.labrador32_py_print_witness_vector
            self.init_statement=lib.labrador32_py_init_statement
            self.append_constraint=lib.labrador32_py_append_constraint
            self.append_quadratic=lib.labrador32_py_append_quadratic
            self.append_deg0_constraint=lib.labrador32_py_append_deg0_constraint
            self.gen_params=lib.labrador32_py_gen_params
            self.simple_verify=lib.labrador32_py_simple_verify
            self.prove=lib.labrador32_py_prove
            self.verify=lib.labrador32_py_verify
            self.free_witness=lib.labrador32_py_free_witness
            self.free_statement=lib.labrador32_py_free_statement
            self.free_params=lib.labrador32_py_free_params
            self.free_proof=lib.labrador32_py_free_proof
        elif primesize == "36":
            self.init_witness=lib.labrador36_py_init_witness
            self.set_witness_vector=lib.labrador36_py_set_witness_vector
            self.print_witness_vector=lib.labrador36_py_print_witness_vector
            self.init_statement=lib.labrador36_py_init_statement
            self.append_constraint=lib.labrador36_py_append_constraint
            self.append_quadratic=lib.labrador36_py_append_quadratic
            self.append_deg0_constraint=lib.labrador36_py_append_deg0_constraint
            self.gen_params=lib.labrador36_py_gen_params
            self.simple_verify=lib.labrador36_py_simple_verify
            self.prove=lib.labrador36_py_prove
            self.verify=lib.labrador36_py_verify
            self.free_witness=lib.labrador36_py_free_witness
            self.free_statement=lib.labrador36_py_free_statement
            self.free_params=lib.labrador36_py_free_params
            self.free_proof=lib.labrador36_py_free_proof
        elif primesize == "38":
            self.init_witness=lib.labrador38_py_init_witness
            self.set_witness_vector=lib.labrador38_py_set_witness_vector
            self.print_witness_vector=lib.labrador38_py_print_witness_vector
            self.init_statement=lib.labrador38_py_init_statement
            self.append_constraint=lib.labrador38_py_append_constraint
            self.append_quadratic=lib.labrador38_py_append_quadratic
            self.append_deg0_constraint=lib.labrador38_py_append_deg0_constraint
            self.gen_params=lib.labrador38_py_gen_params
            self.simple_verify=lib.labrador38_py_simple_verify
            self.prove=lib.labrador38_py_prove
            self.verify=lib.labrador38_py_verify
            self.free_witness=lib.labrador38_py_free_witness
            self.free_statement=lib.labrador38_py_free_statement
            self.free_params=lib.labrador38_py_free_params
            self.free_proof=lib.labrador38_py_free_proof

    

def pack_verify(proof,statement,primesize: str):
    """The verification procedure for the succinct proof, which takes in the output of pack_prove and the statement
    
    """
    params,proof = proof[0],proof[1]
    print("Trying to Pack Verify")
    if primesize == "32":
        out=lib.labrador32_py_verify(statement,params,proof)
    elif primesize == "36":
        out=lib.labrador36_py_verify(statement,params,proof)
    elif primesize == "38":
        out=lib.labrador38_py_verify(statement,params,proof)
    print("Pack Verify =",out==1)
    return out == 1

# the next functions help lift the equation As=t mod p to equationg As+pGr = t mod q
  
def num_pols_in_r(norma,norms,maxr,p):
    """ When As=t mod p is written as As+qGr = t modq, returns the number of polynomials in r
         The matrix G is of the form [1, maxr, maxr^2, ... ]

    Args:
        norma(float): l2 norm of a
        norms(float): l2 norm of s
        maxr(int): the base of the decomposition G
    """
    rsize = math.ceil(norma*norms/p) # by Cauchy-Schwartz, |<a,s>| <= ||a||*||s||.
    # maximum remainder size is thus ||a||*||s||/p
    return math.ceil(math.log(rsize,maxr))


def lift_equation(BIG_RING:polyring_t,a:list,t:poly_t,s:list,pols_in_r,maxr,p,invp,PS=None,witnum_s=None,witnum_r=None,pGvec=None):
    """"
    
    Args:
        PS(proof_statement): the current proof statement
        BIG_RING(polyring_t): the ring with the labrador modulus that we will work in
        a(list): a list of poly_t and/or polyvec_t in the small ring
        s(list): a list of poly_t and/or polyvec_t in the small ring
        t(poly_t): a poly_t in the small ring satisfying <a,s>=t
        witnum_s(list): the witness numbers of s in PS
        witnum_r(int): the witness number of the r in a*s + p*r = t
        pols_in_r(int): the number of polynomials in the decomposition of r
        maxr(int): the decomposition base of the r vector
    
    """

    assert len(a)==len(s)

    a_lift=[]
    s_lift=[]
    for i in range(len(a)):
        a_lift[i]=a[i].lift(BIG_RING) # lift a to the ring with a labrador modulus
        s_lift[i]=s[i].lift(BIG_RING) # lift s to the ring with a labrador modulus
    
    t_lift=t.lift(BIG_RING) # lift t to the ring with a labrador modulus
    v=poly_t(BIG_RING) 
    innp=list_inner_product(a_lift,s_lift)
    v = (innp - t_lift)*invp # a_lift*s_lift + p*v = t_lift in the labrador ring
    v.redc()
    v_dec=neg_decompose(v,maxr,pols_in_r)
    
    if PS is not None:
    # add the lifted equation to the proof system PS     
        assert witnum_r is not None and witnum_s is not None
        if pGvec == None:
            Gvec = makeGvec(BIG_RING,maxr,pols_in_r)
            pGvec=p*Gvec
        PS.append_witness(v_dec)     
        PS.append_statement(a+[pGvec],witnum_s+[witnum_r],t) # the equation a*s+pG*v_dec = t

    else:
    # do not add to the proof system, and just output the lifter versions of the equation
        return a_lift,v_dec,  

def lift_equation_PS(PS:proof_statement,BIG_RING:polyring_t,a:list,t:poly_t,s:list,witnum_s:list,witnum_r:int,pols_in_r:int,maxr,p,invp,pGvec=None):
    """"
    
    Args:
        PS(proof_statement): the current proof statement
        BIG_RING(polyring_t): the ring with the labrador modulus that we will work in
        a(list): a list of poly_t and/or polyvec_t in the small ring
        s(list): a list of poly_t and/or polyvec_t in the small ring
        t(poly_t): a poly_t in the small ring satisfying <a,s>=t
        witnum_s(list): the witness numbers of s in PS
        witnum_r(int): the witness number of the r in a*s + p*r = t
        pols_in_r(int): the number of polynomials in the decomposition of r
        maxr(int): the decomposition base of the r vector
    
    """

    assert len(a)==len(s)

    a_lift=[]
    s_lift=[]
    for i in range(len(a)):
        a_lift[i]=a[i].lift(BIG_RING) # lift a to the ring with a labrador modulus
        s_lift[i]=s[i].lift(BIG_RING) # lift s to the ring with a labrador modulus
    
    t_lift=t.lift(BIG_RING) # lift t to the ring with a labrador modulus
    v=poly_t(BIG_RING) 
    innp=list_inner_product(a_lift,s_lift)
    v = (innp - t_lift)*invp # a_lift*s_lift + p*v = t_lift in the labrador ring
    v.redc()
    v_dec=neg_decompose(v,maxr,pols_in_r)
    
    if pGvec == None:
         Gvec = makeGvec(BIG_RING,maxr,pols_in_r)
         pGvec=p*Gvec
    PS.append_witness(v_dec)     
    PS.append_statement(a+[pGvec],witnum_s+[witnum_r],t) # the equation a*s+pG*v_dec = t

