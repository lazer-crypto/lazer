## @package lazer
#  lazer's python interface.

from _lazer_cffi import ffi, lib
#import numpy as np
import math
import copy

# lazer constructor
lib.lazer_init()

MAX_SINGLE=2**63-1
MAX_ADDS=64
MAX_MULS=1

# internal helper functions

#for debugging. makes test_print easier to find and remove later
def test_print(a):
    if type(a) is poly_t or type(a) is polyvec_t or type(a) is polymat_t:
        a.print()
    else:
        print(a)

# For prime p, reduce z mod p and return centered representation
# in [-(p-1)/2,(p-1)/2].
def _redc(z, p):
    z = int(int(z) % int(p))
    if z > (p-1)/2:
        z = z - p
    if z < -(p-1)/2:
        z = z + p
    return z

# extended euclidean algorithm
def _xgcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _xgcd(b % a, a)
        return (g, x - (b // a) * y, y)


# Return inverse of a mod m
def _invmod(a, m):
    assert m % 2 == 1
    g, x, y = _xgcd(a, m)
    assert g == 1
    res = x % m
    if res > (m-1) / 2:
        res -= m
    return res

def int_t_to_int(apoint):
    if type(apoint) is int_t:
        apoint=apoint.ptr
    a=apoint[0]
    out=0
    for i in range(a.nlimbs):
        out+=a.limbs[i]*(2**(64*i))
    if a.neg==1:
        out=-out
    return out

def _int_t_fromptr(apoint):
    res=int_t(0,apoint[0].nlimbs)
    lib.int_set(res.ptr,apoint)
    return res

# doing conversion from int_t to int and then back so that the number of limbs is set correctly
def int_to_poly(a,ring):
    if type(a) is int_t:
        a=int_t_to_int(a.ptr)
    a=a % ring.mod
    res=poly_t(ring,{0:a})
    return res

def urandom_bnd(lo,hi,seed,dom,inc_size=0):
    if type(seed) is int:
        seed_bytes=seed.to_bytes(32,'little')
    elif type(seed) is list: # the seed is an integer in a list. this allows us to pass it by ref and update the seed
        seed_bytes=seed[0].to_bytes(32,'little')
        seed[0]+=inc_size
    elif type(seed) is bytes:
        seed_bytes=seed
    assert(lo<=hi)
    limbs=_needlimbs(max(abs(lo),abs(hi)))
    res_t=int_t(0,limbs)
    lo_t=int_t(lo,limbs)
    hi_t=int_t(hi,limbs)
    lib.int_urandom_bnd(res_t.ptr,lo_t.ptr,hi_t.ptr,seed_bytes,dom)
    return int_t_to_int(res_t)

def inc_seed(seed,inc):
    if type(seed) is bytes:
        seed=int.from_bytes(seed,'little')
    seed+=inc
    return seed

#zeroes out positions b[l[i]*offset:l[i]*offset+offset]
def zero_out_bytes(b:bytes, l:list, offset:int):
    res=bytearray(b)
    for i in l:
        res[i*offset:i*offset+offset]=bytearray(offset)
    return bytes(res)

def flatten(L):
    return [item for row in L for item in row]

# Return minimum modulus P to lift to from a smaller modulus
# q such that sum of nadds products of two polynomials in Rq
# does not wrap.
def _min_P(d, q, nadds):
    return ((q - 1) ** 2) * d * nadds + 1

def _needlimbs(val):
    nbits = abs(val).bit_length()
    return (nbits + 63) // 64

def _handle_seed(seed,seed_inc):
    if type(seed) is list:
        seed_bytes=seed[0].to_bytes(32,'little')
        seed[0]+=seed_inc
    elif type(seed) is int:
        seed_bytes=seed.to_bytes(32,'little')
    else:
        seed_bytes=seed
    return seed_bytes

def _center_list(L:list,p):
    for i in range(len(L)):
        L[i]=L[i]%p # positive representative
        if L[i]>(p-1)//2:
            L[i]=L[i]-p
    return L

#computes the l2 squared norm of a list
def _l2sq_list(L,centered=False,p=0):
    res=0
    if centered==True:
        L=_center_list(L,p)
    for i in range(len(L)):
        res=res+L[i]**2
    return res


# the int_t class which is the foundational class of the library. its functions are called by
# other classes, but it should never be called by the end-user. one could mess up the number of limbs
# which would give rise to segmentation faults
class int_t:
    def __init__(self, val, nlimbs=0):
        self.ptr = ffi.new("int_t")
        if type(val) is int:
            if nlimbs == 0:
                nlimbs = _needlimbs(val)
            else:
                assert nlimbs >= 0
                assert abs(val) < 2**(64*nlimbs) - 1

            lib.int_alloc(self.ptr, nlimbs)
            self._set(val)
        else: # val is a pointer to the C int_t
            lib.int_alloc(self.ptr,val[0].nlimbs)
            lib.int_set(self.ptr,val)
        self._locked = True

    def _set(self, a):
        assert abs(a) <= 2**(64*self.ptr[0].nlimbs) - 1

        if a < 0:
            a = -a
            self.ptr[0].neg = 1
        else:
            self.ptr[0].neg = 0

        for i in range(self.ptr[0].nlimbs):
            self.ptr[0].limbs[i] = a & 0xffffffffffffffff
            a >>= 64

        return self

    def copy(self):
        return int_t(self.ptr)

    def __del__(self):
        lib.int_free(self.ptr)

    def __str__(self):
        chars_max = 21 * self.ptr[0].nlimbs  # XXX
        buf = ffi.new(f"char[{chars_max}]")
        fh = lib.fmemopen(buf, ffi.sizeof(buf), b'w')
        lib.int_out_str(fh, 10, self.ptr)
        lib.fclose(fh)
        return ffi.string(buf).decode()

    def __eq__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        return lib.int_eq(self.ptr, a.ptr)

    def __lt__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        return lib.int_lt(self.ptr, a.ptr)

    def __le__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        return lib.int_le(self.ptr, a.ptr)

    def __gt__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        return lib.int_gt(self.ptr, a.ptr)

    def __ge__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        return lib.int_ge(self.ptr, a.ptr)

    def __neg__(self):
        res = int_t(0, self.ptr[0].nlimbs)
        for i in range(self.ptr[0].nlimbs):
            res.ptr[0].limbs[i] = self.ptr[0].limbs[i]
        res.ptr[0].neg = self.ptr[0].neg ^ 1
        return res

    def __add__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        res = int_t(0, self.ptr[0].nlimbs)
        lib.int_add(res.ptr, self.ptr, a.ptr)
        return res

    def __iadd__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        lib.int_add(self.ptr, self.ptr, a.ptr)
        return self

    def __sub__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        res = int_t(0, self.ptr[0].nlimbs)
        lib.int_sub(res.ptr, self.ptr, a.ptr)
        return res

    def __isub__(self, a):
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        lib.int_sub(self.ptr, self.ptr, a.ptr)
        return self

    def __mul__(self, a):
        if type(a) is poly_t:
            return a*self
        if type(a) is int:
            a=int_t(a,self.ptr[0].nlimbs)
        assert self.ptr[0].nlimbs == a.ptr[0].nlimbs

        res = int_t(0, 2 * self.ptr[0].nlimbs)
        lib.int_mul(res.ptr, self.ptr, a.ptr)
        return res

    __rmul__ = __mul__

    def print(self):
        lib.int_dump(self.ptr)

class polyring_t:
    # XXX implement deg 128 the same way
    #moduli64 = [8386817, 8386177, 8385281, 8384641, 8383489, 8382977, 8382593, 8380417, 8378369, 8377729, 8377601,
    #            8375041, 8374657, 8374529, 8373377, 8372737, 8370433, 8370049, 8369281, 8367361, 8366977, 8365057, 8364929]
    moduli64 =  [1125899906840833, 1125899906839937, 1125899906837633, 1125899906826241, 1125899906824961, 1125899906822657, 1125899906820097,1125899906819201, 1125899906817793,1125899906815361,1125899906814209]
    # moduli128 = []

    """
    The polynomial ring Z_mod[X]/(X^deg + 1)

    Attributes:
        mod (int): the modulus of the ring
        deg (int): the degree of the ring
    """

    def __init__(self, d, q: int):
        assert q > 2
        assert d>=64 # our multiplications only support degree > =64.  maybe change later
        if d == 64:
            moduliptr = lib.moduli_d64
            moduli = self.moduli64
            log2d = 6
        #elif d == 128:
        #    moduliptr = lib.moduli_d128
        #    moduli = self.moduli128
        #    log2d = 7

        self.mod = q
        self.mod_nlimbs = (q.bit_length() + 63) // 64
        self.deg = d

        # if d == 64 or d == 128:
        if d == 64:
            min_P = _min_P(d, q, 128)
            nmoduli = 1
            P = moduli[0]
            while P < min_P:
                P *= moduli[nmoduli]
                nmoduli += 1
        else:
            log2d = 0
            moduliptr = ffi.new("modulus_ptr *") # shouldn't be used, but needs to be some correct structure
            nmoduli = 0

        coeffbits = (q-1).bit_length()
        self.inv2_ = int_t(_invmod(2, q))
        self.mod_ = int_t(q)

        #if d == 64:
        #    self.Pmodq = int_t(_redc(P % q, q))
        #    self.Ppmodqlist = []
        #    self.Ppmodq = ffi.new(f"int_srcptr[{nmoduli}]")
        #    for i in range(nmoduli):
        #        self.Ppmodqlist += [int_t(_redc(P/moduli[i] % q, q))]
        #        self.Ppmodq[i] = self.Ppmodqlist[i].ptr
        #else:
        self.Pmodq = int_t(0)
        self.Ppmodq = ffi.NULL

        self.ptr = ffi.new("polyring_t",
                           [[self.mod_.ptr, d, coeffbits, log2d, moduliptr, nmoduli, self.Pmodq.ptr, self.Ppmodq, self.inv2_.ptr]])
        self.val = self.ptr[0]
        self._locked = True

    def __eq__(self,a):
        if a==None:
            return 0
        return self.deg == a.deg and self.mod == a.mod

## Polynomials over a ring.
class poly_t:
    """This is the basic class that hold polynomials over a specified ring.

    Attributes:
        ptr (ffi.new("poly_t")): a pointer to the C structure describing the polynomial.
            should not be modified by the user
        ring (polyring_t): the polynomial ring that the polynomial is in
    """
    def __init__(self, ring: polyring_t, coeffs=None):
        """Initializer function

        Args:
            ring (polyring_t): The polynomial ring that poly_t is in
            coeffs (multiple possibilities): The optional coefficients parameter. Not providing one, sets the polynomial to 0.
                There are several types that coeffs can take.
                list - the coefficeints of the polynomial are set to the list in ascending order
                dict - the coefficients of the polynomial are set to the specified dictionary coefficients
                (might be useful for setting parse polynomials)
                poly_t - copies the input polynomial into a new polynomial
                bytes - takes a bytes array and converts each byte to 8 0/1 coefficients and appends them to the polynomial.
                (thus the degree of the polynomial should be 8*len)
        """
        self.ptr = ffi.new("poly_t")
        self.ring = ring
        lib.poly_alloc(self.ptr, ring.ptr)
        self._locked = True
        self.muls=0
        self.adds=0

        if coeffs == None:
            self.set_coeffs([0] * self.ring.deg)
        elif isinstance(coeffs, (dict)):
            self.set_coeffs([0] * self.ring.deg)
            self.set_coeffs(coeffs)
        elif isinstance(coeffs, (list)):
            self.set_coeffs(coeffs)
        elif isinstance(coeffs, poly_t):
            lib.poly_set(self.ptr,coeffs.ptr)
        elif isinstance(coeffs, bytes):
            assert len(coeffs) * 8 == self.ring.deg
            bincoeffs = [int.from_bytes(coeffs, "big") >> i & 1 for i in range(len(coeffs) * 8 - 1, -1, -1)]
            self.set_coeffs(bincoeffs)
        else:   # XXX get a pointer passed in
            lib.poly_set(self.ptr,coeffs)

    def __del__(self):
        """Destructor. Calls the C destructor to release memory from the ptr attribute
        """
        lib.poly_free(self.ptr)


    def copy(self):
        """Returns a copy of the polynomial
        """
        return poly_t(self.ring,self.ptr)

    def copy_zero(self):
        """Returns a 0 polynomial in the same ring
        """
        return poly_t(self.ring)

    ## Set the coefficients of a polynomial'
    # @param coeffs list or dict of coefficients.
    def set_coeffs(self, coeffs, pos=None):
        """Sets the coefficients of the polynomial

        Args:
            coeffs (list or dict or int): If list or dict, sets the polynomial coefficients accordingly.
                if int, then sets the coefficient pos to this integer
            pos (int, optional): If coeffs is an int, then pos corresponds to the position that should be set
        """
        assert isinstance(coeffs, (list, dict))

        if isinstance(coeffs, (dict)):
            for i in coeffs:
                coeff = int_t(coeffs[i], self.ring.mod_nlimbs)
                lib.poly_set_coeff(self.ptr, i, coeff.ptr)

        if isinstance(coeffs, (list)):
            assert len(coeffs) == self.ring.deg
            # if the vector is single precision (< 63 bits), then use pointers to set
            if max([abs(ele) for ele in coeffs])<MAX_SINGLE:
                pnc=ffi.new("int64_t[]",self.ring.deg)
                for i in range(self.ring.deg):
                    pnc[i]=coeffs[i]
                lib.poly_set_coeffvec_i64(self.ptr,pnc)
            else: # otherwise, be inefficient and set coefficients one at a time
                for i in range(self.ring.deg):
                    coeff = int_t(coeffs[i], self.ring.mod_nlimbs)
                    lib.poly_set_coeff(self.ptr, i, coeff.ptr)

        if type(coeffs) is int:
            assert pos != None
            coeff=int_t(coeffs, self.ring.mod_nlimbs)
            lib.poly_set_coeff(self.ptr, i, coeff.ptr)

    def get_coeff(self,pos):
        """Returns the coefficient at a given position

        Args:
            pos (int): The position of the coefficient

        Returns:
            int: the integer in position pos

        """
        res=lib.poly_get_coeff(self.ptr,pos)
        return int_t_to_int(res)

    def component_mul(self,a):
        """Component-wise coefficient multiplication of self with a
        
        Args:
            a (poly_t): the other multiplicand

        """
        assert self.linf()<MAX_SINGLE and a.linf()<MAX_SINGLE
        sar=self.make_i64array()
        aar=a.make_i64array()
        res=poly_t(self.ring)
        resar=res.make_i64array()
        for i in range(self.ring.deg):
            resar[i]=sar[i]*aar[i]
        res.set_i64array(resar)
        return res

    def mod_int(self,m:int,retrem=False):
        """ Returns centered self modulo an integer

        Args:
            m (int): should be  < 2**64.  

        """
        self.redc()
        assert self.linf()<MAX_SINGLE
        sar=self.make_i64array()
        res=poly_t(self.ring)
        resar=res.make_i64array()
        for i in range(self.ring.deg):
            resar[i]=sar[i] % m
        res.set_i64array(resar)
        if retrem:
            minv=_invmod(m,self.ring.mod)
            rem=minv*(self-res)
            return res,rem
        else:
            return res

    def to_list(self):
        """Returns a list of the coefficients of the polynomial

        Returns:
            list: the coefficients of the polynomial
        """
        if self.linf()<MAX_SINGLE: # each of the coefficients fits in 1 limb
            pnl=ffi.new("int64_t []",self.ring.deg)
            lib.poly_get_coeffvec_i64(pnl, self.ptr)
            l=[]
            for i in range(self.ring.deg):
                l.append(pnl[i])
            return l
        else: # be inefficient and use .get_coeff
            l=[]
            for i in range(self.ring.deg):
                l.append(self.get_coeff(i))
            return l

    def __str__(self):
        chars_max = 2 + (2 + (20 * self.ring.mod_nlimbs)) * self.ring.deg
        buf = ffi.new(f"char[{chars_max}]")
        fh = lib.fmemopen(buf, ffi.sizeof(buf), b'w')
        lib.poly_out_str(fh, 10, self.ptr)
        lib.fclose(fh)
        return ffi.string(buf).decode()

    def __eq__(self, a):
        """Overloads the == operator
        """
        if a==None:
            return 0
        return lib.poly_eq(self.ptr, a.ptr)

    def __neg__(self):
        """Returns the negated value of the polynomial. For poly_t p, can write -p"""
        res = poly_t(self.ring)
        lib.poly_set(res.ptr, self.ptr)
        lib.poly_neg_self(res.ptr)
        return res

    def __add__(self, a):
        """Overloads +.

        Args:
            a (poly_t,polyvec_t,polymat_t,int): if a is poly_t, adds the two polynomials.
                if a is polyvec_t, it checks that the dimension of a is 1 and adds
                if a is polymat_t, it checks that the dimension is 1x1 and adds
                if a is int, it converts a to a polynomial and adds

        Returns:
            poly_t,polyvec_t,polymat_t: the sum of the polynomials. if a is a vector or matrix, it returns a vector or a matrix

        """
        if type(a) is polyvec_t and a.dim==1:
            v=polyvec_t(self.ring,1)
            v.set_elem(self,0)
            return v+a
            # TODO: Eventually allow addition of poly_t and a vector whose dimension*deg is the deg of poly_t
            # this addition should compute the automorphism of the poly_t into a polyvec_t and do addition
        if type(a) is polymat_t and a.rows==1 and a.cols==1:
            m=polymat_t(self.ring,1,1)
            m.set_elem(self,0,0)
            return m+a
        if type(a) is int:
            a=int_to_poly(a,self.ring)
        res = poly_t(self.ring)
        
        if self.adds >= MAX_ADDS:
            self.redc()
        if a.adds>= MAX_ADDS:
            a.redc()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.poly_add(res.ptr, self.ptr, a.ptr, 0)
        res.adds+=1
        return res

    def __radd__(self,a):
        """Overloads addition on the right side, so one can write int+poly_t

        Args:
            a: int

        Returns:
            poly_t,polyvec_t,polymat_t: self+a, where a is converted to a polynomial

        """
        assert type(a) is int
        return self+a

    def __iadd__(self, a):
        """Overloads the += operator

        Args:
            a (poly_t): the polynomial being added

        Returns:
            self+a

        """
        if self.adds >= MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        lib.poly_add(self.ptr, self.ptr, a.ptr, 0)
        self.adds+=1
        return self

    def __sub__(self, a):
        """Overloads subtraction

        Args:
            a (poly_t,polyvec_t,polymat_t,int): returns self + (-a) -- look ad the __add__ function

        Returns:
            poly_t,polyvec_t,polymat_t: self-a (if a is polyvec_t or polymat_t, it returns that type)

        """
        if type(a) is polyvec_t or type(a) is polymat_t:
            return self+(-a)
        if type(a) is int:
            a=int_to_poly(a,self.ring)
        res = poly_t(self.ring)
        
        if self.adds >= MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.poly_sub(res.ptr, self.ptr, a.ptr, 0)
        res.adds+=1
        return res

    def __rsub__(self,a):
        """Overloads subtraction on the right side just to allow int-self

        Args:
            int: a

        Returns:
            a-self, where a is first converted to a poly_t

        """
        assert type(a) is int
        a=int_to_poly(a,self.ring)
        return a-self

    def __isub__(self, a):
        """Overloads -= operator

        Args:
            a (poly_t): the element being subtracted

        Returns:
            self-a
        """
        if self.adds >= MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        lib.poly_sub(self.ptr, self.ptr, a.ptr, 0)
        self.adds+=1
        return self

    def __mul__(self, a):
        """Overloads * multiplication

        Args:
            a (poly_t,int): multiplicand

        Returns:
            poly_t: self*a

        """
        
        if type(a) is int_t or type(a) is int:
            res = poly_t(self.ring)
            
            a=int_to_poly(a,self.ring)
            if self.ring.deg !=64:
                return self*a
            if self.muls>=MAX_MULS:
                self.redc()
            res.adds=self.adds
            res.muls=self.muls
            lib.poly_mul(res.ptr, self.ptr, a.ptr)
        elif type(a) is poly_t:
            if self.ring.deg != 64:
                # TODO: need to change this once we have native multiplication in C over arbitrary rings
                # right now it's pretty hackish
                assert self.ring.deg==a.ring.deg and self.ring.mod==a.ring.mod
                selfmat=polymat_t(self.ring,1,1)
                avec=polyvec_t(self.ring,1)
                avec.set_elem(a,0)
                selfmat.set_elem(self,0,0)
                return (selfmat*avec).get_elem(0)
            else:
                res = poly_t(self.ring)
                if self.muls>=MAX_MULS:
                    self.redc()
                if a.muls>=MAX_MULS:
                    a.redc()
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                lib.poly_mul(res.ptr, self.ptr, a.ptr)
        else: # try right multiplication
            return a*self
        
        res.muls+=1
        return res

    def __rmul__(self,a):
        """Overloads multiplication on the right side allowing int*poly_t
        """
        assert type(a) is int
        return self*a
    
    def __imul__(self,a):
        return self*a

    def __getitem__(self,pos):
        return self.get_coeff(pos)
    
    def __setitem__(self,pos,x):
        self.set_coeffs(x,pos)

    # centralize in [-self.ring.mod/2,self.ring.mod/2]
    def redc(self,a=None):
        """Centralizes the polynomial (either self or a) to the range [-mod/2,mod/2] and stores in self

        Args:
            a (poly_t,optional): if a is passed, then it stores the centralization of a into self. otherwise,
                it centralizes self
        """
        if a==None:
            lib.poly_redc(self.ptr,self.ptr)
        else:
            lib.poly_redc(self.ptr, a.ptr)
        self.muls=0
        self.adds=0

    def redp(self,a=None):
        if a==None:
            lib.poly_redp(self.ptr,self.ptr)
        else:
            lib.poly_redp(self.ptr, a.ptr)
        self.muls=0
        self.adds=0

    #infinity norm
    def linf(self):
        """Returns the infinity norm of self
        """
        res=int_t(0,self.ring.mod_nlimbs)
        lib.poly_linf(res.ptr,self.ptr)
        return int_t_to_int(res.ptr)

    # l2 norm
    def l2sq(self):
        """Returns the l2-squared norm of self
        """
        n=0

        if self.linf()<MAX_SINGLE: # each of the coefficients fits in 1 limb
            pnl=ffi.new("int64_t []",self.ring.deg)
            lib.poly_get_coeffvec_i64(pnl, self.ptr)
            for i in range(self.ring.deg):
                n+=pnl[i]*pnl[i]
            return n

        for i in range(self.ring.deg):
            temp=self.get_coeff(i)
            n+=temp*temp
        return n

        #XXXres=int_t(0,_needlimbs((self.ring.mod**2)*self.ring.deg))
        res=int_t(0,2*_needlimbs(self.ring.mod**2)) # XXX fix in C
        lib.poly_l2sqr(res.ptr,self.ptr)
        return int_t_to_int(res.ptr)

    def is_binary(self):
        """Checks if the polynomial is binary
        """
        self.redc()
        for i in range(self.ring.deg):
            if self.get_coeff(i)%self.ring.mod not in (0,1):
                return False
        return True

    def print(self):
        """Prints the polynomial"""
        lib.poly_dump(self.ptr)

    def urandom(self,mod,seed,dom):
        """Makes the polynomial random
        
        Args:
            mod (int): generates a random integer in [0,mod)
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
        """
        if type(mod) is int:
            log2mod=(mod-1).bit_length()
            mod=int_t(mod)
        elif type(mod) is int_t:
            mod2=int_t_to_int(mod.ptr)
            log2mod=(mod2-1).bit_length()
        lib.poly_urandom (self.ptr, mod.ptr, log2mod,seed,dom)

    def urandom_bnd(self,lo:int,hi:int,seed,dom:int,seed_inc=0):
        """Makes the polynomial random in a range

        Args:
            lo (int): the coefficients are in [lo,hi]
            hi (int): the coefficients are in [lo,hi]
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
        """
        assert lo<hi
        lo=int_t(lo,self.ring.mod_nlimbs)
        hi=int_t(hi,self.ring.mod_nlimbs)
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.poly_urandom_bnd (self.ptr, lo.ptr, hi.ptr,seed_bytes,dom)
        self.redc()

    def grandom(self,log2o,seed,dom,seed_inc=0,l2bound=0):
        """Set the polynomial to a discrete gaussian

        Args:
            log2o (int): the standard deviation is 1.55*2**log2o
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2_bound (int,default=0): leave out this argument, used for testing
        """
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.poly_grandom(self.ptr,log2o,seed_bytes,dom)
        if l2bound > 0:
            while self.l2sq() > l2bound:
                # TODO: change this, otherwise can end up with the same value multiple times.
                # perhaps it's best to always leave this at 0, and let the user decide what he wants to do
                dom+=1
                lib.poly_grandom(self.ptr,log2o,seed_bytes,dom)
        self.redc()

    @staticmethod
    def urandom_static(ring:polyring_t,mod,seed,dom):
        """ Returns a uniformly random variable

        Args:
            ring (polyring_t): the ring in which the returned polynomial is in 
            mod (int): generates a random integer in [0,mod)
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable

        Returns:
            poly_t    
        
        """
        p=poly_t(ring)
        p.urandom(mod,seed,dom)
        p.redc()
        return p

    def make_i64array(self):
        assert self.linf() < MAX_SINGLE
        res=ffi.new("int64_t []",self.ring.deg)
        lib.poly_get_coeffvec_i64(res, self.ptr)
        return res

    def set_i64array(self,ar):
        lib.poly_set_coeffvec_i64(self.ptr,ar)

    @staticmethod
    def urandom_bnd_static(ring:polyring_t,lo:int,hi:int,seed,dom,seed_inc=0):
        """Returns a bounded uniformly random poly_t
        
        Args:
            ring (polyring_t): the ring in which the returned polynomial is in 
            lo (int): the coefficients are in [lo,hi]
            hi (int): the coefficients are in [lo,hi]
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
        
        Returns:
            poly_t
        """
        p=poly_t(ring)
        p.urandom_bnd(lo,hi,seed,dom,seed_inc)
        p.redc()
        return p

    @staticmethod    
    def grandom_static(ring,log2o,seed,dom,seed_inc=0,l2bound=0):
        """Return a discrete gaussian

        Args:
            ring (polyring_t): the ring in which the returned polynomial is in 
            log2o (int): the standard deviation is 1.55*2**log2o
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2_bound (int,default=0): leave out this argument, used for testing
        
        Returns:
            poly_t
        """
        p=poly_t(ring)
        p.grandom(log2o,seed,dom,seed_inc,l2bound)
        p.redc()
        return p

    # switch to a smaller ring, internal function used for multiplication of >64 degree rings
    def to_isoring(self,target_ring:polyring_t):
        assert self.ring.mod==target_ring.mod
        assert self.ring.deg % target_ring.deg == 0
        target_dim=self.ring.deg//target_ring.deg
        res=polyvec_t(target_ring,target_dim)
        res.adds=self.adds
        res.muls=self.muls
        lib.poly_toisoring(res.ptr,self.ptr)
        return res

    # lift to a ring with larger modulus
    def lift(self,ring_new: polyring_t):
        """Copies the centralized coefficients into a ring of the same dimension with larger modulus

        Args:
            ring_new (polyring_t): the new ring with a larger modulus

        Returns:
            poly_t: a polynomial in a larger modulus ring
        """
        assert self.ring.deg==ring_new.deg and self.ring.mod <= ring_new.mod 
        self.redc(self)
        if self.linf()<MAX_SINGLE: # each of the coefficients fits in 1 limb
            pnl=ffi.new("int64_t []",self.ring.deg)
            lib.poly_get_coeffvec_i64(pnl, self.ptr)
            pol_new=poly_t(ring_new)
            lib.poly_set_coeffvec_i64 (pol_new.ptr, pnl)
            return pol_new
        # otherwise do it inefficiently
        old_coeff=self.to_list()
        pol_new=poly_t(ring_new,old_coeff)
        return pol_new

    @staticmethod
    def arb_mul(small_ring: polyring_t, pola, polb, in_isoring=False):
        assert pola.ring.deg==polb.ring.deg and pola.ring.mod==polb.ring.mod
        Xpol=poly_t(small_ring,{1:1})
        if in_isoring:
            veca=pola.copy()
            vecb=polb.copy()
            vec_length=veca.dim
            big_ring=polyring_t(veca.dim*veca.ring.deg,pola.ring.mod)
        else:
            veca=pola.to_isoring(small_ring)
            vecb=polb.to_isoring(small_ring)
            vec_length=pola.ring.deg // small_ring.deg
        vecout_small=polyvec_t(small_ring,vec_length)
        temp=poly_t(small_ring)
        temp2=poly_t(small_ring)
        for i in range(vec_length-1,-1,-1):
            lib.poly_mul(temp.ptr,lib.polyvec_get_elem(vecb.ptr,0),lib.polyvec_get_elem(veca.ptr,i))
            for j in range(1,vec_length):
                lib.poly_mul(temp2.ptr,lib.polyvec_get_elem(vecb.ptr,j),lib.polyvec_get_elem(veca.ptr,(i-j)%vec_length))
                lib.poly_add(temp.ptr,temp.ptr,temp2.ptr,1)
            vecout_small.set_elem(temp,i)
            temp=veca.get_elem(i)
            temp=temp*Xpol
            veca.set_elem(temp,i)
        if in_isoring:
            polres=vecout_small.from_isoring_topol(big_ring)
        else:
            polres=vecout_small.from_isoring_topol(pola.ring)
        return polres



class polyvec_t:
    """Class for vectors of poly_t over a specified ring.

    Attributes:
        ptr (ffi.new("polyvec_t")): a pointer to the C structure describing the polynomial vector.
            should not be modified by the user.
        ring (polyring_t): the polynomial ring that the polynomial is in
        dim (int): the size of the vector
    """
    def __init__(self,ring: polyring_t,dim,val=None,tmp=False):
        """ Initializaion

        Args:
            ring (polyring_t): the ring of the polynomial vector
            dim (int): the dimension of the vector
            val (list,bytes,polyvec_t,optional): if val is not provided, creates a 0 polynomial
                There are several types that val can take.
                list - goes through the list and sets the next element to be the next poly_t in the list
                (or the next poly_t in the polyvec_t vector).  the list can be a mix of poly_t and polyvec_t objects
                bytes - converts the bytes array to binary, and places the result in the polyvec_t. for this, we need to make sure that
                8*len(bytes array) is <= dim*ring.deg
                polyvec_t - copies the polyvec_t into a new one
        """
        self.ptr = ffi.new("polyvec_t")

#XXX        if tmp == False:
        lib.polyvec_alloc(self.ptr,ring.ptr,dim)
        self.tmp = tmp

        self.dim=dim
        self.ring=ring
        self.muls=0
        self.adds=0
        if val == None: # create a new polyvec_t
            lib.polyvec_set_zero (self.ptr)
        elif type(val) == bytes:
            lib.polyvec_set_zero (self.ptr)
            offset=ring.deg//8
            for i in range(0,len(val),offset):
                vv=poly_t(ring,val[i:i+offset])
                self.set_elem(vv,i//offset)
        elif type(val) == list:
            cur_pos=0

            if all(type(v) == int for v in val):
                assert len(val)%self.ring.deg==0
                for j in range(len(val)//self.ring.deg):
                    vv=poly_t(self.ring,val[j*self.ring.deg:j*self.ring.deg+self.ring.deg])
                    lib.polyvec_set_elem(self.ptr,cur_pos,vv.ptr)
                    cur_pos+=1
            else:            
                #assert len(val) == dim
                for v in val:
                    if type(v) is poly_t:
                        lib.polyvec_set_elem(self.ptr,cur_pos,v.ptr)
                        cur_pos+=1
                    elif type(v) is polyvec_t:
                        for i in range(v.dim):
                            vv=v.get_elem(i)
                            lib.polyvec_set_elem(self.ptr,cur_pos,vv.ptr)
                            cur_pos+=1
            
            assert cur_pos == dim

            # for i in range(dim):
            #     lib.polyvec_set_elem(self.ptr,i,val[i].ptr)
        elif type(val) == polyvec_t:
            lib.polyvec_set(self.ptr,val.ptr)
        else: # XXX
            lib.polyvec_set(self.ptr,val)

    def __del__(self):
        """Automatic destructor. Calls the C destructor to release memory from the ptr attribute
        """
        if self.tmp == False:
            lib.polyvec_free(self.ptr)

    # lift to a ring with larger modulus
    def lift(self,ring_new: polyring_t):
        """Copies the centralized coefficients into a ring of the same dimension with larger modulus

        Args:
            ring_new (polyring_t): the new ring with a larger modulus

        Returns:
            polyvec_t: a vector of polynomials in a larger modulus ring
        """
        assert self.ring.deg==ring_new.deg and self.ring.mod <= ring_new.mod
        self.redc(self)
        if self.linf()<MAX_SINGLE: # each of the coefficients fits in 1 limb
            pnl=ffi.new("int64_t []",self.ring.deg * self.dim)
            lib.polyvec_get_coeffvec_i64(pnl, self.ptr)
            polvec_new=polyvec_t(ring_new,self.dim)
            lib.polyvec_set_coeffvec_i64 (polvec_new.ptr, pnl)
            return polvec_new
        # otherwise do it inefficiently
        old_coeff=self.to_list()
        polvec_new=polyvec_t(ring_new,self.dim,old_coeff)
        return polvec_new

    def copy(self):
        """Returns a copy of the polynomial vector
        """
        return polyvec_t(self.ring,self.dim,self.ptr)

    def copy_zero(self):
        """Returns a 0 polyvec_t in the same ring and in the same dimension
        """
        return polyvec_t(self.ring,self.dim)

    def set_elem(self,val,row,pos=None):
        """Sets a position (either of the polynomial or a polynomial coefficient)
        
        Args:
            val (poly_t,int): the value that we will be setting
            row (int): the poly_t position in the vector to be set
            pos (int,optional): if it's an int, then val must also be an int. sets the pos coefficient of 
                the polynomial in position row of the vector to val. if it's None, then val must be a polynomial.
        """
        if pos==None: # setting position row to pol_t val 
            lib.polyvec_set_elem(self.ptr,row,val.ptr)
            if val.muls > self.muls:
                self.muls=val.muls
            if val.adds > self.adds:
                self.adds=val.adds
        else: #pos is an integer. setting position row,pos to an int or int_t val 
            if type(val) is int:
                val=int_t(val,self.ring.mod_nlimbs)
            polptr=lib.polyvec_get_elem (self.ptr,row)
            lib.poly_set_coeff(polptr,pos,val.ptr)


    def get_elem(self,row,pos=None):
        """Returns the coefficient or a poly_t at a given position

        Args:
            row (int): the polynomial position which we will be retrieving
            pos: (int, optional): if it's an int, then we will return the integer coefficient of the poly_t
                at position row, coefficient pos.  If it's not provided, then we return the polynomial at position row

        Returns:
            (poly_t or int): if pos is set, then we return an int coefficeint. otherwise a poly_t
        """
        if pos==None: # getting a pol_t from column col
            polptr=lib.polyvec_get_elem(self.ptr,row)
            pol=poly_t(self.ring,polptr)
            pol.muls=self.muls
            pol.adds=self.adds
            return pol
        else: #pos is an integer, and we're getting an integer from column col, position pos
            polptr=lib.polyvec_get_elem (self.ptr,row)
            intptr=lib.poly_get_coeff(polptr,pos)
            return int_t_to_int(intptr)

    def __getitem__(self,pos):
        if type(pos) is int:
            return self.get_elem(pos)
        if type(pos) is tuple:
            return self.get_elem(pos[0],pos[1])
    
    def __setitem__(self,pos,x):
        if type(pos) is int:
            assert type(x) is poly_t
            self.set_elem(x,pos)
        if type(pos) is tuple:
            assert type(x) is int
            self.set_elem(x,pos[0],pos[1])


    # make a list of polynomials
    def to_pol_list(self):
        """Returns the polynomials in the polyvec_t as a list
        
        Returns:
            list: polynomials self
        """
        result=[]
        for i in range(self.dim):
            result.append(self.get_elem(i))
        return result

    def get_pol_list(self,pol_list):
        """Extracts positions from self specified by pol_list
        
        Args:
            pol_list (set,list): the positions from self that are to be extracted
        
        Returns:
            polyvec_t: a new vector with the elements of self specified by pol_list

        """
        if type(pol_list) is set:
            pol_list=list(pol_list)
        res=polyvec_t(self.ring,len(pol_list))
        for i in range(len(pol_list)):
            res.set_elem(self.get_elem(pol_list[i]),i)
        return res

    def zero_out_pols(self,pol_list):
        """Zeroes out positions from self specified by pol_list
        
        Args:
            pol_list (set,list): the positions from self that are to be zeroed out
        
        Returns:
            polyvec_t: a new polynomial of the same dimension as self with some elements zeroed out

        """
        zeropol=poly_t(self.ring)
        res=polyvec_t(self.ring,self.dim,self)
        if type(pol_list) is set:
            pol_list=list(pol_list)
        for i in pol_list:
            res.set_elem(zeropol,i)
        return res

    def redc(self,a=None):
        """Centralizes the polynomial vector (either self or a) to the range [-mod/2,mod/2] and stores in self

        Args:
            a (polyvec_t,optional): if a is passed, then it stores the centralization of a into self. otherwise,
                it centralizes self
        """
        if a==None:
            lib.polyvec_redc(self.ptr,self.ptr)
        else:
            lib.polyvec_redc(self.ptr, a.ptr)
        self.muls=0
        self.adds=0

    def redp(self,a):
        lib.polyvec_redp(self.ptr, a.ptr)

    def __eq__(self, a):
        """Overloads the == operator
        """
        if a==None:
            return 0
        assert type(a) is polyvec_t and a.dim==self.dim
        return lib.polyvec_eq(self.ptr,a.ptr)

    def __neg__(self):
        """Returns the negated value of the vector. For polyvec_t p, can write -p"""
        res=polyvec_t(self.ring,self.dim,self.ptr)
        lib.polyvec_neg_self(res.ptr)
        return res

    def __add__(self, a):
        """Overloads the + operator
        
        Args:
            a (poly_t,polyvec_t,polymat_t,falcon_pol): a can have various types.
                poly_t - if self.dim=1, then it performs polynomial addition
                polymat_t - if the matrix has 1 row/column of the correct dimension, it adds the vector to the row/column.
                polyvec_t - adds two vectors  
        
        Returns:
            polyvec_t,polymat_t : if a is polymat_t, returns a polymat_t type, otherwise polyvec_t
                
        """
        if type(a) is poly_t and self.dim==1:
            return a+self
        if type(a) is polymat_t:
            if a.rows==1 and a.cols==self.dim:
                m=polymat_t(self.ring,1,self.dim)
                m.set_row(0,self)
                return m+self
            if a.cols==1 and a.rows==self.dim:
                m=polymat_t(self.ring,1,self.dim)
                m.set_col(0,self)
                return m+self
        if type(a) is falcon_pol:
            return (a+self)
        elif type(a) is polyvec_t and self.ring.deg != a.ring.deg:
            # Don't think that this is used anywhere
            if a.ring.deg % self.ring.deg == 0:
                anew=a.to_isoring(self.ring)
                return anew+self
            if self.ring.deg % a.ring.deg == 0:
                return a+self
        assert self.dim == a.dim
        res=polyvec_t(self.ring,self.dim)
        if self.adds>=MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.polyvec_add(res.ptr,self.ptr,a.ptr,0)
        res.adds+=1
        return res

    def __sub__(self,a):
        """Overloads the - operator. Outputs self + (-a)
        """
        if type(a) is poly_t or type(a) is polymat_t:
            return self+(-a)
        if type(a) is falcon_pol:
            return (-a)+self
        elif type(a) is polyvec_t and self.ring.deg != a.ring.deg:
            return -a+self
        assert self.dim == a.dim
        res=self.copy_zero()
        if self.adds>=MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.polyvec_sub(res.ptr,self.ptr,a.ptr,0)
        res.adds+=1
        return res

    def __mul__(self,a):
        """Multiplication, or inner product
        
        Args:
            a (int,poly_t,polyvec_t,polymat_t): if a is an int or poly_t, performs scalar multiplication
                if a is a polyvec_t, performs inner product. if a is polymat_t, performs, matrix-vector multiplication
        
        Returns:
            polyvec_t,poly_t : poly_t when a is a polyvec_t, and polyvec_t otherwise
        
        """
        if self.muls>=MAX_MULS:
            self.redc()
        if (type(a) is poly_t or type(a) is polyvec_t or type(a) is polymat_t) and a.muls>=MAX_MULS:
            a.redc() 
        if type(a) is int or type(a) is int_t:
            res=self.copy_zero()
            a=int_to_poly(a,self.ring)
            if self.ring.deg!=64:
                return self*a
            lib.polyvec_scale2(res.ptr,a.ptr,self.ptr)
        elif type(a) is poly_t:
            if a.muls>=MAX_MULS:
                a.redc()
            if self.ring.deg != 64:
                res=self.copy_zero()
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                for i in range(res.dim):
                    res.set_elem(a*self.get_elem(i),i)
            else:
                res=self.copy_zero()
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                lib.polyvec_scale2(res.ptr,a.ptr,self.ptr)
        elif type(a) is polyvec_t: # do inner product
            
            if self.ring.deg != 64:
                assert self.ring.deg==a.ring.deg and self.ring.mod==a.ring.mod
                assert self.dim==a.dim
                selfmat=polymat_t(self.ring,1,self.dim)
                selfmat.set_row(0,self)
                return (selfmat*a).get_elem(0)
            else:
                assert a.dim == self.dim
                res=poly_t(self.ring)
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                lib.polyvec_dot(res.ptr,a.ptr,self.ptr)
        elif type(a) is polymat_t:
            if self.ring.deg != 64:
                #replace when we have arbitrary-degree polynomial multiplication
                assert self.ring.deg==a.ring.deg and self.ring.mod==a.ring.mod
                assert self.dim==a.rows
                new_ring=polyring_t(64,self.ring.mod)
                defmat,defvec=lin_to_isoring(new_ring,self.ring,a.transpose(),self)
                return (defmat*defvec).from_isoring(self.ring)
            else:
                assert self.dim==a.rows
                res=polyvec_t(self.ring,a.cols)
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                lib.polyvec_mul2(res.ptr,self.ptr,a.ptr)
        
        res.muls+=1
        return res

    def __rmul__(self,a):
        """Multiplication from the right side, allowing for int*polyvec_t"""
        assert type(a) is int or type(a) is int_t
        return self*a
    
    def __imul__(self,a):
        return self*a
    
    def elem_mul(self,a):
        res=polyvec_t(self.ring,self.dim)
        lib.polyvec_elem_mul(res.ptr,self.ptr,a.ptr)
        return res

    def l2sqr(self):
        """Returns the l2-squared norm of self

        Returns:
            int
        """
        sum=0
        for i in range(self.dim):
            sum+=self.get_elem(i).l2sq()
        return sum

    def linf(self):
        """Returns the infinity norm of self

        Returns:
            int
        """
        res=int_t(0,self.ring.mod_nlimbs)
        lib.polyvec_linf(res.ptr,self.ptr)
        return int_t_to_int(res.ptr)

    def is_binary(self):
        """Checks if the vector is binary

        Returns:
            bool
        """
        for i in range(self.dim):
            if self.get_elem(i).is_binary() is False:
                return False
        return True

    def urandom_bnd(self,lo:int, hi:int, seed,dom,seed_inc=0):
        """Makes the polyvec_t random in a range

        Args:
            lo (int): the coefficients are in [lo,hi]
            hi (int): the coefficients are in [lo,hi]
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
        """
        assert lo<hi
        lo=int_t(lo,self.ring.mod_nlimbs)
        hi=int_t(hi,self.ring.mod_nlimbs)
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.polyvec_urandom_bnd (self.ptr, lo.ptr, hi.ptr,seed_bytes,dom)

    @staticmethod
    def urandom_bnd_static(ring,dim,lo:int, hi:int, seed,dom,seed_inc=0):
        """Returns a bounded uniformly random polyvec_t
        
        Args:
            ring (polyring_t): the ring in which the returned polyvec_t is in 
            lo (int): the coefficients are in [lo,hi]
            hi (int): the coefficients are in [lo,hi]
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
        
        Returns:
            polyvec_t
        
        """
        pv=polyvec_t(ring,dim)
        pv.urandom_bnd(lo, hi, seed,dom,seed_inc)
        return pv

    def brandom(self, hi:int, seed,dom,seed_inc=0,l2bound=0):
        """Sets the vector to a binomially-distributed random vector
        
        Args:
            hi (int): the coefficients are a_1+...a_hi-(b_1+...b_hi) where a_i,b_i are Bernoulli 
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2bound (int,optional): default is 0.  if > 0, then keep incrementing dom
                until squared norm is less than l2bound          
        """
        assert 0<hi
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.polyvec_brandom (self.ptr, hi,seed_bytes,dom)
        if l2bound > 0:
            while self.l2sqr() > l2bound:
                dom+=1 #check if this works well with the way dom is used in the polyvec_brandom
                lib.polyvec_brandom(self.ptr,hi,seed_bytes,dom)

    @staticmethod
    def brandom_static(ring,dim, hi:int, seed,dom,seed_inc=0,l2bound=0):
        """Returns a a binomially-distributed random vector
        
        Args:
            ring (polyring_t): the ring in which the vector lies
            dim (int): the dimension of the vector
            hi (int): the coefficients are a_1+...a_hi-(b_1+...b_hi) where a_i,b_i are Bernoulli 
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2bound (int,optional): default is 0.  if > 0, then keep incrementing dom
                until squared norm is less than l2bound. best to leave out this argument

        Returns:
            polyvec_t          
        """
        pv=polyvec_t(ring,dim)
        pv.brandom(hi, seed,dom,seed_inc,l2bound)
        return pv

    def grandom(self,log2o,seed,dom,seed_inc=0,l2bound=0):
        """Set the vector to a discrete gaussian

        Args:
            log2o (int): the standard deviation is 1.55*2**log2o
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2bound (int,optional): default is 0.  if > 0, then keep incrementing dom
                until squared norm is less than l2bound. best to leave out this argument

        """
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.polyvec_grandom(self.ptr,log2o,seed_bytes,dom)
        if l2bound > 0:
            while self.l2sqr() > l2bound:
                dom+=1
                lib.polyvec_grandom(self.ptr,log2o,seed_bytes,dom)

    @staticmethod
    def grandom_static(ring,dim,log2o,seed,dom,seed_inc=0,l2bound=0):
        """Return a discrete gaussian

        Args:
            ring (polyring_t): the ring in which the returned polynomial is in 
            log2o (int): the standard deviation is 1.55*2**log2o
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing
            l2bound (int,optional): default is 0.  if > 0, then keep incrementing dom
                until squared norm is less than l2bound. best to leave out this argument

        Returns:
            polyvec_t
        """
        pv=polyvec_t(ring,dim)
        pv.grandom(log2o,seed,dom,seed_inc,l2bound)
        return pv

    def to_isoring(self,target_ring:polyring_t):
        assert self.ring.deg % target_ring.deg == 0
        target_dim=self.dim*self.ring.deg//target_ring.deg
        res=polyvec_t(target_ring,target_dim)
        res.adds=self.adds
        res.muls=self.muls
        lib.polyvec_toisoring(res.ptr,self.ptr)
        return res

    def from_isoring(self,target_ring:polyring_t):
        assert target_ring.deg % self.ring.deg==0
        target_dim=(self.dim*self.ring.deg)//target_ring.deg
        res=polyvec_t(target_ring,target_dim)
        lib.polyvec_fromisoring(res.ptr,self.ptr)
        res.adds=self.adds
        res.muls=self.muls
        return res
    
    def from_isoring_topol(self,ring: polyring_t):
        assert ring.deg == self.ring.deg*self.dim
        resp=poly_t(ring)
        resp.adds=self.adds
        resp.muls=self.muls
        lib.poly_fromisoring(resp.ptr,self.ptr)
        return resp

    def print(self):
        """Prints the vector"""
        lib.polyvec_dump(self.ptr)

class polymat_t:
    """Class for matrices of poly_t over a specified ring.

    Attributes:
        ptr (ffi.new("polyvec_t")): a pointer to the C structure describing the polynomial vector.
            should not be modified by the user.
        ring (polyring_t): the polynomial ring that the polynomial is in
        rows (int): the number of rows
        cols (int): the number of columns
    """
    def __init__(self,ring:polyring_t,rows:int,cols:int,val=None):
        """ Initialization

        Args:
            ring (polyring_t): the ring of the polynomial matrix
            rows (int): number of rows
            cols (int): number of columns
            val (list,polymat_t,optional): if val is not provided, sets the matrix to 0.
                list - the list can be a mix of poly_t,polyvec_t,polymat_t. the function goes
                through the list and sets the next chunk of the matrix to the list element. the 
                dimension/number of rows of all list elements mut be the same. poly_t can only
                be in the list if self.rows==1.
                polymat_t - copies the polymat_t
        """
        self.ptr = ffi.new("polymat_t")
        lib.polymat_alloc(self.ptr,ring.ptr,rows,cols)
        self.rows=rows
        self.cols=cols
        self.ring=ring
        self.adds=0
        self.muls=0
        if val==None:
            lib.polymat_set_zero(self.ptr)
        elif type(val) == list:
            cur_col=0
            for v in val:
                if type(v) is poly_t:
                    assert self.rows==1
                    assert cur_col<self.cols
                    self.set_elem(v,0,cur_col)
                    cur_col+=1
                elif type(v) is polyvec_t:
                    assert v.dim == self.rows
                    assert cur_col<self.cols
                    self.set_col(cur_col,v)
                    cur_col+=1
                elif type(v) is polymat_t:
                    assert v.rows == self.rows
                    for i in range(v.cols):
                        assert cur_col<self.cols
                        vv=v.get_col(i)
                        self.set_col(cur_col,vv)
                        cur_col+=1
            assert cur_col==self.cols
        elif type(val) == polymat_t:
            lib.polymat_set(self.ptr,val.ptr)

    def __del__(self):
        """Automatic destructor. Calls the C destructor to release memory from the ptr attribute
        """
        lib.polymat_free(self.ptr)

    def copy(self):
        """Returns a copy of the polynomial matrix
        """
        return polymat_t(self.ring,self.rows,self.cols,self.ptr)

    def copy_zero(self):
        """Returns a 0 polymat_t in the same ring and in the same dimension
        """
        return polymat_t(self.ring,self.rows,self.cols)
    
    def redc(self,a=None):
        """Centralizes the polynomial vector (either self or a) to the range [-mod/2,mod/2] and stores in self

        Args:
            a (polyvec_t,optional): if a is passed, then it stores the centralization of a into self. otherwise,
                it centralizes self
        """
        if a==None:
            lib.polymat_redc(self.ptr,self.ptr)
        else:
            lib.polymat_redc(self.ptr, a.ptr)
        self.adds=0
        self.muls=0

    def set_elem(self,val,row,col,pos=None):
        """Sets a position (either of the polynomial or a polynomial coefficient)
        
        Args:
            val (poly_t,int): the value that we will be setting
            row (int): the row in the matrix to be set
            col (int): the column in the matrix to be set
            pos (int,optional): if it's an int, then val must also be an int. sets the pos coefficient of 
                the polynomial in position (row,col) of the matrix to val. if it's None, then val must be a polynomial.
        """
        if pos==None:
            lib.polymat_set_elem(self.ptr,row,col,val.ptr)
            if val.muls > self.muls:
                self.muls=val.muls
            if val.adds > self.adds:
                self.adds=val.adds
        else:
            if type(val) is int:
                val=int_t(val,self.ring.mod_nlimbs)
            polptr=lib.polymat_get_elem (self.ptr,row,col)
            lib.poly_set_coeff(polptr,pos,val.ptr)

    def get_elem(self,row,col,pos=None):
        """Returns the coefficient or a poly_t at a given position

        Args:
            row (int): the row which we will be retrieving
            col (int): the column which we will be retrieing
            pos: (int, optional): if it's an int, then we will return the integer coefficient of the poly_t
                at position (row,col) coefficient pos.  If it's not provided, then we return the polynomial 
                at position (row,col)

        Returns:
            (poly_t or int): if pos is set, then we return an int coefficeint. otherwise a poly_t
        """
        if pos==None:
            polptr=lib.polymat_get_elem(self.ptr,row,col)
            pol=poly_t(self.ring,polptr)
            pol.muls=self.muls
            pol.adds=self.adds
            return pol
        else:
            polptr=lib.polymat_get_elem (self.ptr,row,col)
            intptr=lib.poly_get_coeff(polptr,pos)
            return int_t_to_int(intptr)

    def set_row(self,row,val: polyvec_t):
        """Set the matrix row to a polyvec_t
        
        Args:
            row (int): the row to be set
            val (polyvec_t): the vector to be copied
        
        """
        assert self.cols == val.dim
        lib.polymat_set_row (self.ptr, val.ptr,row)
        if val.muls > self.muls:
            self.muls=val.muls
        if val.adds > self.adds:
            self.adds=val.adds

    def set_col(self,col,val: polyvec_t):
        """Set the matrix column to a polyvec_t
        
        Args:
            col (int): the column to be set
            val (polyvec_t): the vector to be copied
        
        """
        assert self.rows == val.dim
        lib.polymat_set_col (self.ptr, val.ptr,col)
        if val.muls > self.muls:
            self.muls=val.muls
        if val.adds > self.adds:
            self.adds=val.adds

    def get_row(self,row):
        """Return the matrix row as a vector

        Args:
            row (int): the row to be returned

        Returns:
            polyvec_t

        """
        resptr=ffi.new("polyvec_t")
        #res=polyvec_t(self.ring,self.cols)
        lib.polymat_get_row(resptr,self.ptr,row)
        polvec=polyvec_t(self.ring,self.cols,resptr)
        polvec.adds=self.adds
        polvec.muls=self.muls
        return polvec

    def get_col(self,col):
        """Return the matrix column as a vector

        Args:
            col (int): the row to be returned

        Returns:
            polyvec_t

        """
        resptr=ffi.new("polyvec_t")
        #res=polyvec_t(self.ring,self.cols)
        lib.polymat_get_col(resptr,self.ptr,col)
        polvec=polyvec_t(self.ring,self.rows,resptr)
        polvec.adds=self.adds
        polvec.muls=self.muls
        return polvec

    def get_col_list(self,col_list):
        """Extracts columns from self specified by col_list
        
        Args:
            col_list (set,list): the positions from self that are to be extracted
        
        Returns:
            polymat_t: a new matrix with the columns of self specified by col_list

        """
        if type(col_list) is set:
            col_list=list(col_list)
        res=polymat_t(self.ring,self.rows,len(col_list))
        for i in range(len(col_list)):
            res.set_col(i,self.get_col(col_list[i]))
        res.adds=self.adds
        res.muls=self.muls
        return res

    def zero_out_cols(self,col_list):
        """Zeroes out the columns from self specified by col_list
        
        Args:
            col_list (set,list): the positions from self that are to be zeroed out
        
        Returns:
            polymat_t: a new matrix with the columns of self specified by col_list zeroed out

        """
        zerocol=polyvec_t(self.ring,self.rows)
        res=polymat_t(self.ring,self.rows,self.cols,self)
        if type(col_list) is set:
            col_list=list(col_list)
        for i in col_list:
            res.set_col(i,zerocol)
        return res

    def append_col(self,newcol:polyvec_t):
        """Appends a column to the end of the matrix
        
        Args:
            newcol (polyvec_t): column to be appended

        Returns:
            polymat_t: a new matrix with one extra column
        """
        res=polymat_t(self.ring,self.rows,self.cols+1)
        for i in range(self.cols):
            res.set_col(i,self.get_col(i))
        res.set_col(self.cols,newcol)
        return res

    def append_row(self,newrow:polyvec_t):
        """Appends a row to the end of the matrix
        
        Args:
            newrow (polyvec_t): row to be appended

        Returns:
            polymat_t: a new matrix with one extra row
        """
        res=polymat_t(self.ring,self.rows+1,self.cols)
        for i in range(self.rows):
            res.set_row(i,self.get_row(i))
        res.set_row(self.cols,newrow)
        return res

    def set_submatrix(self, start_row: int, start_col: int, val: 'polymat_t'):
        """Sets a sub-matrix of the current matrix starting at the given position
        
        Args:
            start_row (int): starting row index for the sub-matrix
            start_col (int): starting column index for the sub-matrix
            val (polymat_t): the matrix to be copied into the sub-matrix position
        
        Raises:
            AssertionError: if the sub-matrix dimensions exceed the main matrix bounds
        """
        assert start_row + val.rows <= self.rows, "Sub-matrix rows exceed matrix bounds"
        assert start_col + val.cols <= self.cols, "Sub-matrix columns exceed matrix bounds"

        # the submatrices are set one element at a time
        for i in range(val.rows):
            for j in range(val.cols):
                # get source element
                elem = val.get_elem(i, j)
                # Set element directly in target matrix
                self.set_elem(elem, start_row + i, start_col + j)

        # update operation counters
        if val.muls > self.muls:
            self.muls = val.muls
        if val.adds > self.adds:
            self.adds = val.adds

    def __eq__(self, a):
        """Overloads the == operator
        """
        if a==None:
            return 0
        ptrs=ffi.new("polyvec_t")
        ptra=ffi.new("polyvec_t")
        for r in range(self.rows):
            lib.polymat_get_row(ptrs,self.ptr,r)
            lib.polymat_get_row(ptra,a.ptr,r)
            if lib.polyvec_eq(ptrs,ptra)==0:
                return 0
        return 1

    def __neg__(self):
        """Returns the negated value of the matrix. For polymat_t p, can write -p"""

        res=self.copy_zero()
        for i in range(res.rows):
            res.set_row(i,-(self.get_row(i)))
        return res

    def __add__(self,a):
        """Overloads the + operator

        Args:
            a (poly_t,polyvec_t,polymat_t): can take multiple values
                poly_t, polyvec_t - see __add__ for poly_t or polyvec_t. self needs to have the right dimensions
                polymat_t - outputs self+a
        
        Returns:
            polymat_t        
        
        """
        if self.adds>=MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()

        if type(a) is poly_t or type(a) is polyvec_t:
            return a+self
        assert self.rows==a.rows and self.cols==a.cols
        res=self.copy_zero()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.polymat_add(res.ptr,self.ptr,a.ptr,0)
        res.adds+=1
        return res

    def __sub__(self,a):
        """Overloads the - operator. Outputs self + (-a)
        """
        if self.adds>=MAX_ADDS:
            self.redc()
        if a.adds>=MAX_ADDS:
            a.redc()
        if type(a) is poly_t or type(a) is polyvec_t:
            return self+(-a)
        assert self.rows==a.rows and self.cols==a.cols
        res=self.copy_zero()
        res.adds=max(self.adds,a.adds)
        res.muls=max(self.muls,a.muls)
        lib.polymat_sub(res.ptr,self.ptr,a.ptr,0)
        res.adds+=1
        return res

    def __mul__(self,a):
        """Multiplication
        
        Args:
            a (int,int_t,poly_t,polyvec_t): can take multiple values

        Returns:
            polyvec_t,polymat_t
        """
        if self.muls>=MAX_MULS:
            self.redc()
        if (type(a) is poly_t or type(a) is polyvec_t or type(a) is polymat_t) and a.muls>=MAX_MULS:
            a.redc()

        if type(a) is int or type(a) is int_t or type(a) is poly_t:
            res=self.copy_zero()
            if type(a) is int or type(a) is int_t:
                a=int_to_poly(a,self.ring)
            res.adds=max(self.adds,a.adds)
            res.muls=max(self.muls,a.muls)
            if self.ring.deg !=64:
                for i in range(res.rows):
                    res.set_row(i,a*self.get_row(i))
                #return res
            lib.polymat_scale2(res.ptr,a.ptr,self.ptr)
        elif type(a) is polyvec_t:
            #multiplication of different rings
            if self.ring.deg != 64:
                assert self.ring.deg==a.ring.deg and self.ring.mod==a.ring.mod
                assert self.cols==a.dim
                new_ring=polyring_t(64,self.ring.mod)
                defmat,defvec=lin_to_isoring(new_ring,self.ring,self,a)
                return (defmat*defvec).from_isoring(self.ring)
            else:
                assert self.cols==a.dim
                res=polyvec_t(self.ring,self.rows)
                res.adds=max(self.adds,a.adds)
                res.muls=max(self.muls,a.muls)
                lib.polyvec_mul(res.ptr,self.ptr,a.ptr)
        elif type(a) is polymat_t:
            assert self.cols==a.rows
            res=polymat_t(self.ring,self.rows,a.cols)
            res.adds=max(self.adds,a.adds)
            res.muls=max(self.muls,a.muls)
            temp_row=polyvec_t(self.ring,a.cols, tmp = True)
            self_row=polyvec_t(self.ring,self.cols, tmp = True)
            for i in range(self.rows):
                lib.polymat_get_row(self_row.ptr,self.ptr,i)
                lib.polyvec_mul2(temp_row.ptr,self_row.ptr,a.ptr)
                lib.polymat_set_row(res.ptr,temp_row.ptr,i)
        
        res.muls+=1
        return res

    def __rmul__(self,a):
        """Multiplication from the right side, allowing for int*polymat_t"""
        assert type(a) is int or type(a) is int_t or type(a) is poly_t
        return self*a
    
    def __getitem__(self,key):
        if isinstance(key, int):
            return self.get_row(key)
        if isinstance(key, tuple) and len(key) == 2:
            return self.get_elem(key[0], key[1])
        if isinstance(key, tuple) and len(key) == 3:
            return self.get_elem(key[0], key[1], key[2])
    
    def __setitem__(self,key,val):
        if isinstance(key, int):
            self.set_row(key,val)
        if isinstance(key, tuple) and len(key) == 2:
            self.set_elem(val, key[0], key[1])
        if isinstance(key, tuple) and len(key) == 3:
            self.set_elem(val, key[0], key[1], key[2])

    def transpose(self):
        """Transpose

        Returns:
            polymat_t
        """
        res=polymat_t(self.ring,self.cols,self.rows)
        for i in range(res.rows):
            res.set_row(i,self.get_col(i))
        return res

    def brandom(self, hi:int, seed,dom,seed_inc=0):
        """Sets the matrix to a a binomially-distributed random matrix
        
        Args:
            hi (int):  the coefficients are a_1+...a_hi-(b_1+...b_hi) where a_i,b_i are Bernoulli 
            seed (bytes[32]): a byte array of length 32. can be the output of e.g. shake128.digest(32)
            dom (int): domain separator variable
            seed_inc (int,default=0): leave out this argument. setting to > 0 is used for testing       
        """
        assert 0<hi
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.polymat_brandom(self.ptr, hi,seed_bytes,dom)

    #don't think this is used anywhere
    def urandom(self,mod,seed,dom,seed_inc=0):
        log2mod=(mod-1).bit_length()
        mod=int_t(mod)
        seed_bytes=_handle_seed(seed,seed_inc)
        lib.polymat_urandom(self.ptr,mod.ptr,log2mod,seed_bytes,dom)

    #don't think this is used anywhere
    @staticmethod
    def urandom_static(ring,rows,cols,mod,seed,dom,seed_inc=0):
        m=polymat_t(ring,rows,cols)
        m.urandom(mod,seed,dom,seed_inc)
        return m

    @staticmethod
    def identity(ring,dim):
        """Returns a square identity matrix over a ring
        
        Args:
            ring (polyring_t): the ring of the matrix
            dim (int): the number of rows and columns in the matrix 

        Returns:
            polymat_t: a dimxdim identity matrix
        """
        res=polymat_t(ring,dim,dim)
        for i in range(dim):
            res.set_elem(1,i,i,0)
        return res


    def print(self):
        lib.polymat_dump(self.ptr)

RING_FALCON=polyring_t(512,12289)

class falcon_pol:
    def __init__(self,coeff=None):
        self.Q=12289
        self.dim=512
        self.ptr=ffi.new("int16_t[512]")
        if coeff==None:
            for i in range(512):
                self.ptr[i]=0
        elif type(coeff) is list:
            for i in range(512):
                self.ptr[i]=coeff[i]
        elif type(coeff) is falcon_pol:
            for i in range(512):
                self.ptr[i]=coeff.ptr[i]
        elif type(coeff) is poly_t:
            assert coeff.ring.deg==512 and coeff.linf()<2**15
            coeff.redc()
            point64=ffi.new("int64_t []",512)
            lib.poly_get_coeffvec_i64(point64, coeff.ptr)
            for i in range(512):
                self.ptr[i]=point64[i]

    def copy(self):
        res=falcon_pol(self)
        return res

    def set_pos(self,pos,val):
        self.ptr[pos]=val

    def get_pos(self,pos):
        return self.ptr[pos]

    def set_list(self,l):
        for i in range(512):
            self.ptr[i]=l[i]

    def redc(self):
        lib.falcon_redc(self.ptr)

    def __neg__(self):
        res=falcon_pol()
        for i in range(512):
            res.ptr[i]=-self.ptr[i]
        return res

    def __add__(self,a):
        if type(a) is falcon_pol:
            res=falcon_pol()
            lib.falcon_add(res.ptr, self.ptr, a.ptr)
            lib.falcon_redc(res.ptr)
            return res
        elif type(a) is polyvec_t:
            assert a.ring.deg*a.dim == 512
            temp=self.to_isoring(a.ring)
            return temp+a

    def __mul__(self,a):
        res=falcon_pol()
        lib.falcon_mul(res.ptr, self.ptr, a.ptr)
        lib.falcon_redc(res.ptr)
        return res

    def __sub__(self,a):
        temp=self+(-a)
        if type(a) is polyvec_t:
            return temp
        return temp.redc()

    def to_list(self):
        resl=[]
        for i in range(512):
            resl+=[self.ptr[i]]
        return resl

    def linf(self):
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        return p.linf()

    def l2sqr(self):
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        return p.l2sq()

    def to_poly(self):
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        #p=poly_t(RING_FALCON,self.to_list())
        return p

    def to_polyvec(self):
        m=polyvec_t(RING_FALCON,1)
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        m.set_elem(p,0)
        return m

    def to_polymat(self):
        m=polymat_t(RING_FALCON,1,1)
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        m.set_elem(p,0,0)
        return m

    def to_isoring(self,ring:polyring_t):
        p=poly_t(RING_FALCON)
        lib.poly_set_coeffvec_i16 (p.ptr, self.ptr)
        return p.to_isoring(ring)

    def print(self):
        print(self.to_list())

class falcon_skenc:
    def __init__(self):
        self.ptr=ffi.new("uint8_t[]",1300)

class falcon_pkenc:
    def __init__(self):
        self.ptr=ffi.new("uint8_t[]",1000)

def falcon_keygen():
    """Creates a public key/secret key for the falcon signature scheme

        Returns [falcon_skenc,falcon_pkenc,poly_t]: falcon_skenc and falcon_pkenc are the secret and public
            reys for falcon. also returns a poly_t version of falcon_pkenc
    """
    skenc=falcon_skenc()
    pkenc=falcon_pkenc()
    pk=falcon_pol()
    lib.falcon_keygen(skenc.ptr,pkenc.ptr)
    lib.falcon_decode_pubkey(pk.ptr,pkenc.ptr)
    pk=pk.to_poly()
    return skenc,pkenc,pk

def falcon_decode_pk(pkenc: falcon_pkenc,target_ring = None):
    """Takes a falcon_pkenc type and produces either a poly_t or a polymat_t
    
    Args:
        pkenc (falcon_pkenc): the falcon public key as a falcon_pkenc type
        target_ring (polyring_t,None): if None, then produces a poly_t in the falcon ring
            if target_ring is some ring of degree deg, then it converts the falcon pk polynomial
            to a matrix M such that for all polynomials s in the falcon ring, (M*aut(s))=aut(pk*s) 
    
    Returns:
        poly_t,polymat_t : either a polynomial in the falcon ring or a polymat_t as described above

    """

    pk=falcon_pol()
    lib.falcon_decode_pubkey(pk.ptr,pkenc.ptr)
    if target_ring == None:
        return pk.to_poly()
        #return pk.to_list()
    else:
        assert target_ring.mod == RING_FALCON.mod
        res_mat,garb_mat=falcon_poly_mul_toisoring(target_ring,pk,pk)
        return res_mat

def falcon_preimage_sample(skenc:falcon_skenc,t,target_ring=None):
    """Produces a pre-image of t
    
    Args:
        skenc (falcon_skenc) : the falcon secret key from falcon_keygen()
        t (poly_t,polyvec_t) : either a poly_t in the falcon ring or a polyvec_t with the same
            modulus as in the falcon ring (i.e. 12289) and such that the ring degree * vector dimension
            is 512. If poly_t, then it does normal pre-image sampling returning s_1,s_2 such that 
            pk*s_2+s_1=t. if t is a polyvec, then it applies the inverse automorphism, as described in
            falcon_decode_pk, to t and then does pre-mage sampling
        target_ring (polyring_t,optional) : in None, just returns the polynomials. if it's some ring,
            then returns polyvec_t aut(s_1) and aut(s_2)
    
    Returns:
        (poly_t,poly_t),(polyvec_t,polyvec_t) - returns s_1,s_2 as explained above 
    """

    s1=falcon_pol()
    s2=falcon_pol()
    if type(t) is falcon_pol:
        lib.falcon_preimage_sample(s1.ptr,s2.ptr,t.ptr,skenc.ptr)
    elif type(t) is poly_t:
        assert t.ring.deg == 512
        # TODO test this
        #tf = falcon_pol(t.to_list())
        tf = falcon_pol(t)
        lib.falcon_preimage_sample(s1.ptr,s2.ptr,tf.ptr,skenc.ptr)
    elif type(t) is polyvec_t:
        assert t.ring.deg*t.dim == 512
        tf=from_isoring_tofalconpol(t)
        lib.falcon_preimage_sample(s1.ptr,s2.ptr,tf.ptr,skenc.ptr)

    if target_ring == None:
        s1res=s1.to_poly()
        s2res=s2.to_poly()
        s1res.redc(s1res)
        s2res.redc(s2res)
    else:
        s1res=s1.to_isoring(target_ring)
        s2res=s2.to_isoring(target_ring)
    return s1res,s2res

def from_isoring_tofalconpol(inp_vec:polyvec_t):
    assert 512 % inp_vec.ring.deg == 0
    resp=poly_t(RING_FALCON)
    lib.poly_fromisoring(resp.ptr,inp_vec.ptr)
    return falcon_pol(resp.to_list())

def lin_to_isoring(ring_out:polyring_t,ring_in:polyring_t,matinp,vecinp):
    assert ring_in.deg % ring_out.deg == 0
    if type(matinp) is poly_t:
        newmat=polymat_t(ring_in,1,1)
        newmat.set_elem(matinp,0,0)
        return lin_to_isoring(ring_out,ring_in,newmat,vecinp)
    if type(matinp) is polyvec_t:
        newmat=polymat_t(ring_in,1,matinp.dim)
        newmat.set_row(0,matinp)
        return lin_to_isoring(ring_out,ring_in,newmat,vecinp)
    if type(vecinp) is poly_t:
        newvec=polyvec_t(ring_in,1)
        newvec.set_elem(vecinp,0)
        return lin_to_isoring(ring_out,ring_in,matinp,newvec)
    #matinp should be a matrix and vecinp should be a vector
    degdif=ring_in.deg//ring_out.deg
    res_mat=polymat_t(ring_out,matinp.rows*degdif,matinp.cols*degdif)
    res_vec=polyvec_t(ring_out,vecinp.dim*degdif)
    lib.lin_toisoring(res_mat.ptr,res_vec.ptr,matinp.ptr,vecinp.ptr)
    return res_mat,res_vec

def falcon_poly_mul_toisoring(ring_out:polyring_t,a1,a2):
    pkmat=a1.to_polymat()
    s2vec=a2.to_polyvec()
    return lin_to_isoring(ring_out,RING_FALCON,pkmat,s2vec)

def list_inner_product(a: list, b:list):
    assert len(a)==len(b)
    res_pol=poly_t(a[0].ring)
    for i in range(len(a)):
        assert type(a[i]) is poly_t or type(a[i]) is polyvec_t
        assert type(a[i])==type(b[i])
        res_pol+=a[i]*b[i]
    return res_pol

class DecodingError(Exception):
    pass


class VerificationError(Exception):
    pass


class coder_t:
    """Encodes input into byte arrays 
    """
    def __init__(self):
        """Initializes the encoder"""
        self.ptr = ffi.new("coder_state_t")

    def enc_begin(self, maxlen):
        """Starts the encoding.

        Args:
            maxlen (int): the maximum number of bytes needed for the encoding

        """
        self.buf = ffi.new(f"char[{maxlen}]")
        lib.coder_enc_begin(self.ptr, self.buf)

    def enc_end(self):
        """Finalizes the encoding"""
        lib.coder_enc_end(self.ptr)

        nbits = lib.coder_get_offset(self.ptr)
        assert nbits % 8 == 0

        return ffi.unpack(self.buf, int(nbits / 8))

    def dec_begin(self, buf: bytes):
        """Begins the decoding
        
        Args:
            buf(bytes): a byte array with the encoding to be decoded
        
        """
        self.buf = buf
        lib.coder_dec_begin(self.ptr, self.buf)

    def dec_end(self):
        """Finilizes the decoding.

        Returns:
            int: number of bytes that got decoded
        
        """
        rc = lib.coder_dec_end(self.ptr)
        if rc != 1:
            raise DecodingError("Decoding failed.")

        nbits = lib.coder_get_offset(self.ptr)
        assert nbits % 8 == 0

        return int(nbits / 8)

    def enc_bytes(self, bin: bytes):
        """Adds an encoding of a byte string to the coder
        
        Args:
            bin (bytes): the byte array to be encoded
        """
        lib.coder_enc_bytes(self.ptr, bin, len(bin))

    def dec_bytes(self, bin: bytes):
        """Decodes the next object in the encoding and places it into a byte array 
            (the object one is decoding should be a byte array)
        
        Args:
            bin (bytes): the decoded byte array 

        """
        lib.coder_dec_bytes(self.ptr, bin, len(bin))

    def enc_urandom(self, bnd: int, x):
        """Encodes a uniformly-random, in [0,bnd) poly_t or polyvec_t
        
        Args:
            bnd (int): the range [0,bnd) of the coefficients
            x (poly_t,polyvec_t): the polynomial (vector) being encoded

        """
        bnd_ = int_t(bnd)
        if type(x) == poly_t:
            x.redp(x)
            lib.coder_enc_urandom2(self.ptr, x.ptr, bnd_.ptr, bnd.bit_length())
        elif type(x) is polyvec_t:
            x.redp(x)
            lib.coder_enc_urandom3(self.ptr, x.ptr, bnd_.ptr, bnd.bit_length())
        else:
            raise NotImplementedError(f"Encoding type {type(x)} not implemented.")

    def dec_urandom(self, bnd: int, x):
        """Decodes a uniformly-random, in [0,bnd) poly_t or polyvec_t
        
        Args:
            bnd (int): he range [0,bnd) of the coefficients
            x (poly_t,polyvec_t): the decoded polynomial (vector) 

        """
        bnd_ = int_t(bnd)
        if type(x) == poly_t:
            rc = lib.coder_dec_urandom2(self.ptr, x.ptr, bnd_.ptr, bnd.bit_length())
            x.redc(x)
        elif type(x) is polyvec_t:
            rc = lib.coder_dec_urandom3(self.ptr, x.ptr, bnd_.ptr, bnd.bit_length())
            x.redc(x)
        else:
            rc = 1
            raise NotImplementedError(f"Decoding type {type(x)} not implemented.")
        if rc != 0:
            raise DecodingError("Decoding failed.")
        
    def enc_grandom(self, sigma: int, x):
        """Encodes a poly_t or polyvec_t whose coefficients are Gaussians
            (One can also encode the binomial distribution if one uses the appropriate
            standard deviation.)
        
        Args:
            sigma (int): standard deviation of the (discrete) Gaussian
            x (poly_t,poly_vec_t): the polynomial (vector) being encoded

        """
        log2o = int(math.ceil(math.log(sigma/1.55,2)))
        if type(x) == poly_t:
            lib.coder_enc_grandom2(self.ptr, x.ptr, log2o)
        elif type(x) is polyvec_t:
            lib.coder_enc_grandom3(self.ptr, x.ptr, log2o)
        else:
            raise NotImplementedError(f"Encoding type {type(x)} not implemented.")

    def dec_grandom(self, sigma: int, x):
        """Decodes a poly_t or polyvec_t, whose coefficients are Gaussians,
            which was encoded with enc_grandom
                   
        Args:
            sigma (int): standard deviation of the (discrete) Gaussian
            x (poly_t,poly_vec_t): the decoded polynomial (vector)

        """
        log2o = int(math.ceil(math.log(sigma/1.55,2)))
        if type(x) == poly_t:
            lib.coder_dec_grandom2(self.ptr, x.ptr, log2o)
        elif type(x) is polyvec_t:
            lib.coder_dec_grandom3(self.ptr, x.ptr, log2o)
        else:
            raise NotImplementedError(f"Decoding type {type(x)} not implemented.")



class lin_prover_state_t:
    """The prover for an equation of the form Aw+t=0
    
    """
    def __init__(self, ppseed: bytes, params):
        """ Initializes the prover

        Args:
            ppseed(bytes): 32-element byte array which is used to derive all the public 
                parameters in the ZK proof
            params (c-type): ib.get_params("PARAM_NAME"), where the PARAM_NAME is the name
                given to the parameter set in the parameter file  
        
        """
        if len(ppseed) != 32:
            raise ValueError("ppseed must be 32 bytes.")

        self.expected_prooflen = lib.lin_params_get_prooflen(params)

        self.ptr = ffi.new("lin_prover_state_t")
        lib.lin_prover_init(self.ptr,ppseed,params)

    def __del__(self):
        """Class destructor"""
        lib.lin_prover_clear(self.ptr)

    def set_statement(self, A: polymat_t, t: polyvec_t):
        """Sets the public statement parameters A and t in Aw+t=0
        
        Args:
            A (polymat_t): the matrix A
            t (polyvec_t): the vector t
        """
        lib.lin_prover_set_statement(self.ptr, A.ptr, t.ptr)

    def set_statement_A(self, A: polymat_t):
        """Sets the public statement parameter A in Aw+t=0
        
        Args:
            A (polymat_t): the matrix A
        
        """
        lib.lin_prover_set_statement_A(self.ptr, A.ptr)

    def set_statement_t(self, t: polyvec_t):
        """Sets the public statement parameter t in Aw+t=0
        
        Args:
            t (polyvec_t): the vector t
        
        """
        lib.lin_prover_set_statement_t(self.ptr, t.ptr)

    def set_witness(self, w: polyvec_t):
        """Sets the secret witness vector in Aw+t=0
        
        Args:
            w (polyvec_t): the vector w
        
        """
        lib.lin_prover_set_witness(self.ptr, w.ptr)

    def prove(self, coins: bytes = None):
        """Produces the ZK proof

        Args:
            coins (bytes,None): if coins is a lenght 32 byte array, then it uses this for internal
                randomness. otherwise, use system randomness.
        
        Returns:
            bytes,int : a byte array containing the proof and the number of bytes in the proof 

        """
        if coins == None:
            coins = ffi.NULL
        elif len(coins) != 32:
            raise ValueError("coins must be 32 bytes.")

        expected_prooflen = int(math.ceil(self.expected_prooflen * 1.2))
        # print(f"expected prooflen {expected_prooflen}")
        proof = ffi.new(f"char[{expected_prooflen}]")
        prooflen = ffi.new("size_t[1]")
        lib.lin_prover_prove(self.ptr, proof, prooflen, coins)
        return ffi.unpack(proof, prooflen[0])


class lin_verifier_state_t:
    """The verifier for an equation of the form Aw+t=0
    
    """
    def __init__(self, ppseed: bytes, params):
        """Initializes the verifier.
        
        Args:
            Args:
            ppseed(bytes): 32-element byte array which is used to derive all the public 
                parameters in the ZK proof
            params (c-type): lib.get_params("PARAM_NAME"), where the PARAM_NAME is the name
                given to the parameter set in the parameter file  

        """
        if len(ppseed) != 32:
            raise ValueError("ppseed must be 32 bytes.")

        self.ptr = ffi.new("lin_verifier_state_t")
        lib.lin_verifier_init(self.ptr,ppseed,params)

    def __del__(self):
        """Class destructor"""
        lib.lin_verifier_clear(self.ptr)

    def set_statement(self, A: polymat_t, t: polyvec_t):
        """Sets the public statement parameters A and t in Aw+t=0
        
        Args:
            A (polymat_t): the matrix A
            t (polyvec_t): the vector t
        """
        lib.lin_verifier_set_statement(self.ptr, A.ptr, t.ptr)

    def set_statement_A(self, A: polymat_t):
        """Sets the public statement parameter A in Aw+t=0
        
        Args:
            A (polymat_t): the matrix A
        
        """
        lib.lin_verifier_set_statement_A(self.ptr, A.ptr)

    def set_statement_t(self, t: polyvec_t):
        """Sets the public statement parameter t in Aw+t=0
        
        Args:
            t (polyvec_t): the vector t
        
        """
        lib.lin_verifier_set_statement_t(self.ptr, t.ptr)

    # def set_witness(self, w: polyvec_t):
    #     lib.lin_verifier_set_witness(self.ptr, w.ptr)

    def verify(self, proof: bytes):
        """Verifies the ZK proof

        Args:
            proof (bytes): the ZK proof
        
        Returns:
            nothing, or throws exception if the proof is invalid

        """
        prooflen = ffi.new("size_t[1]")
        accept = lib.lin_verifier_verify(self.ptr, proof, prooflen)
        if accept != 1:
            raise VerificationError("Verification failed.")

def print_stopwatch_lnp_prover_prove(indent: int):
    lib.print_stopwatch_lnp_prover_prove(indent)

def print_stopwatch_lnp_verifier_verify(indent: int):
    lib.print_stopwatch_lnp_verifier_verify(indent)
