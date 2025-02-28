from lazer import *     # import everything from the lazer python module
SEED=[1]
Rq=polyring_t(64,q=12289)
rvec=polyvec_t.grandom_static(Rq,2,1,SEED,0,1)
print("first")
rvec.print()
rvec2=polyvec_t.grandom_static(Rq,3,1,SEED,0,1)
print("second")
rvec2.print()
rp=poly_t(Rq,[1]*64)
rres=polyvec_t(Rq,7,[rp,rvec,rp,rvec2])
print("result")
rres.print()
M1=polymat_t.urandom_static(Rq,2,2,5,SEED,0,1)
M1.print()
M2=polymat_t.urandom_static(Rq,2,1,5,SEED,0,1)
Mres=polymat_t(Rq,2,5,[M1,rvec,M2,rvec])
Mres.print()
Mres=polymat_t.identity(Rq,2)
Mres.print()
rvec=polyvec_t.grandom_static(Rq,8,1,SEED,0,1)
rvec.print()
print(None == rvec)
zlist=[0,3,5]
rvec2=rvec.zero_out_pols(zlist)
rvec2.print()