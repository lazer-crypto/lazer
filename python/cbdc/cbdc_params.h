// auto-generated by lnp-tbox.sage.
// 
// protocol is statistically complete with correctness error >= 1 - 2^(-4)
// protocol is simulatable under MLWE(28,29,[-1,1])
// protocol is knowledge-sound with knowledge error <= 2^(-127.0) under MSIS(17,78,2^(33.952396))
// 
// Ring
// degree d = 64
// modulus q = 8796093022501, log(q) ~ 43.0
// factors q = q1
// 
// Compression
// D = 10
// gamma = 426300, log(gamma) ~ 18.70151
// 
// Dimensions of secrets
// s1: m1 = 21
// m: l = 0
// s2: m2 = 57
// 
// Size of secrets
// l2(s1) <= alpha = 142.0
// m unbounded
// s2 uniform in [-nu,nu] = [-1,1]
// 
// Norm proofs
// binary: no
// exact euclidean: yes (dimensions: [16, 5], bounds: [109.0, 91.0])
// approximate infinity: yes (psi: 3004.2351, dimension: 8, bound: 73242.54)
// 
// Challenge space
// c uniform in [-omega,omega] = [-8,8], o(c)=c, sqrt(l1(o(c)*c)) <= eta = 140
// 
// Standard deviations
// stdev1 = 203161.6, log(stdev1/1.55) = 17.0
// stdev2 = 6348.8, log(stdev2/1.55) = 12.0
// stdev3 = 12697.6, log(stdev3/1.55) = 13.0
// stdev4 = 6501171.2, log(stdev4/1.55) = 22.0
// 
// Repetition rate
// M1 = 3.7342088
// M2 = 2.4277063
// M3 = 1.0214314
// M4 = 1.021617
// total = 9.4600204
// 
// Security
// MSIS dimension: 17
// MSIS root hermite factor: 1.0042789
// MLWE dimension: 28
// MLWE root hermite factor: 1.0042575
// 
// Proof size
// ~ 19.7832031250000 KiB
// 
// 50 bit moduli for degree 64: [1125899906840833, 1125899906839937]
// bit length of products: [49, 99]
// inverses: [1, -162099428551732]

#include "lazer.h"
static const limb_t _p1_param_q_limbs[] = {8796093022501UL};
static const int_t _p1_param_q = {{(limb_t *)_p1_param_q_limbs, 1, 0}};
static const limb_t _p1_param_qminus1_limbs[] = {8796093022500UL};
static const int_t _p1_param_qminus1 = {{(limb_t *)_p1_param_qminus1_limbs, 1, 0}};
static const limb_t _p1_param_m_limbs[] = {20633575UL};
static const int_t _p1_param_m = {{(limb_t *)_p1_param_m_limbs, 1, 0}};
static const limb_t _p1_param_mby2_limbs[] = {20633575/2UL};
static const int_t _p1_param_mby2 = {{(limb_t *)_p1_param_mby2_limbs, 1, 0}};
static const limb_t _p1_param_gamma_limbs[] = {426300UL};
static const int_t _p1_param_gamma = {{(limb_t *)_p1_param_gamma_limbs, 1, 0}};
static const limb_t _p1_param_gammaby2_limbs[] = {213150UL};
static const int_t _p1_param_gammaby2 = {{(limb_t *)_p1_param_gammaby2_limbs, 1, 0}};
static const limb_t _p1_param_pow2D_limbs[] = {1024UL};
static const int_t _p1_param_pow2D = {{(limb_t *)_p1_param_pow2D_limbs, 1, 0}};
static const limb_t _p1_param_pow2Dby2_limbs[] = {512UL};
static const int_t _p1_param_pow2Dby2 = {{(limb_t *)_p1_param_pow2Dby2_limbs, 1, 0}};
static const limb_t _p1_param_Bsq_limbs[] = {98751252518264UL, 0UL};
static const int_t _p1_param_Bsq = {{(limb_t *)_p1_param_Bsq_limbs, 2, 0}};
static const limb_t _p1_param_scM1_limbs[] = {3771192069573992327UL, 13543761202657432727UL, 3UL};
static const int_t _p1_param_scM1 = {{(limb_t *)_p1_param_scM1_limbs, 3, 0}};
static const limb_t _p1_param_scM2_limbs[] = {11208912776058102363UL, 7889787913383536571UL, 2UL};
static const int_t _p1_param_scM2 = {{(limb_t *)_p1_param_scM2_limbs, 3, 0}};
static const limb_t _p1_param_scM3_limbs[] = {15955925220626281193UL, 395340347106357022UL, 1UL};
static const int_t _p1_param_scM3 = {{(limb_t *)_p1_param_scM3_limbs, 3, 0}};
static const limb_t _p1_param_scM4_limbs[] = {3079511058807299633UL, 398763635391596637UL, 1UL};
static const int_t _p1_param_scM4 = {{(limb_t *)_p1_param_scM4_limbs, 3, 0}};
static const limb_t _p1_param_stdev1sq_limbs[] = {41274635715UL, 0UL};
static const int_t _p1_param_stdev1sq = {{(limb_t *)_p1_param_stdev1sq_limbs, 2, 0}};
static const limb_t _p1_param_stdev2sq_limbs[] = {40307261UL, 0UL};
static const int_t _p1_param_stdev2sq = {{(limb_t *)_p1_param_stdev2sq_limbs, 2, 0}};
static const limb_t _p1_param_stdev3sq_limbs[] = {161229046UL, 0UL};
static const int_t _p1_param_stdev3sq = {{(limb_t *)_p1_param_stdev3sq_limbs, 2, 0}};
static const limb_t _p1_param_stdev4sq_limbs[] = {42265226971709UL, 0UL};
static const int_t _p1_param_stdev4sq = {{(limb_t *)_p1_param_stdev4sq_limbs, 2, 0}};
static const limb_t _p1_param_inv2_limbs[] = {4398046511250UL};
static const int_t _p1_param_inv2 = {{(limb_t *)_p1_param_inv2_limbs, 1, 1}};
static const limb_t _p1_param_inv4_limbs[] = {2199023255625UL};
static const int_t _p1_param_inv4 = {{(limb_t *)_p1_param_inv4_limbs, 1, 1}};
static const unsigned int _p1_param_n[2] = {16, 5};
static const limb_t _p1_param_Bz3sqr_limbs[] = {111012260217UL, 0UL};
static const int_t _p1_param_Bz3sqr = {{(limb_t *)_p1_param_Bz3sqr_limbs, 2, 0}};
static const limb_t _p1_param_Bz4_limbs[] = {104018739UL};
static const int_t _p1_param_Bz4 = {{(limb_t *)_p1_param_Bz4_limbs, 1, 0}};
static const limb_t _p1_param_Pmodq_limbs[] = {1579305345UL};
static const int_t _p1_param_Pmodq = {{(limb_t *)_p1_param_Pmodq_limbs, 1, 0}};
static const limb_t _p1_param_l2Bsq0_limbs[] = {11881UL};
static const int_t _p1_param_l2Bsq0 = {{(limb_t *)_p1_param_l2Bsq0_limbs, 1, 0}};
static const limb_t _p1_param_l2Bsq1_limbs[] = {8281UL};
static const int_t _p1_param_l2Bsq1 = {{(limb_t *)_p1_param_l2Bsq1_limbs, 1, 0}};
static const limb_t _p1_param_Ppmodq_0_limbs[] = {40191UL};
static const int_t _p1_param_Ppmodq_0 = {{(limb_t *)_p1_param_Ppmodq_0_limbs, 1, 1}};
static const limb_t _p1_param_Ppmodq_1_limbs[] = {39295UL};
static const int_t _p1_param_Ppmodq_1 = {{(limb_t *)_p1_param_Ppmodq_1_limbs, 1, 1}};
static const int_srcptr _p1_param_l2Bsq[] = {_p1_param_l2Bsq0, _p1_param_l2Bsq1};
static const int_srcptr _p1_param_Ppmodq[] = {_p1_param_Ppmodq_0, _p1_param_Ppmodq_1};
static const polyring_t _p1_param_ring = {{_p1_param_q, 64, 44, 6, moduli_d64, 2, _p1_param_Pmodq, _p1_param_Ppmodq, _p1_param_inv2}};
static const dcompress_params_t _p1_param_dcomp = {{ _p1_param_q, _p1_param_qminus1, _p1_param_m, _p1_param_mby2, _p1_param_gamma, _p1_param_gammaby2, _p1_param_pow2D, _p1_param_pow2Dby2, 10, 1, 25 }};
static const abdlop_params_t _p1_param_tbox = {{ _p1_param_ring, _p1_param_dcomp, 23, 57, 0, 12, 17, _p1_param_Bsq, 1, 8, 5, 140, 1, 17, _p1_param_scM1, _p1_param_stdev1sq, 2, 12, _p1_param_scM2, _p1_param_stdev2sq}};
static const abdlop_params_t _p1_param_quad_eval_ = {{ _p1_param_ring, _p1_param_dcomp, 23, 57, 9, 3, 17, _p1_param_Bsq, 1, 8, 5, 140, 1, 17, _p1_param_scM1, _p1_param_stdev1sq, 2, 12, _p1_param_scM2, _p1_param_stdev2sq}};
static const abdlop_params_t _p1_param_quad_many_ = {{ _p1_param_ring, _p1_param_dcomp, 23, 57, 11, 1, 17, _p1_param_Bsq, 1, 8, 5, 140, 1, 17, _p1_param_scM1, _p1_param_stdev1sq, 2, 12, _p1_param_scM2, _p1_param_stdev2sq}};
static const lnp_quad_eval_params_t _p1_param_quad_eval = {{ _p1_param_quad_eval_, _p1_param_quad_many_, 4}};
static const lnp_tbox_params_t _p1_param = {{ _p1_param_tbox, _p1_param_quad_eval, 0, _p1_param_n, 8, 2, 23, 2, 13, _p1_param_scM3, _p1_param_stdev3sq, 2, 22, _p1_param_scM4, _p1_param_stdev4sq, _p1_param_Bz3sqr, _p1_param_Bz4, &_p1_param_l2Bsq[0], _p1_param_inv4, 20258UL }};

static const unsigned int p1_param_Es0[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned int p1_param_Es1[5] = {16, 17, 18, 19, 20};
static const unsigned int *p1_param_Es[2] = { p1_param_Es0, p1_param_Es1, };
static const unsigned int p1_param_Es_nrows[2] = {16, 5};

static const limb_t p1_param_p_limbs[] = {12289UL};
static const int_t p1_param_p = {{(limb_t *)p1_param_p_limbs, 1, 0}};
static const limb_t p1_param_pinv_limbs[] = {579773402899UL};
static const int_t p1_param_pinv = {{(limb_t *)p1_param_pinv_limbs, 1, 0}};
static const unsigned int p1_param_s1_indices[21] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
static const lin_params_t p1_param = {{ _p1_param, 64, p1_param_p, p1_param_pinv, 1, p1_param_s1_indices, 21, NULL, 0,  NULL, 0, p1_param_Es, p1_param_Es_nrows, NULL, NULL }};

// auto-generated by lnp-tbox.sage.
// 
// protocol is statistically complete with correctness error >= 1 - 2^(-3)
// protocol is simulatable under MLWE(32,32,[-1,1])
// protocol is knowledge-sound with knowledge error <= 2^(-127.0) under MSIS(20,139,2^(40.619653))
// 
// Ring
// degree d = 64
// modulus q = 2251799813685269, log(q) ~ 51.0
// factors q = q1
// 
// Compression
// D = 16
// gamma = 27699892, log(gamma) ~ 24.723377
// 
// Dimensions of secrets
// s1: m1 = 75
// m: l = 0
// s2: m2 = 64
// 
// Size of secrets
// l2(s1) <= alpha = 5838.0
// m unbounded
// s2 uniform in [-nu,nu] = [-1,1]
// 
// Norm proofs
// binary: yes (dimension: 8)
// exact euclidean: yes (dimensions: [16, 16, 1, 1, 1, 1, 1, 10, 10, 10], bounds: [109.0, 5833.9289, 64.0, 64.0, 64.0, 64.0, 64.0, 39.0, 39.0, 39.0])
// approximate infinity: yes (psi: 4024.1057, dimension: 14, bound: 13998061.0)
// 
// Challenge space
// c uniform in [-omega,omega] = [-8,8], o(c)=c, sqrt(l1(o(c)*c)) <= eta = 140
// 
// Standard deviations
// stdev1 = 13002342.4, log(stdev1/1.55) = 23.0
// stdev2 = 6348.8, log(stdev2/1.55) = 12.0
// stdev3 = 406323.2, log(stdev3/1.55) = 18.0
// stdev4 = 1664299827.2, log(stdev4/1.55) = 30.0
// 
// Repetition rate
// M1 = 2.322376
// M2 = 2.707079
// M3 = 1.0353865
// M4 = 1.0119912
// total = 6.5873798
// 
// Security
// MSIS dimension: 20
// MSIS root hermite factor: 1.0043894
// MLWE dimension: 32
// MLWE root hermite factor: 1.0043992
// 
// Proof size
// ~ 36.8828125000000 KiB
// 
// 50 bit moduli for degree 64: [1125899906840833, 1125899906839937, 1125899906837633]
// bit length of products: [49, 99, 149]
// inverses: [1, -162099428551732, 296975494591860]

#include "lazer.h"
static const limb_t _p2_param_q_limbs[] = {2251799813685269UL};
static const int_t _p2_param_q = {{(limb_t *)_p2_param_q_limbs, 1, 0}};
static const limb_t _p2_param_qminus1_limbs[] = {2251799813685268UL};
static const int_t _p2_param_qminus1 = {{(limb_t *)_p2_param_qminus1_limbs, 1, 0}};
static const limb_t _p2_param_m_limbs[] = {81292729UL};
static const int_t _p2_param_m = {{(limb_t *)_p2_param_m_limbs, 1, 0}};
static const limb_t _p2_param_mby2_limbs[] = {81292729/2UL};
static const int_t _p2_param_mby2 = {{(limb_t *)_p2_param_mby2_limbs, 1, 0}};
static const limb_t _p2_param_gamma_limbs[] = {27699892UL};
static const int_t _p2_param_gamma = {{(limb_t *)_p2_param_gamma_limbs, 1, 0}};
static const limb_t _p2_param_gammaby2_limbs[] = {13849946UL};
static const int_t _p2_param_gammaby2 = {{(limb_t *)_p2_param_gammaby2_limbs, 1, 0}};
static const limb_t _p2_param_pow2D_limbs[] = {65536UL};
static const int_t _p2_param_pow2D = {{(limb_t *)_p2_param_pow2D_limbs, 1, 0}};
static const limb_t _p2_param_pow2Dby2_limbs[] = {32768UL};
static const int_t _p2_param_pow2Dby2 = {{(limb_t *)_p2_param_pow2Dby2_limbs, 1, 0}};
static const limb_t _p2_param_Bsq_limbs[] = {435881818999706017UL, 0UL};
static const int_t _p2_param_Bsq = {{(limb_t *)_p2_param_Bsq_limbs, 2, 0}};
static const limb_t _p2_param_scM1_limbs[] = {7427448185742239138UL, 5946787403776444718UL, 2UL};
static const int_t _p2_param_scM1 = {{(limb_t *)_p2_param_scM1_limbs, 3, 0}};
static const limb_t _p2_param_scM2_limbs[] = {15002606599518648986UL, 13043305028329312333UL, 2UL};
static const int_t _p2_param_scM2 = {{(limb_t *)_p2_param_scM2_limbs, 3, 0}};
static const limb_t _p2_param_scM3_limbs[] = {376617026692790110UL, 652765764862863104UL, 1UL};
static const int_t _p2_param_scM3 = {{(limb_t *)_p2_param_scM3_limbs, 3, 0}};
static const limb_t _p2_param_scM4_limbs[] = {5694108209933650616UL, 221199030876619935UL, 1UL};
static const int_t _p2_param_scM4 = {{(limb_t *)_p2_param_scM4_limbs, 3, 0}};
static const limb_t _p2_param_stdev1sq_limbs[] = {169060907886838UL, 0UL};
static const int_t _p2_param_stdev1sq = {{(limb_t *)_p2_param_stdev1sq_limbs, 2, 0}};
static const limb_t _p2_param_stdev2sq_limbs[] = {40307261UL, 0UL};
static const int_t _p2_param_stdev2sq = {{(limb_t *)_p2_param_stdev2sq_limbs, 2, 0}};
static const limb_t _p2_param_stdev3sq_limbs[] = {165098542858UL, 0UL};
static const int_t _p2_param_stdev3sq = {{(limb_t *)_p2_param_stdev3sq_limbs, 2, 0}};
static const limb_t _p2_param_stdev4sq_limbs[] = {2769893914817949860UL, 0UL};
static const int_t _p2_param_stdev4sq = {{(limb_t *)_p2_param_stdev4sq_limbs, 2, 0}};
static const limb_t _p2_param_inv2_limbs[] = {1125899906842634UL};
static const int_t _p2_param_inv2 = {{(limb_t *)_p2_param_inv2_limbs, 1, 1}};
static const limb_t _p2_param_inv4_limbs[] = {562949953421317UL};
static const int_t _p2_param_inv4 = {{(limb_t *)_p2_param_inv4_limbs, 1, 1}};
static const unsigned int _p2_param_n[10] = {16, 16, 1, 1, 1, 1, 1, 10, 10, 10};
static const limb_t _p2_param_Bz3sqr_limbs[] = {113676554463109UL, 0UL};
static const int_t _p2_param_Bz3sqr = {{(limb_t *)_p2_param_Bz3sqr_limbs, 2, 0}};
static const limb_t _p2_param_Bz4_limbs[] = {26628797235UL};
static const int_t _p2_param_Bz4 = {{(limb_t *)_p2_param_Bz4_limbs, 1, 0}};
static const limb_t _p2_param_Pmodq_limbs[] = {281499281731228UL};
static const int_t _p2_param_Pmodq = {{(limb_t *)_p2_param_Pmodq_limbs, 1, 1}};
static const limb_t _p2_param_l2Bsq0_limbs[] = {11881UL};
static const int_t _p2_param_l2Bsq0 = {{(limb_t *)_p2_param_l2Bsq0_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq1_limbs[] = {34034726UL};
static const int_t _p2_param_l2Bsq1 = {{(limb_t *)_p2_param_l2Bsq1_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq2_limbs[] = {4096UL};
static const int_t _p2_param_l2Bsq2 = {{(limb_t *)_p2_param_l2Bsq2_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq3_limbs[] = {4096UL};
static const int_t _p2_param_l2Bsq3 = {{(limb_t *)_p2_param_l2Bsq3_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq4_limbs[] = {4096UL};
static const int_t _p2_param_l2Bsq4 = {{(limb_t *)_p2_param_l2Bsq4_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq5_limbs[] = {4096UL};
static const int_t _p2_param_l2Bsq5 = {{(limb_t *)_p2_param_l2Bsq5_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq6_limbs[] = {4096UL};
static const int_t _p2_param_l2Bsq6 = {{(limb_t *)_p2_param_l2Bsq6_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq7_limbs[] = {1521UL};
static const int_t _p2_param_l2Bsq7 = {{(limb_t *)_p2_param_l2Bsq7_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq8_limbs[] = {1521UL};
static const int_t _p2_param_l2Bsq8 = {{(limb_t *)_p2_param_l2Bsq8_limbs, 1, 0}};
static const limb_t _p2_param_l2Bsq9_limbs[] = {1521UL};
static const int_t _p2_param_l2Bsq9 = {{(limb_t *)_p2_param_l2Bsq9_limbs, 1, 0}};
static const limb_t _p2_param_Ppmodq_0_limbs[] = {562949939929771UL};
static const int_t _p2_param_Ppmodq_0 = {{(limb_t *)_p2_param_Ppmodq_0_limbs, 1, 1}};
static const limb_t _p2_param_Ppmodq_1_limbs[] = {562949944411115UL};
static const int_t _p2_param_Ppmodq_1 = {{(limb_t *)_p2_param_Ppmodq_1_limbs, 1, 1}};
static const limb_t _p2_param_Ppmodq_2_limbs[] = {562949948561771UL};
static const int_t _p2_param_Ppmodq_2 = {{(limb_t *)_p2_param_Ppmodq_2_limbs, 1, 1}};
static const int_srcptr _p2_param_l2Bsq[] = {_p2_param_l2Bsq0, _p2_param_l2Bsq1, _p2_param_l2Bsq2, _p2_param_l2Bsq3, _p2_param_l2Bsq4, _p2_param_l2Bsq5, _p2_param_l2Bsq6, _p2_param_l2Bsq7, _p2_param_l2Bsq8, _p2_param_l2Bsq9};
static const int_srcptr _p2_param_Ppmodq[] = {_p2_param_Ppmodq_0, _p2_param_Ppmodq_1, _p2_param_Ppmodq_2};
static const polyring_t _p2_param_ring = {{_p2_param_q, 64, 52, 6, moduli_d64, 3, _p2_param_Pmodq, _p2_param_Ppmodq, _p2_param_inv2}};
static const dcompress_params_t _p2_param_dcomp = {{ _p2_param_q, _p2_param_qminus1, _p2_param_m, _p2_param_mby2, _p2_param_gamma, _p2_param_gammaby2, _p2_param_pow2D, _p2_param_pow2Dby2, 16, 1, 27 }};
static const abdlop_params_t _p2_param_tbox = {{ _p2_param_ring, _p2_param_dcomp, 85, 64, 0, 12, 20, _p2_param_Bsq, 1, 8, 5, 140, 1, 23, _p2_param_scM1, _p2_param_stdev1sq, 2, 12, _p2_param_scM2, _p2_param_stdev2sq}};
static const abdlop_params_t _p2_param_quad_eval_ = {{ _p2_param_ring, _p2_param_dcomp, 85, 64, 9, 3, 20, _p2_param_Bsq, 1, 8, 5, 140, 1, 23, _p2_param_scM1, _p2_param_stdev1sq, 2, 12, _p2_param_scM2, _p2_param_stdev2sq}};
static const abdlop_params_t _p2_param_quad_many_ = {{ _p2_param_ring, _p2_param_dcomp, 85, 64, 11, 1, 20, _p2_param_Bsq, 1, 8, 5, 140, 1, 23, _p2_param_scM1, _p2_param_stdev1sq, 2, 12, _p2_param_scM2, _p2_param_stdev2sq}};
static const lnp_quad_eval_params_t _p2_param_quad_eval = {{ _p2_param_quad_eval_, _p2_param_quad_many_, 4}};
static const lnp_tbox_params_t _p2_param = {{ _p2_param_tbox, _p2_param_quad_eval, 8, _p2_param_n, 14, 10, 85, 2, 18, _p2_param_scM3, _p2_param_stdev3sq, 2, 30, _p2_param_scM4, _p2_param_stdev4sq, _p2_param_Bz3sqr, _p2_param_Bz4, &_p2_param_l2Bsq[0], _p2_param_inv4, 37768UL }};

static const unsigned int p2_param_Ps[8] = {16, 17, 18, 19, 20, 21, 22, 23};
static const unsigned int p2_param_Es0[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned int p2_param_Es1[16] = {24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39};
static const unsigned int p2_param_Es2[1] = {40};
static const unsigned int p2_param_Es3[1] = {41};
static const unsigned int p2_param_Es4[1] = {42};
static const unsigned int p2_param_Es5[1] = {43};
static const unsigned int p2_param_Es6[1] = {44};
static const unsigned int p2_param_Es7[10] = {45, 46, 47, 48, 49, 50, 51, 52, 53, 54};
static const unsigned int p2_param_Es8[10] = {55, 56, 57, 58, 59, 60, 61, 62, 63, 64};
static const unsigned int p2_param_Es9[10] = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74};
static const unsigned int *p2_param_Es[10] = { p2_param_Es0, p2_param_Es1, p2_param_Es2, p2_param_Es3, p2_param_Es4, p2_param_Es5, p2_param_Es6, p2_param_Es7, p2_param_Es8, p2_param_Es9, };
static const unsigned int p2_param_Es_nrows[10] = {16, 16, 1, 1, 1, 1, 1, 10, 10, 10};

static const limb_t p2_param_p_limbs[] = {12289UL};
static const int_t p2_param_p = {{(limb_t *)p2_param_p_limbs, 1, 0}};
static const limb_t p2_param_pinv_limbs[] = {449297187985701UL};
static const int_t p2_param_pinv = {{(limb_t *)p2_param_pinv_limbs, 1, 0}};
static const unsigned int p2_param_s1_indices[75] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74};
static const lin_params_t p2_param = {{ _p2_param, 64, p2_param_p, p2_param_pinv, 1, p2_param_s1_indices, 75, NULL, 0,  p2_param_Ps, 8, p2_param_Es, p2_param_Es_nrows, NULL, NULL }};

// auto-generated by lnp-tbox.sage.
// 
// protocol is statistically complete with correctness error >= 1 - 2^(-4)
// protocol is simulatable under MLWE(24,29,[-1,1])
// protocol is knowledge-sound with knowledge error <= 2^(-127.0) under MSIS(17,64,2^(32.245587))
// 
// Ring
// degree d = 64
// modulus q = 274877906957, log(q) ~ 38.0
// factors q = q1
// 
// Compression
// D = 7
// gamma = 63806, log(gamma) ~ 15.961404
// 
// Dimensions of secrets
// s1: m1 = 11
// m: l = 0
// s2: m2 = 53
// 
// Size of secrets
// l2(s1) <= alpha = 75.0
// m unbounded
// s2 uniform in [-nu,nu] = [-1,1]
// 
// Norm proofs
// binary: no
// exact euclidean: yes (dimensions: [1, 10], bounds: [64.0, 39.0])
// approximate infinity: yes (psi: 2441.591, dimension: 2, bound: 2816.2708)
// 
// Challenge space
// c uniform in [-omega,omega] = [-8,8], o(c)=c, sqrt(l1(o(c)*c)) <= eta = 140
// 
// Standard deviations
// stdev1 = 101580.8, log(stdev1/1.55) = 16.0
// stdev2 = 6348.8, log(stdev2/1.55) = 12.0
// stdev3 = 6348.8, log(stdev3/1.55) = 12.0
// stdev4 = 203161.6, log(stdev4/1.55) = 17.0
// 
// Repetition rate
// M1 = 4.0689959
// M2 = 2.2812077
// M3 = 1.024307
// M4 = 1.0329091
// total = 9.8207425
// 
// Security
// MSIS dimension: 17
// MSIS root hermite factor: 1.0043676
// MLWE dimension: 24
// MLWE root hermite factor: 1.0043905
// 
// Proof size
// ~ 16.5410156250000 KiB
// 
// 50 bit moduli for degree 64: [1125899906840833, 1125899906839937]
// bit length of products: [49, 99]
// inverses: [1, -162099428551732]

#include "lazer.h"
static const limb_t _popen_param_q_limbs[] = {274877906957UL};
static const int_t _popen_param_q = {{(limb_t *)_popen_param_q_limbs, 1, 0}};
static const limb_t _popen_param_qminus1_limbs[] = {274877906956UL};
static const int_t _popen_param_qminus1 = {{(limb_t *)_popen_param_qminus1_limbs, 1, 0}};
static const limb_t _popen_param_m_limbs[] = {4308026UL};
static const int_t _popen_param_m = {{(limb_t *)_popen_param_m_limbs, 1, 0}};
static const limb_t _popen_param_mby2_limbs[] = {2154013UL};
static const int_t _popen_param_mby2 = {{(limb_t *)_popen_param_mby2_limbs, 1, 0}};
static const limb_t _popen_param_gamma_limbs[] = {63806UL};
static const int_t _popen_param_gamma = {{(limb_t *)_popen_param_gamma_limbs, 1, 0}};
static const limb_t _popen_param_gammaby2_limbs[] = {31903UL};
static const int_t _popen_param_gammaby2 = {{(limb_t *)_popen_param_gammaby2_limbs, 1, 0}};
static const limb_t _popen_param_pow2D_limbs[] = {128UL};
static const int_t _popen_param_pow2D = {{(limb_t *)_popen_param_pow2D_limbs, 1, 0}};
static const limb_t _popen_param_pow2Dby2_limbs[] = {64UL};
static const int_t _popen_param_pow2Dby2 = {{(limb_t *)_popen_param_pow2Dby2_limbs, 1, 0}};
static const limb_t _popen_param_Bsq_limbs[] = {3499813672292UL, 0UL};
static const int_t _popen_param_Bsq = {{(limb_t *)_popen_param_Bsq_limbs, 2, 0}};
static const limb_t _popen_param_scM1_limbs[] = {9407459591107526497UL, 1272748988834360916UL, 4UL};
static const int_t _popen_param_scM1 = {{(limb_t *)_popen_param_scM1_limbs, 3, 0}};
static const limb_t _popen_param_scM2_limbs[] = {7258830161512368918UL, 5187366606047591109UL, 2UL};
static const int_t _popen_param_scM2 = {{(limb_t *)_popen_param_scM2_limbs, 3, 0}};
static const limb_t _popen_param_scM3_limbs[] = {12222213063317422069UL, 448385836234265775UL, 1UL};
static const int_t _popen_param_scM3 = {{(limb_t *)_popen_param_scM3_limbs, 3, 0}};
static const limb_t _popen_param_scM4_limbs[] = {6132087144669454319UL, 607065038373856493UL, 1UL};
static const int_t _popen_param_scM4 = {{(limb_t *)_popen_param_scM4_limbs, 3, 0}};
static const limb_t _popen_param_stdev1sq_limbs[] = {10318658929UL, 0UL};
static const int_t _popen_param_stdev1sq = {{(limb_t *)_popen_param_stdev1sq_limbs, 2, 0}};
static const limb_t _popen_param_stdev2sq_limbs[] = {40307261UL, 0UL};
static const int_t _popen_param_stdev2sq = {{(limb_t *)_popen_param_stdev2sq_limbs, 2, 0}};
static const limb_t _popen_param_stdev3sq_limbs[] = {40307261UL, 0UL};
static const int_t _popen_param_stdev3sq = {{(limb_t *)_popen_param_stdev3sq_limbs, 2, 0}};
static const limb_t _popen_param_stdev4sq_limbs[] = {41274635715UL, 0UL};
static const int_t _popen_param_stdev4sq = {{(limb_t *)_popen_param_stdev4sq_limbs, 2, 0}};
static const limb_t _popen_param_inv2_limbs[] = {137438953478UL};
static const int_t _popen_param_inv2 = {{(limb_t *)_popen_param_inv2_limbs, 1, 1}};
static const limb_t _popen_param_inv4_limbs[] = {68719476739UL};
static const int_t _popen_param_inv4 = {{(limb_t *)_popen_param_inv4_limbs, 1, 1}};
static const unsigned int _popen_param_n[2] = {1, 10};
static const limb_t _popen_param_Bz3sqr_limbs[] = {27753065054UL, 0UL};
static const int_t _popen_param_Bz3sqr = {{(limb_t *)_popen_param_Bz3sqr_limbs, 2, 0}};
static const limb_t _popen_param_Bz4_limbs[] = {3250585UL};
static const int_t _popen_param_Bz4 = {{(limb_t *)_popen_param_Bz4_limbs, 1, 0}};
static const limb_t _popen_param_Pmodq_limbs[] = {3078606465UL};
static const int_t _popen_param_Pmodq = {{(limb_t *)_popen_param_Pmodq_limbs, 1, 0}};
static const limb_t _popen_param_l2Bsq0_limbs[] = {4096UL};
static const int_t _popen_param_l2Bsq0 = {{(limb_t *)_popen_param_l2Bsq0_limbs, 1, 0}};
static const limb_t _popen_param_l2Bsq1_limbs[] = {1521UL};
static const int_t _popen_param_l2Bsq1 = {{(limb_t *)_popen_param_l2Bsq1_limbs, 1, 0}};
static const limb_t _popen_param_Ppmodq_0_limbs[] = {55935UL};
static const int_t _popen_param_Ppmodq_0 = {{(limb_t *)_popen_param_Ppmodq_0_limbs, 1, 1}};
static const limb_t _popen_param_Ppmodq_1_limbs[] = {55039UL};
static const int_t _popen_param_Ppmodq_1 = {{(limb_t *)_popen_param_Ppmodq_1_limbs, 1, 1}};
static const int_srcptr _popen_param_l2Bsq[] = {_popen_param_l2Bsq0, _popen_param_l2Bsq1};
static const int_srcptr _popen_param_Ppmodq[] = {_popen_param_Ppmodq_0, _popen_param_Ppmodq_1};
static const polyring_t _popen_param_ring = {{_popen_param_q, 64, 39, 6, moduli_d64, 2, _popen_param_Pmodq, _popen_param_Ppmodq, _popen_param_inv2}};
static const dcompress_params_t _popen_param_dcomp = {{ _popen_param_q, _popen_param_qminus1, _popen_param_m, _popen_param_mby2, _popen_param_gamma, _popen_param_gammaby2, _popen_param_pow2D, _popen_param_pow2Dby2, 7, 0, 23 }};
static const abdlop_params_t _popen_param_tbox = {{ _popen_param_ring, _popen_param_dcomp, 13, 53, 0, 12, 17, _popen_param_Bsq, 1, 8, 5, 140, 1, 16, _popen_param_scM1, _popen_param_stdev1sq, 2, 12, _popen_param_scM2, _popen_param_stdev2sq}};
static const abdlop_params_t _popen_param_quad_eval_ = {{ _popen_param_ring, _popen_param_dcomp, 13, 53, 9, 3, 17, _popen_param_Bsq, 1, 8, 5, 140, 1, 16, _popen_param_scM1, _popen_param_stdev1sq, 2, 12, _popen_param_scM2, _popen_param_stdev2sq}};
static const abdlop_params_t _popen_param_quad_many_ = {{ _popen_param_ring, _popen_param_dcomp, 13, 53, 11, 1, 17, _popen_param_Bsq, 1, 8, 5, 140, 1, 16, _popen_param_scM1, _popen_param_stdev1sq, 2, 12, _popen_param_scM2, _popen_param_stdev2sq}};
static const lnp_quad_eval_params_t _popen_param_quad_eval = {{ _popen_param_quad_eval_, _popen_param_quad_many_, 4}};
static const lnp_tbox_params_t _popen_param = {{ _popen_param_tbox, _popen_param_quad_eval, 0, _popen_param_n, 2, 2, 13, 2, 12, _popen_param_scM3, _popen_param_stdev3sq, 2, 17, _popen_param_scM4, _popen_param_stdev4sq, _popen_param_Bz3sqr, _popen_param_Bz4, &_popen_param_l2Bsq[0], _popen_param_inv4, 16938UL }};

static const unsigned int popen_param_Es0[1] = {0};
static const unsigned int popen_param_Es1[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static const unsigned int *popen_param_Es[2] = { popen_param_Es0, popen_param_Es1, };
static const unsigned int popen_param_Es_nrows[2] = {1, 10};

static const limb_t popen_param_p_limbs[] = {12289UL};
static const int_t popen_param_p = {{(limb_t *)popen_param_p_limbs, 1, 0}};
static const limb_t popen_param_pinv_limbs[] = {120405872988UL};
static const int_t popen_param_pinv = {{(limb_t *)popen_param_pinv_limbs, 1, 0}};
static const unsigned int popen_param_s1_indices[11] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
static const lin_params_t popen_param = {{ _popen_param, 64, popen_param_p, popen_param_pinv, 1, popen_param_s1_indices, 11, NULL, 0,  NULL, 0, popen_param_Es, popen_param_Es_nrows, NULL, NULL }};

