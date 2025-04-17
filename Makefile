CFLAGS_FALCON_AMD64 = -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA
CFLAGS_WARN = -Wall -Wextra
CFLAGS_DEFAULT = $(CFLAGS_WARN) -O3 -g -march=native -mtune=native\
 -fomit-frame-pointer
CFLAGS_DEBUG = $(CFLAGS_WARN) -Og -ggdb3
ADD_CPPFLAGS = -DNDEBUG

CPPFLAGS += $(ADD_CPPFLAGS)
LIBS = -lm $(HEXL_DIR)/build/hexl/lib64/libhexl.a -lstdc++

# honor user CFLAGS
ifdef CFLAGS
buildstr = custom
else
ifeq ($(build),debug)
buildstr = debug
CFLAGS = $(CFLAGS_DEBUG)
else
buildstr = default
CFLAGS = $(CFLAGS_DEFAULT) $(CFLAGS_FALCON_AMD64) # XXX
endif
endif

# for rejection sampling,
# must be inked before libgmp
ifndef libmpfr
libmpfr = -lmpfr
endif
LIBS += $(libmpfr)

# for low level constant-time ops
ifndef libgmp
libgmp = -lgmp
endif
LIBS += $(libgmp)

.PHONY: default all
default: lib
all: lib-all


THIRD_PARTY_DIR = third_party

#### third party falcon

FALCON_SUBDIR = Falcon-impl-20211101
FALCON_DIR = $(THIRD_PARTY_DIR)/$(FALCON_SUBDIR)
FALCON_ZIP = $(FALCON_DIR).zip
FALCON_OBJ_STATIC = \
	$(FALCON_DIR)/codec_static.o \
	$(FALCON_DIR)/common_static.o \
	$(FALCON_DIR)/falcon_static.o \
	$(FALCON_DIR)/fft_static.o \
	$(FALCON_DIR)/fpr_static.o \
	$(FALCON_DIR)/keygen_static.o \
	$(FALCON_DIR)/rng_static.o \
	$(FALCON_DIR)/shake_static.o \
	$(FALCON_DIR)/sign_static.o \
	$(FALCON_DIR)/vrfy_static.o
FALCON_OBJ_SHARED = \
	$(FALCON_DIR)/codec_shared.o \
	$(FALCON_DIR)/common_shared.o \
	$(FALCON_DIR)/falcon_shared.o \
	$(FALCON_DIR)/fft_shared.o \
	$(FALCON_DIR)/fpr_shared.o \
	$(FALCON_DIR)/keygen_shared.o \
	$(FALCON_DIR)/rng_shared.o \
	$(FALCON_DIR)/shake_shared.o \
	$(FALCON_DIR)/sign_shared.o \
	$(FALCON_DIR)/vrfy_shared.o
FALCON_INC = \
	$(FALCON_DIR)/config.h \
	$(FALCON_DIR)/falcon.h \
	$(FALCON_DIR)/fpr.h \
	$(FALCON_DIR)/inner.h
FALCON_SRC = \
	$(FALCON_DIR)/codec.c \
	$(FALCON_DIR)/common.c \
	$(FALCON_DIR)/falcon.c \
	$(FALCON_DIR)/fft.c \
	$(FALCON_DIR)/fpr.c \
	$(FALCON_DIR)/keygen.c \
	$(FALCON_DIR)/rng.c \
	$(FALCON_DIR)/shake.c \
	$(FALCON_DIR)/sign.c \
	$(FALCON_DIR)/vrfy.c

$(FALCON_DIR)/config.h: $(FALCON_DIR)
$(FALCON_DIR)/falcon.h: $(FALCON_DIR)
$(FALCON_DIR)/fpr.h: $(FALCON_DIR)
$(FALCON_DIR)/inner.h: $(FALCON_DIR)

$(FALCON_DIR)/codec.c: $(FALCON_DIR)
$(FALCON_DIR)/common.c: $(FALCON_DIR)
$(FALCON_DIR)/falcon.c: $(FALCON_DIR)
$(FALCON_DIR)/fft.c: $(FALCON_DIR)
$(FALCON_DIR)/fpr.c: $(FALCON_DIR)
$(FALCON_DIR)/keygen.c: $(FALCON_DIR)
$(FALCON_DIR)/rng.c: $(FALCON_DIR)
$(FALCON_DIR)/shake.c: $(FALCON_DIR)
$(FALCON_DIR)/sign.c: $(FALCON_DIR)
$(FALCON_DIR)/vrfy.c: $(FALCON_DIR)

$(FALCON_DIR): $(FALCON_ZIP)
	cd $(THIRD_PARTY_DIR) && unzip $(FALCON_SUBDIR).zip
	patch -d $(FALCON_DIR) -p1 < src/falcon.patch


$(FALCON_DIR)/codec_static.o: $(FALCON_DIR)/codec.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/codec_static.o $(FALCON_DIR)/codec.c

$(FALCON_DIR)/common_static.o: $(FALCON_DIR)/common.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/common_static.o $(FALCON_DIR)/common.c

$(FALCON_DIR)/falcon_static.o: $(FALCON_DIR)/falcon.c $(FALCON_DIR)/falcon.h $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/falcon_static.o $(FALCON_DIR)/falcon.c

$(FALCON_DIR)/fft_static.o: $(FALCON_DIR)/fft.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/fft_static.o $(FALCON_DIR)/fft.c

$(FALCON_DIR)/fpr_static.o: $(FALCON_DIR)/fpr.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/fpr_static.o $(FALCON_DIR)/fpr.c

$(FALCON_DIR)/keygen_static.o: $(FALCON_DIR)/keygen.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/keygen_static.o $(FALCON_DIR)/keygen.c

$(FALCON_DIR)/rng_static.o: $(FALCON_DIR)/rng.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/rng_static.o $(FALCON_DIR)/rng.c

$(FALCON_DIR)/shake_static.o: $(FALCON_DIR)/shake.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/shake_static.o $(FALCON_DIR)/shake.c

$(FALCON_DIR)/sign_static.o: $(FALCON_DIR)/sign.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/sign_static.o $(FALCON_DIR)/sign.c

$(FALCON_DIR)/vrfy_static.o: $(FALCON_DIR)/vrfy.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -o $(FALCON_DIR)/vrfy_static.o $(FALCON_DIR)/vrfy.c


$(FALCON_DIR)/codec_shared.o: $(FALCON_DIR)/codec.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/codec_shared.o $(FALCON_DIR)/codec.c

$(FALCON_DIR)/common_shared.o: $(FALCON_DIR)/common.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/common_shared.o $(FALCON_DIR)/common.c

$(FALCON_DIR)/falcon_shared.o: $(FALCON_DIR)/falcon.c $(FALCON_DIR)/falcon.h $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/falcon_shared.o $(FALCON_DIR)/falcon.c

$(FALCON_DIR)/fft_shared.o: $(FALCON_DIR)/fft.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/fft_shared.o $(FALCON_DIR)/fft.c

$(FALCON_DIR)/fpr_shared.o: $(FALCON_DIR)/fpr.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/fpr_shared.o $(FALCON_DIR)/fpr.c

$(FALCON_DIR)/keygen_shared.o: $(FALCON_DIR)/keygen.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/keygen_shared.o $(FALCON_DIR)/keygen.c

$(FALCON_DIR)/rng_shared.o: $(FALCON_DIR)/rng.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/rng_shared.o $(FALCON_DIR)/rng.c

$(FALCON_DIR)/shake_shared.o: $(FALCON_DIR)/shake.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/shake_shared.o $(FALCON_DIR)/shake.c

$(FALCON_DIR)/sign_shared.o: $(FALCON_DIR)/sign.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/sign_shared.o $(FALCON_DIR)/sign.c

$(FALCON_DIR)/vrfy_shared.o: $(FALCON_DIR)/vrfy.c $(FALCON_DIR)/config.h $(FALCON_DIR)/inner.h $(FALCON_DIR)/fpr.h
	$(CC) $(CFLAGS) -I$(FALCON_DIR) -c -fPIC -o $(FALCON_DIR)/vrfy_shared.o $(FALCON_DIR)/vrfy.c


#### third party hexl

HEXL_SUBDIR = hexl-development
HEXL_DIR = $(THIRD_PARTY_DIR)/$(HEXL_SUBDIR)
HEXL_ZIP = $(HEXL_DIR).zip

$(HEXL_DIR): $(HEXL_ZIP)
	cd $(THIRD_PARTY_DIR) && unzip $(HEXL_SUBDIR).zip
	cd $(HEXL_DIR) && cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF
	cd $(HEXL_DIR) && cmake --build build
#	cd $(HEXL_DIR) && cmake -S . -B build -DHEXL_SHARED_LIB=ON
#	cd $(HEXL_DIR) && cmake --build build

#### lib hash 


HASH_DIR = src/lattice-hash
HASH_INC = \
	$(HASH_DIR)/src/data.h \
	$(HASH_DIR)/src/hash.h
HASH_SRC = $(HASH_DIR)/src/hash.c

libhash.so: $(HASH_INC) $(HASH_SRC) src/hexl_shared.o libhexl_wrapper.so
	$(CC) $(CFLAGS) -I$(HASH_DIR)/src -I$(HEXL_DIR)/hexl/include -fPIC -shared -o $@ $(HASH_SRC) $(LIBS) libhexl_wrapper.so src/hexl_shared.o

libhexl_wrapper.so: $(HASH_DIR)/src/hexl_wrapper.cpp
	 $(CC) $(CFLAGS) -I$(HASH_DIR)/src -I$(HEXL_DIR)/hexl/include -fPIC -shared -o $@ $< src/hexl_shared.o

#### lib labrador

LABRADOR_CFLAGS = -std=gnu2x -Wall -Wextra -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -Wno-unused-function -fmax-errors=1 -flto=auto \
  -fwrapv -ffast-math -march=native -mtune=native -O3 -DNDEBUG -fvisibility=hidden 
LABRADOR_LIBS = -lmvec -lm

LABRADOR_DIR = src/labrados
LABRADOR_INC = \
	$(LABRADOR_DIR)/aesctr.h \
	$(LABRADOR_DIR)/comkey.h \
	$(LABRADOR_DIR)/constraints.h\
	$(LABRADOR_DIR)/cpucycles.h \
	$(LABRADOR_DIR)/dachshund.h \
	$(LABRADOR_DIR)/data.h \
	$(LABRADOR_DIR)/fips202.h \
	$(LABRADOR_DIR)/gaussian.h \
	$(LABRADOR_DIR)/jlproj.h \
	$(LABRADOR_DIR)/labradoodle.h \
	$(LABRADOR_DIR)/labrador_core.h \
	$(LABRADOR_DIR)/labrador_tail.h \
	$(LABRADOR_DIR)/labrador.h \
	$(LABRADOR_DIR)/lnp.h \
	$(LABRADOR_DIR)/pack.h \
	$(LABRADOR_DIR)/polx.h \
	$(LABRADOR_DIR)/poly.h \
	$(LABRADOR_DIR)/polz.h \
	$(LABRADOR_DIR)/proofsystem.h \
	$(LABRADOR_DIR)/randombytes.h \
	$(LABRADOR_DIR)/rejection.h \
	$(LABRADOR_DIR)/malloc.h \
	$(LABRADOR_DIR)/labrados_python.h \
	$(LABRADOR_DIR)/timing.h
LABRADOR_SRC = \
	$(LABRADOR_DIR)/aesctr.c \
	$(LABRADOR_DIR)/comkey.c \
	$(LABRADOR_DIR)/constraints.c\
	$(LABRADOR_DIR)/cpucycles.c \
	$(LABRADOR_DIR)/dachshund.c \
	$(LABRADOR_DIR)/data.c \
	$(LABRADOR_DIR)/fips202.c \
	$(LABRADOR_DIR)/gaussian.c \
	$(LABRADOR_DIR)/jlproj.c \
	$(LABRADOR_DIR)/labradoodle.c \
	$(LABRADOR_DIR)/labrador_core.c \
	$(LABRADOR_DIR)/labrador_tail.c \
	$(LABRADOR_DIR)/labrador.c \
	$(LABRADOR_DIR)/lnp.c \
	$(LABRADOR_DIR)/ntt.c \
	$(LABRADOR_DIR)/pack.c \
	$(LABRADOR_DIR)/polx.c \
	$(LABRADOR_DIR)/poly.c \
	$(LABRADOR_DIR)/polz.c \
	$(LABRADOR_DIR)/proofsystem.c \
	$(LABRADOR_DIR)/randombytes.c \
	$(LABRADOR_DIR)/rejection.c \
	$(LABRADOR_DIR)/labrados_python.c \
	$(LABRADOR_DIR)/timing.c

liblabrador32.so: $(LABRADOR_SRC) $(LABRADOR_INC)
	$(CC) $(LABRADOR_CFLAGS) -I$(LABRADOR_DIR) -DLOGQ=32 -shared -fvisibility=hidden -fPIC -o liblabrador32.so $(LABRADOR_SRC) $(LABRADOR_LIBS)

liblabrador36.so: $(LABRADOR_SRC) $(LABRADOR_INC)
	$(CC) $(LABRADOR_CFLAGS) -I$(LABRADOR_DIR) -DLOGQ=36 -shared -fvisibility=hidden -fPIC -o liblabrador36.so $(LABRADOR_SRC) $(LABRADOR_LIBS)

liblabrador38.so: $(LABRADOR_SRC) $(LABRADOR_INC)
	$(CC) $(LABRADOR_CFLAGS) -I$(LABRADOR_DIR) -DLOGQ=38 -shared -fvisibility=hidden -fPIC -o liblabrador38.so $(LABRADOR_SRC) $(LABRADOR_LIBS)


#### lib lazer

LIBSOURCES = \
 src/lazer.c \
 src/abdlop.c \
 src/aes256ctr.h \
 src/aes256ctr.c \
 src/aes256ctr-amd64.c \
 src/blindsig-p1-params.h \
 src/blindsig-p2-params.h \
 src/blindsig.h \
 src/blindsig.c \
 src/brandom.h \
 src/brandom.c \
 src/bytes.c \
 src/coder.c \
 src/dcompress.c \
 src/dom.h \
 src/dump.c \
 src/grandom.h \
 src/grandom.c \
 src/int.c \
 src/intmat.c \
 src/intvec.h \
 src/intvec.c \
 src/lazer-in1.h \
 src/lazer-in2.h \
 src/lin-proofs.c \
 src/lnp.c \
 src/lnp-quad.c \
 src/lnp-quad-eval.c \
 src/lnp-quad-many.c \
 src/lnp-tbox.h \
 src/lnp-tbox.c \
 src/memory.c \
 src/memory.h \
 src/mont.h \
 src/poly.h \
 src/poly.c \
 src/polymat.c \
 src/polyring.c \
 src/polyvec.c \
 src/quad.c \
 src/rejection.c \
 src/rng.h \
 src/rng.c \
 src/shake128.h \
 src/shake128.c \
 src/spolymat.c \
 src/spolyvec.c \
 src/stopwatch.h \
 src/stopwatch.c \
 src/urandom.h \
 src/urandom.c \
 src/version.c

#src/ntt.c \
#src/ntt.h \

TESTS = \
 tests/lazer-test \
 tests/bytes-test \
 tests/shake128-test \
 tests/rng-test \
 tests/int-test \
 tests/intvec-test \
 tests/intmat-test \
 tests/polyring-test \
 tests/poly-test \
 tests/polyvec-test \
 tests/polymat-test \
 tests/spolymat-test \
 tests/quad-test \
 tests/dcompress-test \
 tests/sage-test \
 tests/sage-test.sage \
 tests/valgrind-test \
 tests/coder-test \
 tests/urandom-test \
 tests/brandom-test \
 tests/grandom-test \
 tests/rejection-test \
 tests/abdlop-test \
 tests/lnp-quad-test \
 tests/lnp-quad-many-test \
 tests/lnp-quad-eval-test \
 tests/lnp-tbox-test


TEXSOURCES = \
 doc/references.bib \
 doc/index.tex \
 doc/introduction.tex \
 doc/interface.tex \
 doc/changelog.tex


.PHONY: lib lib-all lib-static lib-shared lib-static-all lib-shared-all
lib-all: lazer.h lib-static-all lib-shared-all
lib: lazer.h lib-static lib-shared

lib-shared-all: lazer.h liblazer.so liblabrador32.so liblabrador36.so liblabrador38.so libhash.so
lib-shared: lazer.h liblazer.so libhash.so
lib-static-all: lazer.h liblazer.a
lib-static: lazer.h liblazer.a

liblazer.a: src/lazer_static.o src/hexl_static.o $(FALCON_OBJ_STATIC)
	ar rcs liblazer.a src/lazer_static.o src/hexl_static.o $(FALCON_OBJ_STATIC)

liblazer.so: src/lazer_shared.o  src/hexl_shared.o $(FALCON_OBJ_SHARED)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -shared -o liblazer.so src/lazer_shared.o src/hexl_shared.o $(FALCON_OBJ_SHARED)

src/lazer_static.o: $(LIBSOURCES) lazer.h $(FALCON_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(FALCON_DIR) -I. -c -o src/lazer_static.o src/lazer.c

src/lazer_shared.o: $(LIBSOURCES) lazer.h $(FALCON_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(FALCON_DIR) -I. -c -fPIC -o src/lazer_shared.o src/lazer.c

src/hexl_static.o: src/hexl.h $(HEXL_DIR)
	$(CXX) $(CPPFLAGS) $(CFLAGS) -Isrc -I$(HEXL_DIR)/hexl/include -c -o src/hexl_static.o src/hexl.cpp

src/hexl_shared.o: src/hexl.h $(HEXL_DIR)
	$(CXX) $(CPPFLAGS) $(CFLAGS) -Isrc -I$(HEXL_DIR)/hexl/include -c -fPIC -o src/hexl_shared.o src/hexl.cpp

lazer.h: src/lazer-in1.h src/lazer-in2.h src/moduli.h config.h
	cat src/lazer-in1.h > lazer.h
	echo "" >> lazer.h

	echo "#ifndef LAZER_CONFIG_H" >> lazer.h
	echo "#define LAZER_CONFIG_H" >> lazer.h
	echo "" >> lazer.h
	cat config.h >> lazer.h
	echo "" >> lazer.h
	echo "#endif" >> lazer.h
	echo "" >> lazer.h

	cat src/lazer-in2.h >> lazer.h
	echo "" >> lazer.h

	cat src/moduli.h >> lazer.h

TESTDEPS = tests/test.h tests/test.o lazer.h liblazer.a
TESTLIBS = tests/test.o liblazer.a $(LIBS)

.PHONY: check
check: $(TESTS)
	cd tests && ./run-tests

tests/test.o: tests/test.c tests/test.h lazer.h liblazer.a
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -c -o $@ $<

tests/lazer-test: tests/lazer-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/bytes-test: tests/bytes-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/shake128-test: tests/shake128-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/rng-test: tests/rng-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/int-test: tests/int-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/intvec-test: tests/intvec-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/intmat-test: tests/intmat-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/polyring-test: tests/polyring-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/poly-test: tests/poly-test.c $(TESTDEPS) tests/abdlop-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/polyvec-test: tests/polyvec-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/polymat-test: tests/polymat-test.c $(TESTDEPS) tests/abdlop-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/spolymat-test: tests/spolymat-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/quad-test: tests/quad-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/dcompress-test: tests/dcompress-test.c $(TESTDEPS) tests/abdlop-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/sage-test: tests/sage-test.c $(TESTDEPS) tests/abdlop-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/sage-test.sage: tests/sage-test
	./tests/sage-test > $@

tests/valgrind-test: tests/valgrind-test.c $(TESTDEPS) tests/abdlop-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/coder-test: tests/coder-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/urandom-test: tests/urandom-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/brandom-test: tests/brandom-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/grandom-test: tests/grandom-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/rejection-test: tests/rejection-test.c $(TESTDEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/abdlop-test: tests/abdlop-test.c $(TESTDEPS) tests/abdlop-params1.h tests/abdlop-params2.h tests/abdlop-params3.h tests/abdlop-params4.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/lnp-quad-test: tests/lnp-quad-test.c $(TESTDEPS) tests/lnp-quad-params1.h tests/lnp-quad-params2.h tests/lnp-quad-params3.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/lnp-quad-many-test: tests/lnp-quad-many-test.c $(TESTDEPS) tests/lnp-quad-params1.h tests/lnp-quad-params2.h tests/lnp-quad-params3.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/lnp-quad-eval-test: tests/lnp-quad-eval-test.c $(TESTDEPS) tests/lnp-quad-eval-params1.h tests/lnp-quad-eval-params2.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)

tests/lnp-tbox-test: tests/lnp-tbox-test.c $(TESTDEPS) tests/lnp-tbox-params1.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -I. -o $@ $< $(TESTLIBS)


.PHONY: pdf
pdf: doc/pdf/lazer_manual.pdf

doc/pdf/lazer_manual.pdf: $(TEXSOURCES)
	mkdir -p doc/pdf
	cd doc && latexmk -norc -pdf -bibtex -usepretex='\def\lazermanualpdf{}' index.tex
	cp doc/index.pdf doc/pdf/lazer_manual.pdf


.PHONY: html
html: doc/html/index.html

doc/html/index.html: $(TEXSOURCES) doc/pdf/lazer_manual.pdf # rely on latexmk for bibtex
	mkdir -p doc/html
	cd doc && make4ht index.tex "mathjax,2,next" -d html


.PHONY: html
clean:
	rm -f lazer.h liblazer.a liblazer.so liblabrador.a liblabrador.so  liblabrador32.so  liblabrador36.so  liblabrador38.so  libhash.so libhexl_wrapper.so
	cd scripts && rm -f moduli.sage.py lnp-codegen.sage.py abdlop-codegen.sage.py lnp-quad-codegen.sage.py lnp-quad-eval-codegen.sage.py lnp-tbox-codegen.sage.py lin-codegen.sage.py
	cd src && rm -f *.o
	cd src/labrados && rm -f *.o
	cd $(THIRD_PARTY_DIR) && rm -rf $(FALCON_SUBDIR)
	cd $(THIRD_PARTY_DIR) && rm -rf $(HEXL_SUBDIR)
	cd tests && rm -f *.o *.dSYM && cd .. && rm -f $(TESTS) && rm -f sage-test.sage.py

