CC = g++
GCC = gcc
INCLUDE_DIRS = ./src/hexl/hexl/include/
FLAGS = -Wall -Wno-unused-function -Wno-unused-result -funroll-all-loops \
        -march=native -lm -Wno-sign-compare -Wno-write-strings -mavx512f -mavx512dq
OPT_FLAGS = -O3 -fwhole-program -flto $(FLAGS)
DEBUG_FLAGS = -O0 -g $(FLAGS)
LD_LIBS = hexl
LIB_DIRS = ./src/hexl/build/hexl/lib ./src/hexl/build/hexl/lib64
LIBS += $(addprefix -L, $(LIB_DIRS)) $(addprefix -l, $(LD_LIBS))
INCLUDE_FLAGS = $(addprefix -I, $(INCLUDE_DIRS))
FLAGS += $(INCLUDE_FLAGS)
LIB_FLAGS = -O3 $(FLAGS)

HASH_SRC = src/hash.c
HASH_LIB = libhash.so
TEST_BIN = test
HEXLLIB_SRC = src/hexl_wrapper.cpp
HEXLLIB = libhexl_wrapper.so
HASH_LIB_FLAGS = -O3 $(FLAGS)
GENERATOR_SRC = src/generate_data.c
GENERATOR_BIN = generate_data
DATA_HEADER = src/data.h

.PHONY: all clean wrapper hexl run_test

all: $(HASH_LIB) $(TEST_BIN)

$(HEXLLIB): $(HEXLLIB_SRC)
	$(CC) -std=c++17 -fPIC -shared -o $@ $< $(OPT_FLAGS) $(LIBS)

$(GENERATOR_BIN): $(GENERATOR_SRC) $(HEXLLIB)
	$(GCC) -std=c11 -o $@ $(GENERATOR_SRC) $(FLAGS) -L. -lhexl_wrapper

$(DATA_HEADER): $(GENERATOR_BIN)
	LD_LIBRARY_PATH=. ./$(GENERATOR_BIN)

$(HASH_LIB): $(HASH_SRC) src/hash.h $(DATA_HEADER) $(HEXLLIB)
	$(GCC) -std=c11 -fPIC -shared -o $@ $(HASH_SRC) $(HASH_LIB_FLAGS) -L. -lhexl_wrapper

$(TEST_BIN): src/test.c $(HASH_LIB) $(DATA_HEADER)
	$(GCC) -std=c11 -o $@ src/test.c -L. -lhash -lhexl_wrapper 

run_test: $(TEST_BIN)
	LD_LIBRARY_PATH=. ./$(TEST_BIN)

wrapper: $(HEXLLIB)

hexl: hexl/build
	cmake --build ./src/hexl/build

hexl/build:
	cmake -S ./src/hexl/ -B ./src/hexl/build -DCMAKE_POLICY_VERSION_MINIMUM=3.5

clean:
	rm -f $(HASH_LIB) $(TEST_BIN) $(HEXLLIB)
