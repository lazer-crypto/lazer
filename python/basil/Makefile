.PHONY: all clean

all: _basil_params_cffi.o

_basil_params_cffi.o: basil_params.h ../_lazer_cffi.o
	python3 ../params_cffi_build.py basil_params.h ../..

basil_params.h: basil_p1_params.py basil_p2_params.py
	cd ../../scripts && sage lin-codegen.sage ../python/basil/basil_p1_params.py > ../python/basil/basil_params.h
	cd ../../scripts && sage lin-codegen.sage ../python/basil/basil_p2_params.py >> ../python/basil/basil_params.h

../_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
