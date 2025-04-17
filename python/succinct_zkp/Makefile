.PHONY: all clean

all: _blns_params_cffi.o

_blns_params_cffi.o: blns_params.h ../_lazer_cffi.o
	python3 ../params_cffi_build.py blns_params.h ../..

blns_params.h: blns_params.py
	cd ../../scripts && sage lin-codegen.sage ../python/succinct_zkp/blns_params.py > ../python/succinct_zkp/blns_params.h

../_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
