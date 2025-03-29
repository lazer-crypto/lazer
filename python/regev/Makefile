.PHONY: all clean

all: _regev_params_cffi.o

_regev_params_cffi.o: regev_params.h ../_lazer_cffi.o
	python3 ../params_cffi_build.py regev_params.h ../..

regev_params.h: regev_params.py
	cd ../../scripts && sage lin-codegen.sage ../python/regev/regev_params.py > ../python/regev/regev_params.h

../_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
