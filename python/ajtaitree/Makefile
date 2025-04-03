.PHONY: all clean

all: _ajtaitree_params_cffi.o

_ajtaitree_params_cffi.o: ajtaitree_params.h ../_lazer_cffi.o
	python3 ../params_cffi_build.py ajtaitree_params.h ../..
	
ajtaitree_params.h: ajtaitree_params.py
	cd ../../scripts && sage lin-codegen.sage ../python/ajtaitree/ajtaitree_params.py > ../python/ajtaitree/ajtaitree_params.h

../_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
