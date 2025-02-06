.PHONY: all clean

LAZER_DIR = ../..

LIBS = $(LAZER_DIR)/liblazer.a -lmpfr -lgmp -lm ../../third_party/hexl-development/build/hexl/lib/libhexl.a -lstdc++ #XXX
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O3 -g

all: blindsig-demo

blindsig-demo: blindsig-demo.c blindsig-demo.h
	$(CC) $(CFLAGS) -I$(LAZER_DIR) -o $@ blindsig-demo.c $(LIBS)

clean:
	rm -f blindsig-demo
