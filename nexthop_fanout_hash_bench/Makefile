CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += -I.. -I../lib

all: fanout_hash_bench

fanout_hash_bench: fanout_hash_bench.c ../lib/jhash.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ fanout_hash_bench.c ../lib/jhash.c

clean:
	rm -f fanout_hash_bench

.PHONY: all clean
