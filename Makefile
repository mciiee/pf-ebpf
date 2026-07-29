CC=clang
CFLAGS=-std=c23 -O2 -g
DFLAGS=-D_DEFAULT_SOURCE
LFLAGS=-lxdp -lbpf -lm
TARGET_BPF=-target bpf

PF_FLAGS=-DDEBUG


# build/pf-stub.bpf.o: src/pf-stub.c
# 	$(CC) -c $(CFLAGS) $(TARGET_BPF) $< -o $@

all: build/pf-userspace build/pf.bpf.o

bpf: build/pf.bpf.o

userspace: build/pf-userspace

build/pf-userspace: build/pf-userspace.o build/protocols.o build/mempool.o
	$(CC) $(LFLAGS) $^ -o $@

build/mempool.o: src/mempool.c src/mempool.h
	$(CC) $(CFLAGS) -c $< -o $@

build/protocols.o: src/protocols.c src/protocols.h
	$(CC) $(CFLAGS) -c $< -o $@

build/pf-userspace.o: src/pf-userspace.c
	$(CC) $(CFLAGS) $(DFLAGS) -c $< -o $@


build/pf.bpf.o: src/pf.c
	$(CC) -c $(PF_FLAGS) $(TARGET_BPF) $< -o $@


