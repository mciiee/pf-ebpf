CC=clang
CFLAGS=-std=c23 -O2 -g
DFLAGS=-D_DEFAULT_SOURCE
LFLAGS=-lxdp -lbpf -lm
TARGET_BPF=-target bpf

PF_FLAGS=-DDEBUG


# build/pf-stub.bpf.o: src/pf-stub.c
# 	$(CC) -c $(CFLAGS) $(TARGET_BPF) $< -o $@

all: build/pf-userspace build/pf.bpf.o


build/pf-userspace: src/pf-userspace.c
	$(CC) $(CFLAGS) $(DFLAGS) $(LFLAGS) $< -o $@

build/pf.bpf.o: src/pf.c
	$(CC) -c $(CFLAGS) $(PF_FLAGS) $(TARGET_BPF) $< -o $@


