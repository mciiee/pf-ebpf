CC=clang
CFLAGS=-std=c23 -O2 -g
DFLAGS=-D_DEFAULT_SOURCE
TARGET_BPF=-target bpf

all: build/pf-userspace build/pf.bpf.o

build/pf-userspace: src/pf-userspace.c
	$(CC) $(CFLAGS) $(DFLAGS) $< -o $@

build/pf.bpf.o: src/pf.c
	$(CC) -c $(CFLAGS) $(TARGET_BPF) $< -o $@


