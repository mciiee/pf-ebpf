CC=clang
CFLAGS=-std=c23 -target bpf -O2 -g

build/pf.bpf.o: src/pf.c
	$(CC) -c $(CFLAGS) $< -o $@


