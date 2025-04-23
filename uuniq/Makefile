.POSIX:
.SUFFIXES:
.PHONY: all test randtest bench clean

CC     = cc
COPT_FLAGS = -O2 -funroll-loops
CFLAGS = -Wall -Wextra -Wconversion -Wdouble-promotion -Wno-unused-parameter \
         -Wno-unused-function -Wno-sign-conversion -Wno-c23-extensions
LDLIBS =
BINS   = uuniq uuniq_test uuniq_randtest uuniq_bench

all: $(BINS)

uuniq: uuniq.c
	$(CC) $(COPT_FLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: uuniq_test
	./uuniq_test

randtest: uuniq_randtest
	./uuniq_randtest

bench: uuniq_bench
	./uuniq_bench

uuniq_test: uuniq.c
	$(CC) -DTEST -g3 -fsanitize=undefined -fsanitize-trap $(CFLAGS) -o $@ $^ $(LDLIBS)

uuniq_randtest: uuniq.c
	$(CC) -DRANDTEST -g3 $(COPT_FLAGS) -fsanitize=undefined -fsanitize-trap $(CFLAGS) -o $@ $^ $(LDLIBS)

uuniq_bench: uuniq.c
	$(CC) -DBENCH $(COPT_FLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(BINS)
