.POSIX:
.SUFFIXES:
.PHONY: all test randtest inttest bench clean

CC        = cc
COPTFLAGS = -O2 -funroll-loops
CDBGFLAGS = -g3 -fsanitize=undefined -fsanitize-trap
CDEVFLAGS = -Wall -Wextra -Wconversion -Wdouble-promotion -Wno-unused-parameter \
            -Wno-unused-function -Wno-sign-conversion -Wno-c23-extensions
CFLAGS    =
LDLIBS    =
BINS      = uuniq uuniq_test uuniq_randtest uuniq_bench

all: $(BINS)

uuniq: uuniq.c
	$(CC) $(COPTFLAGS) $(CDEVFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: uuniq_test
	./uuniq_test

randtest: uuniq_randtest
	./uuniq_randtest

inttest: uuniq
	./inttest

bench: uuniq_bench
	./uuniq_bench

uuniq_test: uuniq.c
	$(CC) -DTEST $(CDBGFLAGS) $(CDEVFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

uuniq_randtest: uuniq.c
	$(CC) -DRANDTEST $(CDBGFLAGS) $(COPTFLAGS) $(CDEVFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

uuniq_bench: uuniq.c
	$(CC) -DBENCH $(COPTFLAGS) $(CDEVFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(BINS)
	rm -rf $$(printf "%s.dSYM " $(BINS))
