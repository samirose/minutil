.POSIX:
.SUFFIXES:
.PHONY: all test randtest clean

CC     = cc
CFLAGS = -W -Wno-c23-extensions
LDLIBS =
BINS   = uuniq uuniq_test uuniq_randtest

all: $(BINS)

uuniq: uuniq.c
	$(CC) -O2 -funroll-loops $(CFLAGS) -o $@ $^ $(LDLIBS)

test: uuniq_test
	./uuniq_test

randtest: uuniq_randtest
	./uuniq_randtest

uuniq_test: uuniq.c
	$(CC) -DTEST -g3 -fsanitize=undefined -fsanitize-trap $(CFLAGS) -o $@ $^ $(LDLIBS)

uuniq_randtest: uuniq.c
	$(CC) -DRANDTEST -g3 -O2 -funroll-loops -fsanitize=undefined -fsanitize-trap $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(BINS)
