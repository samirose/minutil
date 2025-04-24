## Uuniq

`uuniq`: unordered uniq, like POSIX `uniq`, but does not require the input to be sorted in order to remove duplicate lines. Uses a hash trie to keep track of unique lines.

Written in single C source file using arena-based memory allocation. Depends only on POSIX and minimally on libc. Heavily influenced and directly borrows from public domain contributions of Chris Wellons, http://nullprogram.com.

## Compiling

Use the provided Makefile or

To compile the program:
```shell
$ cc -O2 -funroll-loops -s -o uuniq uuniq.c
```

To compile and run tests:
```shell
$ cc -DTEST -g3 -fsanitize=undefined -fsanitize-trap -o uuniq_test uuniq.c && ./uuniq_test
```

For other targets, see `randtest` and `bench` in the Makefile.

## TODO
- Tune raw memory allocation (plt_alloc) to fail before all system memory is consumed
  - One possible strategy is to double the allocation size on every new alloc to fail earlier and leave breathing room for the system?
- Add input and output file command line parameters
- Add command line flags for activating the I/O and memory tracing
- Add integration tests using shell scripts
- Add fuzz testing
- More optimisation ideas:
  - Add NOZERO flag to arena alloc and use it when all allocated memory is immediately written to (e.g string copy)
  - Compute hash for the input line as it is scanned for newline. Possibly utilises better processor's ILP.
- Add Linux x86 CRT-free platform
- Implement suitable set of `uuniq` flags while retaining the immediate output nature of `uuniq`.
- Maybe add Linux aarch64 CRT-free platform
- Test 32bit big endian compatibility using QEMU, see https://nullprogram.com/blog/2021/08/21/.
