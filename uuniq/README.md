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
- Implement suitable set of `uniq` command-line flags while retaining the immediate output nature of `uuniq`.
- Add limit to memory allocation by querying the platform, if feasible, and a command-line flag for user-defined limit
- Add integration tests using shell scripts
- Add fuzz testing
- More optimisation ideas:
  - Compute hash for the input line as it is scanned for newline. Possibly utilises better processor's ILP.
- Add Linux x86 CRT-free platform
- Maybe add Linux aarch64 CRT-free platform
- Test 32bit big endian compatibility using QEMU, see https://nullprogram.com/blog/2021/08/21/.

## Notes
- Adding NOZERO flag to arena alloc and using it when all allocated memory is immediately written to (e.g string copy) had very small or indistinguishable effect on benchmark performance on Apple M1. Left the flag implementation and its use in place still.