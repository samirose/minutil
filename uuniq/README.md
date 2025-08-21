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

To compile the program and run integration tests:
```shell
$ cc -O2 -funroll-loops -s -o uuniq uuniq.c && ./inttest
```

For other targets, see `randtest` and `bench` in the Makefile.

## TODO
- Implement POSIX standard set of `uniq` command-line flags
- Add fuzz testing
- Add Linux x86 CRT-free platform
- Maybe add Linux aarch64 CRT-free platform
- Write a man page for uuniq
- Test 32bit big endian compatibility using QEMU, see https://nullprogram.com/blog/2021/08/21/.

## Notes
- Adding NOZERO flag to arena alloc and using it when all allocated memory is immediately written to (e.g string copy) had very small or indistinguishable effect on benchmark performance on Apple M1. Left the flag implementation and its use in place still.
- Storing the hash set nodes and the line strings to separate arenas did not improve performance at all on Apple M1 and neglibly on Intel i5-8500T. The hypothesis was that improved locality would speed up the hash set lookups. The added complexity did not warrant to keep the change. The code can be found in branch `optimization/separate-hashset-arena`.
- Computing the hash for the input line as it is scanned for newline provides a signifcant speedup in benchmark: Apple M1 11-20%, Intel i5-8500T 16-24%. Possibly, because the line's characters are scanned only once and maybe the processor can exploit instruction level parallelism (ILP) better?