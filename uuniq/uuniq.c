// uuniq: unordered uniq, like POSIX uniq, but does not require the input to
//        be sorted in order to remove duplicate lines.
//
// Requires a C11 compiler and a few GCC/Clang builtins. Depends on POSIX for
// I/O and minimally on libc.
//
// posix:  $ cc        -O2 -funroll-loops -s                    -o uuniq      uuniq.c
// test:   $ cc -DTEST -g3 -fsanitize=undefined -fsanitize-trap -o uuniq_test uuniq.c
//
// Author Sami Rosendahl, sami.rosendahl@gmail.com
// Heavily influenced and directly borrows from public domain contributions of
// Chris Wellons, http://nullprogram.com.

#include <stddef.h>
#include <stdint.h>

#define VERSION "2025-04-02"

typedef uint8_t     u8;
typedef int32_t     b32;
typedef int32_t     i32;
typedef uint32_t    u32;
typedef int64_t     i64;
typedef uint64_t    u64;
typedef char        byte;
typedef ptrdiff_t   iz;
typedef size_t      uz;

typedef struct Arena Arena;

// Platform abstraction
typedef struct Plt Plt;
//static b32  plt_open(Plt *, i32 fd, u8 *, b32 trunc, Arena *);  // open(2)
static i32  plt_read(Plt *, u8 *, i32);                         // read(2)
static b32  plt_write(Plt *, i32 fd, u8 *, i32);                // write(2)
static void plt_exit(Plt *, i32);                               // _exit(2)
static i32  uuniq(i32, u8 **, Plt *, byte *, iz);               // main

// Application

#define countof(a)      (iz)(sizeof(a) / sizeof(*(a)))
#define affirm(c)       while (!(c)) __builtin_unreachable()
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define S(s)            (Str){(u8 *)s, sizeof(s)-1}
#define maxof(t)        ((t)-1<1 ? (((t)1<<(sizeof(t)*8-2))-1)*2+1 : (t)-1)
#define mset(d, c, n)   __builtin_memset(d, c, n)
#define mcpy(d, s, n)   __builtin_memcpy(d, s, n)

typedef struct {
    u8 *data;
    iz  len;
} Str;

typedef struct {
    Str head;
    Str tail;
} Strpair;

typedef struct Output Output;
static void print(Output *, Str);
static void printu8(Output *, u8);
static void flush(Output *);

typedef struct {
    Plt    *plt;
    Output *be;
} Uuniq;

// Main program

enum {
    STATUS_OK       = 0,
    STATUS_CMD      = 1,
    STATUS_INPUT    = 2,
    STATUS_OUTPUT   = 3,
    STATUS_OOM      = 6,
};

struct Arena {
    Uuniq  *ctx;
    byte *beg;
    byte *end;
};

static Arena newarena(Uuniq *ctx, byte *mem, iz cap) {
    return (Arena){ctx, mem, mem+cap};
}

static void oom(Uuniq *ctx)
{
    if (ctx && ctx->be) {
        print(ctx->be, S("uuniq: out of memory\n"));
        flush(ctx->be);
    }
    plt_exit(ctx->plt, STATUS_OOM);
}

static void *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = -(uz)a->beg & (align - 1);
    if (count >= (a->end - a->beg - pad)/size) {
        oom(a->ctx);
    }
    byte *r = a->beg + pad;
    a->beg += pad + count*size;
    return mset(r, 0, count*size);
}

static b32 equals(Str a, Str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (iz i = 0; i < a.len; i++) {
        if (a.data[i] != b.data[i]) {
            return 0;
        }
    }
    return 1;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, r.len, u8);
    if (r.len) mcpy(r.data, s.data, r.len);
    return r;
}

static Str concat(Arena *a, Str head, Str tail)
{
    if (!head.data || (byte *)(head.data+head.len) != a->beg) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static Strpair extend(Arena *a, Str head, iz len)
{
    Strpair r = { head, {0} };
    if (!r.head.data || (byte *)(r.head.data+r.head.len) != a->beg) {
        r.head = clone(a, r.head);
    }
    r.tail.data = new(a, len, u8);
    r.tail.len = len;
    r.head.len += len;
    return r;
}

typedef struct {
    Plt *plt;
    i32  len;
    i32  off;
    b32  eof;
    b32  err;
    u8   buf[1<<12];
} Input;

static Input *newinput(Arena *a, Plt *plt)
{
    Input *b = new(a, 1, Input);
    b->plt = plt;
    return b;
}

static void refill(Input *b)
{
    affirm(b->off == b->len);
    if (!b->eof) {
        b->len = b->off = 0;
        i32 r = plt_read(b->plt, b->buf, countof(b->buf));
        if (r < 0) {
            r = 0;
            b->err = 1;
        }
        b->len = r;
        b->eof = !b->len;
    }
}

// Return the next line, allocated in Arena a.
// Does not include newline, the line is empty on end of file.
static Str nextline(Input *b, Arena *a)
{
    Str line = {0};
    b32 found = 0;
    do {
        if (b->off == b->len) {
            refill(b);
        }

        i32 cut = b->off;
        for (; cut<b->len && b->buf[cut]!='\n'; cut++) {}
        found = cut < b->len;

        Str tail  = {0};
        tail.data = b->buf + b->off;
        tail.len  = cut - b->off;
        b->off    = cut + found;

        line = concat(a, line, tail);
    } while (!b->eof && !found);
    return line;
}

struct Output {
    Plt *plt;
    i32  len;
    i32  fd;
    b32  err;
    u8   buf[1<<12];
};

static Output *newoutput(Arena *a, i32 fd, Plt *plt)
{
    Output *b = new(a, 1, Output);
    b->fd = fd;
    b->plt = plt;
    return b;
}

static void flush(Output *b)
{
    if (!b->err && b->len) {
        b->err = !plt_write(b->plt, b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static void output(Output *b, u8 *buf, iz len)
{
    for (iz off = 0; !b->err && off<len;) {
        i32 avail = countof(b->buf) - b->len;
        i32 count = len-off < avail ? (i32)(len-off) : avail;
        mcpy(b->buf+b->len, buf+off, count);
        off += count;
        b->len += count;
        if (b->len == countof(b->buf)) {
            flush(b);
        }
    }
}

static void print(Output *b, Str s)
{
    output(b, s.data, s.len);
}

static void printu8(Output *b, u8 c)
{
    output(b, &c, 1);
}

typedef struct LineSet LineSet;
struct LineSet {
    LineSet *child[4];
    Str line;
    i64 count;
};

static u64 hash64(Str s)
{
    u64 h = 0x100;
    for (iz i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 1111111111111111111u;
    }
    return h;
}

static i64 upsert(LineSet **set, Str line, Arena *a)
{
    for (uint64_t h = hash64(line); *set; h <<= 2) {
        if (equals(line, (*set)->line)) {
            return ++(*set)->count;
        }
        set = &(*set)->child[h>>62];
    }
    *set = new(a, 1, LineSet);
    (*set)->line = line;
    return (*set)->count = 1;
}

static i32 uuniq_(i32 /*argc*/, u8 **/*argv*/, Uuniq *ctx, Arena a) {
    i32 r = STATUS_OK;
    Plt *plt = ctx->plt;
    Input *bi = newinput(&a, plt);
    LineSet *lineset = 0;
    Output *bo = newoutput(&a, 1, plt);
    Output *be = newoutput(&a, 2, plt);
    ctx->be = be;

    for (;;) {
        // Read the next string to a copy of arena
        Arena m = a;
        Str line = nextline(bi, &m);
        if (!line.len && bi->eof) {
            break;
        }
        if (upsert(&lineset, line, &m) == 1) {
            a = m;  // Commit the line and set entry to arena
            print(bo, line);
            printu8(bo, '\n');
        }
    }

    flush(bo);
    if (bo->err) {
        print(be, S("uuniq: error writing output\n"));
        r = STATUS_OUTPUT;
    } else if (bi->err) {
        print(be, S("uuniq: error reading input\n"));
        r = STATUS_INPUT;
    }
    flush(be);
    return r;
}

static i32 uuniq(i32 argc, u8 **argv, Plt *plt, byte *mem, iz cap)
{
    // Bootstrap a context
    Arena a  = newarena(0, mem, cap);
    Uuniq *ctx = a.ctx = new(&a, 1, Uuniq);  // cannot fail (always fits)
    ctx->plt = plt;

    i32 r = uuniq_(argc, argv, ctx, a);
    return r;
}

#if NO_PLATFORM
// Platform defined external to this source


#elif TEST
// All tests run on a virtual file system, so no real files are read nor
// written during tests. The main program is also run repeatedly in the
// same process with the environment reset between tests.
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct Plt {
    // Output
    i64 off;
    Str output;
    iz  cap;

    // Input
    Str input;
    iz  inpos;

    // Exit
    i32      status;
    jmp_buf *oom;  // pointer hides ugly GDB printout
};

static b32 plt_open(Plt *plt, i32 fd, u8 */*path*/, b32 trunc, Arena *)
{
    switch (fd) {
    case  0: plt->inpos = 0;
             break;
    case  1: plt->off = 0;
             if (trunc) {
                 plt->output.len = 0;
             }
             break;
    default: affirm(0);
    }
    return 1;
}

static i32 plt_read(Plt *plt, u8 *buf, i32 len)
{
    iz rem = plt->input.len - plt->inpos;
    len = rem<len ? (i32)rem : len;
    if (len) memcpy(buf, plt->input.data+plt->inpos, len);
    plt->inpos += len;
    return len;
}

static b32 plt_write(Plt *plt, i32 fd, u8 *buf, i32 len)
{
    affirm(len >= 0);
    affirm(fd==1 || fd==2);

    if (fd != 1) {
        return 1;  // discard standard error
    }

    if (plt->off > plt->cap - len) {
        return 0;  // like ENOSPC "No space left on device"
    }

    iz extend = plt->off - plt->output.len;
    if (extend > 0) {
        u8 *dst = plt->output.data + plt->output.len;
        plt->output.len += extend;
        memset(dst, 0, extend);
    }

    u8 *dst = plt->output.data + plt->off;
    if (plt->off+len > plt->output.len) {
        plt->output.len = plt->off + len;
    }
    memcpy(dst, buf, len);
    return 1;
}

static void plt_exit(Plt *plt, i32 r)
{
    longjmp(*plt->oom, r);
}

static Plt *newtestplt(Arena *a, iz cap)
{
    Plt *plt = new(a, 1, Plt);
    plt->oom = new(a, 1, jmp_buf);
    plt->output.data = new(a, cap, u8);
    plt->cap = cap;
    return plt;
}

#define expect(r, s, ...) \
    do { \
        if (!(plt->status = setjmp(*plt->oom))) { \
            char *argv[] = {"uuniq", __VA_ARGS__, 0}; \
            i32 argc = countof(argv) - 1; \
            plt->status = uuniq(argc, (u8 **)argv, plt, a.beg, a.end-a.beg); \
        } \
        affirm(r == plt->status); \
        affirm(r!=STATUS_OK || equals(plt->output, s)); \
    } while (0)

static void test_basic(Arena scratch)
{
    puts("TEST: uuniq [filename]");

    Arena a   = {0};
    Plt  *plt = 0;

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("");
    expect(
        STATUS_OK,
        S(""),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("\n");
    expect(
        STATUS_OK,
        S("\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("\n\n");
    expect(
        STATUS_OK,
        S("\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello");
    expect(
        STATUS_OK,
        S("Hello\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\n");
    expect(
        STATUS_OK,
        S("Hello\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\nHello");
    expect(
        STATUS_OK,
        S("Hello\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\nworld!!!");
    expect(
        STATUS_OK,
        S("Hello\nworld!!!\n"),
        ""
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("world!!!\nHello\nworld!!!\nHello");
    expect(
        STATUS_OK,
        S("world!!!\nHello\n"),
        ""
    );
}

int main(void)
{
    i32   cap = 1<<20;
    byte *mem = malloc(cap);
    Arena a   = {0, mem, mem+cap};
    test_basic(a);
    puts("all tests passed");
}

#elif RANDTEST

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct Plt {
    Str input;
    i32 inoff;
    Str output;
    i32 outoff;
    i32 cap;
};

//static b32  plt_open(Plt *, i32, u8 *, b32, Arena *) { affirm(0); }
static void plt_exit(Plt *, i32) { affirm(0); }

static i32  plt_read(Plt *plt, u8 *buf, i32 len)
{
    iz avail = plt->input.len - plt->inoff;
    len = avail<len ? (i32)avail : len;
    if (len) {
        memcpy(buf, plt->input.data+plt->inoff, len);
        plt->inoff += len;
    }
    return len;
}

static b32 plt_write(Plt *plt, i32 fd, u8 *buf, i32 len)
{
    affirm(fd == 1);
    affirm(len <= plt->cap - plt->outoff);
    if (len) {
        memcpy(plt->output.data+plt->outoff, buf, len);
        plt->output.len += len;
        plt->outoff += len;
    }
    return 1;
}

static u64 rand64(u64 *rng)
{
    return (*rng = *rng*0x3243f6a8885a308d + 1);
}

static i32 randrange(u64 *rng, i32 lo, i32 hi)
{
    return (i32)(((rand64(rng)>>32) * (hi - lo))>>32) + lo;
}

static void fill_randomchars(Str s, u64 *rng) {
    u8* p = s.data;
    iz len = s.len;
    while (len > 0) {
        u8 ch = (u8)randrange(rng, 0, 255);
        if (ch != '\n') {
            *(p++) = ch;
            len--;
        }
    }
}

typedef struct {
    i32 repeats;
    Str line;
} Inputline;

static void test_random(Arena scratch)
{
    puts("RANDTEST: uuniq");

    u64 rng = 1;
    i32 maxuniqlines = 500;
    i32 maxrepeatedlines = 10;
    i32 reglinelen = 60;
    i32 longlinelen = 5000;

    for (u64 r = 1;; r++) {
        if (!(r % 10000)) {
            printf("%llu\n", (long long)r);
        }

        Plt plt = {0};
        Arena a = scratch;
        i32 uniqlines = randrange(&rng, 0, maxuniqlines+1);
        Inputline *inputlines = new(&a, uniqlines, Inputline);
        Str expectedoutput = {0};
        for (i32 l = 0; l < uniqlines;) {
          i32 linelen = randrange(&rng, 0, 100) < 90
              ? randrange(&rng, 0, reglinelen+1)
              : randrange(&rng, reglinelen+1, longlinelen+1);
            // extend the expected output with a new random line in a temporary arena
            Arena t = a;
            Strpair ext = extend(&t, expectedoutput, linelen+1 /*for '\n'*/);
            fill_randomchars(ext.tail, &rng);
            ext.tail.data[linelen] = '\n';
            i32 i = 0;
            for (; i < l && !equals(inputlines[i].line, ext.tail); i++) {}
            if (i == l) {
                // line was unique, save it and commit it to the expected output
                inputlines[l].line = ext.tail;
                inputlines[l].repeats = randrange(&rng, 1, maxrepeatedlines+1);
                expectedoutput = ext.head;
                a = t;
                l++;
            }
        }

        for (i32 l = 0; l < uniqlines;) {
            i32 i = randrange(&rng, 0, l+1);
            for (; !inputlines[i].repeats; i++) {}
            affirm(i <= l);
            Inputline *inputline = &inputlines[i];
            plt.input = concat(&a, plt.input, inputlines[i].line);
            inputlines[i].repeats--;
            l += i == l;
        }

        plt.cap = uniqlines * (reglinelen + longlinelen);
        plt.output.data = new(&a, plt.cap, u8);

        char *argv[] = {"uuniq", 0};
        i32 argc = countof(argv) - 1;
        i32 status = uuniq(argc, (u8 **)argv, &plt, a.beg, a.end-a.beg);

        affirm(status == STATUS_OK);
        affirm(equals(plt.output, expectedoutput));
    }
}

int main(void)
{
    i32   cap = 1<<24;
    byte *mem = malloc(cap);
    Arena a   = {0, mem, mem+cap};
    test_random(a);
    puts("all tests passed");
}

#elif BENCH
// Benchmark for verifing that any optimisations have an effect in the right direction
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Plt {
    Str input;
    iz  inpos;
    Str output;
    iz  outpos;
};

static i64 perf_counter(void)
{
    #ifdef __x86_64__
        // NOTE: x86_64 not tested yet
        uz hi, lo;
        asm volatile ("rdtscp" : "=d"(hi), "=a"(lo) :: "cx", "memory");
        return (i64)hi<<32 | lo;
    #elif __aarch64__
        uint64_t c;
        asm volatile ("mrs %0, cntvct_el0" : "=r" (c));
        return c;
    #else
        #error("BENCH: Unsupported platform")
    #endif
}

//static b32  plt_open(Plt *, i32, u8 *, b32, Arena *) { affirm(0); }
static void plt_exit(Plt *, i32) { affirm(0); }

static i32 plt_read(Plt *plt, u8 *buf, i32 len)
{
    iz rem = plt->input.len - plt->inpos;
    len = rem<len ? (i32)rem : len;
    memcpy(buf, plt->input.data+plt->inpos, len);
    plt->inpos += len;
    return len;
}

static b32 plt_write(Plt *plt, i32, u8 *buf, i32 len)
{
    if (plt->output.data) {
        affirm(plt->output.len-plt->outpos >= len);
        memcpy(plt->output.data+plt->outpos, buf, len);
        plt->outpos += len;
    }
    return 1;
}

static void report(char *cmd, i64 time)
{
    printf("%-20s%lld\n", cmd, (long long)time);
}

static u64 rand64(u64 *rng)
{
    return (*rng = *rng*0x3243f6a8885a308d + 1);
}

static i32 randrange(u64 *rng, i32 lo, i32 hi)
{
    return (i32)(((rand64(rng)>>32) * (hi - lo))>>32) + lo;
}

int main(void)
{
    i32   cap = 1<<28;
    byte *mem = malloc(cap);
    Arena a   = {0, mem, mem+cap};
    memset(mem, 0xa5, cap);  // pre-commit whole arena

    // Generate random ASCII lines as input.
    // The input should be more representative for uuniq's case, which is that
    // the input is expected to contain duplicated lines.
    Str random = {0};
    random.len = 1<<20;
    random.data = new(&a, random.len, u8);
    u64 rng  = 1;
    for (iz l = 0; l < random.len;) {
        i32 endl = l + randrange(&rng, 0, 200);
        endl = endl < random.len ? endl : random.len - 1;
        for (iz i = l; i < endl; i++) {
            random.data[i] = (u8)randrange(&rng, 32, 126);
        }
        random.data[endl] = '\n';
        l = endl + 1;
    }

    {
        Arena tmp = a;
        Plt  *plt = new(&tmp, 1, Plt);
        plt->input = random;

        i64 best = maxof(i64);
        for (i32 n = 0; n < 1<<9; n++) {
            plt->inpos = 0;
            i64 total = -perf_counter();
            i32 r = uuniq(0, 0, plt, tmp.beg, tmp.end-tmp.beg);
            affirm(r == STATUS_OK);
            total += perf_counter();
            best = total<best ? total : best;
        }
        report("uuniq ASCII", best>>8);
    }
}

#else // POSIX

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

struct Plt {
    // Virtual file descriptor table
    int fds[3];
};

/*
static b32 plt_open(Plt *plt, i32 fd, u8 *path, b32 trunc, Arena *a)
{
    int mode = fd==0 ? O_RDONLY : O_CREAT|O_WRONLY;
    mode |= trunc ? O_TRUNC : 0;
    plt->fds[fd] = open((char *)path, mode, 0666);
    return plt->fds[fd] != -1;
}
*/

static i32 plt_read(Plt *plt, u8 *buf, i32 len)
{
    return (i32)read(plt->fds[0], buf, len);
}

static b32 plt_write(Plt *plt, i32 fd, u8 *buf, i32 len)
{
    return len == write(plt->fds[fd], buf, len);
}

static void plt_exit(Plt *, i32 r)
{
    _exit(r);
}

int main(int argc, char **argv)
{
    Plt   plt = {{0, 1, 2}};
    iz    cap = (iz)1<<24; // Initial memory 16MiB
    byte *mem = mmap(0, cap, PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) {
        Str msg = S("uuniq: not enough memory");
        plt_write(&plt, 2, msg.data, msg.len);
        plt_exit(&plt, STATUS_OOM);
    }
    return uuniq(argc, (u8 **)argv, &plt, mem, cap);
}

#endif
