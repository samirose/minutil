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

#define VERSION "2025-05-21"

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

typedef struct {
    byte *beg;
    iz    cap;
} Mem;

static Mem  plt_alloc(Plt *);                          // mmap(2)
static b32  plt_open(Plt *, i32, u8 *, b32, Arena *);  // open(2)
static i32  plt_read(Plt *, u8 *, i32);                // read(2)
static b32  plt_write(Plt *, i32 fd, u8 *, i32);       // write(2)
static void plt_exit(Plt *, i32);                      // _exit(2)
static i32  uuniq(i32, u8 **, Plt *, Mem);             // main

// Application

#define countof(a)      (iz)(sizeof(a) / sizeof(*(a)))
#define affirm(c)       while (!(c)) __builtin_unreachable()
#define new(...)            newx(__VA_ARGS__,new4,new3,new2)(__VA_ARGS__)
#define newx(a,b,c,d,e,...) e
#define new2(a, t)          (t *)alloc(a, sizeof(t), _Alignof(t), 1, 0)
#define new3(a, t, n)       (t *)alloc(a, sizeof(t), _Alignof(t), n, 0)
#define new4(a, t, n, f)    (t *)alloc(a, sizeof(t), _Alignof(t), n, f)
#define S(s)            (Str){(u8 *)s, sizeof(s)-1}
#define maxof(t)        ((t)-1<1 ? (((t)1<<(sizeof(t)*8-2))-1)*2+1 : (t)-1)
#define mset(d, c, n)   __builtin_memset(d, c, n)
#define mcpy(d, s, n)   __builtin_memcpy(d, s, n)

typedef struct {
    u8 *data;
    iz  len;
} Str;

typedef struct Output Output;
static void print(Output *, Str);
static void printu8(Output *, u8);
static void printi64(Output *, i64);
static void printu64hex(Output *b, u64 x);
static void printq(Output *, Str);
static void flush(Output *);

typedef struct {
    Plt    *plt;
    Output *be;
    b32     traceio;
    b32     tracemem;
    iz      totalmem;
} Uuniq;

// Main program

enum {
    STATUS_OK       = 0,
    STATUS_CMD      = 1,
    STATUS_INPUT    = 2,
    STATUS_OUTPUT   = 3,
    STATUS_OOM      = 6,
};

static u8 lohex[16] = "0123456789abcdef";

struct Arena {
    Uuniq  *ctx;
    byte *beg;
    byte *end;
};

static Arena newarena(Uuniq *ctx, byte *mem, iz cap) {
    return (Arena){ctx, mem, mem+cap};
}

static void oom(Arena *a)
{
    Uuniq *ctx = a->ctx;
    Mem mem = plt_alloc(ctx->plt);
    *a = newarena(ctx, mem.beg, mem.cap);
    ctx->totalmem += mem.cap;

    if (!ctx->tracemem) {
        return;
    }
    Output *be = ctx->be;
    print(be, S("alloc() = "));
    printu64hex(be, (uintptr_t)mem.beg);
    print(be, S(":"));
    printu64hex(be, (uintptr_t)mem.beg+mem.cap);
    print(be, S(" total = "));
    printu64hex(be, ctx->totalmem);
    print(be, S("\n"));
    flush(be);
}

enum {
    NOZERO = 1
};

static void *alloc(Arena *a, iz size, iz align, iz count, u8 flags)
{
    iz pad = -(uz)a->beg & (align - 1);
    if (count >= (a->end - a->beg - pad)/size) {
        oom(a);
    }
    byte *r = a->beg + pad;
    a->beg += pad + count*size;
    return flags & NOZERO ? r : mset(r, 0, count*size);
}

static Str import(u8 *s)
{
    Str r = {0};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static Str span(u8 *beg, u8 *end)
{
    Str r = {0};
    r.data = beg;
    r.len  = end - beg;
    return r;
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
    r.data = new(a, u8, r.len, NOZERO);
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

typedef struct {
    Uuniq *ctx;
    i32    len;
    i32    off;
    b32    eof;
    b32    err;
    u8     buf[1<<12];
} Input;

static b32 uuniq_open(Uuniq *ctx, i32 fd, u8 *path, b32 trunc, Arena *a) {
    b32 r = plt_open(ctx->plt, fd, path, trunc, a);
    if (!ctx->traceio) {
        return r;
    }

    Output *be = ctx->be;
    print(be, S("open(\""));
    printq(be, import(path));
    print(be, S("\", "));

    if (fd == 0) {
        print(be, S("O_RDONLY"));
    } else {
        print(be, S("O_CREAT|O_WRONLY"));
    }
    if (trunc) {
        print(be, S("|O_TRUNC"));
    }
    if (fd != 0) {
        print(be, S(", 0666"));
    }

    print(be, S(") = "));
    printi64(be, r ? fd : -1);

    print(be, S("\n"));
    flush(be);
    return r;
}

static i32 uuniq_read(Uuniq *ctx, u8 *buf, i32 len) {
    i32 r = plt_read(ctx->plt, buf, len);
    if (!ctx->traceio) {
        return r;
    }

    Output *be = ctx->be;
    print(be, S("read(0, ..., "));
    printi64(be, len);
    print(be, S(") = "));
    printi64(be, r);
    print(be, S("\n"));
    flush(be);
    return r;
}

static b32 uuniq_write(Uuniq *ctx, i32 fd, u8 *buf, i32 len)
{
    b32 r = plt_write(ctx->plt, fd, buf, len);
    if (!ctx->traceio || fd==2) {
        return r;
    }

    Output *be = ctx->be;
    print(be, S("write("));
    printi64(be, fd);
    print(be, S(", \""));
    if (len > 12) {
        printq(be, (Str){buf, 6});
        print(be, S("..."));
        printq(be, (Str){buf+len-6, 6});
    } else {
        printq(be, (Str){buf, len});
    }
    print(be, S("\", "));
    printi64(be, len);
    print(be, S(") = "));
    printi64(be, r ? len : -1);
    print(be, S("\n"));
    flush(be);
    return r;
}

static Input *newinput(Arena *a, Uuniq *ctx)
{
    Input *b = new(a, Input);
    b->ctx = ctx;
    return b;
}

static void refill(Input *b)
{
    affirm(b->off == b->len);
    if (!b->eof) {
        b->len = b->off = 0;
        i32 r = uuniq_read(b->ctx, b->buf, countof(b->buf));
        if (r < 0) {
            r = 0;
            b->err = 1;
        }
        b->len = r;
        b->eof = !b->len;
    }
}

typedef struct {
    Str text;
    b32 inbuf; // true if text is viewing the input buffer
} Inputline;

// Return the next line, viewing the input buffer if possible.
// Does not include newline, the line is empty on end of file.
static Inputline nextline(Input *b, Arena *a)
{
    Inputline line = {0};
    do {
        if (b->off == b->len) {
            refill(b);
        }

        i32 cut = b->off;
        for (; cut<b->len && b->buf[cut]!='\n'; cut++) {}
        b32 found = cut < b->len;

        Str tail  = {0};
        tail.data = b->buf + b->off;
        tail.len  = cut - b->off;
        b->off    = cut + found;

        if (found) {
            // Avoid copy if possible; the common case
            if (!line.text.data) {
                line.text = tail;
                line.inbuf = 1;
            } else {
                line.text = concat(a, line.text, tail);
            }
            break;
        }
        line.text = concat(a, line.text, tail);
    } while (!b->eof);
    return line;
}

struct Output {
    Uuniq *ctx;
    i32    len;
    i32    fd;
    b32    err;
    u8     buf[1<<12];
};

static Output *newoutput(Arena *a, i32 fd, Uuniq *ctx)
{
    Output *b = new(a, Output);
    b->fd = fd;
    b->ctx = ctx;
    return b;
}

static void flush(Output *b)
{
    if (!b->err && b->len) {
        b->err = !uuniq_write(b->ctx, b->fd, b->buf, b->len);
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

static void printi64(Output *b, i64 x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i64 t   = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    print(b, span(beg, end));
}

static void printu64hex(Output *b, u64 x)
{
    u8 hex[16];
    for (i32 i = 0; i < 8; i++) {
        u8 v = (u8)(x >> (56 - i*8));
        hex[2*i+0] = lohex[v>>4];
        hex[2*i+1] = lohex[v&15];
    }
    output(b, hex, 16);
}

static void printq(Output *b, Str s)
{
    b32 pending_null = 0;
    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i];
        if (pending_null) {
            Str null = c<'0'||c>'7' ? S("\\0") : S("\\x00");
            print(b, null);
            pending_null = 0;
        }
        switch (c) {
        case '\0': pending_null = 1;    break;
        case '\t': print(b, S("\\t"));  break;
        case '\n': print(b, S("\\n"));  break;
        case '\r': print(b, S("\\r"));  break;
        case '\"': print(b, S("\\\"")); break;
        case '\\': print(b, S("\\\\")); break;
        default:
            if (c<' ' || c >=127) {
                print(b, S("\\x"));
                printu8(b, lohex[c>>4]);
                printu8(b, lohex[c&15]);
            } else {
                printu8(b, c);
            }
        }
    }
    if (pending_null) {
        print(b, S("\\0"));
    }
}

typedef struct Strset Strset;
struct Strset {
    Strset *child[4];
    Str str;
    iz count;
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

static iz upsert(Strset **set, Str str, b32 clonestr, Arena *a)
{
    for (uint64_t h = hash64(str); *set; h <<= 2) {
        if (equals(str, (*set)->str)) {
            return ++(*set)->count;
        }
        set = &(*set)->child[h>>62];
    }
    // new entry
    if (clonestr) {
        str = clone(a, str);
    }
    *set = new(a, Strset);
    (*set)->str = str;
    return (*set)->count = 1;
}

static void writeline(Output *bo, Str str) {
    print(bo, str);
    printu8(bo, '\n');
}

static void usage(Output *b)
{
    static u8 usage_text[] =
    "Usage: uuniq [options] [INPATH [OUTPATH]]\n"
    "  -d            Suppress the writing of lines that are not repeated in the input.\n"
    "  -h            Print this message.\n"
    "  -v            Display version information.\n"
    "  -x[i][m]      Output strace-like log on standard error.\n"
    "                [-xi for I/O only, -xm for memory allocations only]\n";
    print(b, S(usage_text));
}

static i32 uuniq_(i32 argc, u8 **argv, Uuniq *ctx, Arena a) {
    i32 r = STATUS_OK;
    Input *bi = newinput(&a, ctx);
    Strset *lineset = 0;
    Output *bo = newoutput(&a, 1, ctx);
    Output *be = newoutput(&a, 2, ctx);
    ctx->be = be;

    i32 dopt = 0;
    i32 argi = 1;
    for (i32 done = 0; argi < argc; argi++) {
        u8 *arg = argv[argi];
        if (arg[0] != '-') {
            break;
        }

        switch (arg[1]) {

        case '\0':  // "-" standard input
            done = 1;
            break;

        case 'h':
            usage(bo);
            flush(bo);
            return bo->err ? STATUS_OUTPUT : STATUS_OK;

        case 'v':
            print(bo, S("uuniq " VERSION "\n"));
            flush(bo);
            return bo->err ? STATUS_OUTPUT : STATUS_OK;

        case 'd':
            dopt = 1;
            break;

        case 'x':
            ctx->traceio = !arg[2] || (arg[2] == 'i' && !arg[3]);
            ctx->tracemem = !arg[2] || (arg[2] == 'm' && !arg[3]);
            if (ctx->traceio || ctx->tracemem) {
                break;
            }
            // fallthrough

        default:
            print(be, S("uuniq: unknown option "));
            print(be, import(arg));
            print(be, S("\n"));
            usage(be);
            flush(be);
            return STATUS_CMD;
        }

        if (done) break;  // without incrementing argi
    }

    Str inpath = {0};
    Str outpath = {0};
    switch (argc - argi) {
        case  2:
            outpath = import(argv[argi+1]);
            // fallthrough
        case  1:
            inpath = import(argv[argi+0]);
            break;
        case  0:
        case -1:
            break;
        default:
            print(be, S("uuniq: too many arguments\n"));
            usage(be);
            flush(be);
            return STATUS_CMD;
        }

    if (inpath.data && !equals(inpath, S("-"))) {
        if (!uuniq_open(ctx, 0, inpath.data, 0, &a)) {
            print(be, S("uuniq: error opening input file: "));
            print(be, inpath);
            print(be, S("\n"));
            flush(be);
            return STATUS_INPUT;
        }
    }

    if (outpath.data && !equals(outpath, S("-"))) {
        if (!uuniq_open(ctx, 1, outpath.data, 1, &a)) {
            print(be, S("uuniq: error opening output file: "));
            print(be, outpath);
            print(be, S("\n"));
            flush(be);
            return STATUS_INPUT;
        }
    }

    // Main loop
    for (;;) {
        Arena t = a;
        Inputline line = nextline(bi, &t);
        if (!line.text.len && bi->eof) {
            break;
        }
        switch (upsert(&lineset, line.text, line.inbuf, &t)) {
        case 1:  // Initially seen line
            a = t; // Save the line
            if (!dopt) writeline(bo, line.text);
            break;
        case 2: // First detected duplicate line
            if (dopt) writeline(bo, line.text);
            break;
        default:
            break;
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

    if (ctx->tracemem) {
        print(be, S("total alloc = "));
        printu64hex(be, ctx->totalmem);
        print(be, S("\n"));
        flush(be);
    }
    return r;
}

static i32 uuniq(i32 argc, u8 **argv, Plt *plt, Mem mem)
{
    // Bootstrap a context
    Arena a  = newarena(0, mem.beg, mem.cap);
    Uuniq *ctx = a.ctx = new(&a, Uuniq);  // cannot fail (always fits)
    ctx->plt = plt;
    ctx->totalmem = mem.cap;

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

static Mem plt_alloc(Plt *) {
    affirm(0);
}

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
    plt->off += len;
    return 1;
}

static void plt_exit(Plt *plt, i32 r)
{
    longjmp(*plt->oom, r);
}

static Plt *newtestplt(Arena *a, iz cap)
{
    Plt *plt = new(a, Plt);
    plt->oom = new(a, jmp_buf);
    plt->output.data = new(a, u8, cap);
    plt->cap = cap;
    return plt;
}

#define expect(r, s, ...) \
    do { \
        if (!(plt->status = setjmp(*plt->oom))) { \
            char *argv[] = {"uuniq", __VA_ARGS__, 0}; \
            i32 argc = countof(argv) - 1; \
            plt->status = uuniq(argc, (u8 **)argv, plt, (Mem){a.beg, a.end-a.beg}); \
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

static void test_opt_d(Arena scratch)
{
    puts("TEST: uuniq -d [filename]");

    Arena a   = {0};
    Plt  *plt = 0;

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("");
    expect(
        STATUS_OK,
        S(""),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("\n");
    expect(
        STATUS_OK,
        S(""),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("\n\n");
    expect(
        STATUS_OK,
        S("\n"),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello");
    expect(
        STATUS_OK,
        S(""),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\n");
    expect(
        STATUS_OK,
        S(""),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\nHello");
    expect(
        STATUS_OK,
        S("Hello\n"),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("Hello\nworld!!!");
    expect(
        STATUS_OK,
        S(""),
        "-d"
    );

    a   = scratch;
    plt = newtestplt(&a, 1<<12);
    plt->input = S("world!!!\nHello\nworld!!!\nHello\nworld!!!");
    expect(
        STATUS_OK,
        S("world!!!\nHello\n"),
        "-d"
    );
}

static void test_longlines(Arena scratch)
{
    puts("TEST: uuniq long lines");

    Str longline = {0};
    longline.data = new(&scratch, u8, 1000);
    longline.len = 1000;
    for (i32 i = 0; i < 1000; i++) {
        longline.data[i] = '0' + (u8)(i % 10);
    }

    {
        Arena a  = scratch;
        Plt *plt = newtestplt(&a, 1<<20);
        plt->input = longline;
        expect(
            STATUS_OK,
            concat(&a, longline, S("\n")),
            ""
        );
    }

    {
        Arena a  = scratch;
        Plt *plt = newtestplt(&a, 1<<20);
        Str line = concat(&a, longline, S("\n"));
        for (i32 i = 1; i <= 10; i++) {
            plt->input = concat(&a, plt->input, line);
        }
        expect(
            STATUS_OK,
            line,
            ""
        );
    }

    {
        Arena a  = scratch;
        Plt *plt = newtestplt(&a, 1<<20);
        for (i32 i = 1; i <= 10; i++) {
            plt->input = concat(&a, plt->input, longline);
        }
        plt->input = concat(&a, plt->input, S("\n"));
        Str expected = plt->input;
        for (i32 i = 1; i <= 10; i++) {
            plt->input = concat(&a, plt->input, longline);
        }
        expect(
            STATUS_OK,
            expected,
            ""
        );
    }

    {
        Arena a  = scratch;
        Plt *plt = newtestplt(&a, 1<<20);
        Str line = concat(&a, longline, S("\n"));
        for (i32 i = 0; i < 10; i++) {
            Str l = {line.data+i, line.len-i};
            plt->input = concat(&a, plt->input, l);
        }
        Str expected = plt->input;
        for (i32 i = 9; i >= 0; i--) {
            Str l = {line.data+i, line.len-i};
            plt->input = concat(&a, plt->input, l);
        }
        expect(
            STATUS_OK,
            expected,
            ""
        );
    }
}

int main(void)
{
    i32   cap = 1<<24;
    byte *mem = malloc(cap);
    Arena a   = {0, mem, mem+cap};
    test_basic(a);
    test_opt_d(a);
    test_longlines(a);
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

static Mem plt_alloc(Plt *) {
    affirm(0);
}

static b32  plt_open(Plt *, i32, u8 *, b32, Arena *) { affirm(0); }
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

static void test_random(Arena scratch)
{
    puts("RANDTEST: uuniq");

    typedef struct {
        i32 repeats;
        i32 repeated;
        Str line;
    } Inputline;

    u64 rng = 1;
    i32 maxuniqlines = 500;
    i32 maxrepeatedlines = 10;
    i32 reglinelen = 60;
    i32 longlinelen = 5000;

    Str linebuf = {0};
    linebuf.data = new(&scratch, u8, longlinelen + 1);

    for (u64 r = 1;; r++) {
        if (!(r % 10000)) {
            printf("%llu\n", (long long)r);
        }

        Arena a = scratch;
        i32 uniqlines = randrange(&rng, 0, maxuniqlines+1);
        i32 maxoutsz = uniqlines * (reglinelen + longlinelen);
        Inputline *inputlines = new(&a, Inputline, uniqlines);
        for (i32 l = 0; l < uniqlines;) {
            linebuf.len = randrange(&rng, 0, 100) < 90
                ? randrange(&rng, 0, reglinelen+1)
                : randrange(&rng, reglinelen+1, longlinelen+1);
            fill_randomchars(linebuf, &rng);
            linebuf.data[linebuf.len++] = '\n';
            i32 i = 0;
            for (; i < l && !equals(inputlines[i].line, linebuf); i++) {}
            if (i == l) {
                // line was unique, save it and commit it to the expected output
                inputlines[l].line = clone(&a, linebuf);
                inputlines[l].repeats = randrange(&rng, 1, maxrepeatedlines+1);
                l++;
            }
        }

        Inputline **duplines = new(&a, Inputline*, uniqlines);
        i32 nduplines = 0;
        Str input = {0};
        for (i32 l = 0; l < uniqlines;) {
            i32 i = randrange(&rng, 0, l+1);
            for (; !inputlines[i].repeats; i++) {}
            affirm(i <= l);
            input = concat(&a, input, inputlines[i].line);
            inputlines[i].repeats--;
            if (inputlines[i].repeated++ == 1) {
                duplines[nduplines++] = &inputlines[i];
            }
            l += i == l;
        }

        {
            Arena t = a;
            Plt plt = {0};
            plt.input = input;
            plt.cap = maxoutsz;
            plt.output.data = new(&t, u8, plt.cap);

            Str expectedoutput = {0};
            for (i32 i = 0; i < uniqlines; i++) {
                expectedoutput = concat(&t, expectedoutput, inputlines[i].line);
            }

            char *argv[] = {"uuniq", 0};
            i32 argc = countof(argv) - 1;
            i32 status = uuniq(argc, (u8 **)argv, &plt, (Mem){t.beg, t.end-t.beg});

            affirm(status == STATUS_OK);
            affirm(equals(plt.output, expectedoutput));
        }

        {
            Arena t = a;
            Plt plt = {0};
            plt.input = input;
            plt.cap = maxoutsz;
            plt.output.data = new(&t, u8, plt.cap);

            Str expectedoutput = {0};
            for (i32 i = 0; i < nduplines; i++) {
                expectedoutput = concat(&t, expectedoutput, duplines[i]->line);
            }

            char *argv[] = {"uuniq", "-d", 0};
            i32 argc = countof(argv) - 1;
            i32 status = uuniq(argc, (u8 **)argv, &plt, (Mem){t.beg, t.end-t.beg});

            affirm(status == STATUS_OK);
            affirm(equals(plt.output, expectedoutput));
        }
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

static Mem plt_alloc(Plt *) {
    affirm(0);
}

static b32  plt_open(Plt *, i32, u8 *, b32, Arena *) { affirm(0); }
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
    printf("%-40s%lld\n", cmd, (long long)time);
}

static u64 rand64(u64 *rng)
{
    return (*rng = *rng*0x3243f6a8885a308d + 1);
}

static i32 randrange(u64 *rng, i32 lo, i32 hi)
{
    return (i32)(((rand64(rng)>>32) * (hi - lo))>>32) + lo;
}

static Str randomlines(Arena *a, u64 *rng, i32 n, i32 maxlen, i32 maxrepeats) {
    Str *lines = new(a, Str, n);
    for (i32 i = 0; i < n; i++) {
        Str *line = &lines[i];
        line->len = randrange(rng, 1, maxlen + 1);
        line->data = new(a, u8, line->len);
        for (i32 ci = 0; ci < line->len; ci++) {
            line->data[ci] = (u8)randrange(rng, 32, 126);
        }
    }
    Str r = {0};
    i32 rs = maxrepeats;
    for (i32 i = 0; i < n;) {
        i32 pick = rs-- > 0 ? randrange(rng, 0, i + 1) : i;
        r = concat(a, r, lines[pick]);
        r = concat(a, r, S("\n"));
        if (pick == i) {
            i++;
            rs = maxrepeats;
        }
    }
    return r;
}

static void runbench(char *cmd, Plt *plt, Arena a) {
    i64 best = maxof(i64);
    for (i32 n = 0; n < 1<<9; n++) {
        plt->inpos = 0;
        i64 total = -perf_counter();
        i32 r = uuniq(0, 0, plt, (Mem){a.beg, a.end-a.beg});
        affirm(r == STATUS_OK);
        total += perf_counter();
        best = total<best ? total : best;
    }
    report(cmd, best);
}

int main(void)
{
    i32   cap = 1<<24;
    byte *mem = malloc(cap);
    Arena a   = {0, mem, mem+cap};
    memset(mem, 0xa5, cap);  // pre-commit whole arena

    puts("uuniq: BENCH");
    printf("sizeof(Strset): %zu bytes\n", sizeof(Strset));

    {
        u64 rng = 1;
        Arena tmp = a;
        Plt  *plt = new(&tmp, Plt);
        plt->input = randomlines(&tmp, &rng, 300, 30, 1000);
        runbench("short lines", plt, tmp);
    }

    {
        u64 rng = 2;
        Arena tmp = a;
        Plt  *plt = new(&tmp, Plt);
        plt->input = randomlines(&tmp, &rng, 30000, 30, 0);
        runbench("short lines - no repeats", plt, tmp);
    }

    {
        u64 rng = 3;
        Arena tmp = a;
        Plt  *plt = new(&tmp, Plt);
        plt->input = randomlines(&tmp, &rng, 60, 1000, 100);
        runbench("long lines", plt, tmp);
    }

    {
        u64 rng = 4;
        Arena tmp = a;
        Plt  *plt = new(&tmp, Plt);
        plt->input = randomlines(&tmp, &rng, 2500, 1000, 0);
        runbench("long lines - no repeats", plt, tmp);
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

static iz allocsz = 1<<24; // Initially 16MiB

static Mem plt_alloc(Plt *plt) {
    Mem r = {0};
    r.beg = mmap(0, allocsz, PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (r.beg == MAP_FAILED) {
        static const u8 msg[] = "uuniq: not enough memory\n";
        plt_write(plt, 2, (u8*)msg, countof(msg));
        plt_exit(plt, STATUS_OOM);
    }
    r.cap = allocsz;
    allocsz *= 2;
    return r;
}

static b32 plt_open(Plt *plt, i32 fd, u8 *path, b32 trunc, Arena *a)
{
    int mode = fd==0 ? O_RDONLY : O_CREAT|O_WRONLY;
    mode |= trunc ? O_TRUNC : 0;
    plt->fds[fd] = open((char *)path, mode, 0666);
    return plt->fds[fd] != -1;
}

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
    Plt plt = {{0, 1, 2}};
    Mem mem = plt_alloc(&plt);
    return uuniq(argc, (u8 **)argv, &plt, mem);
}

#endif
