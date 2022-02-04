// csvquote: encode quoted CSV fields for easier processing
//   $ cc -std=c11 -march=x86-64-v3 -O3 -o csvquote csvquote.c
//   $ cl /std:c11 /arch:AVX2 /Ox csvquote.c
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <string.h>

// The global work buffer
_Alignas(32)
static unsigned char buf[1<<15];


// ## Input/output handling ##

// Initialize I/O state.
static void io_init(void);

// Fill buf from std input. Return bytes read, 0 for EOF, -1 on error.
static int io_read(void);

// Write buf to std output, Return bytes written, -1 on error.
static int io_write(int len);

#if !defined(PLAIN) && (defined(__unix__) || defined(__APPLE__))
#include <unistd.h>

static void io_init(void) { /* empty */ }

static int
io_read(void)
{
    int n = 0;
    do {
        int r = read(0, buf+n, sizeof(buf)-n);
        switch (r) {
        case -1: return -1;
        case  0: return  n;
        default: n += r;
        }
    } while (n < (int)sizeof(buf));
    return n;
}

static int
io_write(int len)
{
    int n = 0;
    do {
        int r = write(1, buf+n, len-n);
        switch (r) {
        case -1: return -1;
        default: n += r;
        }
    } while (n < len);
    return n;
}

#elif !defined(PLAIN) && defined(_WIN32)
#include <windows.h>

static HANDLE io_in, io_out;

static void
io_init(void)
{
    io_in = GetStdHandle(STD_INPUT_HANDLE);
    io_out = GetStdHandle(STD_OUTPUT_HANDLE);
    // TODO: Check if it's a console and do UTF-16 encoding/decoding?
}

static int
io_read(void)
{
    int n = 0;
    do {
        DWORD c;
        if (!ReadFile(io_in, buf+n, sizeof(buf)-n, &c, 0)) {
            return GetLastError() == ERROR_BROKEN_PIPE ? n : -1;
        }
        if (!c) {
            return n;
        }
        n += c;
    } while (n < (int)sizeof(buf));
    return n;
}

static int
io_write(int len)
{
    int n = 0;
    do {
        DWORD c;
        if (!WriteFile(io_out, buf+n, len-n, &c, 0)) {
            return -1;
        }
        n += c;
    } while (n < len);
    return n;
}

#else // plain old C

static void io_init(void) { /* empty */ }

static int
io_read(void)
{
    int n = fread(buf, 1, sizeof(buf), stdin);
    if (!n) {
        return ferror(stdin) ? -1 : 0;
    }
    return n;
}

static int
io_write(int len)
{
    int n = fwrite(buf, 1, sizeof(buf), stdout);
    if (n < len) {
        return -1;
    }
    return fflush(stdout) ? -1 : n;
}
#endif


// ## Encoder ##

// Initialize encoder table for translating a0/a1 into b0/b1.
static void encode_init(int a0, int a1, int b0, int b1);

// Encode buf according to table configuration.
static void encode(void);

// Count 0x1f and 0x1e bytes in buf.
static int check(void);

#if !defined(PLAIN) && defined(__AVX2__)
#include <immintrin.h>

static unsigned char table[4];

static void
encode_init(int a0, int a1, int b0, int b1)
{
    table[0] = a0;
    table[1] = a1;
    table[2] = b0;
    table[3] = b1;
}

static void
encode(void)
{
    __m256i Q = _mm256_set1_epi8(0x22);  // QUOTATION MARK
    __m256i N = _mm256_set1_epi8(table[0]);
    __m256i C = _mm256_set1_epi8(table[1]);
    __m256i E = _mm256_set1_epi8(table[2]);
    __m256i F = _mm256_set1_epi8(table[3]);
    __m256i S = _mm256_setr_epi64x(
        0x0000000000000000, 0x0101010101010101,
        0x0202020202020202, 0x0303030303030303
    );
    __m256i M = _mm256_set1_epi64x(0x7fbfdfeff7fbfdfe);
    __m256i A = _mm256_set1_epi64x(0xffffffffffffffff);

    static unsigned mode = 0;
    for (int i = 0; i < (int)sizeof(buf); i += 32) {
        __m256i b = _mm256_load_si256((void *)(buf+i));

        // Match various kinds of bytes in the chunk
        __m256i m = _mm256_cmpeq_epi8(b, Q);
        __m256i c = _mm256_cmpeq_epi8(b, C);
        __m256i n = _mm256_cmpeq_epi8(b, N);

        // Compute quoted region mask using bitwise operators
        unsigned mask = _mm256_movemask_epi8(m);
        for (unsigned x = mask; x; x &= x - 1) {
            mask ^= -x ^ x;
        }
        mask ^= mode;
        mode = -(mask >> 31);  // "carry"

        // Convert mask from 32-bit to 32-byte
        m = _mm256_set1_epi32(mask);
        m = _mm256_shuffle_epi8(m, S);
        m = _mm256_or_si256(m, M);
        m = _mm256_cmpeq_epi8(m, A);

        // Copy replacements in quoted region
        n = _mm256_and_si256(n, m);
        c = _mm256_and_si256(c, m);
        b = _mm256_blendv_epi8(b, E, n);
        b = _mm256_blendv_epi8(b, F, c);

        _mm256_store_si256((void *)(buf+i), b);
    }
}

static int
check(void)
{
    #if defined(__GNUC__) || defined(__clang__)
    #  define POPCOUNT __builtin_popcount
    #elif defined(_MSC_VER)
    #  define POPCOUNT __popcnt
    #endif
    int n = 0;
    __m256i M = _mm256_set1_epi8(0xfe);
    __m256i C = _mm256_set1_epi8(0x1e);
    for (int i = 0; i < (int)sizeof(buf); i += 32) {
        __m256i b = _mm256_load_si256((void *)(buf+i));
        b = _mm256_and_si256(b, M);
        b = _mm256_cmpeq_epi8(b, C);
        n += POPCOUNT(_mm256_movemask_epi8(b));
    }
    return n;
}

#else // plain old C

// table[0] for outside quotes, table[1] for inside quotes
static unsigned char table[2][256];

static void
encode_init(int a0, int a1, int b0, int b1)
{
    for (int i = 0; i < 256; i++) {
        table[0][i] = i;
        table[1][i] = i;
    }
    table[1][a0] = b0;
    table[1][a1] = b1;
}

static void
encode(void)
{
    static int mode = 0;
    for (int i = 0; i < (int)sizeof(buf); i++) {
        mode ^= buf[i] == 0x22;
        buf[i] = table[mode][buf[i]];
    }
}

static int
check(void)
{
    int c = 0;
    for (int i = 0; i < (int)sizeof(buf); i++) {
        c += buf[i]>>1 == 0x0f;
    }
    return c;
}

#endif


// ## User interface ##

static int
xisalnum(int c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

static int xoptind = 1;
static int xoptopt;
static char *xoptarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;

    arg = xoptind < argc ? argv[xoptind] : 0;
    if (arg && strcmp(arg, "--") == 0) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !xisalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        xoptopt = arg[optpos];
        if (!opt) {
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                xoptarg = (char *)arg + optpos + 1;
                xoptind++;
                optpos = 1;
                return xoptopt;
            } else if (argv[xoptind + 1]) {
                xoptarg = (char *)argv[xoptind + 1];
                xoptind += 2;
                optpos = 1;
                return xoptopt;
            } else {
                return ':';
            }
        } else {
            if (!arg[++optpos]) {
                xoptind++;
                optpos = 1;
            }
            return xoptopt;
        }
    }
}

static int
usage(FILE *f)
{
    static const char usage[] =
    "usage: csvquote [-Shu]\n"
    "Encodes standard input to standard output.\n"
    "  -S    abort if the encoding would be irreversible (strict)\n"
    "  -h    print this help message\n"
    "  -u    restore the original CSV (reverse)\n";
    return fwrite(usage, sizeof(usage)-1, 1, f) && !fflush(f);
}

static const char *
run(int argc, char **argv)
{
    int option;
    int strict = 0;
    static char missing[] = "missing argument: -?";
    static char illegal[] = "illegal option: -?";

    encode_init(0x0a, 0x2c, 0x1e, 0x1f); // LF COMMA RS US

    while ((option = xgetopt(argc, argv, ":Shu")) != -1) {
        switch (option) {
        case 'S': strict = 1;
                  break;
        case 'h': return usage(stdout) ? 0 : "write error";
        case 'u': encode_init(0x1e, 0x1f, 0x0a, 0x2c); // RS US LF COMMA
                  break;
        case ':': missing[sizeof(missing)-2] = xoptopt;
                  usage(stderr);
                  return missing;
        case '?': illegal[sizeof(illegal)-2] = xoptopt;
                  usage(stderr);
                  return illegal;
        }
    }

    io_init();

    for (;;) {
        int n = io_read();
        switch (n) {
        case -1: return "read error";
        case  0: return 0;
        }

        if (strict && check()) {
            return "ambiguous encoding";
        }

        encode();

        if (io_write(n) == -1) {
            return "write error";
        }

        if (n < (int)sizeof(buf)) {
            return 0;
        }
    }
}

int
main(int argc, char **argv)
{
    const char *err = run(argc, argv);
    if (err) {
        fputs("csvquote: ", stderr);
        fputs(err, stderr);
        fputs("\n", stderr);
        return 1;
    }
    return 0;
}
