// Lottery Simulator
//   $ cc -O3 -s -o lottery lottery.c
//   $ ./lottery -6s0
// Ref: https://memory.psych.mun.ca/models/lottery/
// This is free and unencumbered software released into the public domain.
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define COST   3
#define WIN0   0
#define WIN1   0
#define WIN2   3
#define WIN3   10
#define WIN4   60
#define WIN5   1500
#define WIN6   15000000

static const int payouts[] = {WIN0, WIN1, WIN2, WIN3, WIN4, WIN5, WIN6};

static uint64_t
rng(uint64_t *s)
{
    uint64_t r = (*s += 1111111111111111111U);
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;
    return r;
}

static uint64_t
draw(uint64_t *s)
{
    char n[49] = {
        +0, +1, +2, +3, +4, +5, +6, +7, +8, +9, 10, 11, 12, 13,
        14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48,
    };
    uint64_t r;

    do r = rng(s); while (r < 1275064576);
    r -= 1275064576;

    uint64_t d = 0;
    d |= (uint64_t)1 << n[r % 49]; n[r%49] = n[48];
    d |= (uint64_t)1 << n[r % 48]; n[r%48] = n[47];
    d |= (uint64_t)1 << n[r % 47]; n[r%47] = n[46];
    d |= (uint64_t)1 << n[r % 46]; n[r%46] = n[45];
    d |= (uint64_t)1 << n[r % 45]; n[r%45] = n[44];
    d |= (uint64_t)1 << n[r % 44];
    return d;
}

static char *
print(char *p, uint64_t d)
{
    for (int i = 0; i < 49; i++) {
        if (d & (uint64_t)1 << i) {
            p += sprintf(p, "%3d", i+1);
        }
    }
    *p = '\n';
    return p + 1;
}

static const char *
commas(long long v)
{
    int n = 0;
    int b = v < 0;
    long long f = 1;

    v = llabs(v);
    for (long long x = v/1000; x; x /= 1000, n++, f *= 1000);

    static char buf[64];
    char *p = buf;
    if (b) *p++ = '-';
    p += sprintf(p, "%d", (int)(v / f));
    for (int i = 0; i < n; i++) {
        v %= f;
        f /= 1000;
        p += sprintf(p, ",%03d", (int)(v / f));
    }
    return buf;
}

static int optind = 1;
static int opterr = 1;
static int optopt;
static char *optarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    /* Reset? */
    if (optind == 0) {
        optind = 1;
        optpos = 1;
    }

    arg = argv[optind];
    if (arg && strcmp(arg, "--") == 0) {
        optind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        optopt = arg[optpos];
        if (!opt) {
            if (opterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], optopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                optarg = (char *)arg + optpos + 1;
                optind++;
                optpos = 1;
                return optopt;
            } else if (argv[optind + 1]) {
                optarg = (char *)argv[optind + 1];
                optind += 2;
                optpos = 1;
                return optopt;
            } else {
                if (opterr && *optstring != ':')
                    fprintf(stderr, "%s: option requires an argument: %c\n",
                            argv[0], optopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                optind++;
                optpos = 1;
            }
            return optopt;
        }
    }
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: lottery [-0123456hw] [-s N]\n");
    fprintf(f, "  -#     quit on this match\n");
    fprintf(f, "  -h     print this message\n");
    fprintf(f, "  -s N   skip every 2**N printouts [20]\n");
    fprintf(f, "  -w     quit on positive winnings\n");
}

static int
doquit(int quit, int match, long long winnings)
{
    return !!(1<<match & quit) || (!!(1<<7 & quit) && winnings > 0);
}

int
main(int argc, char **argv)
{
#ifdef _WIN32
    __declspec(dllimport) void *__stdcall GetStdHandle(unsigned);
    __declspec(dllimport) int __stdcall GetConsoleMode(void *, unsigned *);
    __declspec(dllimport) int __stdcall SetConsoleMode(void *, unsigned);
    void *handle;
    unsigned mode;
    handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
    if (GetConsoleMode(handle, &mode)) {
        mode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(handle, mode); // ignore errors
    }
#endif

    int quit = 0;
    long long mask = (1LL<<20) - 1;

    int opt;
    while ((opt = xgetopt(argc, argv, "0123456hs:w")) != -1) {
        switch (opt) {
        case '0': case '1': case '2': case '3': case '4': case '5': case '6':
                  quit |= 1 << (opt - '0');
                  break;
        case 'h': usage(stdout);
                  return 0;
        case 's': opt = atoi(optarg);
                  mask = (1LL << (opt<0 ? 0 : opt>62 ? 62 : opt)) - 1;
                  break;
        case 'w': quit |= 1 << 7;
                  break;
        default:  usage(stderr);
                  return 1;
        }
    }

    long long weeks = 1;
    long long winnings = 0;
    long long hist[7] = {0};
    uint64_t s[] = {time(0)};

    printf("\x1b[2J\x1b[?25l");
    for (;; weeks++) {
        if (rng(s) % 0x100000 == 0) {
            uint64_t h = clock();
            *s ^= rng(&h);  // stir in more entropy
        }

        uint64_t a = draw(s);
        uint64_t b = draw(s);
        int match = __builtin_popcountll(a & b);
        winnings += payouts[match] - COST;
        hist[match]++;

        if (!doquit(quit, match, winnings) && (rng(s)&mask) && weeks > 1) {
            continue;
        }

        static char buf[4096];
        char *p = buf;
        p += sprintf(p, "\x1b[H");
        p += sprintf(p, "Drawings:        %-24s\n", commas(weeks));
        p += sprintf(p, "Years:           %-24s\n", commas(weeks/52));
        p += sprintf(p, "Winnings:        $%s", commas(winnings));
        p += sprintf(p, "%-20s\n", ".00");
        p += sprintf(p, "Your Ticket:    "); p = print(p, a);
        p += sprintf(p, "Winning Numbers:"); p = print(p, b);
        *p++ = '\n';
        for (int i = 0; i < 7; i++) {
            const char *c = commas(hist[i]);
            double part = (double)hist[i] / weeks;
            p += sprintf(p, "Match %c: %16s %.17f\n", '0'+i, c, part);
        }
        if (!fwrite(buf, p-buf, 1, stdout)) {
            break;
        }

        if (doquit(quit, match, winnings)) {
            break;
        }
    }
    printf("\x1b[?25h\x1b[m\n");
}
