// idnabake: Randomly mangles domain names through inverse IDNA mapping
//   $ cc -Os -o idnabake idnabake.c
//   $ idnabake nullprogram.com
// This is free and unencumbered software released into the public domain.
#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <wchar.h>

static const char len[256] = {
    ['-'] =  3, ['.'] =  4, ['0'] =  5, ['1'] =  5, ['2'] =  5, ['3'] =  5,
    ['4'] =  5, ['5'] =  5, ['6'] =  5, ['7'] =  5, ['8'] =  5, ['9'] =  5,
    ['a'] = 10, ['b'] =  9, ['c'] = 12, ['d'] = 10, ['e'] = 10, ['f'] =  9,
    ['g'] =  9, ['h'] =  9, ['i'] = 13, ['j'] = 10, ['k'] = 10, ['l'] = 11,
    ['m'] = 12, ['n'] = 10, ['o'] = 11, ['p'] = 10, ['q'] =  8, ['r'] =  9,
    ['s'] =  9, ['t'] =  9, ['u'] =  9, ['v'] = 11, ['w'] =  8, ['x'] = 10,
    ['y'] =  7, ['z'] =  9,
};

static const signed char off[] = {  // note: biased negatively by i+64
    ['-'] = -109, ['.'] = -107, ['0'] = -105, ['1'] = -101, ['2'] =  -97,
    ['3'] =  -93, ['4'] =  -89, ['5'] =  -85, ['6'] =  -81, ['7'] =  -77,
    ['8'] =  -73, ['9'] =  -69, ['a'] = -104, ['b'] =  -95, ['c'] =  -87,
    ['d'] =  -76, ['e'] =  -67, ['f'] =  -58, ['g'] =  -50, ['h'] =  -42,
    ['i'] =  -34, ['j'] =  -22, ['k'] =  -13, ['l'] =   -4, ['m'] =   +6,
    ['n'] =  +17, ['o'] =  +26, ['p'] =  +36, ['q'] =  +45, ['r'] =  +52,
    ['s'] =  +60, ['t'] =  +68, ['u'] =  +76, ['v'] =  +84, ['w'] =  +94,
    ['x'] = +101, ['y'] = +110, ['z'] = +116,
};

static const unsigned short mapping[] = {  // BMP mappings only
    0x002d, 0xfe63, 0xff0d, 0x002e, 0x3002, 0xff0e, 0xff61, 0x0030, 0x2070,
    0x2080, 0x24ea, 0xff10, 0x0031, 0x00b9, 0x2081, 0x2460, 0xff11, 0x0032,
    0x00b2, 0x2082, 0x2461, 0xff12, 0x0033, 0x00b3, 0x2083, 0x2462, 0xff13,
    0x0034, 0x2074, 0x2084, 0x2463, 0xff14, 0x0035, 0x2075, 0x2085, 0x2464,
    0xff15, 0x0036, 0x2076, 0x2086, 0x2465, 0xff16, 0x0037, 0x2077, 0x2087,
    0x2466, 0xff17, 0x0038, 0x2078, 0x2088, 0x2467, 0xff18, 0x0039, 0x2079,
    0x2089, 0x2468, 0xff19, 0x0041, 0x0061, 0x00aa, 0x1d2c, 0x1d43, 0x2090,
    0x24b6, 0x24d0, 0xff21, 0xff41, 0x0042, 0x0062, 0x1d2e, 0x1d47, 0x212c,
    0x24b7, 0x24d1, 0xff22, 0xff42, 0x0043, 0x0063, 0x1d9c, 0x2102, 0x212d,
    0x216d, 0x217d, 0x24b8, 0x24d2, 0xa7f2, 0xff23, 0xff43, 0x0044, 0x0064,
    0x1d30, 0x1d48, 0x216e, 0x217e, 0x24b9, 0x24d3, 0xff24, 0xff44, 0x0045,
    0x0065, 0x1d31, 0x1d49, 0x2091, 0x2147, 0x24ba, 0x24d4, 0xff25, 0xff45,
    0x0046, 0x0066, 0x1da0, 0x2131, 0x24bb, 0x24d5, 0xa7f3, 0xff26, 0xff46,
    0x0047, 0x0067, 0x1d33, 0x1d4d, 0x210a, 0x24bc, 0x24d6, 0xff27, 0xff47,
    0x0048, 0x0068, 0x02b0, 0x1d34, 0x2095, 0x24bd, 0x24d7, 0xff28, 0xff48,
    0x0049, 0x0069, 0x1d35, 0x1d62, 0x2071, 0x2139, 0x2148, 0x2160, 0x2170,
    0x24be, 0x24d8, 0xff29, 0xff49, 0x004a, 0x006a, 0x02b2, 0x1d36, 0x2149,
    0x24bf, 0x24d9, 0x2c7c, 0xff2a, 0xff4a, 0x004b, 0x006b, 0x1d37, 0x1d4f,
    0x2096, 0x212a, 0x24c0, 0x24da, 0xff2b, 0xff4b, 0x004c, 0x006c, 0x02e1,
    0x1d38, 0x2097, 0x216c, 0x217c, 0x24c1, 0x24db, 0xff2c, 0xff4c, 0x004d,
    0x006d, 0x1d39, 0x1d50, 0x2098, 0x2133, 0x216f, 0x217f, 0x24c2, 0x24dc,
    0xff2d, 0xff4d, 0x004e, 0x006e, 0x1d3a, 0x207f, 0x2099, 0x2115, 0x24c3,
    0x24dd, 0xff2e, 0xff4e, 0x004f, 0x006f, 0x00ba, 0x1d3c, 0x1d52, 0x2092,
    0x2134, 0x24c4, 0x24de, 0xff2f, 0xff4f, 0x0050, 0x0070, 0x1d3e, 0x1d56,
    0x209a, 0x2119, 0x24c5, 0x24df, 0xff30, 0xff50, 0x0051, 0x0071, 0x211a,
    0x24c6, 0x24e0, 0xa7f4, 0xff31, 0xff51, 0x0052, 0x0072, 0x02b3, 0x1d3f,
    0x1d63, 0x24c7, 0x24e1, 0xff32, 0xff52, 0x0053, 0x0073, 0x017f, 0x02e2,
    0x209b, 0x24c8, 0x24e2, 0xff33, 0xff53, 0x0054, 0x0074, 0x1d40, 0x1d57,
    0x209c, 0x24c9, 0x24e3, 0xff34, 0xff54, 0x0055, 0x0075, 0x1d41, 0x1d58,
    0x1d64, 0x24ca, 0x24e4, 0xff35, 0xff55, 0x0056, 0x0076, 0x1d5b, 0x1d65,
    0x2164, 0x2174, 0x24cb, 0x24e5, 0x2c7d, 0xff36, 0xff56, 0x0057, 0x0077,
    0x02b7, 0x1d42, 0x24cc, 0x24e6, 0xff37, 0xff57, 0x0058, 0x0078, 0x02e3,
    0x2093, 0x2169, 0x2179, 0x24cd, 0x24e7, 0xff38, 0xff58, 0x0059, 0x0079,
    0x02b8, 0x24ce, 0x24e8, 0xff39, 0xff59, 0x005a, 0x007a, 0x1dbb, 0x2124,
    0x2128, 0x24cf, 0x24e9, 0xff3a, 0xff5a,
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        puts("usage: idnabake [HOSTNAME]...");
        puts("  Randomly mangle domain names through inverse IDNA mapping");
        return 0;
    }

    // Enable C runtime wide character support. Output may not simply be
    // UTF-8 compatible (e.g. Windows).
    #ifdef _WIN32
        int _isatty(int);
        int _setmode(int, int);
        _setmode(1, _isatty(1) ? 0x20000 : 0x40000);
    #else
        setlocale(LC_ALL, "");
    #endif

    // Seed PRNG using epoch plus some clock jitter
    unsigned long long rng = time(0);
    clock_t end, beg = clock();
    do {
        rng = rng*1111111111111111111U + beg;
    } while ((end = clock()) == beg);
    rng = rng*1111111111111111111U - end;

    for (int i = 1; i < argc; i++) {
        for (char *p = argv[i]; *p; p++) {
            int v = *p & 0xff;
            int n = len[v];
            if (!n) {
                fprintf(stderr, "idnabake: invalid '%c' 0x%02x\n", v, v);
                return 1;
            }
            int o = off[v] + v + 64;
            rng *= 0x3243f6a8885a308d + 1;
            fputwc(mapping[o + (rng >> 32)%n], stdout);
        }
        fputwc('\n', stdout);

        fflush(stdout);
        if (ferror(stdout)) {
            fprintf(stderr, "idnabake: output error\n");
            return 1;
        }
    }
}
