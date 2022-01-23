/* prips: print IPv4 address ranges
 *
 * A feature-complete clone and drop-in replacement for the original
 * GPL-licensed prips command line tool written by Daniel Kelly,
 * improving on the original:
 *
 * - 100% portable to any ANSI C implementation
 * - Validates inputs so it doesn't produce garbage
 * - Correctly handles the entire IPv4 range
 * - No buffer overflows for pathological inputs
 * - Thorough error checks
 * - Faster, especially for large ranges and exclusions
 * - Around 10x-100x faster, especially for large ranges and exclusions
 * - Dedicated to the public domain (better "license")
 *
 * This is free and unencumbered software released into the public domain.
 */

/* Write a buffer to 1 (standard output) or 2 (standard error), without
 * buffering and potentially with multiple underlying writes. Return
 * non-zero on success.
 *
 * This is the only function that interacts with libc or the outside
 * world. The program does its own buffering and formatting.
 */
static int xwrite(int fd, const char *buf, int len);

/* Minimalist build (Linux x86-64)
 *   $ make CFLAGS="-Os -fno-pie -ffreestanding"
 *          LDFLAGS="-s -no-pie -nostdlib --Wl,--omagic"
 * Note: --omagic binaries are much smaller but less compatible
 */
#if defined(__linux__) && defined(__amd64) && !__STDC_HOSTED__
__asm (
    ".global _start\n"
    "_start:\n"
    "   movl  (%rsp), %edi\n"
    "   lea   8(%rsp), %rsi\n"
    "   call  main\n"
    "   movl  %eax, %edi\n"
    "   movl  $60, %eax\n"
    "   syscall\n"
);

static int
xwrite(int fd, const char *buf, int len)
{
    int n = 0;
    do {
        long r;
        __asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(1L), "D"(fd), "S"(buf), "d"(len)
            : "rcx", "r11", "memory"
        );
        if (r < 0) return 0;
        n += (int)r;
    } while (n < len);
    return 1;
}

#elif defined(__unix__) || defined(__APPLE__)
#include <unistd.h>

static int
xwrite(int fd, const char *buf, int len)
{
    int n = 0;
    do {
        int r = write(fd, buf+n, len-n);
        switch (r) {
        case -1: return 0;
        default: n += r;
        }
    } while (n < len);
    return 1;
}

#elif defined(_WIN32)
#include <windows.h>

/* Minimalist build (Windows)
 *   $ make CFLAGS="-Os -ffreestanding"
 *          LDFLAGS="-s -nostdlib" LDLIBS="-lkernel32 -lshell32"
 *   C:\>cl /Os /GS- prips.c
 */
#  if defined(_MSC_VER) || !__STDC_HOSTED__
#  define main oldmain
#  if defined(_MSC_VER)
#      pragma comment(lib, "kernel32")
#      pragma comment(lib, "shell32")
#      pragma comment(linker, "/subsystem:console")
#   endif
int
mainCRTStartup(void)
{
    size_t len;
    int argc, i;
    wchar_t **wargv;
    char **argv, *buf, *p;
    int main(int, char **);

    wargv = CommandLineToArgvW(GetCommandLineW(), &argc);

    len = (1 + argc)*sizeof(*argv);
    for (i = 0; i < argc; i++) {
        len += WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, 0, 0, 0, 0);
    }
    buf = LocalAlloc(0, len);

    argv = (char **)buf;
    p = buf + (1 + argc)*sizeof(*argv);
    for (i = 0; i < argc; i++) {
        argv[i] = p;
        p += WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, p, buf+len-p, 0, 0);
    }
    argv[argc] = 0;

    LocalFree(wargv);
    return main(argc, argv);
}
#  endif

static int
xwrite(int fd, const char *buf, int len)
{
    HANDLE h = GetStdHandle(fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    int n = 0;
    do {
        DWORD c;
        if (!WriteFile(h, buf+n, len-n, &c, 0)) {
            return 0;
        }
        n += c;
    } while (n < len);
    return 1;
}

#else
#include <stdio.h>

static int
xwrite(int fd, const char *buf, int len)
{
    FILE *f = fd == 1 ? stdout : stderr;
    return fwrite(buf, len, 1, f) && !fflush(f);
}
#endif

/* Output a null-terminated string followed by with a newline. Returns
 * non-zero on success.
 */
static int
xputs(int fd, const char *s)
{
    int len = 0;
    const char *p;
    for (p = s; *p; p++) {
        len++;
    }
    /* Two unbuffered writes isn't great, but this function is only used
     * once to print an error message (i.e. the slow path).
     */
    return xwrite(fd, s, len) && xwrite(fd, "\n", 1);
}

/* Return the printed decimal length for any unsigned 32-bit integer.
 */
static int
uint32_len(unsigned long u)
{
    return (u >=         10) + (u >=        100) + (u >=       1000) +
           (u >=      10000) + (u >=     100000) + (u >=    1000000) +
           (u >=   10000000) + (u >=  100000000) + (u >= 1000000000) + 1;
}

/* Try to parse a plain integer from the buffer within range. On
 * failure, err points to a descriptive error message.
 */
static unsigned long
uint32_parse(const char *s, unsigned long max, const char **err)
{
    unsigned long n = 0;
    for (*err = "invalid format"; *s; s++, *err = 0) {
        unsigned v = (*s&0xff) - '0';
        if (v > 9) {
            *err = "invalid format";
            break;
        }

        if (n > max/10) {
            *err = "out of range";
            break;
        }
        n *= 10;

        if (max < v || max-v < n) {
            *err = "out of range";
            break;
        }
        n += v;
    }
    return n;
}

/* Decode a quad-dotted IPv4 address string into a numerical address.
 * Returns non-zero if input was valid.
 */
static int
ipv4_parse(const char *s, unsigned long *ip)
{
    int c = 0, n = 0, a = 0;
    for (*ip = 0;; s++) {
        switch (*s) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            a = a*10 + *s - '0';
            if (a > 255) {
                return 0;
            }
            n++;
            break;
        case '.': case 0:
            if (!n || c == 4) {
                return 0;
            }
            *ip = *ip<<8 | a;
            c++;
            if (!*s) {
                return c == 4;
            }
            n = a = 0;
            break;
        default:
            return 0;
        }
    }
}

/* Convert a count to an actual mask.
 */
static unsigned long
cidr_to_mask(int cidr)
{
    return cidr ? -1UL<<(32 - cidr) : ~0xffffffffUL;
}

/* Parse an IP address with CIDR subnet mask.
 */
static int
cidr_parse(const char *s, unsigned long *ip, unsigned long *mask)
{
    const char *err;
    int i, cidr;
    char copy[16];

    for (i = 0; i < 16; i++) {
        if (s[i] == '/') {
            copy[i] = 0;
            if (!ipv4_parse(copy, ip)) {
                return 0;
            }

            cidr = uint32_parse(s+i+1, 32, &err);
            if (err) {
                return 0;
            }
            *mask = cidr_to_mask(cidr);
            return 1;
        }
        copy[i] = s[i];
    }
    return 0;
}

/* Encode a numerical IPv4 address into a quad-dotted address string.
 * The destination buffer size must be at least 16 bytes. Returns the
 * length not including the null terminator.
 */
static int
ipv4_dot(char *s, unsigned long ip)
{
    int i;
    char *d = s;
    for (i = 3; i >= 0; i--) {
        int v = ip>>(i*8) & 0xff;
        *d = '0' + v/100  ; d += v >= 100;
        *d = '0' + v/10%10; d += v >=  10;
        *d = '0' + v%10   ; d++;
        *d = i ? '.' : 0  ; d++;
    }
    return d - s - 1;
}

/* Encode a numerical IPv4 address into a decimal string. The
 * destination buffer size must be at least 11 bytes. Does not null
 * terminate. Returns the length.
 */
static int
ipv4_dec(char *s, unsigned long ip)
{
    int i, n = uint32_len(ip);
    for (i = n; i; i--) {
        s[i-1] = '0' + ip%10;
        ip /= 10;
    }
    return n;
}

/* Encode a numerical IPv4 address into a hexadecimal string. The
 * destination buffer size must be at least 9 bytes. Does not null
 * terminate. Returns the length.
 */
static int
ipv4_hex(char *s, unsigned long ip)
{
    /* note: optimized for little endian */
    static const unsigned short t[256] = {
        0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730,
        0x3830, 0x3930, 0x6130, 0x6230, 0x6330, 0x6430, 0x6530, 0x6630,
        0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731,
        0x3831, 0x3931, 0x6131, 0x6231, 0x6331, 0x6431, 0x6531, 0x6631,
        0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732,
        0x3832, 0x3932, 0x6132, 0x6232, 0x6332, 0x6432, 0x6532, 0x6632,
        0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733,
        0x3833, 0x3933, 0x6133, 0x6233, 0x6333, 0x6433, 0x6533, 0x6633,
        0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734,
        0x3834, 0x3934, 0x6134, 0x6234, 0x6334, 0x6434, 0x6534, 0x6634,
        0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735,
        0x3835, 0x3935, 0x6135, 0x6235, 0x6335, 0x6435, 0x6535, 0x6635,
        0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736,
        0x3836, 0x3936, 0x6136, 0x6236, 0x6336, 0x6436, 0x6536, 0x6636,
        0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737,
        0x3837, 0x3937, 0x6137, 0x6237, 0x6337, 0x6437, 0x6537, 0x6637,
        0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638, 0x3738,
        0x3838, 0x3938, 0x6138, 0x6238, 0x6338, 0x6438, 0x6538, 0x6638,
        0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539, 0x3639, 0x3739,
        0x3839, 0x3939, 0x6139, 0x6239, 0x6339, 0x6439, 0x6539, 0x6639,
        0x3061, 0x3161, 0x3261, 0x3361, 0x3461, 0x3561, 0x3661, 0x3761,
        0x3861, 0x3961, 0x6161, 0x6261, 0x6361, 0x6461, 0x6561, 0x6661,
        0x3062, 0x3162, 0x3262, 0x3362, 0x3462, 0x3562, 0x3662, 0x3762,
        0x3862, 0x3962, 0x6162, 0x6262, 0x6362, 0x6462, 0x6562, 0x6662,
        0x3063, 0x3163, 0x3263, 0x3363, 0x3463, 0x3563, 0x3663, 0x3763,
        0x3863, 0x3963, 0x6163, 0x6263, 0x6363, 0x6463, 0x6563, 0x6663,
        0x3064, 0x3164, 0x3264, 0x3364, 0x3464, 0x3564, 0x3664, 0x3764,
        0x3864, 0x3964, 0x6164, 0x6264, 0x6364, 0x6464, 0x6564, 0x6664,
        0x3065, 0x3165, 0x3265, 0x3365, 0x3465, 0x3565, 0x3665, 0x3765,
        0x3865, 0x3965, 0x6165, 0x6265, 0x6365, 0x6465, 0x6565, 0x6665,
        0x3066, 0x3166, 0x3266, 0x3366, 0x3466, 0x3566, 0x3666, 0x3766,
        0x3866, 0x3966, 0x6166, 0x6266, 0x6366, 0x6466, 0x6566, 0x6666
    };
    s[0] = t[ip >> 24 & 0xff] >> 0; s[1] = t[ip >> 24 & 0xff] >> 8;
    s[2] = t[ip >> 16 & 0xff] >> 0; s[3] = t[ip >> 16 & 0xff] >> 8;
    s[4] = t[ip >>  8 & 0xff] >> 0; s[5] = t[ip >>  8 & 0xff] >> 8;
    s[6] = t[ip >>  0 & 0xff] >> 0; s[7] = t[ip >>  0 & 0xff] >> 8;
    return 8;
}

/* Determine a format given a string name.
 */
static enum format {FORMAT_BAD, FORMAT_DOT, FORMAT_DEC, FORMAT_HEX}
format_parse(const char *s)
{
    if (s[0] && s[1] && s[2]) {
        switch ((unsigned long)s[0] <<  0 | (unsigned long)s[1] <<  8 |
                (unsigned long)s[2] << 16 | (unsigned long)s[3] << 24) {
        case 0x746f64: return FORMAT_DOT;
        case 0x636564: return FORMAT_DEC;
        case 0x786568: return FORMAT_HEX;
        }
    }
    return FORMAT_BAD;
}

/* Print an IP address according to the chosen format, returning its
 * length. Buffer must be at least 16 bytes long.
 */
static int
format_print(char *buf, enum format f, unsigned long ip)
{
    switch (f) {
    case FORMAT_DOT: return ipv4_dot(buf, ip);
    case FORMAT_DEC: return ipv4_dec(buf, ip);
    case FORMAT_HEX: return ipv4_hex(buf, ip);
    default: return (*(volatile char *)0 = 0);
    }
}

/* Populate an exclusion table from an exclusion specification. Returns
 * non-zero if the specification was valid. May be called repeatedly to
 * append additional exclusions.
 *
 * The table is a bit array with 16-bit elements. Each of the four IP
 * octets uses 16 array elements. A bit is set if that particular octet
 * value should be excluded.
 *
 * Each IP octet is a list of zero or more comma-separated octets to be
 * excluded. Trailing empty IP octets may be omitted. Empty list
 * elements are disallowed, but trailing commas are allowed.
 *
 *   ""       = valid (omitted octets)
 *   "0"      = valid (omitted octets)
 *   "0,"     = valid (trailing comma, omitted octets)
 *   "0,1"    = valid (omitted octets)
 *   ".."     = valid (omitted octets)
 *   "..."    = valid
 *   "...0"   = valid
 *   "...0,"  = valid (trailing comma)
 *   "..0,.0" = valid (trailing comma)
 *   ".0,"    = valid (trailing comma, omitted octets)
 *   "...,"   = invalid (empty list element)
 *   "..,."   = invalid (empty list element)
 *   "...."   = invalid (too many IP octets)
 */
static int
exclude_parse(unsigned short table[4][16], const char *s)
{
    int c, n, a;
    for (a = 0, c = 0, n = 0; ; s++) {
        int v = *s;
        switch (v) {
        case 0: case ',': case '.':
            if (v == ',' && n == 0) {
                return 0;
            }
            if (n != 0) {
                table[c][a/16] |= 1U << (a%16);
            }

            if (v == 0) {
                return 1;
            }

            if (v == '.') {
                if (c == 3) {
                    return 0;
                }
                c++;
            }
            n = a = 0;
            break;

        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            a = a*10 + *s - '0';
            if (a > 255) {
                return 0;
            }
            n++;
            break;

        default:
             return 0;
        }
    }
}

/* Return non-zero if the address is in the exclusion table.
 */
static int
exclude_match(unsigned short table[4][16], unsigned long ip)
{
    int a = ip >> 24       ;
    int b = ip >> 16 & 0xff;
    int c = ip >>  8 & 0xff;
    int d = ip       & 0xff;
    return (table[0][a/16] & 1U<<(a%16)) |
           (table[1][b/16] & 1U<<(b%16)) |
           (table[2][c/16] & 1U<<(c%16)) |
           (table[3][d/16] & 1U<<(d%16));
}

/* Wrap an error with additional context.
 */
static const char *
errwrap(const char *pre, const char *suf)
{
    static int toggle;
    static char errtmp[2][128];
    int i, m = 0, n = sizeof(errtmp[0]) - 4;
    char *dst = errtmp[(toggle = !toggle)], *p = dst;
    const char *src[3];

    src[0] = pre;
    src[1] = ": ";
    src[2] = suf;
    for (i = 0; i < n && m < 3; i++) {
        do {
            *p = *src[m];
            if (*src[m]++) {
                p++;
                break;
            }
            m++;
        } while (m < 3);
    }

    dst[n] = dst[n+1] = dst[n+2] = '.';
    return dst;
}

/* Same as isalnum(3), but without locale.
 */
static int
xisalnum(int c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

/* Same as strchr(3).
 */
static const char *
xstrchr(const char *s, int c)
{
    for (c = (char)c;; s++) {
        if (*s == c) {
            return s;
        } else if (!*s) {
            return 0;
        }
    }
}

static int xoptind = 1;
static int xoptopt;
static char *xoptarg;

/* Like getopt(3) but never prints error messages.
 */
static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    arg = argv[xoptind];
    if (arg && arg[0] == '-' && arg[1] == '-' && !arg[2]) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !xisalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = xstrchr(optstring, arg[optpos]);
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

static void
usage(int fd)
{
    static const char usage[] =
    "usage: prips [-ch] [-d N] [-f FMT] [-i N] [-e SPEC] <FIRST LAST | CIDR>\n"
    "  -c       output in CIDR notation\n"
    "  -d N     delimiter octet (0..255) [10]\n"
    "  -f FMT   output address format (dot, dec, hex) [dot]\n"
    "  -h       print this usage information\n"
    "  -i N     increment between addresses [1]\n"
    "  -e SPEC  exclude addresses with specific octets\n";
    xwrite(fd, usage, sizeof(usage)-1);
}

/* Like main(), but returns a static error string on error.
 */
const char *
run(int argc, char **argv)
{
    const char *err;
    int option;
    char opterr[] = {'-', 0, 0};
    int delim = '\n';
    int print_cidr = 0;
    int exclude = 0;
    unsigned long increment = 1;
    unsigned short exclude_table[4][16] = {{0}};
    enum format fmt = FORMAT_DOT;
    unsigned long beg, end, mask;

    while ((option = xgetopt(argc, argv, ":cd:f:hi:e:")) != -1) {
        switch (option) {
        case 'c':
            print_cidr = 1;
            break;
        case 'd':
            delim = uint32_parse(xoptarg, 255, &err);
            if (err) {
                return errwrap(errwrap("-d", err), xoptarg);
            }
            break;
        case 'f':
            if (!(fmt = format_parse(xoptarg))) {
                return errwrap("-f: invalid format", xoptarg);
            } break;
        case 'h':
            usage(1);
            return 0;
        case 'i':
            increment = uint32_parse(xoptarg, 0xffffffff, &err);
            if (err) {
                return errwrap("-i: invalid increment", xoptarg);
            }
            if (!increment) {
                return errwrap("-i: must be non-zero", xoptarg);
            }
            break;
        case 'e':
            exclude = 1;
            if (!exclude_parse(exclude_table, xoptarg)) {
                return errwrap("-e: invalid table", xoptarg);
            }
            break;
        case ':':
            opterr[1] = xoptopt;
            return errwrap(opterr, "option requires an argument");
        case '?':
            usage(2);
            opterr[1] = xoptopt;
            return errwrap("illegal option", opterr);
        }
    }

    argv += xoptind;
    switch (argc - xoptind) {
    case 1:  /* CIDR */
        if (!cidr_parse(argv[0], &beg, &mask)) {
            return errwrap("invalid CIDR IP address", argv[0]);
        }

        if (~mask & beg) {
            return errwrap("CIDR base address not a subnet boundary", argv[0]);
        }

        end = ~mask | (mask&beg);
        break;

    case 2:  /* START..END */
        if (!ipv4_parse(argv[0], &beg)) {
            return errwrap("invalid IP address", argv[0]);
        }
        if (!ipv4_parse(argv[1], &end)) {
            return errwrap("invalid IP address", argv[1]);
        }
        break;

    default:
        usage(2);
        return "wrong number of arguments";
    }

    if (end < beg) {
        return "start address larger than end address";
    }

    if (print_cidr) {
        char *p;
        char buf[16+3];
        int cidr = 32;
        unsigned long match;

        for (match = beg^end; match; match >>= 1) {
            cidr--;
        }
        mask = cidr_to_mask(cidr);
        p = buf + ipv4_dot(buf, beg&mask);
        *p++ = '/';
        if (cidr > 10) {
            *p++ = cidr/10 + '0';
        }
        *p++ = cidr%10 + '0';
        *p++ = delim;
        if (!xwrite(1, buf, p-buf)) {
            return "write error";
        }

    } else {
        int len = 0;
        static char buf[1<<13];
        for (;;) {
            if (!exclude || !exclude_match(exclude_table, beg)) {
                len += format_print(buf+len, fmt, beg);
                buf[len++] = delim;
                if (len > (int)sizeof(buf) - 16) {
                    if (!xwrite(1, buf, len)) {
                        return "write error";
                    }
                    len = 0;
                }
            }

            if (beg == end || beg+increment > end || beg+increment < beg) {
                break;
            }
            beg += increment;
        }
        if (len && !xwrite(1, buf, len)) {
            return "write error";
        }
    }

    return 0;
}

int
main(int argc, char **argv)
{
    const char *err = run(argc, argv);
    if (err) {
        xputs(2, errwrap("prips", err));
        return 1;
    }
    return 0;
}
