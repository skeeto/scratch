// BSD strtonum(), embeddable, no standard library dependency
// This is free and unencumbered software released into the public domain.
#if __STDC_HOSTED__ == 1
#  include <errno.h>
#endif

// Parse the buffer as a base 10 integer. The buffer may contain
// arbitrary leading whitespace ("\t\n\v\f\r "), one optional + or -,
// then any number of digits ("0123456789").
//
// If the result is < min, err = "too small", errno = ERANGE, return 0
// If the result is > max, err = "too large", errno = ERANGE, return 0
// If the buffer is invalid, err = "invalid", errno = EINVAL, return 0
// Otherwise set err to NULL and return the result
//
// Argument err is optional and may be NULL.
long long
strtonum(const char *buf, long long min, long long max, const char **err)
{
    const char *dummy;
    err = err ? err : &dummy;
    *err = 0;

    if (min > max) {
        goto invalid;
    }

    // Skip any leading whitespace
    for (; (*buf >= 0x09 && *buf <= 0x0d) || (*buf == 0x20); buf++);

    long long mmax, mmin, n = 0;
    switch (*buf) {
    case 0x2b: // +
        buf++; // fallthrough
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
    case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
        // Accumulate in positive direction, watching for max bound
        mmax = max / 10;
        do {
            int v = *buf++ - 0x30;

            if (v < 0 || v > 9) {
                goto invalid;
            }

            if (n > mmax) {
                goto toolarge;
            }
            n *= 10;

            if (max - v < n) {
                goto toolarge;
            }
            n += v;
        } while (*buf);

        // Still need to check min bound
        if (n < min) {
            goto toosmall;
        }
        return n;

    case 0x2d: // -
        buf++;
        // Accumulate in negative direction, watching for min bound
        mmin = min / 10;
        do {
            int v = *buf++ - 0x30;

            if (v < 0 || v > 9) {
                goto invalid;
            }

            if (n < mmin) {
                goto toosmall;
            }
            n *= 10;

            if (min + v > n) {
                goto toosmall;
            }
            n -= v;
        } while (*buf);

        // Still need to check max bound
        if (n > max) {
            goto toolarge;
        }
        return n;
    }

  invalid:
    #if __STDC_HOSTED__ == 1
        errno = EINVAL;
    #endif
    *err = "invalid";
    return 0;

  toolarge:
    // Skip remaining digits
    for (; *buf >= 0x30 && *buf <= 0x39; buf++);
    if (*buf) goto invalid;
    #if __STDC_HOSTED__ == 1
        errno = ERANGE;
    #endif
    *err = "too large";
    return 0;

  toosmall:
    // Skip remaining digits
    for (; *buf >= 0x30 && *buf <= 0x39; buf++);
    if (*buf) goto invalid;
    #if __STDC_HOSTED__ == 1
        errno = ERANGE;
    #endif
    *err = "too small";
    return 0;
}


#ifdef TEST
// $ cc -DTEST -fsanitize=address,undefined -o strtonum strtonum.c
// $ ./strtonum
#include <stdio.h>
#include <string.h>

int
main(void)
{
    static const struct {
        const char *input;
        long long min, max;
        long long expect;
        const char *err;
    } tests[] = {
        {"",  -1, +1, 0, "invalid"},
        {" ", -1, +1, 0, "invalid"},
        {"+", -1, +1, 0, "invalid"},
        {"-", -1, +1, 0, "invalid"},
        {"x", -1, +1, 0, "invalid"},

        {"0", +1, -1, 0, "invalid"},

        {"1",    1,  1, 1, 0},
        {"\t1", -1, +1, 1, 0},
        {"\n1", -1, +1, 1, 0},
        {"\v1", -1, +1, 1, 0},
        {"\f1", -1, +1, 1, 0},
        {"\r1", -1, +1, 1, 0},
        {" 1",  -1, +1, 1, 0},
        {"\t\n\v\f\r 0", 0, 0, 0, 0},

        {"0",  0, 0, 0, 0},
        {"+0", 0, 0, 0, 0},
        {"-0", 0, 0, 0, 0},

        {"00",    0, 0,  0, 0},
        {"+01",  -1, 1,  1, 0},
        {"-01",  -1, 1, -1, 0},
        {"+001", -1, 1,  1, 0},
        {"-001", -1, 1, -1, 0},

        // Good idea to run these under UBSan
        #define LLMIN (-9223372036854775807LL - 1)
        #define LLMAX (+9223372036854775807LL)
        {"-9223372036854775808", LLMIN, LLMAX, LLMIN, 0},
        {"+9223372036854775807", LLMIN, LLMAX, LLMAX, 0},
        {"-9223372036854775809", LLMIN, LLMAX, 0, "too small"},
        {" 9223372036854775808", LLMIN, LLMAX, 0, "too large"},
        {"+9223372036854775808", LLMIN, LLMAX, 0, "too large"},
        {"-9223372036854775808", LLMIN, LLMIN, LLMIN, 0},
        {"+9223372036854775807", LLMAX, LLMAX, LLMAX, 0},

        {"1000x", -100, 100, 0, "invalid"},
        {"1000000000000000000000000000x", LLMIN, LLMAX, 0, "invalid"},

        {"-1",  -10, -5, 0, "too large"},
        {"-11", -10, -5, 0, "too small"},
        {"+1",    5, 10, 0, "too small"},
        {"+11",   5, 10, 0, "too large"},
    };
    int ntests = sizeof(tests)/sizeof(*tests);

    int nfails = 0;
    for (int i = 0; i < ntests; i++) {
        const char *err;
        long long min = tests[i].min;
        long long max = tests[i].max;
        long long r = strtonum(tests[i].input, min, max, &err);
        if (r != tests[i].expect) {
            nfails++;
            printf("FAIL %-3d: \"%s\", want %lld, got %lld\n",
                   i, tests[i].input, tests[i].expect, r);
        }
        if (tests[i].err && (!err || strcmp(tests[i].err, err))) {
            nfails++;
            printf("FAIL %-3d: \"%s\", want \"%s\", got \"%s\"\n",
                   i, tests[i].input, tests[i].err, err ? err : "success");
        }
        if (!tests[i].err && err) {
            nfails++;
            printf("FAIL %-3d: \"%s\", \"%s\"\n", i, tests[i].input, err);
        }
    }

    if (nfails) {
        return 1;
    }
    puts("All tests pass.");
    return 0;
}

#elif defined(FUZZ)
// $ afl-gcc -DFUZZ -fsanitize=undefined -Os -o strtonum strtonum.c
// $ mkdir -p in out
// $ echo -n 0 >in/0
// $ afl-fuzz -i in/ -o out/ -- ./strtonum
#include <stdio.h>

int
main(void)
{
    char buf[4097];
    const char *err;
    buf[fread(buf, 1, sizeof(buf)-1, stdin)] = 0;
    strtonum(buf, -(1LL << 32), 1LL << 32, &err);
    return !!err;
}
#endif
