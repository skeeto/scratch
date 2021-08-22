// Rabin-Karp (rolling hash) string search
//
// Computes a hash of the needle, then runs a rolling hash over the haystack
// looking for collisions. The hash in this implementation is a polynomial of
// the last n elements, where n is the length of the needle:
//
//   (a*257^n + b*257^(n-1) + ... + z*257^0) (mod 2^64)
//
// See also: https://yurichev.com/news/20210205_rolling_hash/
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Find first occurance offset of needle in haystack, or -1 if not found.
ptrdiff_t
search(const char *haystack, const char *needle)
{
    // Compute pattern hash
    ptrdiff_t len = 0;
    uint64_t match = 0;
    for (const char *s = needle; *s; s++) {
        len++;
        match = match*257 + (*s & 0xff);
    }

    // Compute first rolling hash
    uint64_t hash = 0;
    const char *p = haystack;
    for (ptrdiff_t i = 0; i < len-1; i++, p++) {
        if (!*p) {
            return -1;  // haystack too short
        }
        hash = hash*257 + (*p & 0xff);
    }

    // High polynomial coefficient, exponentiation by squaring
    uint64_t f = 1;
    uint64_t x = 257;
    for (ptrdiff_t n = len - 1; n; n >>= 1) {
        f *= n & 1 ? x : 1;
        x *= x;
    }

    // Run rolling hash over the haystack
    for (; *p; p++) {
        hash = hash*257 + (*p & 0xff);
        if (hash == match && !memcmp(p-len+1, needle, len)) {
            return p - haystack - len + 1;
        }
        hash -= f * (p[1-len] & 0xff);
    }
    return -1;
}

// Find first occurance offset of needle in haystack, or NULL if not found.
void *
xmemmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    if (hlen < nlen) {
        return 0;
    }

    // Compute pattern hash
    uint64_t match = 0;
    const unsigned char *n = needle;
    for (size_t i = 0; i < nlen; i++) {
        match = match*257 + n[i];
    }

    // Compute first rolling hash
    uint64_t hash = 0;
    const unsigned char *h = haystack;
    const unsigned char *end = h + hlen;
    for (size_t i = 0; i < nlen-1; i++, h++) {
        hash = hash*257 + *h;
    }

    // High polynomial coefficient, exponentiation by squaring
    uint64_t f = 1;
    uint64_t x = 257;
    for (size_t i = nlen - 1; i; i >>= 1) {
        f *= i & 1 ? x : 1;
        x *= x;
    }

    // Run rolling hash over the haystack
    for (; h < end; h++) {
        hash = hash*257 + *h;
        if (hash == match && !memcmp(h-nlen+1, needle, nlen)) {
            return (char *)h + 1 - nlen;
        }
        hash -= f * (h[1-(ptrdiff_t)nlen] & 0xff);
    }
    return 0;
}


#ifdef TEST
#include <stdio.h>

int
main(void)
{
    uint64_t s = 1;
    static char haystack[1<<20];
    for (size_t i = 0; i < sizeof(haystack)-1; i++) {
        s = s*0x3243f6a8885a308d + 1;
        haystack[i] = 'A' + (s >> 60);
    }

    static const struct {
        const char needle[60];
        int32_t want;
    } tests[] = {
        {"A",                                                44},
        {"PI",                                               10},
        {"NAG",                                            1596},
        {"INCH",                                          10319},
        {"BLOOM",                                          4209},
        {"CACKLE",                                        26523},
        {"KILLING",                                       76176},
        {"TUBE",                                             -1},
        {"ANEMONE",                                          -1},
        {"HLEFOMAHKLDMPKKJOCJPFBPIHEHPEKBCIKIDAIKNJAK", 1047889},
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    int fails = 0;
    for (int i = 0; i < ntests; i++) {
        ptrdiff_t got = search(haystack, tests[i].needle);
        if (tests[i].want != got) {
            fails++;
            printf("FAIL: \"%s\", want %td, got %td\n",
                   tests[i].needle, (ptrdiff_t)tests[i].want, got);
        }
    }

    for (int i = 0; i < ntests; i++) {
        char *got = xmemmem(haystack, sizeof(haystack),
                            tests[i].needle, strlen(tests[i].needle));
        char *want = tests[i].want >= 0 ? haystack + tests[i].want : 0;
        if (want != got) {
            fails++;
            printf("FAIL: \"%s\", want %td, got %td\n",
                   tests[i].needle, (ptrdiff_t)tests[i].want,
                   got ? got - haystack : (ptrdiff_t)-1);
        }
    }

    #if 0
    // Generate the test table
    for (int i = 0; i < ntests; i++) {
        char *r = strstr(haystack,tests[i].needle);
        printf("{\"%s\",%*td},\n",
               tests[i].needle,
               (int)(51 - strlen(tests[i].needle)),
               r ? r - haystack : (ptrdiff_t)-1);
    }
    #endif

    if (fails) {
        return 1;
    }
    puts("All tests pass");
}
#endif
