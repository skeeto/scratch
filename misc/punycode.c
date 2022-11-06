// Punycode Decoder (RFC 3492)
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

// Decode Punycode into UTF-32. Returns the code point count, or -1 for
// invalid input. The destination buffer must have as least as many
// elements as the source.
static int punycode(int32_t *dst, const char *src, int len)
{
    static const unsigned char value[256] = {
        +0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        +0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        +0, 0, 0, 0,27,28,29,30,31,32,33,34,35,36, 0, 0, 0, 0, 0, 0, 0, 1,
        +2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
        24,25,26, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,
        14,15,16,17,18,19,20,21,22,23,24,25,26
    };
    int i, j, t, v, out=0, off=0, old;
    int32_t delta, k, w, bias=72, n=128;

    for (i = 0; i < len; i++) {
        if (src[i] == '-') {
            out = i;
        } else if (!value[src[i]&255]) {
            return -1;
        }
    }
    for (i = 0; i < out; i++) {
        dst[i] = src[i];
    }

    for (i = out+!!out; i < len;) {
        for (k=36, w=1, old=off;; k += 36) {
            if (i == len) return -1;
            v = value[src[i++]&255] - 1;
            if (v<0 || v>(0x7fffffff-off)/w) return -1;
            off += v*w;
            t = k<=bias ? 1 : k>=bias+26 ? 26 : k-bias;
            if (v < t) break;
            if (w > 0x7fffffff/(36 - t)) return -1;
            w *= 36 - t;
        }

        delta = (off - old)/(old ? 2 : 700);
        delta += delta / ++out;
        for (bias = 0; delta > 455; bias += 36) {
            delta /= 35;
        }
        bias += (36 * delta)/(delta + 38);

        if (n > 0x10ffff-off/out) return -1;
        n += off/out;
        if (n>=0xd800 && n<=0xdfff) return -1;
        off %= out;
        for (j = out-1; j > off; j--) {
            dst[j] = dst[j-1];
        }
        dst[off++] = n;
    }
    return out;
}


#if TEST
// $ cc -DTEST -o test punycode.c
// $ ./test
#include <stdio.h>
#include <string.h>

#define ASSERT(c) if (!(c)) *(volatile int *)0 = 0

int main(void)
{
    static const struct {
        char s[48];
        int32_t w[48];
    } t[] = {
        {
            "n28h",
            {
                0x1f609
            }
        },
        {
            "egbpdaj6bu4bxfgehfvwxn",
            {
                0x0644,0x064a,0x0647,0x0645,0x0627,0x0628,0x062a,0x0643,
                0x0644,0x0645,0x0648,0x0634,0x0639,0x0631,0x0628,0x064a,
                0x061f
            }
        },
        {
            "ihqwcrb4cv8a8dqg056pqjye",
            {
                0x4ed6,0x4eec,0x4e3a,0x4ec0,0x4e48,0x4e0d,0x8bf4,0x4e2d,
                0x6587
            }
        },
        {
            "ihqwctvzc91f659drss3x8bo0yb",
            {
                0x4ed6,0x5011,0x7232,0x4ec0,0x9ebd,0x4e0d,0x8aaa,0x4e2d,
                0x6587
            }
        },
        {
            "Proprostnemluvesky-uyb24dma41a",
            {
                0x0050,0x0072,0x006f,0x010d,0x0070,0x0072,0x006f,0x0073,
                0x0074,0x011b,0x006e,0x0065,0x006d,0x006c,0x0075,0x0076,
                0x00ed,0x010d,0x0065,0x0073,0x006b,0x0079
            }
        },
        {
            "4dbcagdahymbxekheh6e0a7fei0b",
            {
                0x05dc,0x05de,0x05d4,0x05d4,0x05dd,0x05e4,0x05e9,0x05d5,
                0x05d8,0x05dc,0x05d0,0x05de,0x05d3,0x05d1,0x05e8,0x05d9,
                0x05dd,0x05e2,0x05d1,0x05e8,0x05d9,0x05ea
            }
        },
        {
            "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd",
            {
                0x092f,0x0939,0x0932,0x094b,0x0917,0x0939,0x093f,0x0928,
                0x094d,0x0926,0x0940,0x0915,0x094d,0x092f,0x094b,0x0902,
                0x0928,0x0939,0x0940,0x0902,0x092c,0x094b,0x0932,0x0938,
                0x0915,0x0924,0x0947,0x0939,0x0948,0x0902
            }
        },
        {
            "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
            {
                0x306a,0x305c,0x307f,0x3093,0x306a,0x65e5,0x672c,0x8a9e,
                0x3092,0x8a71,0x3057,0x3066,0x304f,0x308c,0x306a,0x3044,
                0x306e, 0x304b
            }
        },
        {
            "b1abfaaepdrnnbgefbaDotcwatmq2g4l",
            {
                0x043f,0x043e,0x0447,0x0435,0x043c,0x0443,0x0436,0x0435,
                0x043e,0x043d,0x0438,0x043d,0x0435,0x0433,0x043e,0x0432,
                0x043e,0x0440,0x044f,0x0442,0x043f,0x043e,0x0440,0x0443,
                0x0441,0x0441,0x043a,0x0438
            }
        },
        {
            "PorqunopuedensimplementehablarenEspaol-fmd56a",
            {
                0x0050,0x006f,0x0072,0x0071,0x0075,0x00e9,0x006e,0x006f,
                0x0070,0x0075,0x0065,0x0064,0x0065,0x006e,0x0073,0x0069,
                0x006d,0x0070,0x006c,0x0065,0x006d,0x0065,0x006e,0x0074,
                0x0065,0x0068,0x0061,0x0062,0x006c,0x0061,0x0072,0x0065,
                0x006e,0x0045,0x0073,0x0070,0x0061,0x00f1,0x006f,0x006c
            }
        },
        {
            "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
            {
                0x0054,0x1ea1,0x0069,0x0073,0x0061,0x006f,0x0068,0x1ecd,
                0x006b,0x0068,0x00f4,0x006e,0x0067,0x0074,0x0068,0x1ec3,
                0x0063,0x0068,0x1ec9,0x006e,0x00f3,0x0069,0x0074,0x0069,
                0x1ebf,0x006e,0x0067,0x0056,0x0069,0x1ec7,0x0074
            }
        },
        {
            "3B-ww4c5e180e575a65lsy2b",
            {
                0x0033,0x5e74,0x0042,0x7d44,0x91d1,0x516b,0x5148,0x751f
            }
        },
        {
            "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
            {
                0x5b89,0x5ba4,0x5948,0x7f8e,0x6075,0x002d,0x0077,0x0069,
                0x0074,0x0068,0x002d,0x0053,0x0055,0x0050,0x0045,0x0052,
                0x002d,0x004d,0x004f,0x004e,0x004b,0x0045,0x0059,0x0053
            }
        },
        {
            "Hello-Another-Way--fc4qua05auwb3674vfr0b",
            {
                0x0048,0x0065,0x006c,0x006c,0x006f,0x002d,0x0041,0x006e,
                0x006f,0x0074,0x0068,0x0065,0x0072,0x002d,0x0057,0x0061,
                0x0079,0x002d,0x305d,0x308c,0x305e,0x308c,0x306e,0x5834,
                0x6240
            }
        },
        {
            "2-u9tlzr9756bt3uc0v",
            {
                0x3072,0x3068,0x3064,0x5c4b,0x6839,0x306e,0x4e0b,0x0032
            }
        },
        {
            "MajiKoi5-783gue6qz075azm5e",
            {
                0x004d,0x0061,0x006a,0x0069,0x3067,0x004b,0x006f,0x0069,
                0x3059,0x308b,0x0035,0x79d2,0x524d
            }
        },
        {
            "de-jg4avhby1noc0d",
            {
                0x30d1,0x30d5,0x30a3,0x30fc,0x0064,0x0065,0x30eb,0x30f3,
                0x30d0
            }
        },
        {
            "d9juau41awczczp",
            {
                0x305d,0x306e,0x30b9,0x30d4,0x30fc,0x30c9,0x3067
            }
        },
        {
            "ib9bk1k",
            {
                0
            }
        },
    };
    int ntest = sizeof(t)/sizeof(*t);

    for (int n = 0; n < ntest; n++) {
        int wlen = 0;
        while (t[n].w[wlen]) {
            wlen++;
        }
        wlen = wlen ? wlen : -1;
        int32_t g[63];
        int len = punycode(g, t[n].s, strlen(t[n].s));
        ASSERT(len == wlen);
        for (int i = 0; i < len; i++) {
            ASSERT(t[n].w[i] == g[i]);
        }
    }
    puts("all tests pass");
}
#endif


#if FUZZ
// $ afl-gcc -m32 -DFUZZ -fsanitize=address,undefined punycode.c
// $ mkdir in && touch in/empty
// $ afl-fuzz -m800 -iin -oout ./a.out
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *buf = malloc(1<<8);
    int len = fread(buf, 1, 1<<8, stdin);
    buf = realloc(buf, len);
    int32_t *dst = malloc(sizeof(*dst)*len);
    len = punycode(dst, buf, len);
    for (int i = 0; i < len; i++) {
        printf("U+%06lx%c", (long)dst[i], i==len-1?'\n':' ');
    }
    return len < 0;
}
#endif
