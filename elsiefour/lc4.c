#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lc4.h"

#if _WIN32
#  define C_RED(s)    s
#  define C_GREEN(s)  s
#else
#  define C_RED(s)    "\033[31;1m" s "\033[0m"
#  define C_GREEN(s)  "\033[32;1m" s "\033[0m"
#endif

#define TEST(s, x) \
    do { \
        if (x) { \
            puts("\033[32;1mPASS\033[0m " s); \
            count_pass++; \
        } else { \
            puts("\033[31;1mFAIL\033[0m " s); \
            count_fail++; \
        } \
    } while (0)

static int count_pass = 0;
static int count_fail = 0;

static void
test(void)
{
    struct lc4 lc4[1];
    char key[] = "xv7ydq#opaj_39rzut8b45wcsgehmiknf26l";
    char pt[] = "solwbfim_about_to_put_the_hammer_down#rubberduck";
    char ct[sizeof(pt)] = {0};
    char expect[] = "i2zqpilr2yqgptltrzx2_9fzlmbo3y8_9pyssx8nf2";
    char ptout[sizeof(pt)] = {0};
    char *i, *o;

    TEST("valid 1", lc4_valid(key));
    TEST("valid 2", lc4_valid("#_23456789abcdefghijklmnopqrstuvwxyz"));
    TEST("invalid 1", !lc4_valid(""));
    TEST("invalid 2", !lc4_valid("#_23456789abcdefghijklmnopqrstuvwxyz "));
    TEST("invalid 3", !lc4_valid("#_23456789abcdefghijklmn:pqrstuvwxyz"));
    TEST("invalid 4", !lc4_valid("#_23456789abcdefghijklmnopqrst2vwxyz"));

    lc4_init(lc4, key);
    for (i = pt, o = ct; *i; i++)
        *o++ = lc4_encrypt(lc4, *i);
    TEST("encrypt", !strcmp(ct + 6, expect));

    lc4_init(lc4, key);
    for (i = ct, o = ptout; *i; i++)
        *o++ = lc4_decrypt(lc4, *i);
    TEST("decrypt", !strcmp(pt, ptout));
}

/* Portable getopt() implementation */

static int optind = 1;
static int opterr = 1;
static int optopt;
static char *optarg;

static int
getopt(int argc, char * const argv[], const char *optstring)
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
                    fprintf(stderr, 
                            "%s: option requires an argument: %c\n", 
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
usage(void)
{
    puts("usage: lc4 -D KEY");
    puts("       lc4 -E KEY");
    puts("       lc4 -G");
    puts("       lc4 -N [-n length]");
    puts("       lc4 -T");
    puts("Data is encrypted/decrypted from stdin to stdout.");
}

int
main(int argc, char **argv)
{
    int ct, pt;
    struct lc4 lc4[1];
    const char *key = 0;
    int nonce_length = 6;
    enum {
        M_TEST, M_ENCRYPT, M_DECRYPT, M_KEYGEN, M_NONCEGEN
    } mode = M_TEST;

    int option;
    while ((option = getopt(argc, argv, "DEGNThn:")) != -1) {
        switch (option) {
            case 'D':
                mode = M_DECRYPT;
                break;
            case 'E':
                mode = M_ENCRYPT;
                break;
            case 'G':
                mode = M_KEYGEN;
                break;
            case 'N':
                mode = M_NONCEGEN;
                break;
            case 'T':
                mode = M_TEST;
                break;
            case 'h':
                usage();
                return 0;
            case 'n':
                nonce_length = atoi(optarg);
                break;
            default:
                return -1;
        }
    }
    key = argv[optind];

    switch (mode) {
        case M_TEST:
            test();
            return count_fail == 0 ? 0 : -1;

        case M_ENCRYPT:
        case M_DECRYPT:
            if (!key) {
                fprintf(stderr, "%s: key is required\n", argv[0]);
                usage();
                return -1;
            }
            if (!lc4_valid(key)) {
                fprintf(stderr, "%s: invalid key\n", argv[0]);
                return -1;
            }
            lc4_init(lc4, key);
            if (mode == M_ENCRYPT) {
                while ((pt = getchar()) != EOF) {
                    if (pt == '\n') {
                        putchar('\n');
                    } else {
                        ct = lc4_encrypt(lc4, pt);
                        if (ct) putchar(ct);
                    }
                }
            } else {
                while ((ct = getchar()) != EOF) {
                    if (ct == '\n') {
                        putchar('\n');
                    } else {
                        pt = lc4_decrypt(lc4, ct);
                        if (pt) putchar(pt);
                    }
                }
            }
            return 0;

        case M_KEYGEN: {
            int i, r, tmp;
            char key[] = "#_23456789abcdefghijklmnopqrstuvwxyz";
            FILE *urandom = fopen("/dev/urandom", "rb");
            if (!urandom) {
                fprintf(stderr, "%s: could not open /dev/urandom\n", argv[0]);
                return -1;
            }
            for (i = 35; i > 0; i--) {
                do {
                    r = fgetc(urandom) % 64;
                } while (r > i);
                tmp = key[i];
                key[i] = key[r];
                key[r] = tmp;
            }
            fclose(urandom);
            puts(key);
            return 0;
        }

        case M_NONCEGEN: {
            int i, r;
            char set[] = "#_23456789abcdefghijklmnopqrstuvwxyz";
            FILE *urandom = fopen("/dev/urandom", "rb");
            if (!urandom) {
                fprintf(stderr, "%s: could not open /dev/urandom\n", argv[0]);
                return -1;
            }
            for (i = 0; i < nonce_length; i++) {
                do {
                    r = fgetc(urandom) % 64;
                } while (r > 35);
                putchar(set[r]);
            }
            fclose(urandom);
            putchar('\n');
            return 0;
        }
    }

    usage();
    return -1;
}
