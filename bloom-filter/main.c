#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "bloom.h"

/* Normalizes according to gmail's rules, not an RFC. */
static void email_normalize(char *email)
{
    bool domain = false;
    while (*email) {
        if (isspace(*email) || (!domain && *email == '.')) {
            memmove(email, email + 1, strlen(email + 1) + 1);
        } else if (!domain && *email == '+') {
            char *p = email;
            while (*p && *p != '@') p++;
            memmove(email, p, strlen(p) + 1);
        } else if (*email == '@') {
            domain = true;
            email++;
        } else {
            *email = tolower(*email);
            email++;
        }
    }
}

static void filter_fill(struct bloom *filter, FILE *in)
{
    char line[128];
    while (!feof(stdin)) {
        if (fgets(line, sizeof(line), in)) {
            email_normalize(line);
            if (*line)
                bloom_insert(filter, line);
        }
    }
}

int main(int argc, char **argv)
{
    size_t n_expected = 4929090;
    double p = 0.05;
    struct bloom filter;
    const char *dumpfile = "filter.bloom";
    bool create = false;

    int opt;
    while ((opt = getopt(argc, argv, "cd:p:n:")) != -1) {
        switch (opt) {
        case 'c':
            create = true;
            break;
        case 'd':
            dumpfile = optarg;
            break;
        case 'p':
            p = strtod(optarg, NULL);
            break;
        case 'n':
            n_expected = strtol(optarg, NULL, 10);
            break;
        default:
            abort();
        }
    }

    if (create) {
        bloom_init(&filter, n_expected, p);
        printf("m=%zu (%.0f kB), k=%d, p=%f\n",
               filter.nbits, filter.nbytes / 1024.0, filter.k, p);
        filter_fill(&filter, stdin);
        printf("p_actual = %f\n", bloom_error_rate(&filter));
        bloom_save(&filter, dumpfile);
    } else {
        bloom_load(&filter, dumpfile);
        printf("m=%zu (%.0f kB), k=%d\n",
               filter.nbits, filter.nbytes / 1024.0, filter.k);
        for (int i = optind; i < argc; i++) {
            char email[128];
            snprintf(email, sizeof(email), "%s", argv[i]);
            email_normalize(email);
            printf("%s => %s\n", email,
                   bloom_test(&filter, email) ? "leaked" : "safe");
        }
    }

    bloom_destroy(&filter);
    return 0;
}
