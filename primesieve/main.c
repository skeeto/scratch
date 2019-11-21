#define __USE_MINGW_ANSI_STDIO
#include <stdio.h>
#include <stdlib.h>
#include "primesieve.c"

int
main(int argc, char *argv[])
{
    unsigned long long n = strtoull(argv[argc - 1], 0, 10);
    struct primesieve *ps = primesieve_create(n);
    for (;;) {
        unsigned long long x = primesieve_next(ps);
        if (!x)
            break;
        printf("%lld\n", x);
    }
    free(ps);
}
