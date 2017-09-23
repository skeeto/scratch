#include <stdio.h>
#include <stdint.h>
#include "speck.h"

static int tests = 0;
static int failures = 0;

#define ASSERT(s, a, b) \
    do { \
        tests++; \
        if (a[0] != b[0] || a[1] != b[1]) { \
            failures++; \
            puts("FAIL: " s); \
        } \
    } while (0)

int
main(void)
{
    /* Official test vector for Speck128/128 */
    uint64_t k[2] = {0x0f0e0d0c0b0a0908, 0x0706050403020100};
    uint64_t p[2] = {0x6c61766975716520, 0x7469206564616d20};
    uint64_t c[2] = {0xa65d985179783265, 0x7860fedf5c570d18};

    struct speck ctx[1];
    uint64_t t[2] = {p[0], p[1]};
    speck_init(ctx, k[0], k[1]);
    speck_encrypt(ctx, t + 0, t + 1);
    ASSERT("Speck128/128 encrypt", c, t);
    speck_decrypt(ctx, t + 0, t + 1);
    ASSERT("Speck128/128 decrypt", p, t);

    printf("RESULTS: %d / %d tests pass\n", tests - failures, tests);
    return !!failures;
}
