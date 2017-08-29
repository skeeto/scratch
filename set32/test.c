#define _POSIX_C_SOURCE 200112L
#define SET32_IMPLEMENTATION
#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "set32.h"

static uint32_t
rand32(void)
{
    static uint32_t x = UINT32_C(0x9f41f6af);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

int
main(void)
{
    static uint32_t data[100000];
    uint32_t n = sizeof(data) / sizeof(*data);

    int z = set32_z(n);
    uint32_t *table = calloc(sizeof(*table), UINT32_C(1) << z);
    printf("table size %12zu kB [%lu slots]\n",
            sizeof(*table) * (UINT32_C(1) << z) / 1024,
            (unsigned long)(UINT32_C(1) << z));

    struct timespec ts[2];
    clock_gettime(CLOCK_MONOTONIC, ts + 0);

    for (uint32_t i = 0; i < n; i++) {
        data[i] = rand32();
        assert(!set32_contains(table, z, data[i]));
        set32_insert(table, z, data[i]);
    }

    /* shuffle */
    for (uint32_t i = n - 1; i > 1; i--) {
        uint32_t j = rand32() % (i + 1);
        uint32_t tmp = data[j];
        data[j] = data[i];
        data[i] = tmp;
    }

    for (uint32_t i = 0; i < n; i++) {
        set32_remove(table, z, data[i]);
        for (uint32_t j = i + 1; j < n; j++)
            assert(set32_contains(table, z, data[j]));
    }

    clock_gettime(CLOCK_MONOTONIC, ts + 1);

    for (uint32_t i = 0; i < UINT32_C(1) << z; i++)
        assert(!table[i]);

    double seconds;
    if ((ts[1].tv_nsec - ts[0].tv_nsec) < 0) {
        seconds = ts[1].tv_sec - ts[0].tv_sec - 1 +
            (1e9 + ts[1].tv_nsec - ts[0].tv_nsec) / 1e9;
    } else {
        seconds = ts[1].tv_sec - ts[0].tv_sec +
            (ts[1].tv_nsec - ts[0].tv_nsec) / 1e9;
    }

    unsigned long long ninsert = n;
    unsigned long long nmember = ninsert + ninsert * (ninsert + 1) / 2;
    printf("time   % 16.3fs\n", seconds);
    printf("insert % 16.3f / ms [%lu]\n",
            n / seconds / 1000, (unsigned long)n);
    printf("delete % 16.3f / ms [%lu]\n",
            n / seconds / 1000, (unsigned long)n);
    printf("member % 16.3f / us [%llu]\n",
            nmember / seconds / 1000000, nmember);

    free(table);
}
