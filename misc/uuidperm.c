// Cryptographic permutation-based UUID generator
//
// Generator properties, in constant space and time:
// * Guaranteed never to collide with itself.
// * Can determine if it previously output a particular UUID.
// * Unfeasible to predict future outputs without the key.
//
// Also includes marshalling routines to store/load the generator state
// in a 32-byte buffer.
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

struct uuidperm { uint64_t c[2], s[32], k[2]; };

// Initialize a UUID generator from a 16-byte key.
void uuidperm_init(struct uuidperm *, const void *key);

// Marshal a UUID generator state to a 32-byte buffer.
void uuidperm_dumpstate(const struct uuidperm *, void *buf);

// Unmarshal a UUID generator state from a 32-byte buffer.
void uuidperm_loadstate(struct uuidperm *, const void *buf);

// Generate the next UUID, writing 36 bytes into the output buffer. Does
// not write a terminating null byte. The generator is guaranteed not to
// generate the same UUID twice.
void uuidperm_next(struct uuidperm *, char *uuid);

// Return non-zero if the given case-insensitive, 36-byte UUID came from
// this generator. Does not require a terminating null byte in the input
// buffer.
int uuidperm_seen(const struct uuidperm *, const char *uuid);


// Implementation

void
uuidperm_init(struct uuidperm *g, const void *key)
{
    const unsigned char *p = key;
    uint64_t x = (uint64_t)p[ 0] <<  0 | (uint64_t)p[ 1] <<  8 |
                 (uint64_t)p[ 2] << 16 | (uint64_t)p[ 3] << 24 |
                 (uint64_t)p[ 4] << 32 | (uint64_t)p[ 5] << 40 |
                 (uint64_t)p[ 6] << 48 | (uint64_t)p[ 7] << 56;
    uint64_t y = (uint64_t)p[ 8] <<  0 | (uint64_t)p[ 9] <<  8 |
                 (uint64_t)p[10] << 16 | (uint64_t)p[11] << 24 |
                 (uint64_t)p[12] << 32 | (uint64_t)p[13] << 40 |
                 (uint64_t)p[14] << 48 | (uint64_t)p[15] << 56;
    g->c[0] = g->c[1] = 0;
    g->k[0] = x;
    g->k[1] = y;
    g->s[0] = y;
    for (uint64_t i = 0; i < 31; i++) {
        x = x>>8 | x<<56;
        x += y;
        x ^= i;
        y = y<<3 | y>>61;
        y ^= x;
        g->s[i+1] = y;
    }
}

void
uuidperm_dumpstate(const struct uuidperm *g, void *buf)
{
    unsigned char *p = buf;
    p[ 0] = g->k[0] >>  0; p[ 1] = g->k[0] >>  8;
    p[ 2] = g->k[0] >> 16; p[ 3] = g->k[0] >> 24;
    p[ 4] = g->k[0] >> 32; p[ 5] = g->k[0] >> 40;
    p[ 6] = g->k[0] >> 48; p[ 7] = g->k[0] >> 56;
    p[ 8] = g->k[1] >>  0; p[ 9] = g->k[1] >>  8;
    p[10] = g->k[1] >> 16; p[11] = g->k[1] >> 24;
    p[12] = g->k[1] >> 32; p[13] = g->k[1] >> 40;
    p[14] = g->k[1] >> 48; p[15] = g->k[1] >> 56;
    p[16] = g->c[0] >>  0; p[17] = g->c[0] >>  8;
    p[18] = g->c[0] >> 16; p[19] = g->c[0] >> 24;
    p[20] = g->c[0] >> 32; p[21] = g->c[0] >> 40;
    p[22] = g->c[0] >> 48; p[23] = g->c[0] >> 56;
    p[24] = g->c[1] >>  0; p[25] = g->c[1] >>  8;
    p[26] = g->c[1] >> 16; p[27] = g->c[1] >> 24;
    p[28] = g->c[1] >> 32; p[29] = g->c[1] >> 40;
    p[30] = g->c[1] >> 48; p[31] = g->c[1] >> 56;
}

void
uuidperm_loadstate(struct uuidperm *g, const void *buf)
{
    uuidperm_init(g, buf);
    const unsigned char *p = buf;
    g->c[0] = (uint64_t)p[16] <<  0 | (uint64_t)p[17] <<  8 |
              (uint64_t)p[18] << 16 | (uint64_t)p[19] << 24 |
              (uint64_t)p[20] << 32 | (uint64_t)p[21] << 40 |
              (uint64_t)p[22] << 48 | (uint64_t)p[23] << 56;
    g->c[1] = (uint64_t)p[24] <<  0 | (uint64_t)p[25] <<  8 |
              (uint64_t)p[26] << 16 | (uint64_t)p[27] << 24 |
              (uint64_t)p[28] << 32 | (uint64_t)p[29] << 40 |
              (uint64_t)p[30] << 48 | (uint64_t)p[31] << 56;
}

void
uuidperm_next(struct uuidperm *g, char *uuid)
{
    // Speck-based permutation. Cycle walk to next 122-bit value. On
    // average this takes 2^6 (64) iterations.
    uint64_t x = g->c[0];
    uint64_t y = g->c[1];
    g->c[1] += !++g->c[0];
    do {
        for (int i = 0; i < 32; i++) {
            x = x>>8 | x<<56;
            x += y;
            x ^= g->s[i];
            y = y<<3 | y>>61;
            y ^= x;
        }
    } while (y&0xfc00000000000000);

    // UUID encoder
    static const uint16_t t[256] = {
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
        0x3866, 0x3966, 0x6166, 0x6266, 0x6366, 0x6466, 0x6566, 0x6666,
    };
    y = (y&0x03fffffffffffc00) <<  6 |
           0x0000000000004000        |
        (y&0x00000000000003ff) <<  2 |
        (x&0xc000000000000000) >> 62;
    x = (x&0x3fffffffffffffff)       |
           0x8000000000000000;
    uint8_t h[] = {y, y>>8, y>>16, y>>24, y>>32, y>>40, y>>48, y>>56};
    uint8_t l[] = {x, x>>8, x>>16, x>>24, x>>32, x>>40, x>>48, x>>56};
    uuid[ 0] = t[h[7]]>>0; uuid[ 1] = t[h[7]]>>8;
    uuid[ 2] = t[h[6]]>>0; uuid[ 3] = t[h[6]]>>8;
    uuid[ 4] = t[h[5]]>>0; uuid[ 5] = t[h[5]]>>8;
    uuid[ 6] = t[h[4]]>>0; uuid[ 7] = t[h[4]]>>8;
    uuid[ 8] = 0x2d;
    uuid[ 9] = t[h[3]]>>0; uuid[10] = t[h[3]]>>8;
    uuid[11] = t[h[2]]>>0; uuid[12] = t[h[2]]>>8;
    uuid[13] = 0x2d;
    uuid[14] = t[h[1]]>>0; uuid[15] = t[h[1]]>>8;
    uuid[16] = t[h[0]]>>0; uuid[17] = t[h[0]]>>8;
    uuid[18] = 0x2d;
    uuid[19] = t[l[7]]>>0; uuid[20] = t[l[7]]>>8;
    uuid[21] = t[l[6]]>>0; uuid[22] = t[l[6]]>>8;
    uuid[23] = 0x2d;
    uuid[24] = t[l[5]]>>0; uuid[25] = t[l[5]]>>8;
    uuid[26] = t[l[4]]>>0; uuid[27] = t[l[4]]>>8;
    uuid[28] = t[l[3]]>>0; uuid[29] = t[l[3]]>>8;
    uuid[30] = t[l[2]]>>0; uuid[31] = t[l[2]]>>8;
    uuid[32] = t[l[1]]>>0; uuid[33] = t[l[1]]>>8;
    uuid[34] = t[l[0]]>>0; uuid[35] = t[l[0]]>>8;
}

int
uuidperm_seen(const struct uuidperm *g, const char *uuid)
{
    // Validating UUID parser
    static const int8_t t[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        +0,+1,+2,+3,+4,+5,+6,+7,+8,+9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    uint64_t y =
        (uint64_t)t[uuid[ 0]&255] << 56 | (uint64_t)t[uuid[ 1]&255] << 52 |
        (uint64_t)t[uuid[ 2]&255] << 48 | (uint64_t)t[uuid[ 3]&255] << 44 |
        (uint64_t)t[uuid[ 4]&255] << 40 | (uint64_t)t[uuid[ 5]&255] << 36 |
        (uint64_t)t[uuid[ 6]&255] << 32 | (uint64_t)t[uuid[ 7]&255] << 28 |
        -(uuid[ 8] != 0x2d) |
        (uint64_t)t[uuid[ 9]&255] << 24 | (uint64_t)t[uuid[10]&255] << 20 |
        (uint64_t)t[uuid[11]&255] << 16 | (uint64_t)t[uuid[12]&255] << 12 |
        -(uuid[13] != 0x2d) |
        (uint64_t)t[uuid[14]&255] << 60 | (uint64_t)t[uuid[15]&255] <<  8 |
        (uint64_t)t[uuid[16]&255] <<  4 | (uint64_t)t[uuid[17]&255] <<  0;
    uint64_t x =
        -(uuid[18] != 0x2d) |
        (uint64_t)t[uuid[19]&255] << 60 | (uint64_t)t[uuid[20]&255] << 56 |
        (uint64_t)t[uuid[21]&255] << 52 | (uint64_t)t[uuid[22]&255] << 48 |
        -(uuid[23] != 0x2d) |
        (uint64_t)t[uuid[24]&255] << 44 | (uint64_t)t[uuid[25]&255] << 40 |
        (uint64_t)t[uuid[26]&255] << 36 | (uint64_t)t[uuid[27]&255] << 32 |
        (uint64_t)t[uuid[28]&255] << 28 | (uint64_t)t[uuid[29]&255] << 24 |
        (uint64_t)t[uuid[30]&255] << 20 | (uint64_t)t[uuid[31]&255] << 16 |
        (uint64_t)t[uuid[32]&255] << 12 | (uint64_t)t[uuid[33]&255] <<  8 |
        (uint64_t)t[uuid[34]&255] <<  4 | (uint64_t)t[uuid[35]&255] <<  0;
    if (((y&0xf000000000000000) ^ 0x4000000000000000) |
       (((x&0xc000000000000000) ^ 0x8000000000000000))) {
        return 0; // invalid
    }

    // Compact, removing 6 fixed bits
    x = (y&0x0000000000000003) << 62 |
        (x&0x3fffffffffffffff);
    y = (y&0x0ffffffffffffffc) >>  2;

    // Speck-based permutation (inverse). Cycle walk backwards to
    // previous 122-bit value.
    do {
        for (int i = 31; i >= 0; i--) {
            y ^= x;
            y = y>>3 | y<<61;
            x ^= g->s[i];
            x -= y;
            x = x<<8 | x>>56;
        }
    } while (y & 0xfc00000000000000);
    return y < g->c[1] || (y == g->c[1] && x < g->c[0]);
}


// Tests

#ifdef TEST
// $ cc -DTEST -fsanitize=address,undefined -O3 uuidperm.c
#include <stdio.h>

int
main(void)
{
    static const unsigned char k[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };

    int nfails = 0;
    char uuid[37] = {0};
    struct uuidperm g[1];

    uuidperm_init(g, k);
    for (long i = 0; i < 1L<<16; i++) {
        uuidperm_next(g, uuid);
        if (!uuidperm_seen(g, uuid)) {
            printf("FAIL: %s not recognized\n", uuid);
            nfails++;
        }
    }

    // Make a lagging copy
    struct uuidperm c[1];
    unsigned char dump[32];
    uuidperm_dumpstate(g, dump);
    uuidperm_loadstate(c, dump);
    for (int i = 0; i < 1L<<16; i++) {
        uuidperm_next(g, uuid);
        if (uuidperm_seen(c, uuid)) {
            printf("FAIL: %s recognized early\n", uuid);
            nfails++;
        }
        char tmp[36];
        uuidperm_next(c, tmp);
        if (!uuidperm_seen(c, uuid)) {
            printf("FAIL: %s not recognized late\n", uuid);
            nfails++;
        }
    }

    // Check against some random UUIDs
    static const char uuids[][37] = {
        "6a330561-7790-43d4-9c80-524992f95304",
        "1e0ab7f3-b3e6-42a5-a466-e5599c7e10d2",
        "42023020-b2c7-48c4-b4e3-af5ec02bf218",
        "cdd5c1d2-9497-4f01-b505-e1e4c7e21481",
        "3b9a5b44-cb97-4653-be81-8ed89fc1e913",
        "fa92e8c0-d8de-4181-8b72-9e162e04a290",
        "5f82d316-bc77-4592-b7e0-709cdd43f3c3",
        "bb902fcf-d3a3-410a-9cd9-f5ec32b47bcf",
    };
    for (int i = 0; i < (int)(sizeof(uuids)/sizeof(*uuids)); i++) {
        if (uuidperm_seen(g, uuids[i])) {
            printf("FAIL: %s recognized\n", uuids[i]);
            nfails++;
        }
    }

    if (nfails) {
        return 1;
    }
    puts("All tests pass.");
    return 0;
}
#endif
