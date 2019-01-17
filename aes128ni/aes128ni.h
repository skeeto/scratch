/* An implementation of AES-128 using the AES-NI instruction set
 *
 * For GCC and Clang use the -maes option or equivalent when compiling.
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef AES128NI_H
#define AES128NI_H

#if !defined(__AES__)
#  error AES-NI not supported/enabled
#endif

#include <wmmintrin.h>

#define AES128_KEYLEN    16
#define AES128_BLOCKLEN  16

struct aes128 {
    __m128i k[20];
};

#define AES128_KEYROUND(i, rcon) \
    key = ctx->k[i - 1]; \
    gen = _mm_aeskeygenassist_si128(key, rcon); \
    gen = _mm_shuffle_epi32(gen, 255); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    ctx->k[i] = _mm_xor_si128(key, gen)

static void
aes128_init(struct aes128 *ctx, const void *k)
{
    __m128i key, gen;
    ctx->k[0] = _mm_loadu_si128(k);
    AES128_KEYROUND( 1, 0x01);
    AES128_KEYROUND( 2, 0x02);
    AES128_KEYROUND( 3, 0x04);
    AES128_KEYROUND( 4, 0x08);
    AES128_KEYROUND( 5, 0x10);
    AES128_KEYROUND( 6, 0x20);
    AES128_KEYROUND( 7, 0x40);
    AES128_KEYROUND( 8, 0x80);
    AES128_KEYROUND( 9, 0x1b);
    AES128_KEYROUND(10, 0x36);
    ctx->k[11] = _mm_aesimc_si128(ctx->k[9]);
    ctx->k[12] = _mm_aesimc_si128(ctx->k[8]);
    ctx->k[13] = _mm_aesimc_si128(ctx->k[7]);
    ctx->k[14] = _mm_aesimc_si128(ctx->k[6]);
    ctx->k[15] = _mm_aesimc_si128(ctx->k[5]);
    ctx->k[16] = _mm_aesimc_si128(ctx->k[4]);
    ctx->k[17] = _mm_aesimc_si128(ctx->k[3]);
    ctx->k[18] = _mm_aesimc_si128(ctx->k[2]);
    ctx->k[19] = _mm_aesimc_si128(ctx->k[1]);
}

static void
aes128_encrypt(struct aes128 *ctx, void *pt, const void *ct)
{
    __m128i m = _mm_loadu_si128(ct);
    m =        _mm_xor_si128(m, ctx->k[ 0]);
    m =     _mm_aesenc_si128(m, ctx->k[ 1]);
    m =     _mm_aesenc_si128(m, ctx->k[ 2]);
    m =     _mm_aesenc_si128(m, ctx->k[ 3]);
    m =     _mm_aesenc_si128(m, ctx->k[ 4]);
    m =     _mm_aesenc_si128(m, ctx->k[ 5]);
    m =     _mm_aesenc_si128(m, ctx->k[ 6]);
    m =     _mm_aesenc_si128(m, ctx->k[ 7]);
    m =     _mm_aesenc_si128(m, ctx->k[ 8]);
    m =     _mm_aesenc_si128(m, ctx->k[ 9]);
    m = _mm_aesenclast_si128(m, ctx->k[10]);
    _mm_storeu_si128(pt, m);
}

static void
aes128_decrypt(struct aes128 *ctx, void *ct, const void *pt)
{
    __m128i m = _mm_loadu_si128(pt);
    m =        _mm_xor_si128(m, ctx->k[10]);
    m =     _mm_aesdec_si128(m, ctx->k[11]);
    m =     _mm_aesdec_si128(m, ctx->k[12]);
    m =     _mm_aesdec_si128(m, ctx->k[13]);
    m =     _mm_aesdec_si128(m, ctx->k[14]);
    m =     _mm_aesdec_si128(m, ctx->k[15]);
    m =     _mm_aesdec_si128(m, ctx->k[16]);
    m =     _mm_aesdec_si128(m, ctx->k[17]);
    m =     _mm_aesdec_si128(m, ctx->k[18]);
    m =     _mm_aesdec_si128(m, ctx->k[19]);
    m = _mm_aesdeclast_si128(m, ctx->k[ 0]);
    _mm_storeu_si128(ct, m);
}

#endif
