#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "bloom.h"

uint16_t SEEDS[] = {
    0xd03a, 0xf805, 0x40f9, 0xb993, 0xab36, 0x96b7, 0xe9e3, 0x6787, 0xa1af,
    0x1b0d, 0x6b0b, 0x35f1, 0x8820, 0x24f8, 0x4895, 0xd7f1, 0xe773, 0x66ce,
    0x8830, 0x74a7, 0x71d6, 0x3c07, 0x9fea, 0x721b, 0xf350, 0x9da3, 0x6309,
    0x0596, 0x62dc, 0x11bf, 0x3aef, 0x86d4, 0xac08, 0xa350, 0x9a1c, 0xced5,
};

uint32_t fletcher32(const uint16_t *data, size_t words, int n) {
    uint32_t sum1 = SEEDS[n * 2], sum2 = SEEDS[n * 2 + 1];
    while (words) {
        unsigned tlen = words > 360 ? 360 : words;
        words -= tlen;
        do {
            sum1 += *data++;
            sum2 += sum1;
        } while (--tlen);
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    }
    sum1 = (sum1 & 0xffff) + (sum1 >> 16);
    sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    return sum2 << 16 | sum1;
}

void bloom_init(struct bloom *f, int n, double p)
{
    /* http://stackoverflow.com/a/22467497 */
    f->nbits = -n * log(p) / pow(log(2), 2);
    f->nbits = 1L << (int) ceil(log(f->nbits) / log(2));
    f->nbytes = f->nbits / 8;
    f->bits = calloc(f->nbytes, 1);
    if (f->bits == NULL)
        abort();
    f->k = round(f->nbits / n * log(2));
    f->n = 0;
}

void bloom_save(const struct bloom *f, const char *file) {
    FILE *dump = fopen(file, "w");
    if (dump == NULL)
        abort();
    fputc(f->k, dump);
    if (fwrite(f->bits, f->nbytes, 1, dump) != 1)
        abort();
    fclose(dump);
}

void bloom_load(struct bloom *f, const char *file) {
    FILE *in = fopen(file, "r");
    if (in == NULL)
        abort();
    memset(f, 0, sizeof(struct bloom));
    fseek(in, 0L, SEEK_END);
    f->nbytes = ftell(in) - 1;
    f->nbits = f->nbytes * 8;
    fseek(in, 0L, SEEK_SET);
    f->k = fgetc(in);
    f->bits = malloc(f->nbytes);
    if (f->bits == NULL)
        abort();
    if (fread(f->bits, f->nbytes, 1, in) != 1)
        abort();
    fclose(in);
}

void bloom_destroy(struct bloom *f)
{
    free(f->bits);
    f->bits = NULL;
}

void bloom_set(struct bloom *f, size_t n)
{
    size_t byte = n / 8, bit = n % 8;
    f->bits[byte] |= 1 << bit;
}

int bloom_get(const struct bloom *f, size_t n)
{
    size_t byte = n / 8, bit = n % 8;
    return (f->bits[byte] >> bit) & 1;
}

int bloom_test(const struct bloom *f, const char *value)
{
    int result = 1;
    size_t length = strlen(value);
    for (int i = 0; i < f->k; i++) {
        uint32_t hash =
            fletcher32((const uint16_t *) value, (length + 1) / 2, i);
        result &= bloom_get(f, hash & (f->nbits - 1));
    }
    return result;
}

void bloom_insert(struct bloom *f, const char *value)
{
    size_t length = strlen(value);
    for (int i = 0; i < f->k; i++) {
        uint32_t hash =
            fletcher32((uint16_t *) value, (length + 1) / 2, i);
        bloom_set(f, hash & (f->nbits - 1));
    }
    f->n++;
}

double bloom_error_rate(const struct bloom *f)
{
    double k = f->k;
    return pow(1 - exp(f->n * -k / f->nbits), k);
}
