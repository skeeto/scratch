#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>

struct bloom {
    char *bits;
    size_t nbytes;
    size_t nbits;
    int k;
    size_t n;
};

void    bloom_init(struct bloom *f, int n_expected, double p);
void    bloom_save(const struct bloom *f, const char *file);
void    bloom_load(struct bloom *f, const char *file);
void    bloom_destroy(struct bloom *f);

void    bloom_set(struct bloom *f, size_t n);
int     bloom_get(const struct bloom *f, size_t n);
int     bloom_test(const struct bloom *f, const char *value);
void    bloom_insert(struct bloom *f, const char *value);
double  bloom_error_rate(const struct bloom *f);

#endif
