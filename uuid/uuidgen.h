// This is free and unencumbered software released into the public domain.
#ifndef UUID_H
#define UUID_H

#include <stdint.h>

// UUID generator, initialize to all zeros (UUIDGEN_INIT).
struct uuidgen {
    uint32_t s[16];
    char tmp[3][36];
    int n;
};
#define UUIDGEN_INIT {.n = 0}

// Generate one v4 UUID and write exactly 36 bytes to the destination.
// Does not include a terminating null byte.
void uuidgen(struct uuidgen *, char *);

#endif // UUID_H
