// Thue-Morse sequence, base-N expansion digit histogram
//
// The Thue-Morse sequence is transcendental, so interpreting its decimal
// expansion in some bases should have a uniform distribution. This program
// computes the exact distribution for a given sequence length and chosen
// base.
//
// Usage:
//   $ cc -O3 -o thuemorse thuemorse.c -lm
//   $ ./thuemorse
//
// Ref: https://mathworld.wolfram.com/Thue-MorseConstant.html
// Ref: https://old.reddit.com/r/math/comments/pkvqy4
//
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define NBITS 100000L
#define BASE  10

int main(void)
{
    long ndigits = 1;
    unsigned char *digits = calloc(1, ceil(NBITS * log(2) / log(BASE)));

    for (long i = 0; i < NBITS; i++) {
        // Multiply by 2
        int carry = 0;
        for (long j = 0; carry || (j < ndigits); j++) {
            ndigits = j+1 > ndigits ? j+1 : ndigits;
            digits[j] = 2*digits[j] + carry;
            carry = digits[j] >= BASE;
            digits[j] %= BASE;
        }

        // Add the new bit
        digits[0] += __builtin_popcountl(i) & 1;
        for (long j = 0; digits[j] >= BASE; j++) {
            digits[j] %= BASE;
            digits[j+1]++;
            ndigits = j+1 > ndigits ? j+1 : ndigits;
        }
    }

    long hist[BASE] = {0};
    for (long j = 0; j < ndigits; j++) {
        hist[digits[j]]++;
    }
    for (int i = 0; i < BASE; i++) {
        printf("%3x%8ld\n", i, hist[i]);
    }

    free(digits);
}
