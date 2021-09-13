# Middle Multiplicative Lagged Fibonacci Generator (MMLFG)

An enhanced, two-tap Multiplicative Lagged Fibonacci Generator (MLFG)
where the yield is the "middle" 64 bits of a 128-bit product, much like
the middle of the middle-square algorithm. The low 64 bits are still used
in the usual fashion for the MLFG state. Below, `f` iterates the internal
state and `g` computes, in parallel, output.

    f(n) =  (f(n-j) * f(n-k))         % (1 << N)
    g(n) = ((f(n-j) * f(n-k)) >> N/2) % (1 << N)

For the generators in this repository: `N=64`, `j=13`, `k=15`, making for
a period of `2**76 - 2**61` and, in practice, 128-byte state. They pass
BigCrush, and PractRand to at least to 8TB.

The Go implementation is, on gc, the fastest pure-Go PRNG of which I'm
aware that passes BigCrush and PractRand.

## Canonical seeding

The generator's 15-element state must be seeded to all odd numbers, must
not be all 1, and must not eventually result in all 1. For the sake of
testing, the canonical algorithm for seeding an MMLFG from a 64-bit seed
is a full-period 64-bit Linear Congruential Generator (LCG):

    f(n) = (f(n-1)*0x3243f6a8885a308d + 1111111111111111111) % (1 << 64)

Where f(0) is the seed and f(1) is used to compute the first state
element. The multiplier is the digits of pi as a 64-bit integer (easily
computed with unix `bc`), and the increment is a memorable prime (nineteen
ones). The LCG output is xorshifted by 31 and the lowest bit is locked to
1, making the result odd:

    e(n) = (f(n) ^ (f(n) >> 31)) | 1

Seeded with zero, the first 40 MMLFG outputs are:

    1573aa52f814bda8 3aeaac28b52676e2 8f1b6491309e5792 25bca26e169f58cd
    ee13266f6d5bad81 d688681022995579 c227f64fffc6967a 3d06e4f91995745f
    4077b1108d5150b1 41deb8bcf496aac3 def5ecadb01c5527 42be0306aca9476d
    cc40df9abc49fae2 d6fab4fe6f2c8373 ad02822ecc846c6d 602b2201cc7bf7b7
    ded4343bd0724597 fcbcd8d91b8f65f4 fc76214430f94e44 4c7fc6e9f4291294
    fca3ad5722cee412 e3383e408585396a fbafa05b7c2faecf e684088050284b8c
    8bbb114ed18162a0 0bbde9b2d192d39b b403be5f2fb967e5 c60ea291e01fe627
    1790ba5d87432edc 598bdded3fe137d9 0dba6bcb0e9e17ef 748d4dac10754ca0
    a212d97e7982de85 975ea1c76b0f0a7e ad0170d0b44d8673 a3d8fb24e994e7cf
    5ecef8bd9f6e7279 c3a57186c73c6a98 7f3ad93171dfdff9 0c16dcd911bee1a9


[mlfg]: http://www.cs.fsu.edu/~asriniva/papers/mlfg.ps
