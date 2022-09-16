// Monte Carlo method pi estimator, multi-threaded and SIMD
//   $ cc -Ofast -fopenmp -march=x86-64-v3 -o mcpi mcpi.c -lm
//   $ cl /O2 /fp:fast /openmp /arch:AVX2 mcpi.c
//
// Runs four truncated LCGs side-by-side in parallel SIMD, with each thread
// running independent trials, all merged for the final result. Reports the
// total number of trials, the trial rate (benchmark), and the pi estimate.
//
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define M  0x3243f6a8885a308dU
#define D  9223372036854775808.
#define N0 (1L << 12)
#define N1 (1L << 23)

int main(void)
{
    long n;  // for MSVC OpenMP
    double total = 0.0;
    clock_t start = clock();
    uint64_t seed = time(0);

    seed *= 1111111111111111111;
    seed ^= seed >> 33;
    #pragma omp parallel for reduction(+:total)
    for (n = 0; n < N0; n++) {
        // Expect e and s to be AVX registers
        double e[4], r = 0.0;
        uint64_t s[4] = {seed+n*4+0, seed+n*4+1, seed+n*4+2, seed+n*4+3};
        for (long i = 0; i < N1; i++) {
            s[0] = s[0]*M + 7;  e[0] = (s[0]>>1)/D;  r += sqrt(1 - e[0]*e[0]);
            s[1] = s[1]*M + 5;  e[1] = (s[1]>>1)/D;  r += sqrt(1 - e[1]*e[1]);
            s[2] = s[2]*M + 3;  e[2] = (s[2]>>1)/D;  r += sqrt(1 - e[2]*e[2]);
            s[3] = s[3]*M + 1;  e[3] = (s[3]>>1)/D;  r += sqrt(1 - e[3]*e[3]);
        }
        total += r / N1 / N0;
    }

    double elapsed = (double)(clock() - start)/CLOCKS_PER_SEC;
    long rate = 4.0*N0*N1 / elapsed / 1e6;
    printf("%lld trials, %ldMt/s, %.17g\n", 4LL*N0*N1, rate, total);
}
