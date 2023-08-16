// In-place base-128 unsigned 64-bit radix sort
//
//   $ cc -DTEST -DQSORT -O -o sortu64 sortu64.c
//   $ ./sortu64
//
// The base can be adjusted at compile time with SORTU64_EXP, though
// large bases will blow the stack. The benchmark indicates base-128 is
// the fastest, at least for large-valued elements. Faster on partially
// sorted inputs, and unsurprisingly, in my tests substantially faster
// than qsort on any kind of input.
//
// GCC 13 does poorly starting at -O2 due to -ftree-slp-vectorize. Older
// versions of GCC do not have this problem.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

typedef int i32;
typedef unsigned long long u64;
typedef ptrdiff_t size;

// Use zero shift at the top level call.
static void sortu64(u64 *nums, size len, i32 shift)
{
    if (len < 1<<8) {
        // Insertion sort for small inputs
        for (i32 i = 1; i < (i32)len; i++) {
            for (i32 j = i; j>0 && nums[j-1]>nums[j]; j--) {
                u64 swap = nums[j-1];
                nums[j-1] = nums[j];
                nums[j] = swap;
            }
        }
        return;
    }

    // First pass: count each bin size
    #define SORTU64_EXP 7
    i32 mask  = (1<<SORTU64_EXP) - 1;
    i32 spare = SORTU64_EXP - (64%SORTU64_EXP + SORTU64_EXP)%SORTU64_EXP;
    size fill[1<<SORTU64_EXP] = {0};
    for (size i = 0; i < len; i++) {
        i32 bin = (i32)(nums[i]>>(64 - spare - shift)) & mask;
        fill[bin]++;
    }

    // Locate bin ranges in the sorted array
    size ends[1<<SORTU64_EXP];
    size accum = 0;
    for (i32 b = 0; b < 1<<SORTU64_EXP; b++) {
        size beg = accum;
        accum   += fill[b];
        ends[b]  = accum;
        fill[b]  = beg;
    }

    // Second pass: move elements into allotted bins
    for (i32 b = 0; b < 1<<SORTU64_EXP; b++) {
        for (size i = fill[b]; i < ends[b];) {
            i32 bin = (i32)(nums[i]>>(64 - spare - shift)) & mask;
            if (bin == b) {
                i++;
            } else {
                u64 swap = nums[fill[bin]];
                nums[fill[bin]++] = nums[i];
                nums[i] = swap;
            }
        }
    }

    // Recursively sort each bin on the next digit
    if (shift < 64-spare) {
        for (i32 b = 0; b < 1<<SORTU64_EXP; b++) {
            size beg = b>0 ? ends[b-1] : 0;
            sortu64(nums+beg, ends[b]-beg, shift+SORTU64_EXP);
        }
    }
}


#ifdef TEST
#include <stdio.h>
#include <stdlib.h>
#if _MSC_VER
#  include <intrin.h>
#endif

typedef unsigned u32;

static u64 rdtscp(void)
{
    #if _MSC_VER
    u32 aux;
    return __rdtscp(&aux);
    #else
    u32 lo, hi;
    asm volatile ("rdtscp" : "=a"(lo), "=d"(hi) : : "cx", "memory");
    return (u64)hi<<32 | lo;
    #endif
}

static void fill(u64 *nums, size len, u64 seed)
{
    for (size i = 0; i < len; i++) {
        seed = seed*0x3243f6a8885a308d + 1;
        nums[i] = seed ^ seed>>32;
    }
}

static u64 checksum(u64 *nums, size len)
{
    u64 check = 0;
    for (size i = 0; i < len; i++) {
        check ^= nums[i];
        check *= 1111111111111111111;
    }
    return check ^ check>>32;
}

static int cmp(const void *a, const void *b)
{
    u64 x = *(u64 *)a;
    u64 y = *(u64 *)b;
    return (x>y) - (x<y);
}

int main(void)
{
    u64 seed = 1;              // checksum=1f6dc4a2964f8993
    size len = (size)1 << 24;  //
    u64 start, duration;
    u64 *nums = malloc(sizeof(*nums)*len);

    fill(nums, len, seed);
    start = rdtscp();
    sortu64(nums, len, 0);
    duration = (rdtscp() - start)/len;
    printf("sortu64 %5llu  %016llx\n", duration, checksum(nums, len));

    #ifdef QSORT
    fill(nums, len, seed);
    start = rdtscp();
    qsort(nums, len, sizeof(*nums), cmp);
    duration = (rdtscp() - start)/len;
    printf("qsort   %5llu  %016llx\n", duration, checksum(nums, len));
    #endif
}
#endif
