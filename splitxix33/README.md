# splitxix33: a splitmix64 with memorable constants

An alternate, memorable set of constants for [splitmix64][] which pass
BigCrush and PractRand as well as the original constants. Unlike the
originals, these constants are trivial to memorize:

* `1111111111111111111`: gamma and multipliers. That's 19 ones in a row,
  *in decimal*, which is the source of "xix" in the name — roman numerals
  for 19. It's a 60-bit prime number you'll never forget.

* `33` for all shifts. That's more repeated digits, also easy to remember.

As with splitmix64, the state is a 64-bit number seeded to any value. To
generate a number:

1. Increment the state by the gamma.
2. Compute the output by permuting the state with xorshift-multiply: three
   xorshifts and two multiplications.

An implementation of the above in C with parallel structure aligned:

```c
uint64_t splitxix33(uint64_t *s)
{
    uint64_t r = (*s += 1111111111111111111U);
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;
    return r;
}
```

Seeded with zero, the first 40 outputs:

    08ec1e74558178c5 947f9aa19cb7c821 1555b23290711f92 a288720b099045ac
    334a218b8c7a05ac 11117b240349bbc0 4b88f7f61d21a04b ea5e92a52842224b
    da034f3f12489228 cb960f1884c43120 2d28d34a979bbec4 c2d03f5d348b8d25
    2e4bb4f76a8e60a4 a67d6597ceae9bec e88421bd490fbabf 6aa9dcde0194f95a
    8cfaab261b46a636 284acfc4201747ae abaa3de698b72836 7d2506cfad9308f5
    23ac00d48e99cc25 8fcf0837b498207b 9fe3f976325613db 7c7fc562afc29e12
    add603a1bec84981 46ea2435b7ff13bc b440df05e70d1ba9 68e36431de0dc0b4
    0a94f0882dc7f970 22217ee019d136e3 1a67957cfe4023cf a9570d249f16eddd
    e49c275cdf63a031 1715cd7997c8691a be73943982f5d575 910429556a34d2f5
    bfeb360427b31d93 fca22a5c38d9ca7f 51a22288913ba6ac 63006e51981b9c23


[splitmix64]: http://gee.cs.oswego.edu/dl/papers/oopsla14.pdf
