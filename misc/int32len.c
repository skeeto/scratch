/* This is free and unencumbered software released into the public domain. */

// Return the printed decimal length for any signed 32-bit integer.
int int32len(long n)
{
    unsigned long b = n < 0;
    unsigned long u = (n ^ -b) + b;
    return (u >= 0x0000000a) + (u >= 0x00000064) + (u >= 0x000003e8) +
           (u >= 0x00002710) + (u >= 0x000186a0) + (u >= 0x000f4240) +
           (u >= 0x00989680) + (u >= 0x05f5e100) + (u >= 0x3b9aca00) + b + 1;
}
