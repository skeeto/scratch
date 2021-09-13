# Middle Multiplicative Lagged Fibonacci PRNG
# This is free and unencumbered software released into the public domain.
import array

def mmlfg(seed):
    """Yields 64-bit random numbers."""
    i = 14
    j = 12
    s = array.array("Q", (0,) * 15)

    for i in range(15):
        seed *= 0x3243f6a8885a308d
        seed += 1111111111111111111
        seed &= 0xffffffffffffffff
        s[i] = seed ^ seed>>31 | 1

    while True:
        r = s[i] * s[j]
        s[i] = r & 0xffffffffffffffff
        i = (i + 14) % 15
        j = (j + 14) % 15
        yield r>>32 & 0xffffffffffffffff


# Example
r = tuple(mmlfg(i) for i in range(4))
for _ in range(40):
    print(*(f"{next(r[i]):016x}" for i in range(4)))
