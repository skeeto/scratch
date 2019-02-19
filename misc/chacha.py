"""
The ChaCha stream cipher

This module exports a single generator function: chacha. Given a key and
IV, it returns a generator iterator that produces the keystream a byte
at at time.

    import chacha
    key = b'It is Arthur King of the Britons'
    iv = bytes(chacha.IVSIZE)
    gen = chacha.chacha(key, iv)
    [next(gen) for _ in range(8)]
    # => [183, 63, 147, 244, 204, 140, 132, 235]

This is free and unencumbered software released into the public domain.
"""

from array import array as _array
from sys import byteorder as _byteorder

KEYSIZE = 32
IVSIZE = 8

# Discover the proper array integer type
def _basetype():
    for c in 'HIL':
        if _array(c).itemsize == 4:
            return c
    raise RuntimeError('no suitable integer type available')
_BASETYPE = _basetype()

def _rotate(v, n):
    return (v << n | v >> (32 - n)) & 0xffffffff

def _quarterround(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = _rotate(x[d] ^ x[a],  8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = _rotate(x[b] ^ x[c],  7)

def chacha(key, iv, rounds=20):
    """Return a generator iterator that produces a keystream byte-by-byte.

    key (bytes): Must be exactly 32 bytes long.
    iv (bytes): Initialization vector, must be exactly 8 bytes long.
    rounds: number of cipher rounds to perform (20, 12, 8)

    After 2^70 bytes of output the keystream will be exhausted and an
    OverflowError will be raised. (On conventional hardware, this would
    take CPython millions of years to reach.)
    """
    if len(key) != KEYSIZE:
        raise ValueError('key is the wrong length')
    if len(iv) != IVSIZE:
        raise ValueError('IV is the wrong length')

    state = _array(_BASETYPE, [0] * 16)
    state[ 0] = 0x61707865 # "expand 32-byte k"
    state[ 1] = 0x3320646e #
    state[ 2] = 0x79622d32 #
    state[ 3] = 0x6b206574 #
    view = _array(_BASETYPE, key)
    if _byteorder == 'big':
        view.byteswap()
    state[ 4] = view[0]
    state[ 5] = view[1]
    state[ 6] = view[2]
    state[ 7] = view[3]
    state[ 8] = view[4]
    state[ 9] = view[5]
    state[10] = view[6]
    state[11] = view[7]
    view = _array(_BASETYPE, iv)
    if _byteorder == 'big':
        view.byteswap()
    state[14] = view[0]
    state[15] = view[1]
    view = None

    output = _array(_BASETYPE, [0] * 16)
    while True:
        # Compute the next output block
        for i in range(16):
            output[i] = state[i]
        for i in range(rounds // 2):
            _quarterround(output,  0,  4,  8, 12)
            _quarterround(output,  1,  5,  9, 13)
            _quarterround(output,  2,  6, 10, 14)
            _quarterround(output,  3,  7, 11, 15)
            _quarterround(output,  0,  5, 10, 15)
            _quarterround(output,  1,  6, 11, 12)
            _quarterround(output,  2,  7,  8, 13)
            _quarterround(output,  3,  4,  9, 14)
        for i in range(16):
            output[i] = (output[i] + state[i]) & 0xffffffff

        # Yield each output byte
        if _byteorder == 'big':
            output.byteswap()
        result = output.tobytes()
        for byte in result:
            yield byte

        # Increment the block counter
        counter = (state[12] << 32 | state[13]) + 1
        state[12] = counter & 0xffffffff
        state[13] = counter >> 32

def _test():
    # Official IETF test vectors for 20 rounds on a zero key and IV
    expect0 = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
        ]
    expect1 = [
        0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
        0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
        0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
        0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
        0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
        0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
        0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
        0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f
        ]
    gen = chacha(bytes(KEYSIZE), bytes(IVSIZE))
    block0 = [next(gen) for _ in range(64)]
    block1 = [next(gen) for _ in range(64)]
    assert block0 == expect0
    assert block1 == expect1

if __name__ == '__main__':
    _test()
