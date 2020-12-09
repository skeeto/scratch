/* This is free and unencumbered software released into the public domain. */

/* Must be seeded well! */
uint32_t
jsf32(uint32_t s[4])
{
    uint32_t t = s[0] - (s[1]<<27 | s[1]>>5);
    s[0] = s[1] ^ (s[2]<<17 | s[2]>>15);
    s[1] = s[2] + s[3];
    s[2] = s[3] + t;
    s[3] = s[0] + t;
    return s[3];
}

/* Must be seeded well! */
uint32_t
sfc32(uint32_t s[4])
{
    uint32_t t = s[0] + s[1] + s[3];
    s[3] = s[3] + 1;
    s[0] = s[1] ^ s[1]>>9;
    s[1] = s[2] + (s[2] << 3);
    s[2] = s[2]<<21 | s[2]>>11;
    s[2] = s[2] + t;
    return t;
}

/* Seed to anything. This is one of my own designs, though it's slow! */
uint32_t
dioscuri32(uint32_t s[2])
{
    uint32_t p = s[0], c = s[1];
    p ^= p >> 17;    c ^= c >> 16;
    p *= 0x9e485565; c *= 0xa812d533;
    p ^= p >> 16;    c ^= c >> 15;
    p *= 0xef1d6b47; c *= 0xb278e4ad;
    p ^= p >> 16;    c ^= c >> 17;
    s[0] = p + c;
    s[1]++;
    return p ^ c;
}
