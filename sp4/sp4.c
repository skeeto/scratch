/* Sponge4 sponge-like hash function
 * This is free and unencumbered software released into the public domain.
 */

void
sp4_absorb(unsigned char s[259], int byte)
{
    int t;

    /* Initialize? */
    if (s[0] == s[1])
        for (t = 0; t < 256; t++)
            s[t] = t;

    /* Absorb using key schedule */
    s[257] += s[s[256]] + byte;
        /* swap s[i] and s[j] */
    t = s[s[256]];
    s[s[256]] = s[s[257]];
    s[s[257]] = t;

    /* Increment counters */
    s[256]++; /* i */
    s[258]++; /* k */
}

void
sp4_absorb_stop(unsigned char s[259])
{
    s[257]++;
}

int
sp4_squeeze(unsigned char s[259])
{
    int t;

    /* Pad input? */
    if (s[258]) {
        /* Insert a stop between input and padding */
        sp4_absorb_stop(s);
        /* Pad with the count of remaining pad bytes */
        do sp4_absorb(s, s[258]); while (s[258]);
    }

    /* Run a single iteration of the generator */
    s[257] += s[256]++;
        /* swap s[i] and s[j] */
    t = s[s[256]];
    s[s[256]] = s[s[257]];
    s[s[257]] = t;
    return s[(s[s[256]] + s[s[257]]) % 256];
}
