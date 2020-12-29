/* This is free and unencumbered software released into the public domain. */

typedef int element;  // any integer type is valid

static void
sort5_network(element v[5])
{
    element a, b, t;
    a = v[0]; b = v[1]; t = v[0] = a < b ? a : b; v[1] ^= a ^ t;
    a = v[3]; b = v[4]; t = v[3] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[2]; b = v[4]; t = v[2] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[2]; b = v[3]; t = v[2] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[0]; b = v[3]; t = v[0] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[0]; b = v[2]; t = v[0] = a < b ? a : b; v[2] ^= a ^ t;
    a = v[1]; b = v[4]; t = v[1] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[1]; b = v[3]; t = v[1] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[1]; b = v[2]; t = v[1] = a < b ? a : b; v[2] ^= a ^ t;
}

static void
sort6_network(element v[6])
{
    element a, b, t;
    a = v[1]; b = v[2]; t = v[1] = a < b ? a : b; v[2] ^= a ^ t;
    a = v[4]; b = v[5]; t = v[4] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[0]; b = v[2]; t = v[0] = a < b ? a : b; v[2] ^= a ^ t;
    a = v[3]; b = v[5]; t = v[3] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[0]; b = v[1]; t = v[0] = a < b ? a : b; v[1] ^= a ^ t;
    a = v[3]; b = v[4]; t = v[3] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[1]; b = v[4]; t = v[1] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[0]; b = v[3]; t = v[0] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[2]; b = v[5]; t = v[2] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[1]; b = v[3]; t = v[1] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[2]; b = v[4]; t = v[2] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[2]; b = v[3]; t = v[2] = a < b ? a : b; v[3] ^= a ^ t;
}

static void
sort7_network(element v[7])
{
    element a, b, t;
    a = v[1]; b = v[2]; t = v[1] = a < b ? a : b; v[2] ^= a ^ t;
    a = v[0]; b = v[2]; t = v[0] = a < b ? a : b; v[2] ^= a ^ t;
    a = v[0]; b = v[1]; t = v[0] = a < b ? a : b; v[1] ^= a ^ t;
    a = v[3]; b = v[4]; t = v[3] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[5]; b = v[6]; t = v[5] = a < b ? a : b; v[6] ^= a ^ t;
    a = v[3]; b = v[5]; t = v[3] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[4]; b = v[6]; t = v[4] = a < b ? a : b; v[6] ^= a ^ t;
    a = v[4]; b = v[5]; t = v[4] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[0]; b = v[4]; t = v[0] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[0]; b = v[3]; t = v[0] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[1]; b = v[5]; t = v[1] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[2]; b = v[6]; t = v[2] = a < b ? a : b; v[6] ^= a ^ t;
    a = v[2]; b = v[5]; t = v[2] = a < b ? a : b; v[5] ^= a ^ t;
    a = v[1]; b = v[3]; t = v[1] = a < b ? a : b; v[3] ^= a ^ t;
    a = v[2]; b = v[4]; t = v[2] = a < b ? a : b; v[4] ^= a ^ t;
    a = v[2]; b = v[3]; t = v[2] = a < b ? a : b; v[3] ^= a ^ t;
}
