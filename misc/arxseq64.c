/* ARX-based PRNG
 * This is free and unencumbered software released into the public domain.
 * Ref: https://github.com/danielnager/arxseq64
 */
#include <stdint.h>

static void
arxseq64(uint64_t b[8])
{
    b[2] ^= b[0]; b[3] ^= b[1]; b[2] += b[1]; b[3] += b[0];
    b[2] = b[2]<<22 | b[2]>>42; b[3] = b[3]<<41 | b[3]>>23;
    b[4] ^= b[2]; b[5] ^= b[3]; b[4] += b[3]; b[5] += b[2];
    b[4] = b[4]<<20 | b[4]>>44; b[5] = b[5]<<43 | b[5]>>21;
    b[6] ^= b[4]; b[7] ^= b[5]; b[6] += b[5]; b[7] += b[4];
    b[6] = b[6]<<18 | b[6]>>46; b[7] = b[7]<<45 | b[7]>>19;
    b[0] ^= b[6]; b[1] ^= b[7]; b[0] += b[7]; b[1] += b[6];
    b[0] = b[0]<<16 | b[0]>>48; b[1] = b[1]<<47 | b[1]>>17;
    b[2] ^= b[0]; b[3] ^= b[1]; b[2] += b[1]; b[3] += b[0];
    b[2] = b[2]<<22 | b[2]>>42; b[3] = b[3]<<41 | b[3]>>23;
    b[4] ^= b[2]; b[5] ^= b[3]; b[4] += b[3]; b[5] += b[2];
    b[4] = b[4]<<20 | b[4]>>44; b[5] = b[5]<<43 | b[5]>>21;
    b[6] ^= b[4]; b[7] ^= b[5]; b[6] += b[5]; b[7] += b[4];
    b[6] = b[6]<<18 | b[6]>>46; b[7] = b[7]<<45 | b[7]>>19;
    b[0] ^= b[6]; b[1] ^= b[7]; b[0] += b[7]; b[1] += b[6];
    b[0] = b[0]<<16 | b[0]>>48; b[1] = b[1]<<47 | b[1]>>17;
    b[2] ^= b[0]; b[3] ^= b[1]; b[2] += b[1]; b[3] += b[0];
    b[2] = b[2]<<22 | b[2]>>42; b[3] = b[3]<<41 | b[3]>>23;
    b[4] ^= b[2]; b[5] ^= b[3]; b[4] += b[3]; b[5] += b[2];
    b[4] = b[4]<<20 | b[4]>>44; b[5] = b[5]<<43 | b[5]>>21;
    b[6] ^= b[4]; b[7] ^= b[5]; b[6] += b[5]; b[7] += b[4];
    b[6] = b[6]<<18 | b[6]>>46; b[7] = b[7]<<45 | b[7]>>19;
    b[0] ^= b[6]; b[1] ^= b[7]; b[0] += b[7]; b[1] += b[6];
    b[0] = b[0]<<16 | b[0]>>48; b[1] = b[1]<<47 | b[1]>>17;
}

#ifdef DUMP
#include <string.h>

#ifdef __unix__
#include <unistd.h>

static long
dump(void *p, long n)
{
    return write(1, p, n);
}

#else
#include <windows.h>

static long
dump(void *p, long n)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD nout;
    if (!WriteFile(out, p, n, &nout, 0)) {
        return -1;
    }
    return nout;
}
#endif

int
main(void)
{
    static uint64_t buf[1<<12];
    for (uint64_t c = 0; ; c += sizeof(buf)/64) {
        for (size_t i = 0; i < sizeof(buf)/64; i++) {
            uint64_t *b = buf + i*8;
            b[0] = c + i;
            b[1] = 1;
            arxseq64(b);
        }
        if (dump(buf, sizeof(buf)) != (long)sizeof(buf)) {
            return 1;
        }
        memset(buf, 0, sizeof(buf));
    }
}
#endif
