// BPS patch tool
//   $ cc -O -o bpspatch bpspatch.c
//   $ ./bpspatch SOURCE <PATCH >TARGET
// This is free and unencumbered software released into the public domain.

// BPS patching library: bps_info(), bps_apply()
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum bps_result { BPS_OK, BPS_SRCSUM, BPS_TGTSUM, BPS_RANGE };

struct bps_info {
    int64_t srclen, tgtlen;
    size_t metaoff, metalen;
    uint32_t srcsum, tgtsum, bpssum;
};

// Read a 32-bit little endian integer.
static uint32_t
u32le(uint8_t *buf)
{
    return (uint32_t)buf[0] <<  0 | (uint32_t)buf[1] <<  8 |
           (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24;
}

// Append bytes to a CRC32 checksum. Initialize to zero.
static uint32_t
crc32(uint32_t crc, uint8_t *buf, size_t len)
{
    static const uint32_t crc32_table[] = {
        0x00000000,0x77073096,0xee0e612c,0x990951ba,0x076dc419,0x706af48f,
        0xe963a535,0x9e6495a3,0x0edb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,
        0x09b64c2b,0x7eb17cbd,0xe7b82d07,0x90bf1d91,0x1db71064,0x6ab020f2,
        0xf3b97148,0x84be41de,0x1adad47d,0x6ddde4eb,0xf4d4b551,0x83d385c7,
        0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,0x14015c4f,0x63066cd9,
        0xfa0f3d63,0x8d080df5,0x3b6e20c8,0x4c69105e,0xd56041e4,0xa2677172,
        0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,0x35b5a8fa,0x42b2986c,
        0xdbbbc9d6,0xacbcf940,0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,
        0x26d930ac,0x51de003a,0xc8d75180,0xbfd06116,0x21b4f4b5,0x56b3c423,
        0xcfba9599,0xb8bda50f,0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,
        0x2f6f7c87,0x58684c11,0xc1611dab,0xb6662d3d,0x76dc4190,0x01db7106,
        0x98d220bc,0xefd5102a,0x71b18589,0x06b6b51f,0x9fbfe4a5,0xe8b8d433,
        0x7807c9a2,0x0f00f934,0x9609a88e,0xe10e9818,0x7f6a0dbb,0x086d3d2d,
        0x91646c97,0xe6635c01,0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,
        0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,0x65b0d9c6,0x12b7e950,
        0x8bbeb8ea,0xfcb9887c,0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,
        0x4db26158,0x3ab551ce,0xa3bc0074,0xd4bb30e2,0x4adfa541,0x3dd895d7,
        0xa4d1c46d,0xd3d6f4fb,0x4369e96a,0x346ed9fc,0xad678846,0xda60b8d0,
        0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,0x5005713c,0x270241aa,
        0xbe0b1010,0xc90c2086,0x5768b525,0x206f85b3,0xb966d409,0xce61e49f,
        0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,0x59b33d17,0x2eb40d81,
        0xb7bd5c3b,0xc0ba6cad,0xedb88320,0x9abfb3b6,0x03b6e20c,0x74b1d29a,
        0xead54739,0x9dd277af,0x04db2615,0x73dc1683,0xe3630b12,0x94643b84,
        0x0d6d6a3e,0x7a6a5aa8,0xe40ecf0b,0x9309ff9d,0x0a00ae27,0x7d079eb1,
        0xf00f9344,0x8708a3d2,0x1e01f268,0x6906c2fe,0xf762575d,0x806567cb,
        0x196c3671,0x6e6b06e7,0xfed41b76,0x89d32be0,0x10da7a5a,0x67dd4acc,
        0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,0xd6d6a3e8,0xa1d1937e,
        0x38d8c2c4,0x4fdff252,0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
        0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,0xdf60efc3,0xa867df55,
        0x316e8eef,0x4669be79,0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,
        0xcc0c7795,0xbb0b4703,0x220216b9,0x5505262f,0xc5ba3bbe,0xb2bd0b28,
        0x2bb45a92,0x5cb36a04,0xc2d7ffa7,0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,
        0x9b64c2b0,0xec63f226,0x756aa39c,0x026d930a,0x9c0906a9,0xeb0e363f,
        0x72076785,0x05005713,0x95bf4a82,0xe2b87a14,0x7bb12bae,0x0cb61b38,
        0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0x0bdbdf21,0x86d3d2d4,0xf1d4e242,
        0x68ddb3f8,0x1fda836e,0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,
        0x88085ae6,0xff0f6a70,0x66063bca,0x11010b5c,0x8f659eff,0xf862ae69,
        0x616bffd3,0x166ccf45,0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,
        0xa7672661,0xd06016f7,0x4969474d,0x3e6e77db,0xaed16a4a,0xd9d65adc,
        0x40df0b66,0x37d83bf0,0xa9bcae53,0xdebb9ec5,0x47b2cf7f,0x30b5ffe9,
        0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,0xbad03605,0xcdd70693,
        0x54de5729,0x23d967bf,0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,
        0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d
    };
    crc ^= 0xffffffff;
    for (size_t n = 0; n < len; n++) {
        crc = crc32_table[(crc ^ buf[n])&0xff] ^ crc>>8;
    }
    return crc ^ 0xffffffff;
}

// Read a varint in [0 .. 567,382,630,219,903] (50 bits), returning the
// number of bytes consumed ([0 .. 7]). For invalid input (out of range,
// truncated), sets the value to -1 and returns zero.
static int
bps_number(uint8_t *buf, size_t len, int64_t *r)
{
    int64_t v = 0;
    uint8_t *p = buf, *e = buf + len;
    for (int s = 0; p<e && s<=49; s += 7) {
        v += (int64_t)(*p & 0x7f) << s;
        if (*p++ & 0x80) {
            *r = v;
            return p - buf;
        }
        v += (int64_t)1 << (s+7);
    }
    *r = -1;
    return 0;
}

// Validate and extract basic information about a BPS patch. Returns
// zero on error.
static int
bps_info(uint8_t *bps, size_t len, struct bps_info *info)
{
    // A minimal, empty patch is 19 bytes
    // "BPS1"  80 80 80  00 00 00 00  00 00 00 00  93 1f d8 5e
    if (len < 4+1+1+1+12 || memcmp(bps, "BPS1", 4)) {
        return 0;
    }

    info->srcsum = u32le(bps + len - 12);
    info->tgtsum = u32le(bps + len -  8);
    info->bpssum = u32le(bps + len -  4);
    if (info->bpssum != crc32(0, bps, len-4)) {
        return 0;
    }

    int off = 4;
    off += bps_number(bps+off, len-12-off, &info->srclen);
    off += bps_number(bps+off, len-12-off, &info->tgtlen);
    if (info->srclen<0 || info->tgtlen<0) {
        return 0;
    }

    int64_t metalen;
    off += bps_number(bps+off, len-12-off, &metalen);
    if (metalen<0 || metalen>(int64_t)len-12-off) {
        return 0;
    }
    info->metaoff = off;
    info->metalen = metalen;
    return 1;
}

// Apply the patch to the zero-initialized target buffer. The source and
// targets must match the sizes in bps_info. Returns non-zero if the patch
// failed. Includes checksum validation.
static enum bps_result
bps_apply(uint8_t *bps, size_t len, uint8_t *src, uint8_t *tgt)
{
    // These offsets/lengths have already been validated
    int64_t bp=4, sp=0, tp=0, op=0, bn=len-12, sn, tn, r;
    bp += bps_number(bps+bp, bn-bp, &sn);
    bp += bps_number(bps+bp, bn-bp, &tn);
    bp += bps_number(bps+bp, bn-bp, &r);
    bp += r;  // skip metadata

    // First validate the source checksum
    if (crc32(0, src, sn) != u32le(bps+len-12)) {
        return BPS_SRCSUM;
    }

    while (bp < bn) {
        bp += bps_number(bps+bp, bn, &r);
        if (r < 0) {
            return BPS_RANGE;
        }

        int64_t n = (r>>2) + 1;
        switch (r&3) {
        case 0: // SourceRead
            if (n>tn-op || n>sn-op) {
                return BPS_RANGE;
            }
            memcpy(tgt+op, src+op, n);
            op += n;
            break;
        case 1: // TargetRead
            if (n>tn-op || n>bn-bp) {
                return BPS_RANGE;
            }
            memcpy(tgt+op, bps+bp, n);
            op += n;
            bp += n;
            break;
        case 2: // SourceCopy
            bp += bps_number(bps+bp, bn, &r);
            if (r<0 || r>>1>sn) {
                return BPS_RANGE;
            }
            sp += r&1 ? -(r>>1) : r>>1;
            if (sp<0 || n>sn-sp || n>tn-op) {
                return BPS_RANGE;
            }
            memcpy(tgt+op, src+sp, n);
            op += n;
            sp += n;
            break;
        case 3: // TargetCopy
            bp += bps_number(bps+bp, bn, &r);
            if (r<0 || r>>1>tn) {
                return BPS_RANGE;
            }
            tp += r&1 ? -(r>>1) : r>>1;
            if (tp<0 || n>tn-tp || n>tn-op) {
                return BPS_RANGE;
            }
            for (ptrdiff_t i = 0; i < (ptrdiff_t)n; i++) {
                tgt[(ptrdiff_t)op+i] = tgt[(ptrdiff_t)tp+i];
            }
            op += n;
            tp += n;
            break;
        }
    }
    return crc32(0, tgt, tn) == u32le(bps+len-8) ? BPS_OK : BPS_TGTSUM;
}

// Command line tool
#include <stdio.h>
#include <stdlib.h>

// Read an entire stream into a buffer. Returns -1 on error.
static ptrdiff_t
slurp(FILE *f, uint8_t **buf)
{
    *buf = 0;
    for (size_t len=0, cap=1<<13;;) {
        cap *= 2;
        if (!cap) {
            free(*buf);
            *buf = 0;
            return -1;
        }

        void *p = realloc(*buf, cap);
        if (!p) {
            free(*buf);
            *buf = 0;
            return -1;
        }
        *buf = p;

        size_t z = cap - len;
        size_t in = fread(*buf+len, 1, z, f);
        len += in;
        if (in < z) {
            if (feof(f)) {
                return len;
            }
            free(*buf);
            *buf = 0;
            return -1;
        }
    }
}

int
main(int argc, char **argv)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    if (argc != 2) {
        fputs("usage: bpspatch SOURCE <PATCH >TARGET\n", stderr);
        return 1;
    }

    FILE *sf = fopen(argv[1], "rb");
    if (!sf) {
        fprintf(stderr, "bpspatch: could not open source, %s\n", argv[1]);
        return 1;
    }

    uint8_t *src;
    ptrdiff_t sn = slurp(sf, &src);
    if (sn < 0) {
        fprintf(stderr, "bpspatch: could not load source, %s\n", argv[1]);
        return 1;
    }

    uint8_t *bps;
    ptrdiff_t bn = slurp(stdin, &bps);
    if (bn < 0) {
        fputs("bpspatch: failed to load standard input\n", stderr);
        return 1;
    }

    struct bps_info info;
    if (!bps_info(bps, bn, &info)) {
        fputs("bpspatch: invalid patch data\n", stderr);
        return 1;
    }

    if (sn != info.srclen) {
        fprintf(stderr,"bpspatch: wrong source file size, expected %lld\n",
                (long long)info.srclen);
        return 1;
    }

    uint8_t *tgt = calloc(1, info.tgtlen);
    if ((uint64_t)info.tgtlen>(size_t)-1 || !tgt) {
        fprintf(stderr, "bpspatch: out of memory, wanted %lld bytes\n",
                (long long)info.tgtlen);
        return 1;
    }

    char *err = 0;
    switch (bps_apply(bps, bn, src, tgt)) {
    case BPS_OK:     break;
    case BPS_SRCSUM: err = "source checksum failed"; break;
    case BPS_TGTSUM: err = "target checksum failed"; break;
    case BPS_RANGE:  err = "invalid patch";          break;
    }
    if (err) {
        fprintf(stderr, "bpspatch: patch failed, %s\n", err);
        return 1;
    }

    fwrite(tgt, info.tgtlen, 1, stdout);
    fflush(stdout);
    if (ferror(stdout)) {
        fputs("bpspatch: error writing to standard output\n", stderr);
        return 1;
    }
    return 0;
}
