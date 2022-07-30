// Simple IHEX parser
// Ref: https://en.wikipedia.org/wiki/Intel_HEX
// Ref: https://old.reddit.com/r/C_Programming/comments/wagx62
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

#define IHEX_ERR_TRUNCATED -3  // unexpected EOF
#define IHEX_ERR_INVALID   -2  // malformed input
#define IHEX_ERR_CHECKSUM  -1  // checksum mismatch
#define IHEX_DATA          +0
#define IHEX_EOF           +1
#define IHEX_SEGMENT       +2
#define IHEX_SEGMENT_ENTRY +3
#define IHEX_LINEAR        +4
#define IHEX_LINEAR_ENTRY  +5

// Parses a buffer containing IHEX data. The buffer length is a signed
// 32-bit quanity and so may not exceed 2 GiB.
#define IHEX_PARSER(buf, len) {buf, len, 0, 0, 0}
struct ihex_parser {
    uint8_t  *buf;
    int32_t   len;
    int32_t   off;      // parser cursor
    int32_t   lineno;   // line number of current record/error
    uint32_t  base;     // current extended address
};

struct ihex_record {
    uint32_t address;   // effective address
    int32_t  data_off;  // offset of in-place decoded data
    uint8_t  type;
    uint8_t  data_len;  // length in octets
    uint8_t  checksum;  // expected checksum
};

// Decode the next IHEX record from the input. Returns the record type,
// or one of the error codes for invalid input. Record data is decoded
// in place. The caller must halt parsing at record type 1 (IHEX_EOF).
//
// On a checksum mismatch it returns an error code, but the record
// contains an otherwise valid record, and parsing may continue. The
// checksum field indicates the correct checksum for the record.
// Otherwise it is not possible to continue parsing after an error.
//
// The parser automatically tracks extended addresses, and the record
// address is the segment/linear effective address. You need not compute
// these yourself.
static int
ihex_next(struct ihex_parser *p, struct ihex_record *r)
{
    static uint32_t hexc[] = {0, 0x3ff0000, 0x7e, 0x7e, 0, 0, 0, 0};
    static uint8_t hex[] = {
        0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0xa,0xb,0xc,0xd,0xe,0xf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
        0x0,0xa,0xb,0xc,0xd,0xe,0xf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    };
    static struct ihex_record zero = {0};

    // Avoid mutating p and r during parsing. The compiler will worry it
    // aliases with the input buffer and emit poor code.
    int32_t lineno = p->lineno + 1;
    uint8_t *buf = p->buf;
    int32_t len = p->len;
    int32_t off = p->off;
    *r = zero;

    // Find the next record
    while (off < len && buf[off] != ':') {
        if (buf[off] == '\n') {
            lineno++;
        } else if (buf[off] == '\r') {
            lineno += len-off > 1 && buf[off+1] != '\n';
        }
        off++;
    }
    p->lineno = lineno;
    if (off == len) {
        return IHEX_ERR_TRUNCATED;
    }
    off++;

    // Count hexadecimal characters
    int32_t reclen = 0; // nibbles
    uint8_t *rec = buf + off;
    for (; off < len; reclen++) {
        if (reclen > 2*255 + 10) {
            return IHEX_ERR_INVALID; // impossibly long
        }
        uint8_t b = buf[off];
        if (!(hexc[b>>5] & ((uint32_t)1 << (b&31)))) {
            break;
        }
        off++;
    }

    // Does this record end with a newline?
    int newline = 1;
    switch (len - off) {
    case  0: newline = 0;
             break;
    case  1: if (buf[off] == '\n' || buf[off] == '\r') {
                 off++;
                 break;
             }
             return IHEX_ERR_INVALID;
    default: if (buf[off] == '\n') {
                 off++;
                 break;
             }
             if (buf[off] == '\r') {
                 off++;
                 if (buf[off] == '\n') {
                    off++;
                 }
                 break;
             }
             return IHEX_ERR_INVALID;
    }

    if (reclen<10 || (reclen&1)) {
        return newline ? IHEX_ERR_INVALID : IHEX_ERR_TRUNCATED;
    }

    uint8_t  dlen = hex[rec[0]]<<4 | hex[rec[1]]<<0;
    if (reclen-10 != 2*dlen) {
        return newline ? IHEX_ERR_INVALID : IHEX_ERR_TRUNCATED;
    }
    uint16_t addr = (uint16_t)hex[rec[2]]<<12 | (uint16_t)hex[rec[3]]<<8 |
                    (uint16_t)hex[rec[4]]<<4  | (uint16_t)hex[rec[5]]<<0;
    uint8_t  type = hex[rec[6]]<<4 | hex[rec[7]];
    uint8_t  csum = hex[rec[8+2*dlen]]<<4 | hex[rec[9+2*dlen]]<<0;

    // Decode in place while computing checksum
    unsigned sum = dlen + addr + (addr>>8) + type;
    uint8_t *dst = rec;
    for (int32_t i = 0; i < dlen; i++) {
        uint8_t b = hex[rec[i*2+8]]<<4 | hex[rec[i*2+9]];
        sum += *dst++ = b;
    }
    sum = -sum & 255;

    // Update extended address
    if (sum == csum) {
        switch (type) {
        case IHEX_SEGMENT:
            p->base = (uint32_t)addr<<4;
            break;
        case IHEX_LINEAR:
            if (dlen != 2) {
                return IHEX_ERR_INVALID;
            }
            p->base = (uint32_t)rec[0]<<24 | (uint32_t)rec[1]<<16;
            break;
        }
    }

    p->off = off;
    p->lineno = lineno;
    r->address = p->base + addr;
    r->data_off = (int32_t)(rec - buf);
    r->data_len = dlen;
    r->checksum = sum;
    r->type = type;
    return sum == csum ? type : IHEX_ERR_CHECKSUM;
}


#ifdef TEST
// $ cc -DTEST -O -o ihex ihex.c
#include <stdio.h>

int
main(void)
{
    static uint8_t buf[1L<<21]; // 2MiB ought to be enough
    int32_t len = fread(buf, 1, sizeof(buf), stdin);
    struct ihex_parser p = IHEX_PARSER(buf, len);

    for (;;) {
        struct ihex_record r;
        int type = ihex_next(&p, &r);
        printf("<stdin>:%ld%4d ", (long)p.lineno, type);
        printf("type%4d, addr %08lx, dlen%4d, csum %02x\n",
               r.type, (unsigned long)r.address, r.data_len, r.checksum);
        if (r.data_len) {
            for (int i = 0; i < r.data_len; i++) {
                printf("%c%02x", i?' ':'\t', buf[r.data_off+i]);
            }
            putchar('\n');
        }
        switch (type) {
        case IHEX_ERR_INVALID:
        case IHEX_ERR_TRUNCATED:
            return 1;
        case IHEX_EOF:
            return 0;
        }
    }
}
#endif
