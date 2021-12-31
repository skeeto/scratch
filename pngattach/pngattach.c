// pngattach: attach files to a PNG image as metadata
//
// The intention is to attach the source script(s) from which the image
// was rendered. Attachments take the form of private "atCh" chunks.
//
// Usage:
//   $ cc -O3 -o pngattach pngattach.c -lz
//   $ ./pngattach <input.png >output.png source.dot
//   $ ./pngattach -xO <output.png >source.dot
//
// Define NO_ZLIB to build without zlib support.
//
// Most functions return a char pointer representing an error. NULL
// means no error, and any non-NULL pointer is a static error message.
// Except for attachments, PNG input is never loaded into memory, so
// this program can handle arbitrarily-large PNGs. However, it assumes
// individual attachments can reasonably fit in memory.
//
// This is free and unencumbered software released into the public domain.
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NO_ZLIB
#  include <zlib.h>
#endif

#ifdef _WIN32
#  include <io.h>
#  define ISATTY(x) _isatty(x)
#else
#  include <unistd.h>
#  define ISATTY(x) isatty(x)
#endif

#define TYPE_IEND 0x49454e44
#define TYPE_atCh 0x61744368

#define FLAG_LIST    (1<<0)  // list attachments while parsing
#define FLAG_STDOUT  (1<<1)  // dump attachments to standard output
#define FLAG_DUMP    (1<<2)  // dump attachments while parsing
#define FLAG_STORE   (1<<3)  // store new attachments while parsing
#define FLAG_RAW     (1<<4)  // do not compress attachments

// Wrap an error with additional context, such as a file name.
static const char *
errwrap(const char *pre, const char *post)
{
    static char errtmp[2][256], i;
    int n = i = !i;  // toggle between two static buffers
    snprintf(errtmp[n], sizeof(errtmp[n]), "%s: %s", pre, post);
    return errtmp[n];
}

// Read a 32-bit big endian integer from a buffer.
static uint32_t
loadu32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] <<  8 | (uint32_t)p[3] <<  0;
}

// Read a 64-bit big endian integer from a buffer.
static uint64_t
loadu64(const unsigned char *p)
{
    return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 |
           (uint64_t)p[2] << 40 | (uint64_t)p[3] << 32 |
           (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
           (uint64_t)p[6] <<  8 | (uint64_t)p[7] <<  0;
}

// Write a 32-bit big endian integer to a buffer.
static void
storeu32(unsigned char *p, uint32_t x)
{
    p[0] = x >> 24; p[1] = x >> 16;
    p[2] = x >>  8; p[3] = x >>  0;
}

// Append data to a CRC-32 checksum. Use 0 for the initial checksum.
static uint32_t
crc32_update(uint32_t crc, const void *buf, size_t len)
{
    static const uint32_t crc32_table[] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
        0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
        0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
        0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
        0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
        0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
        0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
        0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
        0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
        0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
        0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
        0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
        0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
        0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
        0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
        0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
        0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
        0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
        0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
        0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
        0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
        0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
        0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
        0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
        0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
        0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
        0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
        0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
        0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
        0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
        0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
        0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
        0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
        0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
        0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
        0x2d02ef8d
    };
    const unsigned char *p = buf;
    crc ^= 0xffffffff;
    for (size_t n = 0; n < len; n++)
        crc = crc32_table[(crc ^ p[n]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffff;
}

// Read an entire stream into a buffer.
static const char *
slurp(FILE *f, unsigned char **buf, size_t *len)
{
    size_t cap = 1 << 11;

    *buf = 0;
    for (*len = 0;;) {
        cap *= 2;
        if (!cap) {
            free(*buf);
            *buf = 0;
            return "input too large";
        }

        void *tmp = realloc(*buf, cap);
        if (!tmp) {
            free(*buf);
            *buf = 0;
            return "out of memory";
        }
        *buf = tmp;

        size_t in = fread(*buf+*len, 1, cap-*len, f);
        *len += in;
        if (in < cap-*len) {
            if (feof(f)) {
                return 0;
            }
            free(*buf);
            *buf = 0;
            return "read error";
        }
    }
}

// Read, validate, and optionally pass PNG header. Output may be NULL.
static const char *
png_begin(FILE *fi, FILE *fo)
{
    unsigned char buf[8];
    if (!fread(buf, 8, 1, fi)) {
        return feof(fi) ? "PNG input invalid" : "PNG input error";
    }
    if (loadu64(buf) != 0x89504e470d0a1a0a) {
        return "PNG input invalid";
    }
    if (fo && !fwrite(buf, 8, 1, fo)) {
        return "PNG write error";
    }
    return 0;
}

struct chunk { uint32_t len, type; };

// Read the next chunk header from the stream.
static const char *
png_next(FILE *fi, struct chunk *c)
{
    unsigned char buf[8];
    if (!fread(buf, 8, 1, fi)) {
        return feof(fi) ? "PNG truncated" : "PNG input error";
    }
    c->len  = loadu32(buf+0);
    c->type = loadu32(buf+4);
    return 0;
}

// Read, validate, and optionally pass the next chunk. Output may be NULL.
static const char *
png_pass(FILE *fi, FILE *fo, const struct chunk *c)
{
    uint32_t crc = 0;
    static unsigned char buf[1<<14];

    storeu32(buf+0, c->len);
    storeu32(buf+4, c->type);
    crc = crc32_update(crc, buf+4, 4);
    if (fo && !fwrite(buf, 8, 1, fo)) {
        return "PNG write error";
    }

    uint32_t len = c->len;
    while (len) {
        size_t z = len > sizeof(buf) ? sizeof(buf) : len;
        if (!fread(buf, z, 1, fi)) {
            return feof(fi) ? "PNG truncated" : "PNG input error";
        }
        crc = crc32_update(crc, buf, z);
        if (fo && !fwrite(buf, z, 1, fo)) {
            return "PNG write error";
        }
        len -= z;
    }

    if (!fread(buf, 4, 1, fi)) {
        return feof(fi) ? "PNG truncated" : "PNG input error";
    }
    if (loadu32(buf) != crc) {
        return "bad PNG chunk CRC";
    }
    if (fo && !fwrite(buf, 4, 1, fo)) {
        return "PNG write error";
    }

    return 0;
}

struct offlen { size_t off, len; };

// Compute the offset+length of the basename of a path.
static struct offlen
basename(const char *path)
{
    size_t len = strlen(path);
    for (size_t i = len; i; i--) {
        int c = path[i-1];
        if (c == '/' || c == '\\') {
            return (struct offlen){i, len-i};
        }
    }
    return (struct offlen){0, len};
}

// Attempt to compress an attachment buffer, returning true if successful.
static _Bool
atch_compress(unsigned char *buf, size_t *len)
{
    #ifdef NO_ZLIB
    (void)buf; (void)len;
    return 0;
    #else
    unsigned char *tmp = malloc(*len-1);
    if (!tmp) {
        return "out of memory";
    }

    struct z_stream_s z = {
        .next_in = buf,
        .avail_in = *len,
        .next_out = tmp,
        .avail_out = *len - 1,
    };
    if (deflateInit(&z, 9) != Z_OK) {
        free(tmp);
        return 0;
    }

    if (deflate(&z, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&z);
        free(tmp);
        return 0;  // result was no smaller, give up
    }

    deflateEnd(&z);
    *len = z.next_out - tmp;
    memcpy(buf, tmp, *len);
    free(tmp);
    return 1;
    #endif
}

// Write an atCh chunk to standard output.
static const char *
png_atch(FILE *fo, const char *path, int flags)
{
    struct offlen name = basename(path);
    if (name.len > (uint32_t)-1 - 2) {
        return errwrap("attachment name too large", path);
    }
    if (name.len < 1) {
        return errwrap("attachment name too short", path);
    }

    if (path[name.off] == '.') {
        return "invalid attachment name (begins with .)";
    }
    for (size_t i = 0; i < name.len; i++) {
        if ((path[name.off+i]&0xff) < ' ') {
            return "invalid attachment name (contains control byte)";
        }
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return errwrap("failed to open file", path);
    }

    size_t len;
    unsigned char *buf;
    _Bool compressed = 0;
    const char *err = slurp(f, &buf, &len);
    fclose(f);
    if (err) {
        return errwrap(err, path);
    }

    if (!(flags & FLAG_RAW)) {
        compressed = atch_compress(buf, &len);
    }

    if (len > (uint32_t)-1 - (name.len + 2)) {
        free(buf);
        return errwrap("attachment too large", path);
    }

    unsigned char hdr[8];
    storeu32(hdr+0, name.len+2+len);
    storeu32(hdr+4, TYPE_atCh);
    uint32_t crc = crc32_update(0, hdr+4, 4);
    if (!fwrite(hdr, 8, 1, fo)) {
        free(buf);
        return "PNG write error";
    }

    crc = crc32_update(crc, path+name.off, name.len);
    if (!fwrite(path+name.off, name.len, 1, fo)) {
        free(buf);
        return "PNG write error";
    }

    hdr[0] = 0;
    hdr[1] = compressed;
    crc = crc32_update(crc, hdr, 2);
    if (!fwrite(hdr, 2, 1, fo)) {
        free(buf);
        return "PNG write error";
    }

    crc = crc32_update(crc, buf, len);
    if (len && !fwrite(buf, len, 1, fo)) {
        free(buf);
        return "PNG write error";
    }

    storeu32(hdr, crc);
    if (!fwrite(hdr, 4, 1, fo)) {
        free(buf);
        return "PNG write error";
    }

    free(buf);
    return 0;
}

// Read an entire chunk into a buffer.
static const char *
png_slurp(FILE *fi, const struct chunk *c, unsigned char **buf, size_t *cap)
{
    unsigned char tmp[4];
    storeu32(tmp, c->type);
    uint32_t crc = crc32_update(0, tmp, 4);

    if (*cap < c->len) {
        void *p = realloc(*buf, c->len);
        if (!p) {
            return "out of memory";
        }
        *buf = p;
        *cap = c->len;
    }

    if (!fread(*buf, c->len, 1, fi)) {
        return "PNG truncated";
    }

    crc = crc32_update(crc, *buf, c->len);
    if (!fread(tmp, 4, 1, fi)) {
        return "PNG truncated";
    }
    if (loadu32(tmp) != crc) {
        return "bad PNG chunk CRC";
    }

    return 0;
}

// Write a slurped chunk back out.
static const char *
png_unslurp(FILE *fo, const struct chunk *c, const unsigned char *buf)
{
    unsigned char hdr[8];
    storeu32(hdr+0, c->len);
    storeu32(hdr+4, c->type);

    uint32_t crc = crc32_update(0, hdr+4, 4);
    if (!fwrite(hdr, 8, 1, fo)) {
        return "PNG write error";
    }

    crc = crc32_update(crc, buf, c->len);
    if (c->len && !fwrite(buf, c->len, 1, fo)) {
        return "PNG write error";
    }

    storeu32(hdr, crc);
    if (!fwrite(hdr, 4, 1, fo)) {
        return "PNG write error";
    }

    return 0;
}

struct atch {
    char *path;
    size_t pathlen;
    unsigned char *data;
    size_t datalen;
    _Bool compressed;
};

// Validate and extract the components of a slurped chunk.
static _Bool
atch_parse(struct atch *a, unsigned char *buf, size_t len)
{
    if (len < 3) {
        return 0;
    }
    if (!buf[0] || buf[0] == '.') {
        return 0;
    }

    unsigned char *end = buf;
    for (; end < buf+len-1 && *end; end++) {
        if ((*end&0xff) < ' ' || *end == '/' || *end == '\\') {
            return 0;
        }
    }
    if (end == buf+len-1) {
        return 0;
    }

    a->path = (char *)buf;
    a->pathlen = end - buf;
    a->data = buf + a->pathlen + 2;
    a->datalen = len - a->pathlen - 2;
    a->compressed = buf[a->pathlen+1];
    return 1;
}

// Decompress an attachment into the output stream.
static const char *
atch_decompress(FILE *fo, unsigned char *buf, size_t len)
{
    #ifdef NO_ZLIB
    (void)fo; (void)buf; (void)len;
    return "compression unsupported";
    #else
    static unsigned char tmp[1<<12];
    struct z_stream_s z = {
        .next_in = buf,
        .avail_in = len,
        .next_out = tmp,
        .avail_out = sizeof(tmp),
    };
    if (inflateInit(&z) != Z_OK) {
        return "out of memory";
    }

    for (;;) {
        switch (inflate(&z, Z_FINISH)) {
        case Z_STREAM_END:
            inflateEnd(&z);
            size_t n = z.next_out - tmp;
            if (n && !fwrite(tmp, n, 1, fo)) {
                return "attachment write error";
            }
            return 0;
        case Z_OK:
        case Z_BUF_ERROR:
            if (!fwrite(tmp, sizeof(tmp), 1, fo)) {
                inflateEnd(&z);
                return "attachment write error";
            }
            z.next_out = tmp;
            z.avail_out = sizeof(tmp);
            break;
        default:
            inflateEnd(&z);
            return "attachment decompression error";
        }
    }
    #endif
}

// Covers creating (-c) and deleting (-d)
static const char *
cmd_write(char **paths, int flags)
{
    unsigned char *buf = 0;
    size_t cap = 0;
    const char *err = 0;

    err = png_begin(stdin, stdout);
    if (err) {
        return err;
    }

    for (;;) {
        struct chunk c[1];
        err = png_next(stdin, c);
        if (err) {
            free(buf);
            return err;
        }

        switch (c->type) {
        case TYPE_IEND:
            if (flags & FLAG_STORE) {
                for (char **path = paths; *path; path++) {
                    err = png_atch(stdout, *path, flags);
                    if (err) {
                        free(buf);
                        return err;
                    }
                }
            }
            free(buf);
            return png_pass(stdin, stdout, c);

        case TYPE_atCh:
            err = png_slurp(stdin, c, &buf, &cap);
            if (err) {
                free(buf);
                return err;
            }

            _Bool skip = 0;
            struct atch a;
            if (atch_parse(&a, buf, c->len)) {
                // Skip matching file names
                for (char **path = paths; *path; path++) {
                    struct offlen n = basename(*path);
                    const char *b = *path + n.off;
                    if (n.len == a.pathlen && !memcmp(b, a.path, n.len)) {
                        skip = 1;
                        break;
                    }
                }
            }
            if (!skip) {
                err = png_unslurp(stdout, c, buf);
                if (err) {
                    free(buf);
                    return err;
                }
            }
            break;

        default:
            err = png_pass(stdin, stdout, c);
            if (err) {
                free(buf);
                return err;
            }
        }
    }
}

// Dump an attachment to its named file.
static const char *
atch_dump(const struct atch *a)
{
    FILE *f = fopen(a->path, "wb");
    if (!f) {
        return errwrap("failed to open file", a->path);
    }

    if (a->compressed) {
        const char *err = atch_decompress(f, a->data, a->datalen);
        if (err) {
            fclose(f);
            return errwrap(err, a->path);
        }
    } else {
        if (a->datalen && (!fwrite(a->data, a->datalen, 1, f) || fflush(f))) {
            fclose(f);
            return errwrap("failed to write file", a->path);
        }
        fclose(f);
    }
    return 0;
}

// Covers listing (-t) and extraction (-x)
static const char *
cmd_read(int flags)
{
    unsigned char *buf = 0;
    size_t cap = 0;
    const char *err = 0;

    err = png_begin(stdin, 0);
    if (err) {
        return err;
    }

    for (;;) {
        struct chunk c[1];
        err = png_next(stdin, c);
        if (err) {
            free(buf);
            return err;
        }

        switch (c->type) {
        case TYPE_atCh:
            err = png_slurp(stdin, c, &buf, &cap);
            if (err) {
                free(buf);
                return err;
            }

            struct atch a;
            if (atch_parse(&a, buf, c->len)) {
                if (flags & FLAG_LIST) {
                    if (puts(a.path) == EOF) {
                        free(buf);
                        return "attachment listing write error";
                    }
                }

                if (flags & FLAG_DUMP) {
                    if (flags & FLAG_STDOUT) {
                        if (a.compressed) {
                            err = atch_decompress(stdout, a.data, a.datalen);
                            if (err) {
                                free(buf);
                                return err;
                            }
                        } else {
                            if (a.datalen &&
                                !fwrite(a.data, a.datalen, 1, stdout)) {
                                return "attachment write error";
                            }
                        }

                    } else {
                        err = atch_dump(&a);
                        if (err) {
                            free(buf);
                            return err;
                        }
                    }
                }
            }
            break;

        case TYPE_IEND:
            free(buf);
            return png_pass(stdin, 0, c);

        default:
            err = png_pass(stdin, 0, c);
            if (err) {
                free(buf);
                return err;
            }
        }
    }
}

static int xoptind = 1;
static int xopterr = 1;
static int xoptopt;
static char *xoptarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    arg = argv[xoptind];
    if (arg && strcmp(arg, "--") == 0) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        xoptopt = arg[optpos];
        if (!opt) {
            if (xopterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], xoptopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                xoptarg = (char *)arg + optpos + 1;
                xoptind++;
                optpos = 1;
                return xoptopt;
            } else if (argv[xoptind + 1]) {
                xoptarg = (char *)argv[xoptind + 1];
                xoptind += 2;
                optpos = 1;
                return xoptopt;
            } else {
                if (xopterr && *optstring != ':')
                    fprintf(stderr,
                            "%s: option requires an argument: %c\n",
                            argv[0], xoptopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                xoptind++;
                optpos = 1;
            }
            return xoptopt;
        }
    }
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: pngattach -c <PNG >PNG [FILE]...\n");
    fprintf(f, "       pngattach -d <PNG >PNG [FILE]...\n");
    fprintf(f, "       pngattach -t <PNG\n");
    fprintf(f, "       pngattach -x <PNG\n");
    fprintf(f, "  -c     create/update attachments (default)\n");
    fprintf(f, "  -d     delete attachments by name\n");
    fprintf(f, "  -h     print this usage message\n");
    fprintf(f, "  -O     write attachments to standard output\n");
    fprintf(f, "  -t     list attached files\n");
    fprintf(f, "  -u     do not compress attachments\n");
    fprintf(f, "  -v     print extracted file names (verbose)\n");
    fprintf(f, "  -x     extract all PNG attachments\n");
}

int
main(int argc, char **argv)
{
    #ifdef _WIN32
    // set stdin/stdout to binary mode
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    int option;
    int flags = FLAG_STORE;
    enum {MODE_WRITE, MODE_READ} mode = MODE_WRITE;

    while ((option = xgetopt(argc, argv, "cdhOtuvx")) != -1) {
        switch (option) {
        case 'c': flags |= FLAG_STORE;  break;
        case 'd': mode = MODE_WRITE;
                  flags &= ~FLAG_STORE; break;
        case 'h': usage(stdout);        return 0;
        case 'O': flags |= FLAG_STDOUT; break;
        case 't': mode = MODE_READ;
                  flags |= FLAG_LIST;   break;
        case 'u': flags |= FLAG_RAW;    break;
        case 'v': flags |= FLAG_LIST;   break;
        case 'x': mode = MODE_READ;
                  flags |= FLAG_DUMP;   break;
        default : usage(stderr);        return 1;
        }
    }

    if (ISATTY(0)) {
        usage(stderr);
        return 1;
    }

    const char *err = 0;

    switch (mode) {
    case MODE_WRITE:
        if (ISATTY(1)) {
            err = "binary data cannot be written to a terminal";
            break;
        }
        err = cmd_write(argv + xoptind, flags);
        break;

    case MODE_READ:
        if (argv[xoptind]) {
            err = "too many arguments";
            break;
        }
        err = cmd_read(flags);
        break;
    }

    if (err) {
        fprintf(stderr, "pngattach: %s\n", err);
        return 1;
    }

    fflush(stdout);
    if (ferror(stdout)) {
        fprintf(stderr, "pngattach: write error\n");
        return 1;
    }

    return 0;
}
