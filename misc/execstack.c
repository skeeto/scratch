// execstack -- clear/set/query executable stack bit of ELF binaries
//
// When querying, 'X' means execstack, '-' means noexecstack, and '?'
// means the input was not a valid ELF binary.
//
// This is a clone of the original "execstack" included with "prelink"
// but with the following differences:
//   * much more portable
//   * dependency-free (no libelf)
//   * simpler and faster
//   * no integer overflows
//   * short options only
//   * requires PT_GNU_STACK for set/clear
//   * uses '?' for error rather than "unknown"
//   * missing PT_GNU_STACK means noexecstack (true on newer ABIs)
//
// The original will attempt to create a PT_GNU_STACK program header if
// it not yet exist, there is room for one without moving anything, and
// the binary contains enough information to be reasonably confident
// that that the space to be used for a new PT_GNU_STACK is unused. I
// could not easily convince any linker to leave such unused space after
// the program headers, so I assume this was rare.
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OFF_INVALID -1
#define OFF_MISSING -2

#ifdef __GNUC__
#  define UNREACHABLE __builtin_unreachable()
#else
#  define UNREACHABLE abort()
#endif

static uint16_t u16le(uint8_t *buf)
{
    return (uint16_t)buf[0] <<  0 | (uint16_t)buf[1] <<  8;
}

static uint16_t u16be(uint8_t *buf)
{
    return (uint16_t)buf[0] <<  8 | (uint16_t)buf[1] <<  0;
}

static uint32_t u32le(uint8_t *buf)
{
    return (uint32_t)buf[0] <<  0 | (uint32_t)buf[1] <<  8 |
           (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24;
}

static uint32_t u32be(uint8_t *buf)
{
    return (uint32_t)buf[0] << 24 | (uint32_t)buf[1] << 16 |
           (uint32_t)buf[2] <<  8 | (uint32_t)buf[3] <<  0;
}

static uint64_t u64le(uint8_t *buf)
{
    return (uint64_t)buf[0] <<  0 | (uint64_t)buf[1] <<  8 |
           (uint64_t)buf[2] << 16 | (uint64_t)buf[3] << 24 |
           (uint64_t)buf[4] << 32 | (uint64_t)buf[5] << 40 |
           (uint64_t)buf[6] << 48 | (uint64_t)buf[7] << 56;
}

static uint64_t u64be(uint8_t *buf)
{
    return (uint64_t)buf[0] << 56 | (uint64_t)buf[1] << 48 |
           (uint64_t)buf[2] << 40 | (uint64_t)buf[3] << 32 |
           (uint64_t)buf[4] << 24 | (uint64_t)buf[5] << 16 |
           (uint64_t)buf[6] <<  8 | (uint64_t)buf[7] <<  0;
}

static uint16_t u16(uint8_t *buf, int data)
{
    switch (data) {
    case 1: return u16le(buf);
    case 2: return u16be(buf);
    }
    UNREACHABLE;
}

static uint32_t u32(uint8_t *buf, int data)
{
    switch (data) {
    case 1: return u32le(buf);
    case 2: return u32be(buf);
    }
    UNREACHABLE;
}

static uint64_t size(uint8_t *buf, int class, int data)
{
    switch (class<<4 | data) {
    case 0x11: return u32le(buf);
    case 0x12: return u32be(buf);
    case 0x21: return u64le(buf);
    case 0x22: return u64be(buf);
    }
    UNREACHABLE;
}

static int overlapped(int32_t a0, int32_t a1, int32_t b0, int32_t b1)
{
    return a0<b0 ? a1>b0 : b1>a0;
}

static int32_t find(uint8_t *buf, int32_t len)
{
    if (len<0x40 || u32le(buf+0x00)!=0x464c457f) {
        return OFF_INVALID;
    }

    int class = buf[0x04];
    if (class!=1 && class!=2) {
        return OFF_INVALID;
    }

    int data = buf[0x05];
    if (data!=1 && data!=2) {
        return OFF_INVALID;
    }

    int vers = buf[0x06];
    if (vers != 1) {
        return OFF_INVALID;
    }

    int type = buf[0x10];
    if (type!=2 && type!=3) {
        return OFF_INVALID;
    }

    vers = buf[0x14];
    if (vers != 1) {
        return OFF_INVALID;
    }

    int phoffs[] = {0x1c, 0x20};
    uint64_t phoff64 = size(buf+phoffs[class-1], class, data);
    if (phoff64 > (uint64_t)len) {
        return OFF_INVALID;
    }
    int32_t phoff = phoff64;

    int phentsizes[] = {0x2a, 0x36};
    int32_t phentsize = u16(buf+phentsizes[class-1], data);
    int phentsizemin[] = {0x20, 0x38};
    if (phentsize < phentsizemin[class-1]) {
        return OFF_INVALID;
    }

    int phnums[] = {0x2c, 0x38};
    int32_t phnum = u16(buf+phnums[class-1], data);
    if (phnum > (len - phoff)/phentsize) {
        return OFF_INVALID;
    }

    for (int32_t i = 0; i < phnum; i++) {
        uint8_t *ph = buf+phoff + i*phentsize;
        uint32_t type = u32(ph, data);
        if (type == 0x6474e551) {  // PT_GNU_STACK
            int pflags[] = {0x18, 0x04};
            return (ph - buf) + pflags[class-1];
        }
    }
    return OFF_MISSING;
}

struct xgetopt { char *optarg; int optind, optopt, optpos; };

static int
xgetopt(struct xgetopt *x, int argc, char **argv, const char *optstring)
{
    char *arg = argv[!x->optind ? (x->optind += !!argc) : x->optind];
    if (arg && arg[0] == '-' && arg[1] == '-' && !arg[2]) {
        x->optind++;
        return -1;
    } else if (!arg || arg[0] != '-' || ((arg[1] < '0' || arg[1] > '9') &&
                                         (arg[1] < 'A' || arg[1] > 'Z') &&
                                         (arg[1] < 'a' || arg[1] > 'z'))) {
        return -1;
    } else {
        while (*optstring && arg[x->optpos+1] != *optstring) {
            optstring++;
        }
        x->optopt = arg[x->optpos+1];
        if (!*optstring) {
            return '?';
        } else if (optstring[1] == ':') {
            if (arg[x->optpos+2]) {
                x->optarg = arg + x->optpos + 2;
                x->optind++;
                x->optpos = 0;
                return x->optopt;
            } else if (argv[x->optind+1]) {
                x->optarg = argv[x->optind+1];
                x->optind += 2;
                x->optpos = 0;
                return x->optopt;
            } else {
                return ':';
            }
        } else {
            if (!arg[++x->optpos+1]) {
                x->optind++;
                x->optpos = 0;
            }
            return x->optopt;
        }
    }
}

static int usage(FILE *f)
{
    static const char usage[] =
    "usage: execstack [-chqsV] [FILE]...\n"
    "  -c    mark files as accepting unexecutable stack\n"
    "  -h    print this usage information\n"
    "  -s    mark files as requiring executable stack\n"
    "  -q    query files for executable stack marker\n";
    return fwrite(usage, sizeof(usage)-1, 1, f) && !fflush(f) && !ferror(f);
}

int main(int argc, char **argv)
{
    struct xgetopt xgo = {0};
    enum {M_QUERY, M_CLEAR, M_SET } mode = M_QUERY;
    static const char unknown[]  = "execstack: unknown option: ";
    static const char missing[]  = "execstack: missing PT_GNU_STACK: ";
    static const char notelf[]   = "execstack: not an ELF binary: ";
    static const char seekfail[] = "execstack: seek failed: ";
    static const char openfail[] = "execstack: open failed: ";

    for (int opt; (opt = xgetopt(&xgo, argc, argv, "cqsh")) != -1;) {
        switch (opt) {
        case 'c': mode = M_CLEAR; break;
        case 'h': return !usage(stdout);
        case 'q': mode = M_QUERY; break;
        case 's': mode = M_SET;   break;
        default : usage(stderr);
                  fwrite(unknown, sizeof(unknown)-1, 1, stderr);
                  fputc(xgo.optopt, stderr);
                  fputc('\n', stderr);
                  return 1;
        }
    }

    int errors = 0;
    for (int i = xgo.optind; i < argc; i++) {
        char *path=argv[i], *flags=0;
        switch (mode) {
        case M_QUERY: flags = "rb"; break;
        case M_SET:
        case M_CLEAR: flags = "r+b";
        }
        FILE *f = fopen(path, flags);

        if (f) {
            uint8_t buf[1<<12];  // enough for any practical ELF binary PHDR
            int32_t len = fread(buf, 1, sizeof(buf), f);
            int32_t off = find(buf, len);

            switch (mode) {
            case M_QUERY:
                switch (off) {
                case OFF_INVALID: fputc('?', stdout); break;
                case OFF_MISSING: fputc('-', stdout); break;
                default         : fputc(buf[off]&1 ? 'X' : '-', stdout);
                }
                fputc(' ', stdout);
                fwrite(path, strlen(path), 1, stdout);
                fputc('\n', stdout);
                break;
            case M_CLEAR:
            case M_SET:
                if (off == OFF_INVALID) {
                    fwrite(notelf, sizeof(notelf)-1, 1, stderr);
                    fwrite(path, strlen(path), 1, stderr);
                    fputc('\n', stderr);
                    errors++;
                    break;
                } else if (off == OFF_MISSING) {
                    fwrite(missing, sizeof(missing)-1, 1, stderr);
                    fwrite(path, strlen(path), 1, stderr);
                    fputc('\n', stderr);
                    errors++;
                    break;
                } else if (fseek(f, off, SEEK_SET)) {
                    fwrite(missing, sizeof(seekfail)-1, 1, stderr);
                    fwrite(path, strlen(path), 1, stderr);
                    fputc('\n', stderr);
                    errors++;
                    break;
                }
                if (mode == M_CLEAR) {
                    buf[off] &= ~1;
                } else {
                    buf[off] |=  1;
                }
                errors += (fputc(buf[off], f)==EOF || !!fflush(f));
                break;
            }
            fclose(f);

        } else {
            errors++;
            switch (mode) {
            case M_QUERY: fputc('?', stderr);
                          fputc(' ', stderr);
                          break;
            case M_SET:
            case M_CLEAR: fwrite(openfail, sizeof(openfail)-1, 1, stderr);
            }
            fwrite(path, strlen(path), 1, stderr);
            fputc('\n', stderr);
        }
    }

    fflush(stdout);
    return ferror(stdout) || errors;
}
