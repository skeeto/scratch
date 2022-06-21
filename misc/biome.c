// "Grown biomes" terrain generator
//
// Reads a PPM (P6) on standard input and writes a PPM to standard output.
//
// Usage:
//   $ cc -O3 -o biome biome.c
//   $ base64 -d <<EOF | gunzip | ./biome >output.ppm
//   H4sIALwLsmICAwsw47JQsOAyMjXlYlj0ggz0/xMDEL
//   2VUQEiYsSVNvoA0WLPJUBEjDjxCAAaaLf9ywAAAA==
//   EOF
//
// Minimal Windows build (GCC):
//   $ gcc -Os -s -ffreestanding -fno-ident -fno-asynchronous-unwind-tables
//         -nostdlib -o biome.exe biome.c -lntdll -lkernel32
// Or with MSVC:
//   C:\>cl /Os /GS- biome.c
//
// The optional command line argument is a "program" comprising a series of
// "grow" (g) and "smooth" (s) operations, e.g. "gsggggsgsgs". Note: each
// growth doubles the input map size.
//
// Ref: http://cuberite.xoft.cz/docs/Generator.html#biome.grown
// Ref: https://old.reddit.com/r/proceduralgeneration/comments/vhaykb
#include <stdint.h>

// This program only uses these libc definitions:
// putchar, getchar, feof, ferror, fflush, stdin, stdout, EOF, time, clock

#if defined(_MSC_VER) || (_WIN32 && !__STDC_HOSTED__)
#  define stdin  -10
#  define stdout -11
#  define EOF    -1
#  define main   oldmain
char *GetCommandLineA(void);
void ExitProcess(int);
void *GetStdHandle(int);
char WriteFile(void *, void *, int, int *, void *);
char ReadFile(void *, void *, int, int *, void *);
int NtQuerySystemTime(int64_t *);
#  if defined(_MSC_VER)
#      pragma comment(lib, "ntdll")
#      pragma comment(lib, "kernel32")
#      pragma comment(linker, "/subsystem:console")
#  endif

static int err, olen, ibeg, iend;
static uint8_t obuf[1<<12], ibuf[1<<12];

static int
fflush(int fd)
{
    int len;
    if (err) return EOF;
    err |= !WriteFile(GetStdHandle(fd), obuf, olen, &len, 0);
    err |= len != olen;
    olen = 0;
    return err;
}

static int
ferror(int fd)
{
    (void)fd;
    return err;
}

static int
feof(int fd)
{
    (void)fd;
    return err;
}

static int
putchar(int c)
{
    if (err) return EOF;
    if (olen == (int)sizeof(obuf)) {
        fflush(stdout);
    }
    obuf[olen++] = c;
    return c;
}

static int
getchar(void)
{
    if (err) return EOF;
    if (ibeg == iend) {
        ibeg = 0;
        err |= !ReadFile(GetStdHandle(stdin), ibuf, sizeof(ibuf), &iend, 0);
        err |= !iend;
    }
    if (err) return EOF;
    return ibuf[ibeg++];
}

static int64_t
time(void *arg)
{
    int64_t t;
    (void)arg;
    NtQuerySystemTime(&t);
    return t / 1000000000;
}

static int64_t
clock(void)
{
    return time(0) % 1000000000;
}

void
mainCRTStartup(void)
{
    int argc = 1;
    char *p, *argv[3] = {"biome", 0, 0};

    p = GetCommandLineA();
    switch (p[0]) {
    case '"': for (p++; *p && *p != '"'; p++) {}
              if (*p) p++;
              break;
    default : for (p++; *p && *p != ' '; p++) {}
    }
    while (*p && *p == ' ') p++;
    if (*p) {
        argc = 2;
        argv[1] = p;
    }
    ExitProcess(oldmain(argc, argv));
}

#else  // plain C
#  include <stdio.h>
#  include <time.h>

#  if _WIN32
#  include <io.h>
#  include <fcntl.h>
   __attribute__((constructor))
   void init(void)
   {
       _setmode(0, _O_BINARY);
       _setmode(1, _O_BINARY);
   }
#  endif  // _WIN32
#endif  // plain C

// Attempt to generate a unique 64-bit seed.
static uint64_t
seed64(void)
{
    uint64_t m = 1111111111111111111, s = -m;
    s += (uint64_t)seed64; s *= m; s ^= s >> 32;  // ASLR (self)
    s += (uint64_t)time;   s *= m; s ^= s >> 32;  // ASLR (libc)
    s += (uint64_t)&s;     s *= m; s ^= s >> 32;  // random stack gap
    s += time(0);          s *= m; s ^= s >> 32;  // lo-res clock
    s += clock();          s *= m; s ^= s >> 32;  // hi-res clock
    return s;
}

// Input a byte into the NetPBM parser state machine, updating the width
// / height / depth array and returning the next state. The initial
// state is zero. A negative return is not a state, but an error:
// PGM_OVERFLOW, PGM_INVALID. The accept state is PGM_DONE, and no
// further input will be accepted. Fields may be left uninitialized on
// error. This parser supports arbitrary whitespace and comments.
static int
pgm_parse(int state, uint8_t c, int32_t *whd)
{
    #define PGM_MAX       (1<<12)
    #define PGM_OVERFLOW  -2
    #define PGM_INVALID   -1
    #define PGM_DONE      +5
    switch (state) {
    default: return PGM_INVALID;
    case  0: switch (c) {
             default : return PGM_INVALID;
             case 'P': return 1;
             }
    case  1: switch (c) {
             default : return PGM_INVALID;
             case '6': return 2;
             }
    case  2:
    case  3:
    case  4: switch (c) {  // between fields
             default : return 0;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 whd[state-2] = c - '0';
                 return state + 4;
             case ' ': case '\n': case '\r': case '\t':
                 return state;
             case '#':
                 return state + 7;
             }
    case  6:
    case  7:
    case  8: switch (c) {  // dimensions
             default : return PGM_INVALID;
             case ' ': case '\n': case '\r': case '\t':
                 return state - 3;  // possibly PGM_DONE
             case '#':
                 return state + 4;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 whd[state-6] = whd[state-6]*10 + c - '0';
                 if (whd[state-6] > PGM_MAX) return PGM_OVERFLOW;
                 return state;
             }
    case  9:
    case 10:
    case 11: switch (c) {  // comments
             default  : return state;
             case '\n': return state - 7;
             }
    }
}

// Return 0, 1, 2, or 3.
static int
rng4(uint64_t *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return *rng >> 62;
}

// Apply "grow" operation to source, storing result in destination.
// Returns 1 if the destination image size would exceed PGM_MAX.
static int
grow(uint32_t *d, uint32_t *s, int32_t *pw, int32_t *ph, uint64_t *rng)
{
    int32_t sw = *pw, sh = *ph;
    int32_t dw = sw*2 - 1, dh = sh*2 - 1;
    uint32_t options[4];

    if (dw > PGM_MAX || dh > PGM_MAX) {
        return 1;
    }
    *pw = dw;
    *ph = dh;

    for (int32_t dy = 0; dy < dw; dy++) {
        int32_t sy = dy/2;
        for (int32_t dx = 0; dx < dh; dx++) {
            int32_t sx = dx/2;
            uint32_t r;
            if (dx%2 && dy%2) {
                options[0] = s[(sy+0)*sw+(sx+0)];
                options[1] = s[(sy+0)*sw+(sx+1)];
                options[2] = s[(sy+1)*sw+(sx+0)];
                options[3] = s[(sy+1)*sw+(sx+1)];
                r = options[rng4(rng)];
            } else if (dx%2) {
                options[0] = s[(sy+0)*sw+(sx+0)];
                options[1] = s[(sy+0)*sw+(sx+1)];
                r = options[rng4(rng)>>1];
            } else if (dy%2) {
                options[0] = s[(sy+0)*sw+(sx+0)];
                options[1] = s[(sy+1)*sw+(sx+0)];
                r = options[rng4(rng)>>1];
            } else {
                r = s[sy*sw+sx];
            }
            d[dy*dw+dx] = r;
        }
    }

    return 0;
}

// Apply "smooth" operation to source, storing result in destination.
// Returns 1 if the source image is too small.
static int
smooth(uint32_t *d, uint32_t *s, int32_t *pw, int32_t *ph, uint64_t *rng)
{
    int32_t sw = *pw, sh = *ph;
    int32_t dw = sw - 2, dh = sh - 2;
    uint32_t n[4];

    if (dw < 1 || dh < 1) {
        return 1;
    }
    *pw = dw;
    *ph = dh;

    for (int32_t dy = 0; dy < dw; dy++) {
        int32_t sy = dy + 1;
        for (int32_t dx = 0; dx < dh; dx++) {
            int32_t sx = dx + 1;
            uint32_t r = s[sy*sw+sx];
            n[0] = s[(sy+0)*sw+(sx+1)];
            n[1] = s[(sy+1)*sw+(sx+0)];
            n[2] = s[(sy+0)*sw+(sx-1)];
            n[3] = s[(sy-1)*sw+(sx+0)];
            if (n[0]==n[2] && n[1] == n[3]) {
                r = n[rng4(rng)];
            } else if (n[0]==n[2]) {
                r = n[0];
            } else if (n[1]==n[2]) {
                r = n[1];
            }
            d[dy*dw+dx] = r;
        }
    }
    return 0;
}

// Write an integer to standard output in base 10.
static void
putint(int32_t v)
{
    char buf[32];
    char *p = buf + 32;
    do {
        *--p = v%10 + '0';
    } while (v /= 10);
    while (p < buf+32) {
        putchar(*p++);
    }
}

int
main(int argc, char **argv)
{
    char *program = "gsggggsgsgs";
    uint64_t rng = seed64();
    int32_t w, h, whd[3];
    static uint32_t image[2][PGM_MAX*PGM_MAX];

    if (argc > 1) {
        program = argv[1];
    }

    for (int state = 0;;) {
        int c = getchar();
        if (c == EOF) {
            return 1;
        }

        state = pgm_parse(state, c, whd);
        switch (state) {
        case PGM_OVERFLOW:
            return 1;
        case PGM_INVALID:
            return 1;
        case PGM_DONE:
            if (whd[2] != 255) {
                return 1;
            }
            w = whd[0];
            h = whd[1];

            for (int32_t y = 0; y < h; y++) {
                for (int32_t x = 0; x < w; x++) {
                    uint32_t r = getchar();
                    uint32_t g = getchar();
                    uint32_t b = getchar();
                    image[0][y*w+x] = r<<16 | g<<8 | b;
                }
            }
            if (feof(stdin) || ferror(stdin)) {
                return 1;
            }

            int src = 0;
            while (*program) {
                switch (*program++) {
                case 'g':
                    if (grow(image[!src], image[src], &w, &h, &rng)) {
                        return 1;
                    }
                    src = !src;
                    break;
                case 's':
                    if (smooth(image[!src], image[src], &w, &h, &rng)) {
                        return 1;
                    }
                    src = !src;
                }
            }

            putchar('P');
            putchar('6');
            putchar('\n');
            putint(w);
            putchar(' ');
            putint(h);
            putchar('\n');
            putchar('2');
            putchar('5');
            putchar('5');
            putchar('\n');
            for (int32_t y = 0; y < h; y++) {
                for (int32_t x = 0; x < w; x++) {
                    uint32_t p = image[src][y*w + x];
                    putchar(p >> 16);
                    putchar(p >>  8);
                    putchar(p >>  0);
                }
            }

            return fflush(stdout) || ferror(stdout);
        }
    }
}
