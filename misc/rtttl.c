// RTTTL parser and demo tone generator (-DDEMO)
// TODO: specific error values (invalid duration, invalid octave, etc.)
// Ref: https://old.reddit.com/r/C_Programming/comments/1653gpw
// Ref: https://github.com/eriknyquist/ptttl
// Ref: https://en.wikipedia.org/wiki/Ring_Tone_Text_Transfer_Language
// Ref: https://www.mobilefish.com/tutorials/rtttl/rtttl_quickguide_specification.html
// This is free and unencumbered software released into the public domain.

// Interface

typedef enum {
    rtttl_OK,
    rtttl_DONE,
    rtttl_ERROR
} rtttl_status;

typedef enum {
    rtttl_C, rtttl_CS, rtttl_D, rtttl_DS, rtttl_E, rtttl_F, rtttl_FS,
    rtttl_G, rtttl_GS, rtttl_A, rtttl_AS, rtttl_B, rtttl_P
} rtttl_pitch;

typedef struct {
    int         duration;
    rtttl_pitch pitch;
    int         octave;
    _Bool       dot;
} rtttl_note;

typedef struct {
    char *ptr;
    char *end;
    int   namelen;
    int   duration;
    int   octave;
    int   beat;
    _Bool comma;
} rtttl_parser;

// Initialize a parser, populating name length and the defaults.
static rtttl_status rtttl_init(rtttl_parser *, char *, int);

// Parse the next note (OK), end-of-input (DONE), or an error (ERROR).
static rtttl_status rtttl_next(rtttl_parser *, rtttl_note *);

// Implementation

static _Bool rtttl_space(char c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

static _Bool rtttl_digit(char c)
{
    return c>='0' && c<='9';
}

typedef enum {
    rtttl_EOF,
    rtttl_UNKNOWN,
    rtttl_COLON,
    rtttl_COMMA,
    rtttl_DOT,
    rtttl_EQUALS,
    rtttl_INTEGER,
    rtttl_LETTER,
    rtttl_SHARP
} rtttl_type;

typedef struct {
    char      *beg;
    char      *end;
    rtttl_type type;
} rtttl_token;

static _Bool rtttl_done(rtttl_parser *p)
{
    return p->ptr == p->end;
}

static rtttl_token rtttl_lex(rtttl_parser *p)
{
    rtttl_token tok = {0};
    for (;; p->ptr++) {
        if (rtttl_done(p)) {
            return tok;
        } else if (!rtttl_space(*p->ptr)) {
            break;
        }
    }

    tok.beg = p->ptr;
    tok.end = p->ptr + 1;
    switch (*p->ptr++) {
    case ':': tok.type = rtttl_COLON;
              return tok;
    case ',': tok.type = rtttl_COMMA;
              return tok;
    case '.': tok.type = rtttl_DOT;
              return tok;
    case '=': tok.type = rtttl_EQUALS;
              return tok;
    case '#': tok.type = rtttl_SHARP;
              return tok;
    case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
              tok.type = rtttl_INTEGER;
              for (; !rtttl_done(p) && rtttl_digit(*p->ptr); p->ptr++) {}
              tok.end = p->ptr;
              return tok;
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'o': case 'p':
              tok.type = rtttl_LETTER;
              return tok;
    }
    tok.type = rtttl_UNKNOWN;
    return tok;
}

static int rtttl_atoi(char *beg, char *end)
{
    int v = *beg++ - '0';
    while (beg < end) {
        v *= 10;
        v += *beg++ - '0';
        if (v > 900) {
            return -1;  // too large
        }
    }
    return v;
}

static _Bool rtttl_duration(int v)
{
    return v==1 || v==2 || v==4 || v==8 || v==16 || v==32;
}

static _Bool rtttl_octave(int v)
{
    return v==4 || v==5 || v==6 || v==7;
}

static _Bool rtttl_beat(int v)
{
    switch (v) {
    case  25:case  28:case  31:case  35:case  40:case  45:case  50:case  56:
    case  63:case  70:case  80:case  90:case 100:case 112:case 125:case 140:
    case 160:case 180:case 200:case 225:case 250:case 285:case 320:case 355:
    case 400:case 450:case 500:case 565:case 635:case 715:case 800:case 900:
        return 1;
    }
    return 0;
}

static rtttl_status rtttl_init(rtttl_parser *p, char *buf, int len)
{
    p->ptr      = buf;
    p->end      = buf + len;
    p->namelen  = 0;
    p->duration = 4;
    p->octave   = 6;
    p->beat     = 63;
    p->comma    = 0;

    for (;;) {
        if (rtttl_done(p)) {
            return rtttl_ERROR;
        } else if (*p->ptr++ == ':') {
            break;
        }
        p->namelen++;
    }

    for (int count = 0;; count++) {
        char which;
        rtttl_token tok = rtttl_lex(p);
        switch (tok.type) {
        case rtttl_COLON:
            return count ? rtttl_ERROR : rtttl_OK;

        case rtttl_LETTER:
            which = *tok.beg;
            tok = rtttl_lex(p);
            if (tok.type != rtttl_EQUALS) {
                return rtttl_ERROR;
            }

            tok = rtttl_lex(p);
            if (tok.type != rtttl_INTEGER) {
                return rtttl_ERROR;
            }

            int v = rtttl_atoi(tok.beg, tok.end);
            if (v < 0) {
                return rtttl_ERROR;
            }
            switch (which) {
            case 'd':
                if (!rtttl_duration(v)) return rtttl_ERROR;
                p->duration = v;
                break;
            case 'o':
                if (!rtttl_octave(v)) return rtttl_ERROR;
                p->octave = v;
                break;
            case 'b':
                if (!rtttl_beat(v)) return rtttl_ERROR;
                p->beat = v;
                break;
            default:
                return rtttl_ERROR;
            }

            tok = rtttl_lex(p);
            switch (tok.type) {
            case rtttl_COMMA:
                break;
            case rtttl_COLON:
                return rtttl_OK;
            default:
                return rtttl_ERROR;
            }
            break;

        default:
            return rtttl_ERROR;
        }
    }
}

static rtttl_status rtttl_next(rtttl_parser *p, rtttl_note *note)
{
    note->duration = p->duration;
    note->octave   = p->octave;
    note->dot      = 0;

    // 0 == empty
    // 1 == duration
    // 2 == pitch
    // 3 == sharp
    // 4 == octave
    // 5 == dot
    int state = 0;
    for (;;) {
        int v;
        rtttl_token tok = rtttl_lex(p);
        switch (tok.type) {
        case rtttl_UNKNOWN:
        case rtttl_COLON:
        case rtttl_EQUALS:
            return rtttl_ERROR;

        case rtttl_EOF:
            switch (state) {
            case  0: return p->comma ? rtttl_ERROR : rtttl_DONE;
            case  1: return rtttl_ERROR;
            }
            p->comma = 0;
            return rtttl_OK;

        case rtttl_COMMA:
            p->comma = 1;
            return state>=2 ? rtttl_OK : rtttl_ERROR;

        case rtttl_INTEGER:
            v = rtttl_atoi(tok.beg, tok.end);
            switch (state) {
            case 0:
                if (!rtttl_duration(v)) {
                    return rtttl_ERROR;
                }
                note->duration = v;
                state = 1;
                break;
            case 2:
            case 3:
                if (!rtttl_octave(v)) {
                    return rtttl_ERROR;
                }
                note->octave = v;
                state = 4;
                break;
            default:
                return rtttl_ERROR;
            }
            break;

        case rtttl_LETTER:
            if (state > 1) {
                return rtttl_ERROR;
            }
            state = 2;
            switch (*tok.beg) {
            case 'a': note->pitch = rtttl_A; break;
            case 'b':
            case 'h': note->pitch = rtttl_B; break;
            case 'c': note->pitch = rtttl_C; break;
            case 'd': note->pitch = rtttl_D; break;
            case 'e': note->pitch = rtttl_E; break;
            case 'f': note->pitch = rtttl_F; break;
            case 'g': note->pitch = rtttl_G; break;
            case 'p': note->pitch = rtttl_P;
                      state = 5;
            }
            break;

        case rtttl_SHARP:
            if (state != 2) {
                return rtttl_ERROR;
            }
            switch (note->pitch) {
            case rtttl_A: case rtttl_B: case rtttl_C:
            case rtttl_D: case rtttl_E: case rtttl_F: case rtttl_G:
                break;
            default:
                return rtttl_ERROR;
            }
            note->pitch++;
            state = 3;
            break;

        case rtttl_DOT:
            if (state<2 || state>4) {
                return rtttl_ERROR;
            }
            note->dot = 1;
            state = 5;
            break;
        }
    }
}


#ifdef DEMO
// Generates a .wav from RTTTL input
// $ cc -nostartfiles -fno-builtin -DDEMO -o rtttl rtttl.c
// $ ./rtttl <song.rtttl >song.wav

static int fullread(int fd, char *buf, int len);
static int fullwrite(int fd, char *buf, int len);

typedef struct {
    char *buf;
    int   len;
    int   cap;
    int   fd;
    int   err;
} bufout;

static void flush(bufout *o)
{
    if (!o->err && o->len) {
        o->err = !fullwrite(o->fd, o->buf, o->len);
    }
    o->len = 0;
}

static void put(bufout *o, char c)
{
    if (o->len == o->cap) {
        flush(o);
    }
    o->buf[o->len++] = c;
}

static void u32le(bufout *o, unsigned long x)
{
    put(o, (char)(x >>  0));
    put(o, (char)(x >>  8));
    put(o, (char)(x >> 16));
    put(o, (char)(x >> 24));
}

static void u16le(bufout *o, unsigned x)
{
    put(o, (char)(x >>  0));
    put(o, (char)(x >>  8));
}

// x is in turns (0..1), not radians (0..2*pi)
static float fast_sinf(float x)
{
    x  = x<0 ? 0.5f-x : x;
    x -= 0.500f + (float)(int)x;
    x *= 16.00f * ((x<0 ? -x : x) - 0.50f);
    x += 0.225f * ((x<0 ? -x : x) - 1.00f) * x;
    return x;
}

static const float freqs[] = {
    261.625565301f,  // rtttl_C
    277.182630977f,  // rtttl_CS
    293.664767918f,  // rtttl_D
    311.126983723f,  // rtttl_DS
    329.627556913f,  // rtttl_E
    349.228231433f,  // rtttl_F
    369.994422712f,  // rtttl_FS
    391.995435982f,  // rtttl_G
    415.304697580f,  // rtttl_GS
    440.000000000f,  // rtttl_A
    466.163761518f,  // rtttl_AS
    493.883301256f   // rtttl_B
};

int run(void)
{
    static char dst[1<<12];
    bufout stdout[1] = {0};
    stdout->fd  = 1;
    stdout->buf = dst;
    stdout->cap = sizeof(dst);

    static char src[1<<21];
    int len = fullread(0, src, sizeof(src));

    rtttl_parser p;
    if (rtttl_init(&p, src, len) != rtttl_OK) {
        return 1;
    }

    enum { HZ = 44100 };
    u32le(stdout, 0x46464952); // "RIFF"
    u32le(stdout, 0xffffffff); // file length
    u32le(stdout, 0x45564157); // "WAVE"
    u32le(stdout, 0x20746d66); // "fmt "
    u32le(stdout, 16        ); // struct size
    u16le(stdout, 1         ); // PCM
    u16le(stdout, 1         ); // mono
    u32le(stdout, HZ        ); // sample rate
    u32le(stdout, HZ*2      ); // byte rate
    u16le(stdout, 2         ); // block size
    u16le(stdout, 16        ); // bits per sample
    u32le(stdout, 0x61746164); // "data"
    u32le(stdout, 0xffffffff); // byte length
    for (int i = 0; i < HZ/5; i++) {
        u16le(stdout, 0);  // silence at the beginning
    }

    float samples_per_duration = 4 * 60 * HZ / (float)p.beat;
    for (;;) {
        rtttl_note note;
        switch (rtttl_next(&p, &note)) {
        case rtttl_OK:;
            float dotted = note.dot ? 1.5f : 1.0f;
            float duration = (float)note.duration;
            int nsamples = (int)(samples_per_duration / duration * dotted);

            if (note.pitch == rtttl_P) {
                while (nsamples--) {
                    u16le(stdout, 0);
                }
                break;
            }

            int scale = 1 << (note.octave - 4);
            float freq = freqs[note.pitch] * (float)scale;
            for (int i = 0; i < nsamples; i++) {
                float v = (float)i / HZ;
                float attack = v<0.05f ? v/0.05f : 1;
                float decay = (float)(nsamples - i - 1) / (float)nsamples;
                float sample = fast_sinf(freq * v) * attack * decay;
                u16le(stdout, (unsigned)(sample * 0x7ff8));
            }
            break;
        case rtttl_DONE:
            for (int i = 0; i < HZ/5; i++) {
                u16le(stdout, 0);  // silence at the end
            }
            flush(stdout);
            return stdout->err;
        case rtttl_ERROR:
            return 1;
        }
    }
}


#if _WIN32
#include <stddef.h>

#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(int);
W32(void *) GetStdHandle(int);
W32(int)    ReadFile(void *, char *, int, int *, void *);
W32(void *) VirtualAlloc(void *, size_t, int, int, int);
W32(int)    WriteFile(void *, char *, int, int *, void *);

static int fullread(int fd, char *buf, int len)
{
    void *h = GetStdHandle(-10 - fd);
    ReadFile(h, buf, len, &len, 0);
    return len;
}

static int fullwrite(int fd, char *buf, int len)
{
    void *h = GetStdHandle(-10 - fd);
    return WriteFile(h, buf, len, &len, 0);
}

void mainCRTStartup(void)
{
    ExitProcess(run());
}


#elif __linux
static int fullread(int fd, char *buf, int len)
{
    for (long off = 0; off < len;) {
        int r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(0), "D"(fd), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r <  0) return 0;
        if (r == 0) return off;
        off += r;
    }
    return len;
}

static int fullwrite(int fd, char *buf, int len)
{
    for (int off = 0; off < len;) {
        int r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(1), "D"(fd), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) return 0;
        off += r;
    }
    return 1;
}

__attribute((force_align_arg_pointer))
void _start(void)
{
    int r = run();
    asm volatile ("syscall" : : "a"(60), "D"(r));
}
#endif
#endif  // DEMO


#ifdef FUZZ
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    char *src = 0;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        src = realloc(src, len);
        memcpy(src, buf, len);
        rtttl_parser p;
        if (rtttl_init(&p, src, len) == rtttl_OK) {
            rtttl_note n;
            while (rtttl_next(&p, &n) == rtttl_OK) {}
        }
    }
}
#endif  // FUZZ
