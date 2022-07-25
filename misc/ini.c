// Single-function, zero-allocation, freestanding INI parser
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

struct ini_tok {
    enum {INI_ERR, INI_EOF, INI_SECTION, INI_KEY, INI_VALUE} type;
    int32_t beg, end;
};

// Parse the next INI token, indicating its type and position in the
// buffer. All returned tokens remain valid indefinitely, but the buffer
// contents are otherwise destroyed and cannot be parsed a second time.
// Structure is enforced, and a value always follows a key. Initialize
// the state to zero, but lineno may be left uninitialized.
//
// If the input is valid UTF-8, then all tokens are valid UTF-8.
//
// White space in section names, keys, and unquoted values are collapsed
// into a single space, like XML text content.
//
// Values may have quoted spans, which are passed through literally,
// including white space, and these may span multiple lines. Backslash
// is used for escapes, and escaped newlines are omitted. These six
// escape sequences are supported: \t \r \n \" \\ \uXXXX. Values are
// decoded in place in the input buffer.
//
// The parser state is undefined after INI_ERR or INI_EOF.
static struct ini_tok
ini_next(void *buf, int32_t len, int32_t *state, int32_t *lineno)
{
    // The state is the offset, and its sign bit tracks the parser's
    // current mode. There are 4 modes, but only the first two modes
    // persist between calls.
    //   0: beginning of line
    //   1: reading value
    //   2: reading section
    //   3: reading key
    int mode = *state < 0;
    int32_t off = *state < 0 ? -*state : *state;
    unsigned char *b = buf;
    struct ini_tok tok = {INI_ERR, off, off};
    static uint32_t hexc[] = {0, 0x3ff0000, 0x7e, 0x7e, 0, 0, 0, 0};
    static uint8_t hex[256] = {
        ['0']=0x0, ['1']=0x1, ['2']=0x2, ['3']=0x3, ['4']=0x4,
        ['5']=0x5, ['6']=0x6, ['7']=0x7, ['8']=0x8, ['9']=0x9,
        ['a']=0xa, ['b']=0xb, ['c']=0xc, ['d']=0xd, ['e']=0xe, ['f']=0xf,
        ['A']=0xa, ['B']=0xb, ['C']=0xc, ['D']=0xd, ['E']=0xe, ['F']=0xf
    };

    #if __GNUC__
    #  define INI_UNREACHABLE() __builtin_trap()
    #elif _MSC_VER
    #  define INI_UNREACHABLE() __debugbreak()
    #else
    #  define INI_UNREACHABLE() *(volatile int *)0 = 0
    #endif

    *lineno = !*state ? 1 : *lineno + !mode;

    restart:
    // Consume whitespace, except newline
    while (off < len) {
        unsigned char v = b[off];
        switch (v) {
        case '\t':
        case '\r':
        case ' ' :
            off++;
            continue;
        }
        break;
    }

    if (off == len) {
        *state = off;
        switch (mode) {
        case 0: tok.type = INI_EOF;   break;
        case 1: tok.type = INI_VALUE; break;
        case 2:
        case 3: tok.type = INI_ERR;
        }
        return tok;
    }

    unsigned char v = b[off++];
    switch (v) {
    case '\n':
        switch (mode) {
        case 0: *lineno += 1;
                goto restart; // empty line
        case 1: tok.type = INI_VALUE;
                *state = off;
                return tok;
        case 2:
        case 3: tok.type = INI_ERR;
                return tok;
        }
        INI_UNREACHABLE();

    case '[':
        switch (mode) {
        case 0: mode = 2; // begin parsing a section name
                goto restart;
        case 2: tok.type = INI_ERR; // invalid in section name
                return tok;
        }
        break;

    case ']':
        switch (mode) {
        case 0:
        case 2: // Consume the rest of the line, including newline
                while (off < len) {
                    v = b[off];
                    switch (v) {
                    default:
                        tok.type = INI_ERR; // garbage following section
                        return tok;
                    case '\t':
                    case '\r':
                    case ' ' :
                        off++;
                        continue;
                    case '\n':
                        off++;
                        break;
                    case ';':
                        // Consume the comment, including newline
                        off++;
                        while (off < len) {
                            v = b[off++];
                            if (v == '\n') {
                                break;
                            }
                        }
                    }
                    break;
                }
                tok.type = INI_SECTION;
                *state = off;
                return tok;
        case 3: tok.type = INI_ERR; // invalid at this position
                return tok;
        }
        break;

    case ';':
        switch (mode) {
        case 2:
        case 3: tok.type = INI_ERR; // prohibited inside section/key
                return tok;
        }
        // Consume the comment, but leave the newline
        while (off < len && b[off] != '\n') {
            off++;
        }
        goto restart;

    case '=':
        switch (mode) {
        case 0: tok.type = INI_ERR; // prohibited in keys
                return tok;
        case 3: tok.type = INI_KEY;
                *state = -off;
                return tok;
        }
        break;

    default:
        switch (mode) {
        case 0: mode = 3;
        }
    }

    if (tok.beg != tok.end) {
        b[tok.end++] = ' ';
    }

    switch (mode) {
    case 1: // value
        off--;
        while (off < len) {
            v = b[off];
            switch (v) {
            case '"' :
                // Process a quoted span
                off++;
                int escape = 0, done = 0;
                for (;;) {
                    if (off == len) {
                        tok.type = INI_ERR;
                        return tok;
                    }
                    v = b[off++];
                    switch (v) {
                    case '\n' :
                        *lineno += 1;
                        if (escape) {
                            escape = 0;
                            continue; // discard
                        }
                        break;
                    case 't' :
                        v = escape ? '\t' : v;
                        escape = 0;
                        break;
                    case 'n' :
                        v = escape ? '\n' : v;
                        escape = 0;
                        break;
                    case 'r' :
                        v = escape ? '\r' : v;
                        escape = 0;
                        break;
                    case 'u' : // process 16-bit Unicode rune
                        if (!escape) {
                            break;
                        }
                        escape = 0;

                        if (off > len-4) {
                            tok.type = INI_ERR; // unexpected EOF
                            return tok;
                        }

                        uint16_t u[] = {
                            b[off+0], b[off+1], b[off+2], b[off+3]
                        };
                        off += 4;
                        for (int i = 0; i < 4; i++) {
                            if (!(hexc[u[i]>>5] & ((uint32_t)1<<(u[i]&31)))) {
                                tok.type = INI_ERR; // invalid hex
                                return tok;
                            }
                        }

                        // Encode as UTF-8
                        // The input was 6 bytes, and this outputs at
                        // most 3 bytes, so it always fits.
                        uint16_t cp = hex[u[0]] << 12 | hex[u[1]] <<  8 |
                                      hex[u[2]] <<  4 | hex[u[3]] <<  0;
                        if (cp >= 0xd800 && cp <= 0xdfff) {
                            cp = 0xfffd;
                        }
                        if (cp < 0x80) {
                            b[tok.end++] = cp;
                        } else if (cp < 0x800) {
                            b[tok.end++] = 0xc0 | (cp >>  6     );
                            b[tok.end++] = 0x80 | (cp >>  0 & 63);
                        } else {
                            b[tok.end++] = 0xe0 | (cp >> 12     );
                            b[tok.end++] = 0x80 | (cp >>  6 & 63);
                            b[tok.end++] = 0x80 | (cp >>  0 & 63);
                        }
                        continue;
                    case '"' :
                        done = !escape;
                        escape = 0;
                        break;
                    case '\\':
                        if (!escape) {
                            escape = 1;
                            continue;
                        }
                        escape = 0;
                    }
                    if (done) {
                        break;
                    }
                    if (escape) {
                        // unhandled: pass through backslash
                        b[tok.end++] = '\\';
                    }
                    b[tok.end++] = v;
                    escape = 0;
                }
                continue;

            case '\t':
            case '\r':
            case '\n':
            case ' ' :
            case ';' :
                goto restart;
            }
            b[tok.end++] = v;
            off++;
        }
        goto restart;

    case 2: // section name
        b[tok.end++] = v;
        while (off < len) {
            v = b[off];
            switch (v) {
            case ']' :
            case '\t':
            case '\r':
            case '\n':
            case ' ' :
            case ';' : goto restart;
            }
            b[tok.end++] = v;
            off++;
        }
        goto restart;

    case 3: // key name
        b[tok.end++] = v;
        while (off < len) {
            v = b[off];
            switch (v) {
            case '=' :
            case '\t':
            case '\r':
            case '\n':
            case ' ' :
            case ';' : goto restart;
            }
            b[tok.end++] = v;
            off++;
        }
        goto restart;
    }
    INI_UNREACHABLE();
}


#if TEST
// Tidy up an INI file, stripping comments
//   $ cc -Os -DTEST -o initidy ini.c
// This also works as a good afl fuzz target.
#include <stdio.h>

int
main(void)
{
    int first = 1, special;
    int32_t len, lineno, state = 0;
    static unsigned char ini[1<<24];

    len = fread(ini, 1, sizeof(ini), stdin);
    for (;;) {
        struct ini_tok tok = ini_next(ini, len, &state, &lineno);
        switch (tok.type) {
        case INI_ERR:
            printf("<stdin>:%ld: invalid input\n", (long)lineno);
            return 1;
        case INI_EOF:
            fflush(stdout);
            return ferror(stdin) || ferror(stdout);
        case INI_SECTION:
            printf("%s[%.*s]\n", "\n"+first, tok.end-tok.beg, ini+tok.beg);
            first = 0;
            break;
        case INI_KEY:
            printf("%.*s = ", tok.end-tok.beg, ini+tok.beg);
            break;
        case INI_VALUE:
            special = 0;
            for (int32_t i = tok.beg; i < tok.end; i++) {
                special |= ini[i] < ' ';
                special |= ini[i] == '"';
                if (ini[i] == ' ') {
                    special |= i == tok.beg || ini[i-1] == ' ';
                    special |= i == tok.end-1;
                }
            }
            if (special) {
                putchar('"');
                for (int32_t i = tok.beg; i < tok.end; i++) {
                    switch (ini[i]) {
                    case  0: case  1: case  2: case  3: case  4: case  5:
                    case  6: case  7: case  8: case 11: case 12: case 14:
                    case 15: case 16: case 17: case 18: case 19: case 20:
                    case 21: case 22: case 23: case 24: case 25: case 26:
                    case 27: case 28: case 29: case 30: case 31:
                        printf("\\u%04x", ini[i]);
                        break;
                    case '\t':
                        printf("\\t");
                        break;
                    case '\n':
                        printf("\\n");
                        break;
                    case '\r':
                        printf("\\r");
                        break;
                    case '\"':
                        printf("\\\"");
                        break;
                    default:
                        putchar(ini[i]);
                    }
                }
                putchar('"');
                putchar('\n');
            } else {
                printf("%.*s\n", tok.end-tok.beg, ini+tok.beg);
            }
            break;
        }
    }
}
#endif
