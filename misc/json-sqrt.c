// Bespoke JSON parser example
//
// Demonstrates how to hand roll a simple, but robust, JSON parser for a
// simple schema. In this case a numeric array. It parses tokens from a
// byte buffer, rejecting input if it's not the expected token. Observe
// how no inputs are null-terminated.
//
// This is free and unencumbered software released into the public domain.
#include <stdlib.h>

#define TOK_INIT(buf, len) {buf, 0, len, 0, 0}
struct tok {
    char *buf, *tok;
    size_t buflen, toklen;
    enum tok_type {
        TOK_ERR=-1, TOK_EOF, TOK_BL, TOK_BR, TOK_COMMA, TOK_NUM
    } type;
};

// Advance to the next JSON token.
struct tok
tok_next(struct tok t)
{
    while (t.buflen) {
        int c = *t.buf++;
        t.buflen--;

        switch (c) {
        case '\t': case '\n': case '\r': case ' ':
            continue;
        case '[':
            t.tok = t.buf - 1;
            t.toklen = 1;
            t.type = TOK_BL;
            return t;
        case ']':
            t.tok = t.buf - 1;
            t.toklen = 1;
            t.type = TOK_BR;
            return t;
        case ',':
            t.tok = t.buf - 1;
            t.toklen = 1;
            t.type = TOK_COMMA;
            return t;
        case '+': case '-': case '0': case '1': case '2': case '3':
        case '4': case '5': case '6': case '7': case '8': case '9':
            t.tok = t.buf - 1;
            t.toklen = 1;
            t.type = TOK_NUM;
            while (t.buflen) {
                // Keep gathering number-ish bytes
                c = *t.buf;
                switch (c) {
                case '+': case '-': case '0': case '1': case '2':
                case '3': case '4': case '5': case '6': case '7':
                case '8': case '9': case '.': case 'E': case 'e':
                    t.buflen--;
                    t.buf++;
                    t.toklen++;
                    continue;
                }
                break;
            }
            return t;
        default:
            t.buf--;
            t.buflen++;
            t.tok = 0;
            t.toklen = 0;
            t.type = TOK_ERR;
            return t;
        }
    }

    t.tok = 0;
    t.toklen = 0;
    t.type = TOK_EOF;
    return t;
}

// Numeric array parser
struct parser {
    struct tok tok;
    double d;
    int state;
};

static const char parser_eof[] = "EOF";

// Try to parse the entire current token as a double.
static const char *
parsenum(struct parser *p)
{
    char *end, save = p->tok.tok[p->tok.toklen];
    p->tok.tok[p->tok.toklen] = 0;
    p->d = strtod(p->tok.tok, &end);
    p->tok.tok[p->tok.toklen] = save;
    if (end != p->tok.tok+p->tok.toklen) {
        return "invalid number";
    }
    return 0;
}

// Initialize a numeric array parser. Returns an error, if any. Input
// buffer must have one writable byte past the end for strtod().
const char *
parser_init(struct parser *p, char *buf, size_t len)
{
    p->tok = tok_next((struct tok)TOK_INIT(buf, len));
    if (p->tok.type != TOK_BL) {
        return "expected '['";
    }
    p->state = 0;
    return 0;
}

// Retrieve the next number from the input. Returns an error, if any.
const char *
parser_next(struct parser *p)
{
    for (;;) {
        p->tok = tok_next(p->tok);
        switch (p->state) {
        case 0: switch (p->tok.type) {
                default:        return "expected number or ']'";
                case TOK_BR:    return parser_eof;
                case TOK_NUM:   p->state = 1;
                                return parsenum(p);
                }
        case 1: switch (p->tok.type) {
                default:        return "expected ',' or ']'";
                case TOK_BR:    return parser_eof;
                case TOK_COMMA: p->state = 2;
                                continue;
                }
        case 2: switch (p->tok.type) {
                default:        return "expected number";
                case TOK_NUM:   p->state = 1;
                                return parsenum(p);
                }
        }
    }
}


// Usage example
//   $ cc -Os -o json-sqrt json-sqrt.c -lm
//   $ printf '[ 1.23, 4.56e7 ]\n' | ./json-sqrt

#include <math.h>
#include <stdio.h>

// Compute square root over each array element.
static const char *
sqrt_array(char *buf, size_t len)
{
    const char *err;
    struct parser p[1];

    err = parser_init(p, buf, len);
    if (err) {
        return err;
    }

    putchar('[');
    for (int first = 1;; first = 0) {
        err = parser_next(p);
        if (err) {
            if (err == parser_eof) {
                break;
            }
            return err;
        }
        printf("%s%.17g", first ? "" : ", ", sqrt(p->d));
    }
    puts("]");

    // Trailing garbage?
    p->tok = tok_next(p->tok);
    if (p->tok.type != TOK_EOF) {
        return "expected EOF";
    }

    fflush(stdout);
    return ferror(stdout) ? "write error" : 0;
}

int
main(void)
{
    char buf[1024];
    size_t len = fread(buf, 1, sizeof(buf)-1, stdin);
    const char *err = sqrt_array(buf, len);
    if (err) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    return 0;
}
