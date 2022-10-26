// HTML builder library
//
// Construct HTML documents using an "immediate mode" interface. Inputs
// are automatically entity-encoded as needed. No dynamic allocation,
// but stack discipline is left to the caller. Tags and attribute names
// are trusted inputs, most likely short string literals. Text nodes and
// attribute values are untrusted, but neither can contain null bytes.
//
// This is free and unencumbered software released into the public domain.

// Interface
#include <stddef.h>

struct html {
    int (*write)(struct html *, char *, size_t);
    int inside;
};
int htmlopen(struct html *, char *tag);
int htmlattr(struct html *, char *attr, char *value);
int htmltext(struct html *, char *text, ptrdiff_t len);
int htmlclose(struct html *, char *tag);

// HTML writer that appends to a buffer.
struct htmlbuf {
    struct html html;
    char *buf;
    size_t cap, len;
};
struct htmlbuf htmlbuf(char *, size_t);


// Implementation
#include <assert.h>
#include <string.h>

// Use the write "method" to append data to an HTML buffer. Returns
// false if the method failed. (internal)
static int htmlwrite(struct html *b, char *s, size_t len)
{
    return b->write(b, s, len);
}

// Returns true if tag is self-closing. (internal)
static int htmlclosing(char *tag)
{
    static const unsigned char t[] = {
        +26,  5, 31,  5, 36,  4, 40,  4, 44,  3, 47,  2, 49,  3, 52,  4,
        +56,  2, 58,  4, 62,  6, 68,  3, 71,  5,116,114, 97, 99,107,105,
        110,112,117,116,109,101,116, 97, 98, 97,115,101,105,109,103, 98,
        114,119, 98,114, 97,114,101, 97,104,114,108,105,110,107,115,111,
        117,114, 99,101, 99,111,108,101,109, 98,101,100
    };
    assert(strlen(tag));
    // Hash the first two bytes, then do a string comparison on the slot
    unsigned h = (tag[0]&255) | (unsigned)(tag[1]&255)<<8;
    h = (h*0xdfd48U)>>15 & 30;
    return h<26 && strlen(tag)==t[h+1] && !memcmp(tag, t+t[h], t[h+1]);
}

// Append data to the buffer, entity-encoding as needed. (internal)
static int htmlescape(struct html *b, char *s, size_t n, int quot)
{
    assert(!memchr(s, 0, n));
    for (size_t i = 0; i < n; i++) {
        int en;
        char *e;
        switch (s[i]) {
        default: continue;
        case '<': e = "&lt;";   en = 4; break;
        case '&': e = "&amp;";  en = 5; break;
        case '"': if (!quot) continue;
                  e = "&quot;"; en = 6; break;
        }
        if (!htmlwrite(b, s, i)) {
            return 0;
        }
        if (!htmlwrite(b, e, en)) {
            return 0;
        }
        s += i + 1;
        n -= i + 1;
        i = -1;
    }
    return htmlwrite(b, s, n);
}

int htmlopen(struct html *b, char *tag)
{
    if (b->inside) {
        return htmlwrite(b, "><", 2) &&
               htmlwrite(b, tag, strlen(tag));
    } else {
        b->inside = 1;
        return htmlwrite(b, "<", 1) &&
               htmlwrite(b, tag, strlen(tag));
    }
}

int htmlattr(struct html *b, char *attr, char *value)
{
    assert(b->inside);
    if (!htmlwrite(b, " ", 1) ||
        !htmlwrite(b, attr, strlen(attr)) ||
        !htmlwrite(b, "=\"", 2)) {
        return 0;
    }
    return htmlescape(b, value, strlen(value), 1) &&
           htmlwrite(b, "\"", 1);
}

int htmltext(struct html *b, char *text, ptrdiff_t len)
{
    size_t n = len<0 ? strlen(text) : (size_t)len;
    if (b->inside) {
        b->inside = 0;
        return htmlwrite(b, ">", 1) &&
               htmlescape(b, text, n, 0);

    } else {
        return htmlescape(b, text, n, 0);
    }
}

int htmlclose(struct html *b, char *tag)
{
    if (b->inside && htmlclosing(tag)) {
        b->inside = 0;
        return htmlwrite(b, "/>", 2);
    } else if (b->inside) {
        b->inside = 0;
        return htmlwrite(b, "></", 3) &&
               htmlwrite(b, tag, strlen(tag)) &&
               htmlwrite(b, ">", 1);
    } else {
        return htmlwrite(b, "</", 2) &&
               htmlwrite(b, tag, strlen(tag)) &&
               htmlwrite(b, ">", 1);
    }
}

static int htmlbufwrite(struct html *h, char *buf, size_t len)
{
    struct htmlbuf *b = (struct htmlbuf *)h;
    size_t r = b->cap - b->len;
    size_t n = r<len ? r : len;
    memcpy(b->buf+b->len, buf, n);
    b->len += n;
    return n == len;
}

struct htmlbuf htmlbuf(char *buf, size_t len)
{
    struct htmlbuf b = {{htmlbufwrite, 0}, buf, len, 0};
    return b;
}


// Test and demo
#include <stdio.h>

// HTML writer that writes to a stdio stream.
struct htmlfile {
    struct html html;
    FILE *f;
};

static int htmlfilewrite(struct html *h, char *buf, size_t len)
{
    struct htmlfile *f = (struct htmlfile *)h;
    return fwrite(buf, len, 1, f->f);
}

struct htmlfile htmlfile(FILE *stream)
{
    struct htmlfile f = {{htmlfilewrite, 0}, stream};
    return f;
}

int main(void)
{
    char buf[1<<10];
    struct htmlbuf b = htmlbuf(buf, sizeof(buf));
    htmlopen(&b.html, "div");
        htmlopen(&b.html, "p");
        htmlattr(&b.html, "lang", "en-US");
        htmlattr(&b.html, "class", "article");
            htmltext(&b.html, "Hello, ", -1);
            htmlopen(&b.html, "b");
                htmltext(&b.html, "world!", -1);
            htmlclose(&b.html, "b");
            htmltext(&b.html, "123<456 && 678>90", -1);
            htmlopen(&b.html, "img");
            htmlattr(&b.html, "src", "http://example.com/?a=1&b=2");
            htmlclose(&b.html, "img");
        htmlclose(&b.html, "p");
    htmlclose(&b.html, "div");
    htmltext(&b.html, "\n", 1);
    fwrite(b.buf, b.len, 1, stdout);

    struct htmlfile f = htmlfile(stdout);
    htmlopen(&f.html, "table");
        for (int r = 0; r < 20; r++) {
            htmlopen(&f.html, "tr");
            for (int i = 0; i < 4; i++) {
                htmlopen(&f.html, "td");
                char cell[32];
                int len = sprintf(cell, "cell-%d", r*4+i);
                htmltext(&f.html, cell, len);
                htmlclose(&f.html, "td");
            }
            htmlclose(&f.html, "tr");
        }
    htmlclose(&f.html, "table");

    fflush(stdout);
    return ferror(stdout);
}
