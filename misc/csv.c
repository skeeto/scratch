// CSV parser and in-memory index
//
// Parses a CSV file in memory, building an index over a chosen field
// allowing for exact-match searches against that field, returning the
// row index/offset/length. The library itself makes no allocations,
// which is left to the caller, and the index is just a single, large
// allocation.
//
// Example usage:
//
//    size_t len = ...;
//    const char *csv = mmap(..., len, ...);
//
//    // Build an index for the third (2) column
//    size_t size = csv_idx_size(csv, len);
//    struct csv_idx *idx = csv_idx(malloc(size), size, 2, csv, len);
//    if (!idx) {
//        die("oom");
//    }
//
//    // Search for matching rows
//    struct csv_idx_it it = csv_idx_it(idx, "foobar", 6);
//    struct csv_slice row;
//    while (csv_idx_it_next(&it, &row)) {
//        // consume row
//    }
//
//    free(idx);
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

struct csv_parser {
    const void *buf;
    size_t len;
    size_t off;

    // internal state
    size_t row_off;
    size_t nrows;
    size_t nfields;
    int state;
};

struct csv_slice {
    size_t idx;
    size_t off;
    size_t len;
};

// Initialize a new parser on the given buffer.
static struct csv_parser
csv_parser(const void *buf, size_t len)
{
    return (struct csv_parser){buf, len, 0, 0, 0, 0, 0};
}

// Parse and return the next token from the input CSV. The token offset
// and length are written into the output slice. The return indicates
// the kind of token parsed.
//
// * CSV_FIELD: Once per each field. The token contains the offset and
//   length of the encoded field value. Does not include the comma.
//
// * CSV_ROW: At the end of the row. The token contains the offset and
//   length of the entire row, including newline (if any).
//
// * CSV_EOF: When all input has been exhausted.
//
// Does no validation — so no errors — though it will never read out of
// bounds regardless. An improper CSV simply returns improperly-encoded
// fields.
//
// Note: An zero-length input is one row with one empty field. It's not
// possible to have zero rows.
static enum csv_tok { CSV_EOF, CSV_ROW, CSV_FIELD }
csv_parse(struct csv_parser *c, struct csv_slice *s)
{
    const unsigned char *restrict buf = c->buf;
    switch (c->state) {
    case 0:
        s->idx = c->nfields++;
        s->off = c->off;
        s->len = 0;
        for (int state = 1; c->off < c->len;) {
            int b = buf[c->off++];
            state ^= b == 0x22;
            switch (-state & b) {
            case 0x2c: return CSV_FIELD;
            case 0x0d: c->off += c->off < c->len && buf[c->off] == 0x0a;
                       // fallthrough
            case 0x0a: c->state = 1;
                       return CSV_FIELD;
            }
            s->len++;
        }
        c->state = 1;
        return CSV_FIELD;

    case 1:
        s->idx = c->nrows++;
        s->off = c->row_off;
        s->len = c->off - c->row_off;
        c->nfields = 0;
        c->row_off = c->off;
        c->state = c->off < c->len ? 0 : 2;
        return CSV_ROW;

    case 2:
        return CSV_EOF;
    }
    return -1;
}

// Hash an encoded CSV field as though it were decoded.
static unsigned long long
csv_field_hash(const void *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned long long h = 0x3243f6a8885a308d;

    if (!len || p[0] != 0x22) {
        // No encoding, hash normally
        for (size_t i = 0; i < len; i++) {
            h ^= p[i];
            h *= 1111111111111111111U;
        }
    } else {
        // Decode quotes during hashing
        int s = 1;
        for (size_t i = 1; i < len; i++) {
            s ^= p[i] == 0x22;
            if (s) {
                h ^= p[i];
                h *= 1111111111111111111U;
            }
        }
    }
    h &= 0xffffffffffffffffU;
    return h ^ h >> 32;
}

// Compare an encoded CSV field (f) with a non-encoded buffer (b).
static int
csv_field_equal(const void *f, size_t fn, const void *b, size_t bn)
{
    const unsigned char *fp = f;
    const unsigned char *bp = b;

    if (!fn || fp[0] != 0x22) {
        // No encoding, compare directly
        if (fn != bn) {
            return 0;
        }
        for (size_t i = 0; i < bn; i++) {
            if (fp[i] != bp[i]) {
                return 0;
            }
        }
        return 1;
    }

    // Decode the field and compare decoded bytes
    fp++;
    fn -= 2;
    for (int s = 1; bn && fn; fp++, fn--) {
        s ^= *fp == 0x22;
        if (s) {
            if (*bp++ != *fp) {
                return 0;
            }
            bn--;
        }
    }
    return 1;
}

struct csv_idx {
    size_t len;
    struct {
        const unsigned char *field;
        size_t len;
        struct csv_slice row;
    } slots[];
};

// Compute the allocation size for an index over the given CSV data.
// Returns zero if the index would be too large to allocate.
static size_t
csv_idx_size(const void *buf, size_t len)
{
    size_t nrows = 0;
    struct csv_slice s;
    struct csv_idx idx;
    for (struct csv_parser csv = csv_parser(buf, len);;) {
        switch (csv_parse(&csv, &s)) {
        case CSV_EOF:
            if (nrows > (size_t)-1/4) {
                return 0;  // overflow
            }
            nrows *= 4;

            // Round down to a power of 2
            while (nrows & (nrows - 1)) {
                nrows &= nrows - 1;
            }

            if (nrows > (size_t)-1/sizeof(*idx.slots)) {
                return 0;  // overflow
            }
            return sizeof(idx) + nrows*sizeof(*idx.slots);

        case CSV_ROW:
            nrows++;
            break;

        case CSV_FIELD:
            break;
        }
    }
}

// Build an index of field N (zero-indexed) over the given CSV data. The
// size must be computed with csv_idx_size(). If idx is NULL, returns
// NULL. Rows lacking the field (too field fields) are not present in
// the index.
static struct csv_idx *
csv_idx(struct csv_idx *idx, size_t size, size_t n, const void *buf, size_t len)
{
    if (!idx || !size) {
        return 0;
    }

    struct csv_slice s;
    const unsigned char *p = buf;

    idx->len = (size - sizeof(*idx)) / sizeof(*idx->slots);
    size_t mask = idx->len - 1;

    for (size_t i = 0; i < idx->len; i++) {
        idx->slots[i].field = 0;
    }

    size_t i = -1;
    for (struct csv_parser csv = csv_parser(buf, len);;) {
        switch (csv_parse(&csv, &s)) {
        case CSV_EOF:
            return idx;

        case CSV_ROW:
            if (i != (size_t)-1) {
                idx->slots[i].row = s;
                i = -1;
            }
            break;

        case CSV_FIELD:
            if (s.idx == n) {
                i = csv_field_hash(p+s.off, s.len) & mask;
                while (idx->slots[i].field) {
                    i = (i + 1) & mask;
                }
                idx->slots[i].field = p + s.off;
                idx->slots[i].len = s.len;
            }
            break;
        }
    }
}

struct csv_idx_it {
    struct csv_idx *idx;
    const void *buf;
    size_t len;
    size_t i;
};

// Initialize a results iterator for a new search. No resources are
// allocated, but the field pointer must remain valid for the entire
// iteration process. The value buffer should not be CSV-encoded.
static struct csv_idx_it
csv_idx_it(struct csv_idx *idx, const void *value, size_t len)
{
    size_t mask = idx->len - 1;
    const unsigned char *p = value;
    unsigned long long h = 0x3243f6a8885a308dU;

    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1111111111111111111U;
    }
    h &= 0xffffffffffffffffU;
    h ^= h >> 32;

    return (struct csv_idx_it){idx, value, len, h&mask};
}

// Find the next search result in the index. Returns 1 if there is
// another result. Otherwise it returns 0 and the iterator should not be
// used further.
static int
csv_idx_it_next(struct csv_idx_it *it, struct csv_slice *s)
{
    size_t mask = it->idx->len - 1;
    for (;;) {
        // Multiple matches are stored along the hash table itself, so
        // keep looking for the next result.
        size_t i = it->i;
        it->i = (it->i + 1) & mask;

        const unsigned char *field = it->idx->slots[i].field;
        if (!field) {
            return 0;
        }

        size_t len = it->idx->slots[i].len;
        if (csv_field_equal(field, len, it->buf, it->len)) {
            *s = it->idx->slots[i].row;
            return 1;
        }
    }
}


#ifdef TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
test_parser(void)
{
    static const char buf[] = "a,bc,def\r\n\"x \"\"y\"\" z\",\"1,2,3\"\r\n";
    static const struct {
        enum csv_tok tok;
        int idx;
        char *field;
        int len;
    } expect[] = {
        { CSV_FIELD, 0,   "a",  1 },
        { CSV_FIELD, 1,  "bc",  2 },
        { CSV_FIELD, 2, "def",  3 },
        { CSV_ROW,   0,     0, 10 },

        { CSV_FIELD, 0, "\"x \"\"y\"\" z\"", 11 },
        { CSV_FIELD, 1, "\"1,2,3\"",          7 },
        { CSV_ROW,   1,                   0, 21 },

        { CSV_EOF,   0, 0, 0 },
    };
    int nexpect = sizeof(expect)/sizeof(*expect);
    const char *names[] = {
        [CSV_EOF]   = "CSV_EOF",
        [CSV_ROW]   = "CSV_ROW",
        [CSV_FIELD] = "CSV_FIELD",
    };

    struct csv_parser csv = csv_parser(buf, sizeof(buf)-1);
    for (int i = 0; i < nexpect; i++) {
        struct csv_slice s;
        enum csv_tok tok = csv_parse(&csv, &s);
        if (tok != expect[i].tok) {
            printf("FAIL: got %s, want %s\n",
                   names[tok], names[expect[i].tok]);
            return 1;
        }

        switch (tok) {
        case CSV_EOF:
            return 0;
        case CSV_ROW:
            if ((int)s.len != expect[i].len) {
                printf("FAIL: (%s) got %d, want %d\n",
                       names[tok], (int)s.len, expect[i].len);
                return 1;
            }
            break;
        case CSV_FIELD:
            if ((int)s.len != expect[i].len ||
                    (memcmp(buf+s.off, expect[i].field, s.len))) {
                printf("FAIL: (%s) got %*s, want %s\n",
                        names[tok],
                        (int)s.len, buf+s.off,
                        expect[i].field);
                return 1;
            }
            break;
        }
    }
    return 0;
}

static int
test_idx(void)
{
    static const char xbuf[] =
        "abc,123,xyz\n"
        "abc,456,xyz,\n"
        "abc,789,xyz,\n"
        "bca,\"1\"\"3\",yzx\n"
        "bc,\"123\",yz\n"
        "c,123,z,\"\"\n"
        "abc,0,xyz\n";
    size_t z = csv_idx_size(xbuf, sizeof(xbuf)-1);
    struct csv_idx *idx = malloc(z);
    struct csv_idx_it it;
    struct csv_slice row;

    static const struct {
        int field;
        char *key;
        int len;
        int expect;
    } tests[] = {
        {0, "abc",  3, 4},
        {1, "123",  3, 3},
        {1, "1\"3", 3, 1},
        {3, "",     0, 3},
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    int nfails = 0;
    for (int i = 0; i < ntests; i++) {
        int nmatches = 0;
        csv_idx(idx, z, tests[i].field, xbuf, sizeof(xbuf)-1);
        it = csv_idx_it(idx, tests[i].key, tests[i].len);
        while (csv_idx_it_next(&it, &row)) {
            nmatches++;
        }
        if (nmatches != tests[i].expect) {
            printf("FAIL: \"%s\" %d: got %d matches, want %d matches\n",
                   tests[i].key, tests[i].field, nmatches, tests[i].expect);
            nfails++;
        }
    }

    free(idx);
    return !!nfails;
}

int
main(void)
{
    int nfails = 0;
    nfails += test_parser();
    nfails += test_idx();
    if (!nfails) {
        puts("All tests pass.");
    }
    return !!nfails;
}
#endif
