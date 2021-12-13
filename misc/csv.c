// CSV parser and in-memory index
//
// Parses a CSV file in memory, building an index over a chosen field
// allowing for exact-match searches against that field, returning the
// row index/offset/length. The library itself makes no allocations,
// which is left to the caller, and the index is just a single, large
// allocation. While the index references the CSV buffer, it contains no
// pointers into that buffer, only offsets, so it can be serialized for
// later use with a different copy of the CSV buffer.
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
//    struct csv_it it = csv_it(idx, csv, len, "foobar", 6);
//    struct csv_slice row;
//    while (csv_it_next(&it, &row)) {
//        // consume row
//    }
//
//    free(idx);
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

struct csv_parser {
    const void *csv;
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
csv_parser(const void *csv, size_t len)
{
    return (struct csv_parser){csv, len, 0, 0, 0, 0, 0};
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
// Note: A zero-length input is one row with one empty field. It's not
// possible to have zero rows.
static enum csv_tok { CSV_EOF, CSV_ROW, CSV_FIELD }
csv_parse(struct csv_parser *c, struct csv_slice *s)
{
    const unsigned char *restrict csv = c->csv;
    switch (c->state) {
    case 0:
        s->idx = c->nfields++;
        s->off = c->off;
        s->len = 0;
        for (int state = 1; c->off < c->len;) {
            int b = csv[c->off++];
            state ^= b == 0x22;
            switch (-state & b) {
            case 0x2c: return CSV_FIELD;
            case 0x0d: c->off += c->off < c->len && csv[c->off] == 0x0a;
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

// Compute a simple string hash over the given buffer.
static unsigned long long
csv_hash(const void *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned long long h = 0x3243f6a8885a308d;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1111111111111111111U;
    }
    return h ^ h>>32;
}

// Hash an encoded CSV field as though it were decoded.
static unsigned long long
csv_field_hash(const void *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned long long h = 0x3243f6a8885a308d;

    if (!len || p[0] != 0x22) {
        // No encoding, hash normally
        return csv_hash(buf, len);
    }

    // Decode quotes during hashing
    int s = 1;
    for (size_t i = 1; i < len; i++) {
        s ^= p[i] == 0x22;
        if (s) {
            h ^= p[i];
            h *= 1111111111111111111U;
        }
    }
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
        size_t off, len;
        struct csv_slice row;
    } slots[];
};

// Compute the allocation size for an index over the given CSV data.
// Returns zero if the index would be too large to allocate.
static size_t
csv_idx_size(const void *csv, size_t len)
{
    size_t nrows = 0;
    struct csv_slice s;
    struct csv_idx idx;
    for (struct csv_parser c = csv_parser(csv, len);;) {
        switch (csv_parse(&c, &s)) {
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
// size must be computed with csv_idx_size(). If idx is NULL or size is
// zero, returns NULL. Rows lacking the field (too field fields) are not
// present in the index.
//
// The index retains no pointers into the original CSV buffer, only
// offsets, so the index can be used later with the CSV buffer located
// at a different address. The iterator will need to be provided with
// the CSV buffer.
static struct csv_idx *
csv_idx(struct csv_idx *idx, size_t size, size_t n, const void *csv, size_t len)
{
    if (!idx || !size) {
        return 0;
    }

    struct csv_slice s;
    const unsigned char *p = csv;

    idx->len = (size - sizeof(*idx)) / sizeof(*idx->slots);
    size_t mask = idx->len - 1;

    for (size_t i = 0; i < idx->len; i++) {
        idx->slots[i].off = -1;
    }

    size_t i = -1;
    for (struct csv_parser c = csv_parser(csv, len);;) {
        switch (csv_parse(&c, &s)) {
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
                unsigned long long h = csv_field_hash(p+s.off, s.len);
                i = h & mask;
                while (idx->slots[i].off != (size_t)-1) {
                    i = (i + 1) & mask;
                }
                idx->slots[i].off = s.off;
                idx->slots[i].len = s.len;
            }
            break;
        }
    }
}

struct csv_it {
    const struct csv_idx *idx;
    size_t i;
    const void *csv;
    size_t csvlen;
    const void *key;
    size_t keylen;
};

// Initialize a results iterator for a new search. No resources are
// allocated, but the CSV and key pointers must remain valid for the
// entire iteration process. The key buffer should not be CSV-encoded.
static struct csv_it
csv_it(const struct csv_idx *idx,
       const void *csv, size_t csvlen,
       const void *key, size_t keylen)
{
    unsigned long long h = csv_hash(key, keylen);
    size_t mask = idx->len - 1;
    size_t i = h & mask;
    return (struct csv_it){idx, i, csv, csvlen, key, keylen};
}

// Find the next search result in the index. Returns 1 if there is
// another result. Otherwise it returns 0 and the iterator must not be
// used further.
static int
csv_it_next(struct csv_it *it, struct csv_slice *s)
{
    size_t mask = it->idx->len - 1;
    for (;;) {
        // Multiple matches are stored along the hash table itself, so
        // keep looking for the next result.
        size_t i = it->i;
        it->i = (it->i + 1) & mask;

        if (it->idx->slots[i].off == (size_t)-1) {
            return 0;
        }

        const unsigned char *field = it->csv + it->idx->slots[i].off;
        size_t len = it->idx->slots[i].len;
        if (csv_field_equal(field, len, it->key, it->keylen)) {
            *s = it->idx->slots[i].row;
            return 1;
        }
    }
}


#ifdef TEST
// Test suite for parser and index
//   $ cc -DTEST -g -fsanitize=address,undefined -o test csv.c
//   $ ./test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
test_parser(void)
{
    static const char csv[] = "a,bc,def\r\n\"x \"\"y\"\" z\",\"1,2,3\"\r\n";
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

    struct csv_parser c = csv_parser(csv, sizeof(csv)-1);
    for (int i = 0; i < nexpect; i++) {
        struct csv_slice s;
        enum csv_tok tok = csv_parse(&c, &s);
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
                    (memcmp(csv+s.off, expect[i].field, s.len))) {
                printf("FAIL: (%s) got %*s, want %s\n",
                        names[tok],
                        (int)s.len, csv+s.off,
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
    static const char csv[] =
        "abc,123,xyz\n"
        "abc,456,xyz,\n"
        "abc,789,xyz,\n"
        "bca,\"1\"\"3\",yzx\n"
        "bc,\"123\",yz\n"
        "c,123,z,\"\"\n"
        "abc,0,xyz\n";
    size_t z = csv_idx_size(csv, sizeof(csv)-1);
    struct csv_idx *idx = malloc(z);
    struct csv_it it;
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
        csv_idx(idx, z, tests[i].field, csv, sizeof(csv)-1);
        it = csv_it(idx, csv, sizeof(csv)-1, tests[i].key, tests[i].len);
        while (csv_it_next(&it, &row)) {
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

#ifdef CMD
// Command line CSV indexer demonstration
//   $ cc -DCMD -O3 -o csvidx csv.c
//   $ ./csvidx <csv  >idx INT    # build index for field INT
//   $ ./csvidx <csv 3<idx KEY... # print rows matching keys
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

static void
usage(FILE *f)
{
    fprintf(f, "usage: csvidx <csv  >idx INT\n");
    fprintf(f, "       csvidx <csv 3<idx [KEY]...\n");
}

static const void *
map(int fd, size_t *len)
{
    struct stat st;
    if (fstat(fd, &st) == -1) {
        fprintf(stderr, "csvidx: fstat(%d): %s\n", fd, strerror(errno));
        return 0;
    }
    if (len) {
        *len = st.st_size;
    }

    const void *p = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "csvidx: mmap(%d): %s\n", fd, strerror(errno));
        return 0;
    }

    return p;
}

static int
build(size_t n)
{
    size_t len;
    const char *csv = map(0, &len);
    if (!csv) {
        return 1;
    }

    size_t z = csv_idx_size(csv, len);
    struct csv_idx *idx = csv_idx(malloc(z), z, n, csv, len);
    if (!idx) {
        fprintf(stderr, "csvidx: out of memory\n");
        return 1;
    }

    fwrite(idx, z, 1, stdout);
    fflush(stdout);
    free(idx);

    if (ferror(stdout)) {
        fprintf(stderr, "csvidx: write error\n");
        return 1;
    }

    return 0;
}

static int
query(char **argv)
{
    size_t csvlen;
    const char *csv = map(0, &csvlen);
    if (!csv) {
        return 1;
    }

    const struct csv_idx *idx = map(3, 0);
    if (!idx) {
        return 1;
    }

    for (int i = 1; argv[i]; i++) {
        char *key = argv[i];
        size_t keylen = strlen(argv[i]);
        struct csv_it it = csv_it(idx, csv, csvlen, key, keylen);
        struct csv_slice row;
        while (csv_it_next(&it, &row)) {
            if (!fwrite(csv+row.off, row.len, 1, stdout)) {
                fprintf(stderr, "csvidx: write error\n");
                return 1;
            }
        }
    }

    fflush(stdout);
    if (ferror(stdout)) {
        fprintf(stderr, "csvidx: write error\n");
        return 1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "-h")) {
        usage(stdout);
        return 0;
    }

    struct stat st;
    if (fstat(3, &st) == -1) {
        if (errno != EBADF) {
            fprintf(stderr, "csvidx: %s\n", strerror(errno));
            return 1;
        }

        if (argc != 2) {
            usage(stderr);
            return 1;
        }
        return build(strtoull(argv[1], 0, 10));
    } else {
        return query(argv);
    }
}
#endif
