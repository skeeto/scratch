// This is free and unencumbered software released into the public domain.
#include <string.h>
#include <stddef.h>

#define countof(a)  (size)(sizeof(a) / sizeof(*(a)))
#define s8(s)       (s8){(u8 *)s, countof(s)-1}

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef          float     f32;
typedef          ptrdiff_t size;
typedef          size_t    uptr;
typedef          char      byte;

typedef struct {
    u8  *data;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {0};
    s.data = beg;
    s.len = beg ? end-beg : 0;
    return s;
}

static s8 s8cstr(char *s)
{
    s8 r = {0};
    r.data = (u8 *)s;
    r.len = strlen(s);
    return r;
}

static b32 s8equals(s8 a, s8 b)
{
    return a.len==b.len && !memcmp(a.data, b.data, a.len);
}

static s8 s8take(s8 s, size len)
{
    s.len = len;
    return s;
}

static s8 s8drop(s8 s, size len)
{
    s.data += len;
    s.len  -= len;
    return s;
}

static u64 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 0x100000001b3;
    }
    return h;
}

static f32 s8tof32(s8 s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;

    f32 sign  = 1.0f;
    f32 value = 0.0f;
    f32 scale = 1.0f;
    f32 div   = 1.0f;

    if (beg<end) {
        switch (*beg) {
        case '+': beg++;
                  break;
        case '-': beg++;
                  sign =-1.0f;
        }
    }

    for (; beg < end; beg++) {
        switch (*beg) {
        case '.': scale = 10.0f;
                  break;
        default : value = value*10.0f + (*beg - '0');
                  div *= scale;
        }
    }
    return value / div * sign;
}

typedef struct {
    s8 head;
    s8 tail;
} cut;

static cut s8cut(s8 s, u8 c)
{
    size len = 0;
    for (; len<s.len && s.data[len]!=c; len++) {}
    cut r = {0};
    r.head = s8take(s, len);
    r.tail = s8drop(s, len<s.len ? len+1 : len);
    return r;
}

static i32 msi_scale(i32 len)
{
    i32 exp = 0;
    while ((double)len/(1<<exp) > 0.8) {
        exp++;
    }
    return exp;
}

typedef struct {
    size db_size;
    i32  num_words;
    i32  num_dims;
    i32  msi_exp;
} glove_specs;

void glove_examine(glove_specs *s, void *data, size len)
{
    // TODO: validate "wordlen   < 2^31"
    // TODO: validate "num_words < 2^31"
    // TODO: validate "num_dims  < 2^31"

    glove_specs r = {0};
    size wordlen = 0;

    cut line = {0};
    line.tail.data = data;
    line.tail.len = len;
    while ((line = s8cut(line.tail, '\n')).head.len) {
        cut token = s8cut(line.head, ' ');
        wordlen += token.head.len;
        if (!r.num_words++) {
            while ((token = s8cut(token.tail, ' ')).head.len) {
                r.num_dims++;
            }
        }
    }
    r.msi_exp = msi_scale(r.num_words);
    i32 num_slots = 1 << r.msi_exp;

    r.db_size += (size)4;                         // i32: num_words
    r.db_size += (size)4;                         // i32: num_dims
    r.db_size += (size)4;                         // i32: msi_exp
    r.db_size += (size)4*r.num_words;             // i32: string table offset
    r.db_size += (size)4*r.num_words*r.num_dims;  // f32: embeddings
    r.db_size += (size)4*num_slots;               // i32: hash table
    r.db_size += wordlen;                         // u8:  string table
    *s = r;
}

typedef struct {
    i32  num_words;
    i32  num_dims;
    i32  msi_exp;
    i32 *offsets;
    f32 *embeddings;
    i32 *slots;
    u8  *strtab;
} glove;

void glove_load_db(glove *g, void *db)
{
    glove r = {0};
    i32 *header  = db;
    r.num_words  = header[0];
    r.num_dims   = header[1];
    r.msi_exp    = header[2];
    r.offsets    = (i32 *)((byte *)db + 4 + 4 + 4);
    r.embeddings = (f32 *)(r.offsets + r.num_words);
    r.slots      = (i32 *)(r.embeddings + r.num_words*r.num_dims);
    r.strtab     = (u8  *)(r.slots + (1<<r.msi_exp));
    *g = r;
}

typedef struct {
    i32 mask;
    u32 step;
    i32 index;
} msi_params;

static msi_params msi_init(s8 key, i32 msi_exp)
{
    msi_params r = {0};
    u64 hash = s8hash(key);
    r.mask  = (1 << msi_exp) - 1;
    r.step  = (u32)(hash >> (64 - msi_exp)) | 1;
    r.index = (i32)hash;
    return r;
}

void glove_make_db(void *db, glove_specs *s, void *data, size len)
{
    memset(db, 0, s->db_size);

    i32 *header = db;
    i32 num_words = header[0] = s->num_words;
    i32 num_dims  = header[1] = s->num_dims;
    i32 msi_exp   = header[2] = s->msi_exp;
    i32 tablelen  = 0;

    glove g;
    glove_load_db(&g, db);

    cut line = {0};
    line.tail.data = data;
    line.tail.len = len;
    for (i32 i = 0; i < num_words; i++) {
        line = s8cut(line.tail, '\n');
        cut token = s8cut(line.head, ' ');
        s8 word = token.head;

        memcpy(g.strtab+tablelen, word.data, word.len);
        tablelen += (i32)word.len;
        g.offsets[i] = tablelen;

        msi_params p = msi_init(word, msi_exp);
        for (;;) {
            p.index = (p.index + p.step) & p.mask;
            if (!g.slots[p.index]) {
                g.slots[p.index] = i + 1;
                break;
            }
        }

        for (i32 d = 0; d < num_dims; d++) {
            token = s8cut(token.tail, ' ');
            g.embeddings[i*num_dims+d] = s8tof32(token.head);
        }
    }
}

f32 *glove_get_embedding(glove *g, char *word)
{
    s8 key = s8cstr(word);
    msi_params p = msi_init(key, g->msi_exp);
    for (;;) {
        p.index = (p.index + p.step) & p.mask;
        if (!g->slots[p.index]) {
            return 0;
        }
        i32 i = g->slots[p.index] - 1;
        s8 entry = {0};
        entry.data = i ? g->strtab + g->offsets[i-1]     : g->strtab;
        entry.len =  i ? g->offsets[i] - g->offsets[i-1] : g->offsets[i] ;
        if (s8equals(entry, key)) {
            return g->embeddings + i*g->num_dims;
        }
    }
}
