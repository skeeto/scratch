// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <string.h>

#define affirm(c)       while (!(c)) *(volatile i32 *)0 = 0
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define S(s)            (Str){(u8 *)s, sizeof(s)-1}
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

typedef unsigned char               u8;
typedef   signed int                b32;
typedef   signed int                i32;
typedef unsigned long long          u64;
typedef double                      f64;
typedef __typeof__((u8*)0-(u8*)0)   iz;
typedef __typeof__(sizeof(0))       uz;

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static u8 *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return memset(r, 0, (uz)(count*size));
}

#define push(a, s) \
  ((s)->len == (s)->cap \
    ? (s)->data = push_( \
        (a), \
        (s)->data, \
        &(s)->cap, \
        sizeof(*(s)->data), \
        _Alignof(__typeof__(*(s)->data)) \
      ), \
      (s)->data + (s)->len++ \
    : (s)->data + (s)->len++)

static void *push_(Arena *a, void *data, iz *pcap, iz size, iz align)
{
    iz cap   = *pcap;
    if (!data || a->beg != (u8 *)data + cap*size) {
        void *copy = alloc(a, cap, size, align);
        memcpy(copy, data, (uz)(cap*size));
        data = copy;
    }
    iz extend = cap ? cap : 4;
    alloc(a, extend, size, align);
    *pcap = cap + extend;
    return data;
}

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str span(u8 *beg, u8 *end)
{
    affirm(beg <= end);
    Str r  = {};
    r.data = beg;
    r.len  = end - beg;
    return r;
}

static b32 equals(Str a, Str b)
{
    return a.len==b.len && !memcmp(a.data, b.data, (uz)a.len);
}

static u64 hash(Str s, u64 seed)
{
    u64 r = ~seed;
    for (iz i = 0; i < s.len; i++) {
        r ^= s.data[i];
        r *= 1111111111111111111u;
    }
    return r;
}

typedef struct {
    Str head;
    Str tail;
    b32 ok;
} Cut;

static Cut cut(Str s, u8 c)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    u8 *cut = beg;
    for (; cut<end && *cut!=c; cut++) {}
    Cut r = {};
    r.ok   = cut < end;
    r.head = span(beg, cut);
    r.tail = span(cut+r.ok, end);
    return r;
}

typedef iz Token;

typedef struct Map Map;
struct Map {
    Map  *child[4];
    Token namespace;
    Str   key;
    Token token;
};

static Token *upsert(Map **m, Token namespace, Str key, Arena *a)
{
    for (u64 h = hash(key, (u64)namespace); *m; h <<= 2) {
        if (namespace==(*m)->namespace && equals(key, (*m)->key)) {
            return &(*m)->token;
        }
        m = &(*m)->child[h>>62];
    }
    *m = new(a, 1, Map);
    (*m)->namespace = namespace;
    (*m)->key = key;
    return &(*m)->token;
}

typedef struct {
    Map *map;
    Str *data;
    iz   len;
    iz   cap;
} StrTable;

static Token intern(StrTable *t, Token namespace, Str s, Arena *a)
{
    Token *token = upsert(&t->map, namespace, s, a);
    if (!*token) {
        *push(a, t) = s;
        *token = t->len;
    }
    return *token;
}

static Str getstr(StrTable t, Token token)
{
    return token ? t.data[token-1] : (Str){};
}

typedef struct {
    Token *data;
    iz     len;
    iz     cap;
} Tokens;

typedef struct {
    Str    name;
    iz     index;
    Tokens tokens;
} Field;

typedef struct {
    StrTable strtab;
    Field   *data;
    iz       len;
    iz       cap;
} Fields;

static Fields parseheader(Str header, Arena *a)
{
    Fields fields = {};

    for (Cut c = {.tail=header, .ok=1}; c.ok;) {
        c = cut(c.tail, ',');
        Field field = {};
        field.name  = c.head;
        field.index = fields.len;

        Token prev = 0;
        for (Cut f = {.tail=field.name, .ok=1}; f.ok;) {
            f = cut(f.tail, '.');
            prev = intern(&fields.strtab, prev, f.head, a);
            *push(a, &field.tokens) = prev;
        }

        *push(a, &fields) = field;
    }

    return fields;
}

static iz fieldcompare(Field a, Field b)
{
    iz len = a.tokens.len<b.tokens.len ? a.tokens.len : b.tokens.len;
    for (iz i = 0; i < len; i++) {
        Token d = a.tokens.data[i] - b.tokens.data[i];
        if (d) {
            return d;
        }
    }
    return a.tokens.len - b.tokens.len;
}

static void splitmerge(Field *dst, iz beg, iz end, Field *src)
{
    if (end-beg < 2) {
        return;
    }

    iz mid = beg + (end - beg)/2;
    splitmerge(src, beg, mid, dst);
    splitmerge(src, mid, end, dst);

    iz i = beg;
    iz j = mid;
    for (iz k = beg; k < end; k++) {
        if (i<mid && (j==end || fieldcompare(src[i], src[j])<1)) {
            dst[k] = src[i++];
        } else {
            dst[k] = src[j++];
        }
    }
}

static void sort(Fields fields, Arena scratch)
{
    Field *workspace = new(&scratch, fields.len, Field);
    for (iz i = 0; i < fields.len; i++) {
        workspace[i] = fields.data[i];
    }
    splitmerge(fields.data, 0, fields.len, workspace);
}

enum { OP_OPEN, OP_KEY, OP_READ, OP_COMMA, OP_CLOSE };

typedef struct {
    i32   op;
    union {
        iz    index;
        Token token;
    };
} Op;

typedef struct {
    Op *data;
    iz  len;
    iz  cap;
} Program;

static Program compile(Fields fields, Arena *a)
{
    Program r = {};

    sort(fields, *a);

    *push(a, &r) = (Op){OP_OPEN};
    Tokens stack = {};
    for (iz i = 0; i < fields.len; i++) {
        Tokens tokens = fields.data[i].tokens;
        for (; stack.len > tokens.len-1; stack.len--) {
            *push(a, &r) = (Op){OP_CLOSE};
        }

        while (stack.len) {
            if (stack.data[stack.len-1] == tokens.data[stack.len-1]) {
                break;
            }
            *push(a, &r) = (Op){OP_CLOSE};
            stack.len--;
        }

        if (i > 0) {
            *push(a, &r) = (Op){OP_COMMA};
        }

        while (stack.len < tokens.len-1) {
            Token token = tokens.data[stack.len];
            *push(a, &stack) = token;
            *push(a, &r) = (Op){OP_KEY, .token=token};
            *push(a, &r) = (Op){OP_OPEN};
        }

        *push(a, &r) = (Op){OP_KEY,  .token=tokens.data[tokens.len-1]};
        *push(a, &r) = (Op){OP_READ, .index=fields.data[i].index};
    }

    for (; stack.len; stack.len--) {
        *push(a, &r) = (Op){OP_CLOSE};
    }
    *push(a, &r) = (Op){OP_CLOSE};
    return r;
}

static void run(Program program, StrTable strtab, f64 *record)
{
    // TODO: replace stdio with custom buffered output
    for (iz i = 0; i < program.len; i++) {
        switch (program.data[i].op) {
        case OP_OPEN:
            printf("{");
            break;
        case OP_KEY:
            Str key = getstr(strtab, program.data[i].token);
            printf("\"%.*s\":", (int)key.len, key.data);
            break;
        case OP_READ:
            printf("%.17g", record[program.data[i].index]);
            break;
        case OP_COMMA:
            printf(",");
            break;
        case OP_CLOSE:
            printf("}");
            break;
        }
    }
    printf("\n");
}

// Test code

static Str import(u8 *s)
{
    Str r = {};
    for (r.data = s; r.data[r.len]; r.len++) {}
    return r;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, s.len, u8);
    memcpy(r.data, s.data, (uz)r.len);
    return r;
}

static Str concat(Arena *a, Str pre, Str suf)
{
    if (pre.data+pre.len != a->beg) {
        pre = clone(a, pre);
    }
    pre.len += clone(a, suf).len;
    return pre;
}

static i32 randint(u64 *s, i32 lo, i32 hi)
{
    *s = *s*0x3243f6a8885a308d + 1;
    return (i32)(((*s>>32)*(u64)(hi - lo))>>32) + lo;
}

static Str generate_field(Str dst, u64 *rng, Arena *a)
{
    static u8 words[64][8] = {
        "entry", "debtor", "better", "threw", "earl", "car", "tray", "grip",
        "plane", "hair", "feeder", "field", "maple", "thirty", "picked",
        "grey", "not", "lifted", "miner", "idea", "glance", "throw", "dumped",
        "pepper", "keep", "recipe", "extra", "hoop", "owe", "throat", "roe",
        "ounce", "mirage", "hereby", "coded", "rib", "atomic", "funded",
        "yacht", "affair", "coop", "length", "fatal", "hack", "jam", "wave",
        "hitch", "native", "long", "tattoo", "many", "enroll", "clergy",
        "tab", "ended", "fun", "bound", "windy", "incur", "forty", "pound",
        "upward", "cavity", "mad",
    };
    i32 len = randint(rng, 1, 7);
    for (i32 i = 0; i < len; i++) {
        if (i) {
            dst = concat(a, dst, S("."));;
        }
        dst = concat(a, dst, import(words[randint(rng, 0, lenof(words))]));
    }
    return dst;
}

static Str generate_header(u64 *rng, Arena *a)
{
    i32 len = randint(rng, 10, 100);
    Str r = {};
    for (i32 i = 0; i < len; i++) {
        if (i) {
            r = concat(a, r, S(","));
        }
        r = generate_field(r, rng, a);
    }
    return r;
}

int main()
{
    static u8 mem[1<<21];
    Arena a = {mem, mem+sizeof(mem)};

    // Visual test/debugging
    {
        Arena scratch = a;
        Str header = S(
            "timestamp,"
            "point.x,"
            "point.y,"
            "foo.bar.baz,"
            "point.z,"
            "foo.bar.bax,"
            "foo.bar.quux"
        );
        f64 record[] = {
            1758158348.649643,
            1.23,
            4.56,
            -100,
            7.89,
            -200,
            -300,
        };
        Fields fields = parseheader(header, &scratch);
        Program program = compile(fields, &scratch);
        run(program, fields.strtab, record);
    }

    // Benchmark
    u64 rng = 1;
    for (i32 i = 0; i < 10000; i++) {
        Arena scratch = a;
        Str header = generate_header(&rng, &scratch);
        Fields fields = parseheader(header, &scratch);
        Program program = compile(fields, &scratch);
        #if 0
        f64 *record = new(&scratch, fields.len, f64);
        run(program, fields.strtab, record);
        #else
        (void)program;
        #endif
    }

    return 0;
}
