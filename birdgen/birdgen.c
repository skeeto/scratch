// This is free and unencumbered software released into the public domain.

typedef unsigned char    u8;
typedef __INT32_TYPE__   b32;
typedef __INT32_TYPE__   i32;
typedef __UINT32_TYPE__  u32;
typedef __UINT64_TYPE__  u64;
typedef __PTRDIFF_TYPE__ iz;
typedef __SIZE_TYPE__    uz;

#define affirm(c)       while (!(c)) __builtin_unreachable()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define s(s)            (Str){(u8 *)s, lenof(s)-1}
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static void *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, (uz)(count*size));
}

typedef struct {
    i32  len;
    i32 *offs;
    u8  *strings;
} Table;

static Table split(Arena *a, u8 *strings, i32 len)
{
    Table r = {};
    r.strings = strings;

    for (i32 i = 0; i < len; i++) {
        r.len += strings[i] == '\n';
    }
    r.offs = new(a, r.len+1, i32);

    r.len = 0;
    for (i32 i = 0; i < len; i++) {
        if (strings[i] == '\n') {
            r.offs[++r.len] = i + 1;
        }
    }
    return r;
}

typedef struct {
    Table qualifiers;
    Table species;
    Table prefixes;
    Table suffixes;
    Table colors;
    Table actual;
} Tables;

static Tables gentables(Arena *a)
{
    Tables r = {};

    static u8 qualifiers[] = {
        #embed "qualifiers.list"
    };
    r.qualifiers = split(a, qualifiers, lenof(qualifiers));

    static u8 species[] = {
        #embed "species.list"
    };
    r.species = split(a, species, lenof(species));

    static u8 prefixes[] = {
        #embed "prefixes.list"
    };
    r.prefixes = split(a, prefixes, lenof(prefixes));

    static u8 suffixes[] = {
        #embed "suffixes.list"
    };
    r.suffixes = split(a, suffixes, lenof(suffixes));

    static u8 colors[] = {
        #embed "colors.list"
    };
    r.colors = split(a, colors, lenof(colors));

    static u8 actual[] = {
        #embed "actual.list"
    };
    r.actual = split(a, actual, lenof(actual));

    return r;
}

static i32 randn(u64 *s, i32 n)
{
    *s = *s*0x3243f6a8885a308d + 1;
    return (i32)(((*s >> 32) * (u64)n) >> 32);
}

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, s.len, u8);
    affirm(r.len >= 0);
    __builtin_memcpy(r.data, s.data, (uz)r.len);
    return r;
}

static Str concat(Arena *a, Str head, Str tail)
{
    if (!head.data || a->beg != head.data+head.len) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static iz compare(Str a, Str b)
{
    iz len = a.len<b.len ? a.len : b.len;
    for (iz i = 0; i < len; i++) {
        iz r = a.data[i] - b.data[i];
        if (r) {
            return r;
        }
    }
    return a.len - b.len;
}

static Str get(i32 i, Table t)
{
    affirm(i >= 0 && i < t.len);
    Str r = {};
    r.data = t.strings + t.offs[i];
    r.len  = t.offs[i+1] - t.offs[i] - 1;
    return r;
}

static i32 find(Str key, Table t)
{
    i32 lo = 0;
    i32 hi = t.len - 1;
    while (lo <= hi) {
        i32 mid = lo + (hi - lo)/2;
        Str val = get(mid, t);
        iz  cmp = compare(key, val);
        if (!cmp) {
            return mid;
        } else if (cmp < 0) {
            hi = mid - 1;
        } else if (cmp > 0) {
            lo = mid + 1;
        }
    }
    return -1;
}

static Str choice(u64 *rng, Table t)
{
    i32 i = randn(rng, t.len);
    return get(i, t);
}

static Str generate(Arena *a, u64 *rng, Tables t)
{
    for (;;) {
        Arena x[1] = {*a};
        Str   r    = {};

        while (!r.len) {
            if (!randn(rng, 10)) {
                r = concat(x, r, choice(rng, t.qualifiers));
                r = concat(x, r, s(" "));
            }

            switch (randn(rng, 12)) {
            case 0 ... 5:
                r = concat(x, r, choice(rng, t.prefixes));
                r = concat(x, r, s("-"));
                r = concat(x, r, choice(rng, t.suffixes));
                r = concat(x, r, s(" "));
                break;
            case 6 ... 8:
                r = concat(x, r, choice(rng, t.colors));
                r = concat(x, r, s(" "));
                break;
            case 9:
                r = concat(x, r, choice(rng, t.colors));
                if (!randn(rng, 6)) {
                    r = concat(x, r, s("-"));
                } else {
                    r = concat(x, r, s("-and-"));
                }
                r = concat(x, r, choice(rng, t.colors));
                r = concat(x, r, s(" "));
                break;
            }
        }
        r = concat(x, r, choice(rng, t.species));

        if (find(r, t.actual) < 0) {
            *a = *x;  // commit
            return r;
        }
    }
}


#if _WIN32
// $ cc -std=gnu23 -nostartfiles -O -s -o birdgen.exe birdgen.c

#define W32  __attribute((dllimport, stdcall))
W32 void    ExitProcess(i32) __attribute((noreturn));
W32 uz      GetStdHandle(i32);
W32 b32     ReadFile(uz, u8 *, i32, i32 *, uz);
W32 b32     WriteFile(uz, u8 *, i32, i32 *, uz);

static void print(Str s)
{
    affirm(s.len < 0x7fffffff);
    uz h = GetStdHandle(-11);
    WriteFile(h, s.data, (i32)s.len, &(i32){}, 0);
}

i32 __stdcall mainCRTStartup()
{
    static u8 mem[1<<15];
    Arena a = {mem, mem+lenof(mem)};
    Tables t = gentables(&a);

    uz seed;
    asm volatile ("rdrand %0" : "=r"(seed));
    u64 rng = seed * 1111111111111111111u;

    Str real = choice(&rng, t.actual);
    affirm(find(real, t.actual) >= 0);

    Str names[4] = {};
    names[0] = real;
    for (i32 i = 1; i < 4; i++) {
        names[i] = generate(&a, &rng, t);
    }

    for (i32 i = 4; i > 0; i--) {
        i32 r = randn(&rng, i);
        print(names[r]);
        print(s("\n"));
        names[r] = names[i-1];
    }

    uz h = GetStdHandle(-10);
    ReadFile(h, (u8[1]){}, 1, &(i32){}, 0);
    print(real);
    print(s("\n"));

    ExitProcess(0);
    affirm(0);
}


#elif __wasm
// $ clang --target=wasm32 -std=gnu23 -Os -nostdlib -s -Wl,--no-entry
//       -o birdgen.wasm birdgen.c

typedef struct {
    Str names[4];
    i32 answer;
} Result;

static u64    rng;
static Arena  arena;
static Tables tables;

static void *sbrk(iz size)
{
    uz npages = ((uz)size + 0xffff) >> 16;
    uz old    = __builtin_wasm_memory_grow(0, npages);
    if (old == (uz)-1) {
        return 0;
    }
    return (void *)(old << 16);
}

__attribute((export_name("set_seed")))
void wasm_set_seed(u64 seed)
{
    seed += 1111111111111111111u;  seed ^= seed >> 33;
    seed *= 1111111111111111111u;  seed ^= seed >> 33;
    rng = seed;
}

__attribute((export_name("generate")))
Result *wasm_generate()
{
    if (!arena.beg) {  // initialized?
        iz cap = 1<<15;
        arena.beg = sbrk(cap);
        arena.end = arena.beg + cap;
        tables = gentables(&arena);
    }

    Str real = choice(&rng, tables.actual);

    Arena scratch = arena;
    Result *r = new(&scratch, 1, Result);
    r->answer = randn(&rng, 4);
    for (i32 i = 0; i < 4; i++) {
        if (i == r->answer) {
            r->names[i] = real;
        } else {
            r->names[i] = generate(&scratch, &rng, tables);
        }
    }
    return r;
}
#endif
