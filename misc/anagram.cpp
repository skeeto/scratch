// Accumulate words on standard input into anagram groups (of a least three)
// $ cc -std=c++23 -nostartfiles -o anagram.exe anagram.cpp
// $ ./anagram.exe <words
// This is free and unencumbered software released into the public domain.
using u8   = unsigned char;
using b8   = decltype(false);
using byte = decltype('0');
using i32  = decltype(0);
using u64  = decltype(0ull);
using iz   = decltype(0z);
using uz   = decltype(0uz);

#define assert(c)  while (!(c)) *(volatile i32 *)0 = 0

namespace platform {
static iz read(i32, u8 *, iz);
static b8 write(i32, u8 *, iz);
};

template<typename T>
void *operator new(uz, T *p) { return p; }

namespace anagram {

template<typename T> u64 hash(T);

struct Arena {
    byte *beg = {};
    byte *end = {};
    uz   *oom = {};
};

template<typename T>
T *alloc(iz count, Arena *a)
{
    iz size = sizeof(T);
    iz pad  = -(uz)a->beg & (alignof(T) - 1);
    if (count >= (a->end - a->beg - pad)/size) {
        __builtin_longjmp(a->oom, 1);
    }
    T *r = (T *)(a->beg + pad);
    a->beg += pad + count*size;
    for (iz i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

struct Str {
    u8 *data = {};
    iz  len  = {};

    Str() = default;

    template<iz N>
    Str(char const (&s)[N]) : data{(u8 *)s}, len{N-1} {}

    u8 &operator[](iz i) { return data[i]; }

    b8 operator==(Str s)
    {
        return len==s.len && (!len || !__builtin_memcmp(data, s.data, len));
    }
};

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = alloc<u8>(s.len, a);
    for (iz i = 0; i < r.len; i++) {
        r[i] = s[i];
    }
    return r;
}

template<>
inline u64 hash(Str s)
{
    u64 h = 0x100;
    for (iz i = 0; i < s.len; i++) {
        h ^= s[i];
        h *= 1111111111111111111;
    }
    return h;
}

static Str trunc(Str s, iz n)
{
    assert(n <= s.len);
    s.len = n;
    return s;
}

static Str substr(Str s, iz n)
{
    assert(n <= s.len);
    s.data += n;
    s.len  -= n;
    return s;
}

struct Cut {
    Str head;
    Str tail;
    b8  ok;
};

static Cut cut(Str s, u8 c)
{
    Cut r = {};
    iz  i = 0;
    for (; i < s.len && s[i] != c; i++) {}
    r.ok   = i < s.len;
    r.head = trunc(s, i);
    r.tail = substr(s, i+r.ok);
    return r;
}

static b8 whitespace(u8 c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static Str trimspace(Str s)
{
    while (s.len && whitespace(s[0])) {
        s.data++;
        s.len--;
    }
    while (s.len && whitespace(s[s.len-1])) {
        s.len--;
    }
    return s;
}

static Str sort(Str s)
{
    iz hist[256] = {};
    for (iz i = 0; i < s.len; i++) {
        hist[s.data[i]]++;
    }
    s.len = 0;
    for (i32 b = 0; b < 256; b++) {
        for (iz i = 0; i < hist[b]; i++) {
            s[s.len++] = (u8)b;
        }
    }
    return s;
}

template<typename T>
struct Slice {
    T *data = {};
    iz len  = {};
    iz cap  = {};

    T &operator[](iz i) { return data[i]; }
};

template<typename T>
Slice<T> clone(Arena *a, Slice<T> s)
{
    Slice<T> r = s;
    r.data = alloc<T>(s.cap, a);
    for (iz i = 0; i < r.len; i++) {
        r[i] = s[i];
    }
    return r;
}

template<typename T>
Slice<T> append(Arena *a, Slice<T> s, T v)
{
    if (s.len == s.cap) {
        if ((byte *)(s.data+s.len) != a->beg) {
            s = clone(a, s);
        }
        iz extend = s.cap ? s.cap : 4;
        alloc<T>(extend, a);
        s.cap += extend;
    }
    s[s.len++] = v;
    return s;
}

template<typename K, typename V>
struct Map {
    Map *child[4];
    Map *next;
    K    key;
    V    val;
};

template<typename K, typename V>
Map<K, V> *upsert(Map<K, V> **m, K key, Arena *a)
{
    for (u64 h = hash(key); *m; h <<= 2) {
        if ((*m)->key == key) {
            return *m;
        }
        m = &(*m)->child[h>>62];
    }
    *m = alloc<Map<K, V>>(1, a);
    (*m)->key = key;
    return *m;
}

static Str readall(Arena *a)
{
    Str r   = {};
    r.data  = (u8 *)a->beg;
    r.len   = platform::read(0, r.data, a->end - a->beg);
    a->beg += r.len;
    return r;
}

struct Bufout {
    u8 *buf = {};
    iz  len = {};
    iz  cap = {};
    b8  err = {};

    Bufout(Arena *a, iz cap = 1<<12)
        : buf(alloc<u8>(cap, a)), cap(cap) {}
};

static void flush(Bufout *b)
{
    if (b->len && !b->err) {
        b->err = !platform::write(1, b->buf, b->len);
        b->len = 0;
    }
}

static void write(Bufout *b, Str s)
{
    for (iz off = 0; !b->err && off<s.len;) {
        iz avail = b->cap - b->len;
        iz count = avail<s.len-off ? avail : s.len-off;
        __builtin_memcpy(b->buf+b->len, s.data+off, count);
        off += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static u8 main(byte *mem, iz cap)
{
    uz     oom[5] = {};
    Arena  arena  = {mem, mem+cap, oom};
    if (__builtin_setjmp(oom)) {
        Str oom = "anagram: out of memory\n";
        platform::write(2, oom.data, oom.len);
        return 123;  // oom
    }

    using Node  = Map<Str, Slice<Str>>;
    Node  *m    = 0;
    Node  *head = 0;
    Node **tail = &head;

    for (Str input = readall(&arena); input.len;) {
        Arena temp = arena;
        Cut   c    = cut(input, '\n');
        Str   line = trimspace(c.head);
        Str   key  = sort(clone(&temp, line));
        Node *e    = upsert(&m, key, &temp);

        if (!e->val.len) {
            arena = temp;
            *tail = e;
            tail = &e->next;
        }
        e->val = append(&arena, e->val, line);

        input = c.tail;
    }

    Bufout out(&arena);
    for (Node *e = head; e; e = e->next) {
        if (e->val.len > 2) {
            for (iz i = 0; i < e->val.len; i++) {
                if (i) write(&out, " ");
                write(&out, e->val[i]);
            }
            write(&out, "\n");
        }
    }
    flush(&out);

    return out.err;
}

} // anagram


#ifdef _WIN32
#define W32(r, p) extern "C" __declspec(dllimport) r __stdcall p noexcept
W32(void,   ExitProcess[[noreturn]](i32));
W32(uz,     GetStdHandle(i32));
W32(i32,    ReadFile(uz, u8 *, i32, i32 *, uz));
W32(byte *, VirtualAlloc(uz, iz, i32, i32));
W32(i32,    WriteFile(uz, u8 *, i32, i32 *, uz));

static iz platform::read(i32 fd, u8 *buf, iz len)
{
    uz h = GetStdHandle(-10 - fd);
    for (iz off = 0; off < len;) {
        iz  avail = len - off;
        i32 max   = 1<<21;
        i32 count = avail<max ? (i32)avail : max;
        if (!ReadFile(h, buf+off, count, &count, 0) || count==0) {
            return off;
        }
        off += count;
    }
    return len;
}

static bool platform::write(i32 fd, u8 *buf, iz len)
{
    uz h = GetStdHandle(-10 - fd);
    for (iz off = 0; off < len;) {
        iz  avail = len - off;
        i32 max   = 1<<21;
        i32 count = avail<max ? (i32)avail : max;
        if (!WriteFile(h, buf+off, count, &count, 0)) {
            return false;
        }
        off += count;
    }
    return true;
}

extern "C" void mainCRTStartup(void *)
{
    iz    cap = 1z<<26;
    byte *mem = VirtualAlloc(0, cap, 0x3000, 4);
    u8    ret = anagram::main(mem, cap);
    ExitProcess(ret);
}
#endif  // _WIN32
