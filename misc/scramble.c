// Scramble String solvers
//   $ cc -fopenmp -O2 -fsanitize=undefined -fsanitize-trap scramble.c
// Ref: https://old.reddit.com/r/algorithms/comments/1m3ugb1
// Ref: https://leetcode.com/problems/scramble-string/description/
// Ref: https://oeis.org/A006318
// Ref: https://en.wikipedia.org/wiki/Schr%C3%B6der_number
// Ref: https://en.wikipedia.org/wiki/Separable_permutation
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define assert(c)       while (!(c)) unreachable()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define maxof(t)        ((t)-1<1 ? (((t)1<<(sizeof(t)*8-2))-1)*2+1 : (t)-1)
#define S(s)            (Str){(u8 *)s, lenof(s)-1}

typedef unsigned char   u8;
typedef int16_t         i16;
typedef int32_t         b32;
typedef int32_t         i32;
typedef uint32_t        u32;
typedef uint64_t        u64;
typedef ptrdiff_t       iz;
typedef size_t          uz;

// Slow solver: enumerate all permutations, then check
//
// The recursive generator is memoized with a hash trie, and results are
// MSI hash table sets for deduplication.

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static uz touz(iz n)
{
    assert(n >= 0);
    return (uz)n;
}

static u8 *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    assert(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return memset(r, 0, touz(count*size));
}

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str span(u8 *beg, u8 *end)
{
    assert(beg <= end);
    return (Str){beg, end-beg};
}

static b32 equals(Str a, Str b)
{
    return a.len==b.len && !memcmp(a.data, b.data, touz(a.len));
}

static u64 hash64(Str s)
{
    u64 r = 0x100;
    for (iz i = 0; i < s.len; i++) {
        r ^= s.data[i];
        r *= 1111111111111111111;
    }
    return r;
}

static Str takehead(Str s, iz i)
{
    assert(i>=0 && i<=s.len);
    s.len = i;
    return s;
}

static Str drophead(Str s, iz i)
{
    assert(i>=0 && i<=s.len);
    s.data += i;
    s.len  -= i;
    return s;
}

typedef struct {
    u8 *data;
    iz  len;
    iz  cap;
} Buf;

static Buf append(Arena *a, Buf b, Str s)
{
    if (b.cap-b.len < s.len) {
        b.cap = b.cap ? b.cap : 4;
        do {
            b.cap *= 2;
        } while (b.cap-b.len < s.len);
        u8 *data = new(a, b.cap, u8);
        b.data = memcpy(data, b.data, touz(b.len));
    }
    memcpy(b.data+b.len, s.data, touz(s.len));
    b.len += s.len;
    return b;
}

static Str concat(Arena *a, Buf *b, Str pre, Str suf)
{
    iz off = b->len;
    *b = append(a, *b, pre);
    *b = append(a, *b, suf);
    return span(b->data+off, b->data+b->len);
}

typedef struct {
    Buf buf;
    iz *slots;
    iz  len;
    i16 keylen;
    i16 exp;
} Set;

static Str get(Set s, iz i)
{
    assert(i>=0 && i<s.len);
    u8 *data = s.buf.data + i*s.keylen;
    return (Str){data, s.keylen};
}

static i16 trunc16(iz n)
{
    assert(n>=0 && n<=maxof(i16));
    return (i16)n;
}

static b32 insert(Set *s, Str pre, Str suf, Arena *a)
{
    if (!s->exp) {
        s->exp    = 4;
        s->slots  = new(a, (iz)1<<s->exp, iz);
        s->keylen = trunc16(pre.len+suf.len);
    }

    iz cap = (iz)1 << s->exp;
    if (s->len > cap - cap/4) {
        iz *slots = new(a, (iz)1<<++s->exp, iz);
        for (iz k = 0; k < s->len; k++) {
            Str key  = get(*s, k);
            u64 hash = hash64(key);
            uz  mask = ((uz)1<<s->exp) - 1;
            uz  step = (uz)(hash>>(64 - s->exp)) | 1;
            for (uz i = (uz)hash;;) {
                i = (i + step) & mask;
                if (!slots[i]) {
                    slots[i] = k + 1;
                    break;
                }
            }
        }
        s->slots = slots;
    }

    iz  save = s->buf.len;
    Str key  = concat(a, &s->buf, pre, suf);
    u64 hash = hash64(key);
    uz  mask = ((uz)1<<s->exp) - 1;
    uz  step = (uz)(hash>>(64 - s->exp)) | 1;
    for (uz i = (uz)hash;;) {
        i = (i + step) & mask;
        if (!s->slots[i]) {
            s->slots[i] = ++s->len;
            return true;
        } else if (equals(key, get(*s, s->slots[i]-1))) {
            s->buf.len = save;
            return false;
        }
    }
}

typedef struct Cache Cache;
struct Cache {
    Cache *child[2];
    Str    key;
    Set    values;
};

static Set *upsert(Cache **m, Str key, Arena *a)
{
    for (u64 h = hash64(key); *m; h <<= 1) {
        if (equals(key, (*m)->key)) {
            return &(*m)->values;
        }
        m = &(*m)->child[h>>63];
    }
    if (!a) return 0;
    *m = new(a, 1, Cache);
    (*m)->key = key;
    return &(*m)->values;
}

static Set generate(Str s, Cache **m, Arena *a)
{
    Set *r = upsert(m, s, a);
    if (!r->len) {
        insert(r, s, S(""), a);
        for (iz n = 1; n < s.len; n++) {
            Set xs = generate(takehead(s, n), m, a);
            Set ys = generate(drophead(s, n), m, a);
            for (iz xi = 0; xi < xs.len; xi++) {
                Str x = get(xs, xi);
                for (iz yi = 0; yi < ys.len; yi++) {
                    Str y = get(ys, yi);
                    insert(r, x, y, a);
                    insert(r, y, x, a);
                }
            }
        }
    }
    return *r;
}

static b32 solve_brute(Str s1, Str s2, Arena scratch)
{
    Set r = generate(s1, &(Cache *){}, &scratch);
    return !insert(&r, s2, S(""), &scratch);
}


// Fast solver: search down the tree, pruning bad paths
//
// Each symbol is assigned a prime. A set of non-unique symbols is a
// product of its symbols. To remove a symbol from a set, multiply by
// its modular multiplicative inverse (rprimes). Set equality is the
// same as numeric equality. Overflow is fine, and should only be a
// problem for huge strings.

static u32 primes[256] = {
    0xffffead1, 0xffffeae5, 0xffffeae9, 0xffffeb01, 0xffffeb07, 0xffffeb15,
    0xffffeb27, 0xffffeb2b, 0xffffeb63, 0xffffeb7f, 0xffffeb9f, 0xffffebd9,
    0xffffebe7, 0xffffec23, 0xffffec2f, 0xffffec39, 0xffffec5f, 0xffffec65,
    0xffffec7b, 0xffffec89, 0xffffeca5, 0xffffecad, 0xffffecbf, 0xffffecc9,
    0xffffecd5, 0xffffecd7, 0xffffece1, 0xffffece9, 0xffffed11, 0xffffed29,
    0xffffed43, 0xffffed65, 0xffffed6d, 0xffffed9d, 0xffffedbb, 0xffffedc5,
    0xffffedd1, 0xffffeddd, 0xffffee01, 0xffffee03, 0xffffee0f, 0xffffee1f,
    0xffffee2b, 0xffffee3f, 0xffffee45, 0xffffee5b, 0xffffee79, 0xffffee81,
    0xffffee8b, 0xffffeea5, 0xffffeec7, 0xffffeed3, 0xffffeedf, 0xffffeef1,
    0xffffef09, 0xffffef5f, 0xffffef6b, 0xffffef95, 0xffffef99, 0xffffefa7,
    0xffffefad, 0xffffefe3, 0xfffff025, 0xfffff05b, 0xfffff071, 0xfffff085,
    0xfffff095, 0xfffff0a9, 0xfffff0e3, 0xfffff0e5, 0xfffff103, 0xfffff12b,
    0xfffff143, 0xfffff151, 0xfffff161, 0xfffff173, 0xfffff17f, 0xfffff1a3,
    0xfffff1b5, 0xfffff1b7, 0xfffff1bb, 0xfffff1d3, 0xfffff1e1, 0xfffff20b,
    0xfffff223, 0xfffff245, 0xfffff24b, 0xfffff287, 0xfffff28d, 0xfffff2b3,
    0xfffff2bd, 0xfffff2d1, 0xfffff2e7, 0xfffff2f5, 0xfffff313, 0xfffff319,
    0xfffff331, 0xfffff33b, 0xfffff33d, 0xfffff347, 0xfffff371, 0xfffff39b,
    0xfffff3a3, 0xfffff3bf, 0xfffff3cd, 0xfffff3eb, 0xfffff3ef, 0xfffff3f1,
    0xfffff3f5, 0xfffff3fd, 0xfffff40f, 0xfffff419, 0xfffff421, 0xfffff427,
    0xfffff439, 0xfffff43f, 0xfffff455, 0xfffff467, 0xfffff475, 0xfffff49d,
    0xfffff4c3, 0xfffff4d5, 0xfffff4d9, 0xfffff4ed, 0xfffff509, 0xfffff50b,
    0xfffff529, 0xfffff539, 0xfffff53f, 0xfffff551, 0xfffff563, 0xfffff577,
    0xfffff58d, 0xfffff599, 0xfffff5cb, 0xfffff5d1, 0xfffff60d, 0xfffff623,
    0xfffff635, 0xfffff649, 0xfffff65b, 0xfffff661, 0xfffff68f, 0xfffff697,
    0xfffff69d, 0xfffff6a1, 0xfffff6a3, 0xfffff6a7, 0xfffff6bb, 0xfffff6c1,
    0xfffff6cb, 0xfffff6df, 0xfffff6e9, 0xfffff6f1, 0xfffff6f5, 0xfffff71b,
    0xfffff78b, 0xfffff791, 0xfffff79f, 0xfffff7a9, 0xfffff7c9, 0xfffff7d3,
    0xfffff7ed, 0xfffff803, 0xfffff80f, 0xfffff83b, 0xfffff841, 0xfffff853,
    0xfffff863, 0xfffff871, 0xfffff887, 0xfffff8a5, 0xfffff8d1, 0xfffff8d5,
    0xfffff8ef, 0xfffff919, 0xfffff94d, 0xfffff961, 0xfffff96d, 0xfffff971,
    0xfffff989, 0xfffff99b, 0xfffff9a7, 0xfffff9a9, 0xfffff9af, 0xfffff9b3,
    0xfffff9bb, 0xfffff9d9, 0xfffff9e5, 0xfffff9e9, 0xfffff9fd, 0xfffffa07,
    0xfffffa21, 0xfffffa3d, 0xfffffa4f, 0xfffffa51, 0xfffffa57, 0xfffffa7f,
    0xfffffa97, 0xfffffab1, 0xfffffabd, 0xfffffacf, 0xfffffad3, 0xfffffad9,
    0xfffffaf1, 0xfffffaf7, 0xfffffb1b, 0xfffffb39, 0xfffffb47, 0xfffffb53,
    0xfffffb69, 0xfffffb71, 0xfffffb89, 0xfffffb93, 0xfffffba1, 0xfffffbab,
    0xfffffbc9, 0xfffffbd7, 0xfffffbdd, 0xfffffbe3, 0xfffffc19, 0xfffffc41,
    0xfffffc5f, 0xfffffc65, 0xfffffc9b, 0xfffffca9, 0xfffffcaf, 0xfffffccd,
    0xfffffd19, 0xfffffd37, 0xfffffd3f, 0xfffffd5b, 0xfffffd6f, 0xfffffd7b,
    0xfffffd81, 0xfffffd85, 0xfffffd8b, 0xfffffdf1, 0xfffffe1d, 0xfffffe2d,
    0xfffffe5d, 0xfffffe7d, 0xfffffe8f, 0xfffffe9f, 0xfffffec5, 0xfffffed5,
    0xfffffef5, 0xffffff2f, 0xffffff47, 0xffffff67, 0xffffff79, 0xffffff95,
    0xffffff9d, 0xffffffbf, 0xffffffef, 0xfffffffb,
};

static u64 rprimes[256] = {
  0x6ff6db11ce4aae31,0x2c83f0c784aac2ed,0xd0acd96ded5d8d59,0x521252d42eb91501,
  0x6adfe3f1719392b7,0xf9a739833d000c3d,0xf8d3bc4f7630d497,0x6fac754b63a77b83,
  0xb0ca8ae33f10ee4b,0xff268d86957bd47f,0x1148456831ce705f,0x71fa573aebf3e469,
  0x6e6c15e43a43f7d7,0xe1576a150556238b,0x12acca191210dacf,0x510be0c3e1ea4209,
  0x3798fab951d16f9f,0x5929bb4a152ae56d,0xe54a9a5ca93712b3,0x406fcabd400349b9,
  0x28b420c2d6761b2d,0xee92d4b43f645725,0xc3855e8d8ae1833f,0x7adc8b78c3bbed79,
  0x597245e78161ec7d,0x766c49ff00d5c6e7,0x7d69867a04c25721,0xc96f6e255e2fab59,
  0xecb602e2ca20a3f1,0x00372ac80f56ff19,0x62e3d3de0719076b,0x052b5b812daf7c6d,
  0x05d1f3d71ab42465,0x120ef784093100b5,0x8807e962388acf73,0xde4f9ce1d561090d,
  0x1ca905f825738b31,0x864f6c8df27dd275,0x754a9625c9441201,0x23da9221f2b6acab,
  0xdf887acd7fa340ef,0x90541f8c70080ddf,0x17994d12d0ab6083,0x2aa6817e362101bf,
  0x95f8e7851430f48d,0xfffae21ba5b791d3,0x534a4e1cdb5f1bc9,0xf4a04c0900925181,
  0xb8051da5714e8923,0x946d5116053e492d,0x02e9e6982e6472f7,0xac18965ce24e995b,
  0x245e665bf4f74d1f,0x74b4d682d8d74211,0x2c8ed6eeeb404f39,0x4ff0e59c54da2c9f,
  0xf99383a27b15c543,0x20a92baa396fe3bd,0x4dceef3b3d35f4a9,0x3a845dd29de1c817,
  0x6c49bbf5b7a74c25,0x0e50a5a0a97ccdcb,0x39fc6f6c657aabad,0x622952c2b07bbfd3,
  0xcc3e582bbdfdd091,0xff93216e6aa6884d,0xfc9e7133dedb5abd,0x954522fcc78bb399,
  0x3d37ec783630d4cb,0xb05f0c882bc24ced,0xb2e24a4229b301ab,0xc4991621f2954583,
  0x25e01f5b382e236b,0x21a3e686f5a5f7b1,0x8981103d760c72a1,0x97e9d195753e9bbb,
  0xda5819c5d7cdce7f,0x43001e4558b2ca0b,0x3e4e95518d30349d,0x7e9f499fd172bc07,
  0xeb21e2703a842b73,0x85d4c7f529568e5b,0x8ed857d121001221,0x16b2fce2d02389a3,
  0xddff790f9eb14d8b,0x71089b27012a508d,0x1fda59229be7c763,0x60a4a5d50a3e3337,
  0x9f517d71b4fa2045,0x4e7fa4bb17c20c7b,0xf70cb95a4dbe1895,0xa0ae903e5d5fa631,
  0xd95eb10e093d00d7,0x1b539b896b7da95d,0xd219a25fb557cf1b,0x08c07e4feb9db929,
  0x458ee5e2f15285d1,0x396708e200b46df3,0x1e26635bc3e5fc15,0x1ba107c383bbc677,
  0x4bcc5a2beb606d91,0xc36af9291ce23a93,0x2a8dc5c01ac5d80b,0xc066e13bacadfc3f,
  0xac4402cd81ae3105,0xfb8368eacab29cc3,0x20c1d03b42a19b0f,0xbb81444d0bc69d11,
  0xf99cfcab1596e05d,0x88df8ec715500155,0x9d2e048ff2847aef,0x4172baddfc8e2829,
  0xc927f18ef12c8fe1,0x014b68ef566e3b97,0x8374aad03307ba09,0xac705cbbd4b1fbbf,
  0x50827f7a62a568fd,0xb30c92668ccde757,0xb2afff3d95873bdd,0x84402028e62e31b5,
  0x84d74514e7435beb,0x94945e5854f9a47d,0x4fb0ba9fbbf14b69,0x79271c21ac1c88e5,
  0x5b16f327c8a42939,0x2841a737175d2ea3,0x1fb2cab89b137719,0xdd0fa98f73cc6909,
  0xf84601b7e8d87abf,0xcb2b345d929473b1,0x6084882b5e99344b,0x1ba9077267bf7447,
  0x894f414cc7275545,0x5a1300b9fbac8ea9,0x3a50d0a23ae187e3,0x3b601b8ba7b88331,
  0x7830c304cd2448c5,0x943eae1f2e3b698b,0xcfa49a0170f02c1d,0xc8da62644191dbf9,
  0xbbb465a452d849d3,0x1ee5317e3f172da1,0x0442e38d3b86686f,0x2c557739303ee927,
  0xf3f12bcfd0ce3fb5,0x1e9eb855f1616d61,0x2ab5709ce4df6d0b,0xa2b9b9db1a1a5117,
  0x38ef4f62c24ade73,0xc62b216048c99941,0xaa38a1c03b693ee3,0xd71272b85f69451f,
  0x17481d4aa0824159,0x1294785a4eee3a11,0xfa2b23ff441e855d,0xc5fcf17202cf8b13,
  0xea7475d3cae87823,0xf2efba79d3c5a971,0x37958d97bc17645f,0xd34317b1e48a9c99,
  0x588f8c558339d279,0x2f690a359dc8785b,0x20f630ac23cafde5,0x1892b2914bdc72ab,
  0x938634a18cc7f6ef,0xcab55977f30020f3,0x4ea134d012b817c1,0xb51df1ce36d90bdb,
  0x3a27dc92c17a494b,0x125a9512baacc891,0xd14d139408f74d37,0xe3fc76fbf1ff2f2d,
  0xe0c4987ba4436031,0x79b028f241b5807d,0xfaffe9abaa62360f,0xc68ccfcd75ee5329,
  0xc464ba46aecbe785,0xaa126d6910026aa1,0xebd7e27c7c45f865,0xe0cc3bb75b7ba791,
  0x6b241be3a6704cb9,0x13bcb91f35cbc493,0x8581859c73291e17,0x1699cb464907ba99,
  0xefb8b7ce2dc0fd4f,0x3883697113ff5d7b,0xd2606ed5f696e373,0x717ca2b235ccf669,
  0x4667681ad9589bed,0xd78caa30a9a06e59,0x9fe9606c57feab55,0xa0509ac2816c53b7,
  0x81d438e53cfa09e1,0x5cdd1fec0e0eed15,0xfc163e59ba98dcaf,0xf49229cc0abb8eb1,
  0x7591127972219167,0xaf9e4c449641c57f,0xf0dff4032b9f2527,0x379e0df3400c0e51,
  0xa0df450c76c85095,0x0a4ba09c729ccc2f,0xdbd3cb24c7326d5b,0x045082363acee569,
  0xf9ad33ef0329b611,0x4733b1228346e6c7,0x4e05814ee0f1e713,0xcdd9e7d36c028309,
  0xec1787fdfb213e77,0x5bf75257036c00db,0x612ae3f3fbdc44d9,0xc86ed587b13f6591,
  0x33442a4fe558eab9,0xc69790afeccb5a9b,0x2b42512316e0a861,0x2e577bc3c0fb2703,
  0x40a3e79372d50e79,0x6b6aeaa4dfca27e7,0x402c47d8772d3475,0xb20b7b0c593921cb,
  0x4d64bbff0419a029,0x7e7454e8b5ca13c1,0x00fec4079c855f9f,0xeebe074dc724556d,
  0x041d365cf7298993,0xdd46001f04ca6799,0x1405db78676cda4f,0x0501e03705005005,
  0x7874d1819b0c0f29,0x159ff6c43a864887,0x612f7bfca3c472bf,0xe92c2edba1d7ead3,
  0xf4b5ab0f063c018f,0x3f2e7272300659b3,0x35bbc0ce1fa64281,0x9176220bd006734d,
  0x47edc61bbb37c223,0xba4909df7c5b5311,0x1ddc2ac65664b435,0xf24e5a7404ef01a5,
  0x3afbc5d18a14c5f5,0xcc2b3ec9a55fead5,0x07e1a98a5c45606f,0x353a66b365879d5f,
  0xd4f7e0270d00d00d,0xc37ad8dd507b4a7d,0x10a05c4657403d5d,0x33346677cdc7a7cf,
  0x7ca9041f1623fa77,0xbda3fc1b5701ac57,0xc755fabf1e573ac9,0x718599e772d753bd,
  0x3c20b3b440a57eb5,0x6b4ed46f3f03f03f,0x886a4c2e0f0f0f0f,0x70a3d70a33333333,
};

static b32 solve_r(u8 *src, u8 *dst, iz len, u64 csrc, u64 cdst)
{
    if (csrc != cdst) {
        return false;
    } else if (len<2 && csrc==cdst) {
        return true;
    }

    u64 shead = 1;
    u64 stail = csrc;
    u64 lhead = 1;
    u64 ltail = cdst;
    u64 rhead = 1;
    u64 rtail = cdst;
    for (iz i = 1; i < len; i++) {
        shead *=  primes[src[i-1]];  // shift from right to left
        stail *= rprimes[src[i-1]];

        lhead *=  primes[dst[i-1]];  // shift from right to left
        ltail *= rprimes[dst[i-1]];
        if (shead==lhead && stail==ltail &&
            solve_r(src  , dst  ,     i, shead, lhead) &&
            solve_r(src+i, dst+i, len-i, stail, ltail)) {
            return true;
        }

        rhead *=  primes[dst[len-i]];  // shift from left to right
        rtail *= rprimes[dst[len-i]];
        if (shead==rhead && stail==rtail &&
            solve_r(src  , dst+len-i,     i, shead, rhead) &&
            solve_r(src+i, dst      , len-i, stail, rtail)) {
            return true;
        }
    }
    return false;
}

static u64 compress(Str s)
{
    u64 r = 1;
    for (iz i = 0; i < s.len; i++) {
        r *= primes[s.data[i]];
    }
    return r;
}

static b32 solve_fast(Str src, Str dst)
{
    if (src.len != dst.len) return false;
    u64 csrc = compress(src);
    u64 cdst = compress(dst);
    return solve_r(src.data, dst.data, src.len, csrc, cdst);
}

static i32 randint(u64 *rng, i32 lo, i32 hi)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (i32)(((*rng>>32)*(u64)(hi - lo))>>32) + lo;
}

static void permute(u64 *rng, u8 *src, u8 *dst, i32 len)
{
    switch (len) {
    case 1: *dst = *src;
    case 0: return;
    }

    i32 n = randint(rng, 1, len);
    if (randint(rng, 0, 2)) {
        permute(rng, src  , dst  , n);
        permute(rng, src+n, dst+n, len-n);
    } else {
        permute(rng, src,   dst+len-n, n);
        permute(rng, src+n, dst      , len-n);
    }
}

void test_fast(void)
{
    assert( solve_fast(S("great"), S("rgeat")));
    assert(!solve_fast(S("abcde"), S("caebd")));

    u8 src[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "abcdefghijklmnopqrstuvwxyz" "0123456789";

    #pragma omp parallel for
    for (i32 i = 0; i < 1000000; i++) {
        u8 dst[lenof(src)];
        u64 rng = (u64)i + 1111111111111111111;
        permute(&rng, src, dst, lenof(src)-1);
        assert(solve_fast(S(src), S(dst)));
    }

    #pragma omp parallel for
    for (i32 i = 0; i < 1000000; i++) {
        u8 dst[lenof(src)];
        for (i32 i = 0; i < lenof(src)-1; i++) {
            dst[i] = src[i];
        }

        // Random permutations are astronomically unlikely reachable
        // permutations for long strings. Here it's 1 in ~3.8x10^41.
        u64 rng = (u64)i + 1111111111111111111;
        for (i32 i = 0; i < lenof(dst)-2; i++) {
            i32 j = randint(&rng, i, lenof(dst));
            u8 tmp = dst[i];
            dst[i] = dst[j];
            dst[j] = tmp;
        }

        assert(!solve_fast(S(src), S(dst)));
    }
}


// Tests

#include <stdio.h>
#include <stdlib.h>

static Str import(char *s)
{
    Str r = {};
    r.data = (u8 *)s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

int main(int argc, char **argv)
{
    iz  cap = (iz)1<<34;  // enough for brute force of length 14
    u8 *mem = malloc(touz(cap));

    if (argc == 3) {
        Arena a = {mem, mem+cap};
        b32   r = solve_brute(import(argv[1]), import(argv[2]), a);
        puts(r ? "true" : "false");

    } else {
        test_fast();

        // Count permutations for each size: Schröder numbers [A006318]
        for (i32 n = 1; n <= 14; n++) {
            Arena a = {mem, mem+cap};
            Str   k = S("0123456789abcdef");
            Set   r = generate(takehead(k, n), &(Cache *){}, &a);
            printf("%d\t%tdM\t%td\n", n, (cap-(a.end-a.beg))>>20, r.len);
        }
    }
}
