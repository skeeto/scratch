// Advent of Code 2025 Day 9
#include <stddef.h>
#include <stdint.h>

#define S(s)            (Str){s, sizeof(s)-1}
#define affirm(c)       while (!(c)) __builtin_unreachable()
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

static int32_t abs32(int32_t x)
{
    return x<0 ? -x : +x;
}

static int32_t min32(int32_t x, int32_t y)
{
    return x<y ? x : y;
}

static int32_t max32(int32_t x, int32_t y)
{
    return x>y ? x : y;
}

typedef struct {
    char *beg;
    char *end;
} Arena;

static char *alloc(Arena *a, ptrdiff_t count, int size, int align)
{
    ptrdiff_t pad = (ptrdiff_t)-(size_t)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    char *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, (size_t)(count*size));
}

typedef struct {
    char     *data;
    ptrdiff_t len;
} Str;

static Str span(char *beg, char *end)
{
    affirm(beg <= end);
    return (Str){beg, end-beg};
}

typedef struct {
    Str  tail;
    Str  head;
    bool eof;
} Cut;

static Cut cut(Str s, char c)
{
    char *beg = s.data;
    char *end = s.data + s.len;
    char *cut = beg;
    for (; cut<end && *cut!=c; cut++) {}

    Cut r = {};
    r.eof  = cut == end;
    r.head = span(beg, cut);
    r.tail = span(cut+!r.eof, end);
    return r;
}

static int32_t parse32(Str s)
{
    int32_t r = 0;
    for (ptrdiff_t i = 0; i < s.len; i++) {
        char c = s.data[i];
        if (c<'0' || c>'9') break;
        r = r*10 + c - '0';
    }
    return r;
}

typedef struct {
    int32_t x;
    int32_t y;
} V2;

typedef struct {
    V2       *data;
    ptrdiff_t len;
} V2s;

static V2s parse(Arena *a, Str s)
{
    V2s r = {};

    for (Cut c = {s}; c.tail.len; r.len++) {
        c = cut(c.tail, '\n');
    }

    r.data = new(a, r.len, V2);
    r.len = 0;

    for (Cut c = {s}; c.tail.len;) {
        c = cut(c.tail, '\n');
        Cut pair = cut(c.head, ',');
        int32_t x = parse32(pair.head);
        int32_t y = parse32(pair.tail);
        r.data[r.len++] = (V2){x, y};
    }

    return r;
}


// Part 1: naive brute force (good enough)

static int64_t part1(V2s vs)
{
    int64_t best = -1;
    for (ptrdiff_t i = 0; i < vs.len-1; i++) {
        V2 a = vs.data[i];
        for (ptrdiff_t j = i+1; j < vs.len; j++) {
            V2 b = vs.data[j];
            int64_t dx = abs32(a.x - b.x) + 1;
            int64_t dy = abs32(a.y - b.y) + 1;
            int64_t area = dx * dy;
            if (area > best) {
                best = area;
            }
        }
    }
    return best;
}


// Part 2: raycasting solution

// Is v inside the polygon traced out by vs?
static bool inside(V2s vs, V2 v)
{
    ptrdiff_t count = 0;
    for (ptrdiff_t i = 0; i < vs.len; i++) {
        V2 a = vs.data[i];
        V2 b = vs.data[(i+1) % vs.len];
        if (a.x == b.x) {
            // Vertical: count crossings
            int32_t y0 = min32(a.y, b.y);
            int32_t y1 = max32(a.y, b.y);
            count += v.y>=y0 && v.y<y1 && v.x<a.x;
        } else if (a.y == v.y) {
            // Horizontal
            int32_t x0 = min32(a.x, b.x);
            int32_t x1 = max32(a.x, b.x);
            if (v.x>=x0 && v.x<=x1) {
                // On line, must be inside
                return true;
            }
        }
    }
    return count % 2;
}

// Do h0->h1 and v0->v1 cross?
static bool cross(V2 h0, V2 h1, V2 v0, V2 v1)
{
    affirm(v0.x==v1.x);
    affirm(h0.y==h1.y);
    int32_t y0 = min32(v0.y, v1.y);
    int32_t y1 = max32(v0.y, v1.y);
    int32_t x0 = min32(h0.x, h1.x);
    int32_t x1 = max32(h0.x, h1.x);
    return h0.y>y0 && h0.y<y1 && x0<v0.x && x1>v0.x;
}

// Does v0->v1 cross any horizontal line?
static bool any_hcross(V2s vs, V2 v0, V2 v1)
{
    for (ptrdiff_t i = 0; i < vs.len-1; i++) {
        V2 a = vs.data[i];
        V2 b = vs.data[(i+1) % vs.len];
        if (a.y == b.y) {
            if (cross(a, b, v0, v1)) {
                return true;
            }
        }
    }
    return false;
}

// Does h0->h1 cross any vertical line?
static bool any_vcross(V2s vs, V2 h0, V2 h1)
{
    for (ptrdiff_t i = 0; i < vs.len-1; i++) {
        V2 a = vs.data[i];
        V2 b = vs.data[(i+1) % vs.len];
        if (a.x == b.x) {
            if (cross(h0, h1, a, b)) {
                return true;
            }
        }
    }
    return false;
}

static int64_t part2(V2s vs)
{
    int64_t best = -1;
    for (ptrdiff_t i = 0; i < vs.len-1; i++) {
        V2 a = vs.data[i];
        for (ptrdiff_t j = i+1; j < vs.len; j++) {
            V2 b = vs.data[j];
            V2 c = {a.x, b.y};
            V2 d = {b.x, a.y};
            int64_t dx = abs32(a.x - b.x) + 1;
            int64_t dy = abs32(a.y - b.y) + 1;
            int64_t area = dx * dy;
            // Corners must be inside the polygon, and no polygon edge
            // may cross the square edges.
            if (area>best &&
                inside(vs, c) &&
                inside(vs, d) &&
                !any_hcross(vs, a, c) &&
                !any_hcross(vs, b, d) &&
                !any_vcross(vs, a, d) &&
                !any_vcross(vs, b, c)) {
                best = area;
            }
        }
    }
    return best;
}


// Part 2: compress and raster solution (via Kris Kujawksi)

enum { RED = 0xff, GREEN = 0x00, WHITE = 0x7f };

static void splitmerge(
    ptrdiff_t *dst,
    ptrdiff_t  beg,
    ptrdiff_t  end,
    ptrdiff_t *src,
    int32_t   *field
)
{
    if (end-beg > 1) {
        ptrdiff_t mid = beg + (end - beg)/2;
        splitmerge(src, beg, mid, dst, field);
        splitmerge(src, mid, end, dst, field);

        ptrdiff_t i = beg;
        ptrdiff_t j = mid;
        for (ptrdiff_t k = beg; k < end; k++) {
            if (i<mid && (j==end || field[2*src[i]] < field[2*src[j]])) {
                dst[k] = src[i++];
            } else {
                dst[k] = src[j++];
            }
        }
    }
}

// Remove empty stretches between red tiles, reducing "area" by ~40,000x.
// Leaves a 1-tile border around the outside of the polygon.
static V2 compress(V2s vs, Arena scratch)
{
    int32_t max[2] = {};

    ptrdiff_t *dst = new(&scratch, vs.len, ptrdiff_t);
    ptrdiff_t *src = new(&scratch, vs.len, ptrdiff_t);

    int32_t *fields[] = {&vs.data[0].x, &vs.data[0].y};
    for (int i = 0; i < 2; i++) {
        int32_t *field = fields[i];
        for (ptrdiff_t i = 0; i < vs.len; i++) {
            src[i] = dst[i] = i;
        }
        splitmerge(dst, 0, vs.len, src, field);

        int32_t off  =  0;
        int32_t prev = -1;
        for (ptrdiff_t i = 0; i < vs.len; i++) {
            int32_t *next = &field[2*dst[i]];
            if (*next > prev) {
                prev = *next;
                off += 2;
            }
            *next = off;
        }
        max[i] = off;
    }

    return (V2){max[0]+2, max[1]+2};
}

static V2s copy(Arena *a, V2s vs)
{
    V2s r = vs;
    r.data = new(a, r.len, V2);
    for (ptrdiff_t i = 0; i < r.len; i++) {
        r.data[i] = vs.data[i];
    }
    return r;
}

typedef struct {
    V2       dims;
    uint8_t *data;
} Bitmap;

static uint8_t *get(Bitmap b, V2 v)
{
    return b.data + v.y*b.dims.x + v.x;
}

static ptrdiff_t dims_size(V2 dims)
{
    return (ptrdiff_t)dims.x * dims.y;
}

static bool in_bounds(Bitmap map, V2 v)
{
    return v.x>=0 && v.x<map.dims.x && v.y>=0 && v.y<map.dims.y;
}

static void flood(Bitmap map, Arena scratch)
{
    V2 *queue = new(&scratch, dims_size(map.dims), V2);
    for (ptrdiff_t head=1, tail=0; head != tail;) {
        V2 p = queue[tail++];
        static V2 dirs[] = {{+1, +0}, {-1, +0}, {+0, +1}, {+0, -1}};
        for (int i = 0; i < 4; i++) {
            V2 t = {p.x+dirs[i].x, p.y+dirs[i].y};
            if (in_bounds(map, t)) {
                uint8_t *pt = get(map, t);
                if (*pt == GREEN) {
                    *pt = WHITE;
                    queue[head++] = t;
                }
            }
        }
    }
}

static bool check_area(Bitmap map, V2 a, V2 b)
{
    int32_t y0 = min32(a.y, b.y);
    int32_t y1 = max32(a.y, b.y);
    int32_t x0 = min32(a.x, b.x);
    int32_t x1 = max32(a.x, b.x);
    for (int32_t y = y0; y <= y1; y++) {
        for (int32_t x = x0; x <= x1; x++) {
            if (*get(map, (V2){x, y}) == WHITE) {
                return false;
            }
        }
    }
    return true;
}

static int64_t part2_raster(V2s vs, Arena scratch)
{
    Bitmap map = {};
    V2s cvs = copy(&scratch, vs);
    map.dims = compress(cvs, scratch);
    map.data = new(&scratch, dims_size(map.dims), uint8_t);

    // Render the filled polygon into the map
    for (ptrdiff_t i = 0; i < cvs.len; i++) {
        V2 a = cvs.data[i];
        V2 b = cvs.data[(i+1) % cvs.len];
        int32_t dx = a.x<b.x ? +1 : a.x>b.x ? -1 : 0;
        int32_t dy = a.y<b.y ? +1 : a.y>b.y ? -1 : 0;
        for (V2 p = a; p.x!=b.x || p.y!=b.y; p.x+=dx, p.y+=dy) {
            *get(map, p) = RED;
        }
    }
    flood(map, scratch);

    int64_t best = -1;
    for (ptrdiff_t i = 0; i < cvs.len-1; i++) {
        V2  a = vs.data[i];
        V2 ca = cvs.data[i];
        for (ptrdiff_t j = i+1; j < vs.len; j++) {
            V2  b = vs.data[j];
            V2 cb = cvs.data[j];
            int64_t dx = abs32(a.x - b.x) + 1;
            int64_t dy = abs32(a.y - b.y) + 1;
            int64_t area = dx * dy;
            if (area>best && check_area(map, ca, cb)) {
                best = area;
            }
        }
    }
    return best;
}
