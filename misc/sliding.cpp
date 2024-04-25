// Sliding puzzle solver and generator
// $ cc -std=c++23 -o sliding sliding.cpp
// $ ./map <map.txt
//
// Map legend:
//   '.' empty tile
//   '0' solid tile
//   'S' start
//   'F' finish
//
// Starting at S, the player moves in a cardinal direction until hitting
// either a solid tile or the edge of the map. The goal is to stop on F.
//
// Sample input:
// ...0..0.....00..000.
// .0......0..0..0...0.
// .....0........0.....
// 0.0.0.....0....0....
// ..00...0..0...0.....
// 0....0..0.......000.
// ......0.....0..0....
// ..............00....
// 0....0.....0........
// 00....0.........S...
// 0.....0.0.......0..0
// ..............0.....
// .00......0...0...0..
// ....0....0...F.0...0
// .......0.00.....0...
// ..0.....0.0...00..0.
// .......0...0......0.
// .00....0....0......0
// ...0....0.0..0......
// 0.....0.............
//
// Ref: https://old.reddit.com/r/algorithms/comments/1ca80ml
// This is free and unencumbered software released into the public domain.

#define assert(c)  while (!(c)) [[assume(0)]]

typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned long long u64;
typedef decltype(0z)       isize;
typedef decltype(0uz)      usize;
typedef decltype(0uz)      uptr;
typedef          char      byte;

template<typename T>
T max(T a, T b) { return a>b ? a : b; }

template<typename T, isize N>
constexpr isize countof(T const (&a)[N]) { return N; }

static b32 whitespace(u8 c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

struct arena {
    byte *beg = 0;
    byte *end = 0;
    arena(isize);  // [platform]
};

void *operator new(usize, void *p) { return p; };

template<typename T, typename ...A>
static T *alloc(isize count, arena *perm, A ...args)
{
    assert(count >= 0);
    isize size  = sizeof(T);
    isize align = (uptr)perm->end & (alignof(T) - 1);
    assert(count < (perm->end - perm->beg - align)/size);
    T *r = (T *)(perm->end -= size*count + align);
    for (isize i = 0; i < count; i++) new (r+i) T(args...);
    return r;
}

template<typename T>
static T *alloc(arena *perm) { return alloc<T>(1, perm); }

template<typename T, typename ...A>
static T *alloc(arena *perm, A ...args) { return alloc<T>(1, perm, args...); }

struct s8 {
    u8   *data = 0;
    isize len  = 0;

    s8() = default;

    template<isize N>
    s8(char const (&s)[N]) : data{(u8 *)s}, len{N-1} {}

    s8(u8 *beg, u8 *end) : data{beg}, len{end-beg} {}

    s8(arena *perm, s8 s) : data{}, len{s.len}
    {
        data = alloc<u8>(s.len, perm);
        len  = s.len;
        for (isize i = 0; i < len; i++) {
            data[i] = s[i];
        }
    }

    u8 &operator[](isize i) { return data[i]; }
    operator u8*() { return data; }
};

static s8 prepend(arena *perm, s8 a, s8 b)
{
    if ((byte *)b.data != perm->end) {
        b = s8(perm, b);
    }
    s8 r(perm, a);
    r.len += b.len;
    return r;
}

static s8 prepend(arena *perm, i32 x, s8 b)
{
    u8  buf[32];
    u8 *beg = buf + countof(buf);
    do *--beg = (u8)(x%10) + '0';
    while (x /= 10);
    return prepend(perm, s8(beg, buf+countof(buf)), b);
}

static s8 prepend(arena *perm, u8 a, s8 b)
{
    return prepend(perm, s8(&a, &a+1), b);
}

struct v2 {
    i32 x, y;
    v2 operator+(v2 c) { return {x+c.x, y+c.y}; }
    b32 operator==(v2 c) { return x==c.x && y==c.y; }
};

enum { EMPTY, SOLID, MARKED };

struct grid {
    u8 *data;
    v2  size;
    v2  start;
    v2  stop;

    u8 &operator[](v2 c)
    {
        if (c.x<0 || c.x>=size.x || c.y<0 || c.y>=size.y) {
            static const u8 wall = SOLID;
            return *(u8 *)&wall;
        }
        return data[c.y*size.x + c.x];
    }
};

static grid parse(s8 s, arena *perm)
{
    grid r = {};

    b32 state = 0;
    v2  coord = {};
    for (isize i = 0; i < s.len; i++) {
        switch (s[i]) {
        case 'F': r.stop.x = coord.x;
                  r.stop.y = coord.y;
                  break;
        case 'S': r.start.x = coord.x;
                  r.start.y = coord.y;
                  break;
        }
        b32 next = !whitespace(s[i]);
        r.size.x = max(coord.x, r.size.x);
        coord.x  = next<state ? 0 : coord.x+next;
        coord.y += next < state;
        r.size.y = coord.y;
        state    = next;
    }
    r.size.x += state;
    r.size.y += state;

    r.data = alloc<u8>(r.size.x*r.size.y, perm);

    state = 0;
    coord = {};
    for (isize i = 0; i<s.len && coord.y<r.size.y; i++) {
        if (whitespace(s[i])) {
            coord.x  = 0;
            coord.y += state;
            state = 0;
        } else {
            r[coord] = s[i] == '0';
            coord.x++;
            state = 1;
        }
    }

    return r;
}

static u8 todir(v2 src, v2 dst)
{
    return src.x==dst.x ? "NS"[src.y<dst.y] : "WE"[src.x<dst.x];
}

// Solve the given puzzle, returning a formatted solution string.
static s8 solve(s8 s, arena *perm, arena scratch)
{
    grid g = parse(s, &scratch);

    struct node {
        node *next = 0;
        node *prev;
        v2    coord;
        node(node *p, v2 c) : prev{p}, coord{c} {}
    };

    node  *head = 0;
    node **tail = &head;
    *tail = alloc<node>(&scratch, (node *)0, g.start);
    tail = &(*tail)->next;
    g[g.start] = MARKED;

    // Breadth-first search
    for (; head; head = head->next) {
        if (head->coord == g.stop) {
            // Format a solution string, back to front.
            s8 text;
            for (; head->prev; head = head->prev) {
                v2 src = head->prev->coord;
                v2 dst = head->coord;
                u8 dir = todir(src, dst);
                text = prepend(perm, ")\n", text);
                text = prepend(perm, dst.y, text);
                text = prepend(perm, ", ",  text);
                text = prepend(perm, dst.x, text);
                text = prepend(perm, " (",  text);
                text = prepend(perm, dir,   text);
            }
            return text;
        }

        static v2 dirs[] = {{+0,-1}, {+1,+0}, {+0,+1}, {-1,+0}};
        for (i32 i = 0; i < countof(dirs); i++) {
            for (v2 c = head->coord;; c = c + dirs[i]) {
                if (g[c+dirs[i]] == SOLID) {
                    if (g[c] == EMPTY) {
                        g[c] = MARKED;
                        *tail = alloc<node>(&scratch, head, c);
                        tail = &(*tail)->next;
                    }
                    break;
                }
            }
        }
    }
    return {};
}

static i32 randint(u64 *rng, i32 lo, i32 hi)
{
    *rng = *rng*0x3243f6a8885a308du + 1;
    return (i32)(((*rng>>32)*(hi - lo))>>32) + lo;
}

static v2 randv2(u64 *rng, i32 w, i32 h)
{
    v2 r = {};
    r.x = randint(rng, 0, w);
    r.y = randint(rng, 0, h);
    return r;
}

// Generate a random puzzle, returning it as a formatted string.
static s8 gen(u64 seed, i32 w, i32 h, i32 steps, arena *perm, arena scratch)
{
    for (arena reset = *perm;; *perm = reset) {
        arena temp = scratch;

        grid g  = {};
        g.data  = alloc<u8>(w*h, &temp);
        g.size  = v2{w, h};
        g.start = randv2(&seed, w, h);
        do {
            g.stop = randv2(&seed, w, h);
        } while (g.stop == g.start);
        for (i32 i = 0; i < w*h/5; i++) {
            v2 c;
            do {
                c = randv2(&seed, w, h);
            } while (g[c]);
            g[c] = SOLID;
        }

        s8 r;
        r.len = (w + 1)*h;
        r.data = alloc<u8>(r.len, perm);
        for (i32 y = 0; y < h; y++) {
            for (i32 x = 0; x < w; x++) {
                i32 i = y*(w+1) + x;
                r[i] = g[v2{x, y}] ? '0' : '.';
            }
            r[y*(w+1) + w] = '\n';
        }
        r[g.start.y*(w+1) + g.start.x] = 'S';
        r[g.stop.y *(w+1) + g.stop.x ] = 'F';

        s8 s = solve(r, &temp, *perm);
        i32 check = 0;
        for (isize i = 0; i < s.len; i++) {
            check += s[i] == '\n';
        }
        if (check >= steps) {
            return r;
        }
    }
}


// Platform code
#include <stdio.h>
#include <stdlib.h>

inline arena::arena(isize cap)
{
    beg = (byte *)malloc(cap);
    end = beg + cap;
}

int main()
{
    arena perm(1<<20);
    arena scratch(1<<20);

    s8 input;
    #if 0
    // Generate a puzzle
    input = gen(1, 20, 20, 30, &perm, scratch);
    fwrite(input, input.len, 1, stdout);
    #else
    // Load puzzle from standard input
    input.data = (u8 *)scratch.beg;
    input.len = scratch.end - scratch.beg;
    input.len = fread(input.data, 1, input.len, stdin);
    scratch.beg += input.len;
    #endif

    s8 solution = solve(input, &perm, scratch);
    fwrite(solution, solution.len, 1, stdout);
    fflush(stdout);
    return ferror(stdout);
}
