// Animated Wilson's algorithm maze generator
//   $ cc -O2 -o wilson wilson.c
//   $ ./wilson | mpv --no-correct-pts --fps=60 -
//   $ ./wilson | x264 --fps=60 -o wilson.mp4
// https://weblog.jamisbuck.org/2011/1/20/maze-generation-wilson-s-algorithm
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n)

typedef struct { char *beg, *end; } arena;

static char *alloc(arena *a, ptrdiff_t size, ptrdiff_t align, ptrdiff_t len)
{
    ptrdiff_t pad = (uintptr_t)a->end & (align - 1);
    assert(len < (a->end - a->beg - pad)/size);
    return memset(a->end -= pad + size*len, 0, size*len);
}

typedef struct { int16_t x, y; } v2;

static v2 newv2(int32_t x, int32_t y)
{
    v2 r = {0};
    r.x = (int16_t)x;
    r.y = (int16_t)y;
    return r;
}

static const v2 dirs[] = {{+1, +0}, {+0, +1}, {-1, +0}, {+0, -1}};

typedef struct {
    unsigned dir    : 2;
    unsigned east   : 1;
    unsigned south  : 1;
    unsigned mark   : 1;
    unsigned active : 1;
    unsigned select : 1;
} cell;

typedef struct {
    cell   *cells;
    int16_t width;
    int16_t height;
} maze;

static cell *get(maze m, v2 p)
{
    return m.cells + p.y*m.width + p.x;
}

static _Bool valid(maze m, v2 p)
{
    return p.x>=0 && p.x<m.width && p.y>=0 && p.y<m.height;
}

static v2 apply(v2 p, int dir, int16_t scale)
{
    p.x += (int16_t)(scale * dirs[dir].x);
    p.y += (int16_t)(scale * dirs[dir].y);
    return p;
}

static void connect(maze m, v2 s, int dir)
{
    v2 d = apply(s, dir, 1);
    switch (dir) {
    case 0: get(m, s)->east  = 1;
            break;
    case 1: get(m, s)->south = 1;
            break;
    case 2: get(m, d)->east  = 1;
            break;
    case 3: get(m, d)->south = 1;
            break;
    }
}

typedef struct {
    uint8_t  *data;
    ptrdiff_t len;
    uint8_t  *pixels;
    int32_t   width;
    int32_t   height;
} image;

static void put(image im, v2 p, uint32_t color)
{
    uint8_t *pixel = im.pixels + 3*im.width*p.y + 3*p.x;
    pixel[0] = (uint8_t)(color >> 16);
    pixel[1] = (uint8_t)(color >>  8);
    pixel[2] = (uint8_t)(color >>  0);
}

enum {
    FLAG_dir    = 1<<0,
    FLAG_active = 1<<1,
};

static image render(maze m, int8_t scale, int32_t flags, arena *perm)
{
    enum { header_len = 3 + 11 + 11 + 4, };
    image im  = {0};
    im.width  = m.width  * scale;
    im.height = m.height * scale;
    im.len    = header_len + (ptrdiff_t)3 * im.height * im.width;
    im.data   = new(perm, uint8_t, im.len);
    im.pixels = im.data + header_len;

    uint8_t *p = im.data;
    *p++ = 'P';
    *p++ = '6';
    *p++ = '\n';
    for (int i = 0; i < 10; i++) *p++ = '0';
    uint8_t *px = p;
    *p++ = ' ';
    for (int i = 0; i < 10; i++) *p++ = '0';
    uint8_t *py = p;
    *p++ = '\n';
    *p++ = '2';
    *p++ = '5';
    *p++ = '5';
    *p++ = '\n';

    int w = scale * m.width;
    do *--px = '0' + (uint8_t)(w%10);
    while (w /= 10);
    int h = scale * m.height;
    do *--py = '0' + (uint8_t)(h%10);
    while (h /= 10);

    for (int16_t y = 0; y < m.height; y++) {
        for (int16_t x = 0; x < m.width; x++) {
            cell c = *get(m, newv2(x, y));

            uint32_t color = c.mark ? 0xffffff :
                c.select ? 0xffff00 :
                c.active ? 0x7fff7f : 0xafafaf;
            for (int cy = 0; cy < scale; cy++) {
                for (int cx = 0; cx < scale; cx++) {
                    put(im, newv2(x*scale+cx, y*scale+cy), color);
                }
            }
            put(im, newv2(x*scale+scale-1, y*scale+scale-1), 0);

            if (!c.east) {
                for (int cy = 0; cy < scale; cy++) {
                    put(im, newv2(x*scale+scale-1, y*scale+cy), 0);
                }
            }

            if (!c.south) {
                for (int cx = 0; cx < scale; cx++) {
                    put(im, newv2(x*scale+cx, y*scale+scale-1), 0);
                }
            }

            if (flags & FLAG_dir) {
                v2 center = newv2(x*scale+scale/2, y*scale+scale/2);
                for (int8_t d = 0; d < scale/2; d++) {
                    v2 p = apply(center, c.dir, d);
                    put(im, p, 0x0000ff);
                }
            }
        }
    }

    return im;
}

static uint32_t rand32(uint64_t *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (uint32_t)(*rng >> 32);
}

static int randint(uint64_t *rng, int lo, int hi)
{
    return (int)(((uint64_t)rand32(rng)*(hi - lo)) >> 32) + lo;
}

static void clear(maze m)
{
    v2 p = {0};
    for (; p.y < m.height; p.y++) {
        for (p.x = 0; p.x < m.width; p.x++) {
            cell *c = get(m, p);
            c->active = 0;
            c->select = 0;
        }
    }
}

static maze wilson(v2 dims, uint64_t seed, void (cb)(maze, arena), arena *perm)
{
    int32_t ncells = dims.x * dims.y;

    maze m   = {0};
    m.width  = dims.x;
    m.height = dims.y;
    m.cells  = new(perm, cell, ncells);

    {
        int16_t x = (int16_t)randint(&seed, 0, m.width);
        int16_t y = (int16_t)randint(&seed, 0, m.height);
        get(m, newv2(x, y))->mark = 1;
    }

    arena scratch = *perm;

    v2 *unvisited = new(&scratch, v2, ncells);
    for (int16_t y = 0; y < m.height; y++) {
        for (int16_t x = 0; x < m.width; x++) {
            int32_t i = y*m.width + x;
            unvisited[i].x = x;
            unvisited[i].y = y;
        }
    }

    while (ncells) {
        int32_t i = randint(&seed, 0, ncells);
        v2 start = unvisited[i];
        unvisited[i] = unvisited[--ncells];

        for (v2 p = start; !get(m, p)->mark;) {
            if (cb) {
                get(m, p)->active = 1;
                get(m, p)->select = 1;
                cb(m, scratch);
                get(m, p)->select = 0;
            }

            int dir = rand32(&seed)>>30;
            v2 target = newv2(
                p.x + dirs[dir].x,
                p.y + dirs[dir].y
            );
            if (valid(m, target)) {
                get(m, p)->dir = dir & 3u;
                p = target;
            }
        }

        for (v2 p = start; !get(m, p)->mark;) {
            if (cb) {
                get(m, p)->active = 1;
                cb(m, scratch);
            }
            cell *c = get(m, p);
            c->mark = 1;
            connect(m, p, c->dir);
            p.x += dirs[c->dir].x;
            p.y += dirs[c->dir].y;
        }

        if (cb) {
            clear(m);
        }
    }

    return m;
}


#include <stdio.h>

static void dumpframe(maze m, arena scratch)
{
    image im = render(m, 15, FLAG_dir|FLAG_active, &scratch);
    if (!fwrite(im.data, 1, im.len, stdout)) {
        exit(1);
    }
}

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    int   cap     = 1<<21;
    char *mem     = malloc(cap);
    arena scratch = {mem, mem+cap};

    maze   m = wilson((v2){50, 40}, -1234, dumpframe, &scratch);
    image im = render(m, 15, 0, &scratch);
    for (int i = 0; i < 3*60; i++) {
        fwrite(im.data, 1, im.len, stdout);
    }

    fflush(stdout);
    return ferror(stdout);
}
