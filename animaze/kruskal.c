/* Animated Kruskal maze generator and solver.
 * Usage:
 *   $ cc -O3 kruskal.c
 *   $ ./a.out | mpv --no-correct-pts --fps=60 --fs -
 *   $ ./a.out | x264 --fps=60 -o maze.mp4 /dev/stdin
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long long s = 0;

static void
r32s(unsigned long long seed)
{
    s = seed;
}

static unsigned long
r32(void)
{
    s = s*0x7c3c3267d015ceb5ULL + 0x24bd2d95276253a9ULL;
    unsigned long r = s>>32 & 0xffffffffUL;
    r ^= r>>16;
    r *= 0x60857ba9UL;
    return r & 0xffffffff;
}

static unsigned long
randint(unsigned long r)
{
    unsigned long long x = r32();
    unsigned long long m = x * r;
    unsigned long y = m & 0xffffffffUL;
    if (y < r) {
        unsigned long t = -r % r;
        while (y < t) {
            x = r32();
            m = x * r;
            y = m & 0xffffffffUL;
        }
    }
    return m >> 32;
}

struct image {
    int width;
    int height;
    unsigned char buf[];
};

static struct image *
image_create(int width, int height)
{
    struct image *im = malloc(sizeof(*im) + 3*width*height);
    im->width = width;
    im->height = height;
    return im;
}

static void
image_set(struct image *im, int x, int y, long color)
{
    im->buf[y*im->width*3 + x*3 + 0] = color >> 16;
    im->buf[y*im->width*3 + x*3 + 1] = color >>  8;
    im->buf[y*im->width*3 + x*3 + 2] = color >>  0;
}

static void
image_write(const struct image *im)
{
    if (printf("P6\n%d %d\n255\n", im->width, im->height) < 0)
        exit(EXIT_FAILURE);
    if (!fwrite(im->buf, im->height*im->width*3, 1, stdout))
        exit(EXIT_FAILURE);
}

static void
image_fill(struct image *im, int x0, int y0, int x1, int y1, long color)
{
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            image_set(im, x, y, color);
        }
    }
}

#define F_SOUTH   (1<<0)
#define F_EAST    (1<<1)
#define F_VISITED (1<<2)
#define F_QUEUED  (1<<3)
struct maze {
    int width;
    int height;
    unsigned char cells[];
};

static unsigned char *
maze_get(struct maze *m, int x, int y)
{
    return m->cells + y*m->width + x;
}

static struct maze *
maze_create(int width, int height)
{
    struct maze *m = malloc(sizeof(*m) + width*height*sizeof(m->cells[0]));
    m->width = width;
    m->height = height;
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
             *maze_get(m, x, y) = F_SOUTH | F_EAST;
        }
    }
    return m;
}

static int
maze_valid(struct maze *m, int x, int y)
{
    return x >= 0 && x < m->width && y >= 0 && y < m->height;
}

static void
draw_walls(struct image *im, struct maze *m, int scale, long color)
{
    for (int y = 0; y < im->height; y++) {
        image_set(im, 0, y, color);
    }
    for (int x = 0; x < im->width; x++) {
        image_set(im, x, 0, color);
    }

    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            int c = *maze_get(m, x, y);
            if (c & F_SOUTH) {
                int py = 1 + (y + 1)*scale;
                for (int i = 0; i < scale; i++) {
                    int px = 1 + x*scale + i;
                    image_set(im, px, py, color);
                }
            }
            if (c & F_EAST) {
                int px = 1 + (x + 1)*scale;
                for (int i = 0; i < scale; i++) {
                    int py = 1 + y*scale + i;
                    image_set(im, px, py, color);
                }
            }
            image_set(im, 1 + (x + 1)*scale, 1 + (y + 1)*scale, color);
        }
    }
}

static void
draw_mask(struct image *im, struct maze *m, int mask, int scale, long color)
{
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            if (*maze_get(m, x, y) & mask) {
                int px = x*scale + 1;
                int py = y*scale + 1;
                image_fill(im, px, py, px + scale, py + scale, color);
            }
        }
    }
}

struct set {
    struct set *parent;
    long color;
    long size;
};

static struct set *
set_find(struct set *s)
{
    if (s->parent != s)
        s->parent = set_find(s->parent);
    return s->parent;
}

static long
kruskal(struct maze *m, int scale)
{
    struct set *sets = malloc(sizeof(*sets)*m->width*m->height);
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            struct set *s = sets + y*m->width + x;
            s->parent = s;
            s->color = (r32() & 0xffffffUL) | 0x404040UL;
            s->size = 1;
        }
    }

    struct {
        int x;
        int y;
        int which;
    } *walls = malloc(sizeof(*walls)*m->width*m->height*2);
    long nwalls = 0;

    struct image *im = image_create(m->width*scale + 2, m->height*scale + 2);

    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            if (y < m->height - 1) {
                walls[nwalls].x = x;
                walls[nwalls].y = y;
                walls[nwalls++].which = F_SOUTH;
            }
            if (x < m->width - 1) {
                walls[nwalls].x = x;
                walls[nwalls].y = y;
                walls[nwalls++].which = F_EAST;
            }
        }
    }

    while (nwalls) {
        long i = randint(nwalls);
        int x = walls[i].x;
        int y = walls[i].y;
        int w = walls[i].which;
        walls[i] = walls[--nwalls];

        int nx, ny;
        switch (w) {
        case F_SOUTH: nx = x + 0; ny = y + 1; break;
        case F_EAST:  nx = x + 1; ny = y + 0; break;
        default: abort();
        }
        struct set *a = set_find(sets + y*m->width + x);
        struct set *b = set_find(sets + ny*m->width + nx);
        if (a != b) {
            if (a->size > b->size) {
                b->parent = a;
                a->size += b->size;
            } else {
                a->parent = b;
                b->size += a->size;
            }
            *maze_get(m, x, y) &= ~w;

            for (int y = 0; y < m->height; y++) {
                for (int x = 0; x < m->width; x++) {
                    struct set *s = sets + y*m->width + x;
                    long c = set_find(s)->color;
                    int x0 = 1 + x*scale;
                    int y0 = 1 + y*scale;
                    image_fill(im, x0, y0, x0 + scale, y0 + scale, c);
                }
            }
            draw_walls(im, m, scale, 0x000000);
            image_write(im);
        }
    }
    long final = set_find(sets)->color;

    free(im);
    free(walls);
    free(sets);

    return final;
}

static void
flood(struct maze *m, int scale, long base)
{
    long qlen = m->width * m->height;
    struct {
        int x;
        int y;
        int d;
    } *queue = malloc(qlen*sizeof(*queue));
    long head = 1;
    long tail = 0;
    queue[0].x = 0;
    queue[0].y = 0;
    queue[0].d = 0;
    *maze_get(m, 0, 0) |= F_VISITED | F_QUEUED;

    struct image *im = image_create(m->width*scale + 2, m->height*scale + 2);

    long lastd = 0;
    while (head != tail) {
        int x = queue[tail].x;
        int y = queue[tail].y;
        int d = queue[tail].d;
        tail++;
        int w = *maze_get(m, x, y);
        *maze_get(m, x, y) &= ~F_QUEUED;

        static const int dir[] = {+0, -1, +1, +0, +0, +1, -1, +0};
        for (int i = 0; i < 4; i++) {
            int nx = x + dir[i*2 + 0];
            int ny = y + dir[i*2 + 1];
            if (maze_valid(m, nx, ny)) {
                int nw = *maze_get(m, nx, ny);
                if (!(nw & F_VISITED)) {
                    int r;
                    switch (i) {
                    case 0: r = !(nw & F_SOUTH); break;
                    case 1: r = !( w & F_EAST ); break;
                    case 2: r = !( w & F_SOUTH); break;
                    case 3: r = !(nw & F_EAST ); break;
                    }
                    if (r) {
                        *maze_get(m, nx, ny) |= F_VISITED | F_QUEUED;
                        queue[head].x = nx;
                        queue[head].y = ny;
                        queue[head].d = d + 1;
                        head++;
                    }
                }
            }
        }

        if (d > lastd) {
            image_fill(im, 0, 0, im->width, im->height, base);
            draw_mask(im, m, F_VISITED, scale, 0xffffff);
            draw_mask(im, m, F_QUEUED, scale, 0xff7f00);
            draw_walls(im, m, scale, 0x000000);
            image_write(im);
            draw_mask(im, m, F_QUEUED, scale, 0xff0000);
            draw_walls(im, m, scale, 0x000000);
            image_write(im);
            lastd = d;
        }
    }

    free(im);
    free(queue);
}

int
main(void)
{
#ifdef _WIN32
    int _setmode(int, int);
    _setmode(_fileno(stdout), 0x8000);
#endif

    r32s(time(0));

    int scale = 14;
    int width = 1920/scale;
    int height = 1080/scale;

    for (;;) {
        struct maze *m = maze_create(width, height);

        long final = kruskal(m, scale);

        flood(m, scale, final);

        struct image *im = image_create(width*scale + 2, height*scale + 2);
        image_fill(im, 0, 0, im->width, im->height, 0xffffff);
        draw_walls(im, m, scale, 0x000000);
        for (int i = 0; i < 3*60; i++) {
            image_write(im);
        }
        free(im);

        free(m);
    }
}
