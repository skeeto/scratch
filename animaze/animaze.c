/* Animated Kruskal maze generator and solver.
 * Usage:
 *   $ cc -O3 kruskal.c
 *   $ ./a.out | mpv --no-correct-pts --fps=60 --fs -
 *   $ ./a.out | x264 --fps=60 -o maze.mp4 /dev/stdin
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned long
r32(unsigned long long *s)
{
    *s = *s*0x7c3c3267d015ceb5ULL + 0x24bd2d95276253a9ULL;
    unsigned long r = *s>>32 & 0xffffffffUL;
    r ^= r>>16;
    r *= 0x60857ba9UL;
    return r & 0xffffffffUL;
}

static unsigned long
randint(unsigned long long *s, unsigned long r)
{
    unsigned long long x = r32(s);
    unsigned long long m = x * r;
    unsigned long y = m & 0xffffffffUL;
    if (y < r) {
        unsigned long t = -r % r;
        while (y < t) {
            x = r32(s);
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
        goto fail;
    if (!fwrite(im->buf, im->height*im->width*3, 1, stdout))
        goto fail;
    return;
fail:
    fprintf(stderr, "animaze: output error\n");
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
kruskal(struct maze *m, unsigned long long *rng, int scale)
{
    struct set *sets = malloc(sizeof(*sets)*m->width*m->height);
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            struct set *s = sets + y*m->width + x;
            s->parent = s;
            s->color = (r32(rng) & 0xffffffUL) | 0x404040UL;
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
        long i = randint(rng, nwalls);
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

            if (scale) {
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
    }
    long final = set_find(sets)->color;

    free(im);
    free(walls);
    free(sets);

    return final;
}

static long
depthfirst(struct maze *m, unsigned long long *rng, int scale)
{
    struct {
        int x;
        int y;
    } *stack = malloc(m->width*m->height*sizeof(*stack));
    stack[0].x = randint(rng, m->width);
    stack[0].y = randint(rng, m->height);
    *maze_get(m, stack[0].x, stack[0].y) |= F_VISITED;
    long nstack = 1;

    struct image *im = image_create(m->width*scale + 2, m->height*scale + 2);

    static const int dir[] = {+0, -1, +1, +0, +0, +1, -1, +0};
    while (nstack) {
        int x = stack[nstack - 1].x;
        int y = stack[nstack - 1].y;

        int dirs[4];
        int ndirs = 0;
        for (int i = 0; i < 4; i++) {
            int tx = x + dir[i*2 + 0];
            int ty = y + dir[i*2 + 1];
            if (maze_valid(m, tx, ty) && !(*maze_get(m, tx, ty) & F_VISITED)) {
                dirs[ndirs++] = i;
            }
        }

        int tx, ty, r = 0;
        switch (ndirs) {
        case 4:
        case 3:
        case 2:
            r = randint(rng, ndirs); /* fallthrough */
        case 1:
            tx = stack[nstack].x = x + dir[dirs[r]*2 + 0];
            ty = stack[nstack].y = y + dir[dirs[r]*2 + 1];
            nstack++;
            *maze_get(m, tx, ty) |= F_VISITED;
            switch (dirs[r]) {
            case 0: *maze_get(m, tx, ty) &= ~F_SOUTH; break;
            case 1: *maze_get(m,  x,  y) &= ~F_EAST;  break;
            case 2: *maze_get(m,  x,  y) &= ~F_SOUTH; break;
            case 3: *maze_get(m, tx, ty) &= ~F_EAST;  break;
            }
            break;
        case 0:
            nstack--;
            break;
        }

        if (scale) {
            for (int y = 0; y < m->height; y++) {
                for (int x = 0; x < m->width; x++) {
                    int px = 1 + x*scale;
                    int py = 1 + y*scale;
                    int visited = !!(*maze_get(m, x, y) & F_VISITED);
                    long color = visited ? 0xafafaf : 0xffffff;
                    image_fill(im, px, py, px + scale, py + scale, color);
                }
            }
            for (long i = 0; i < nstack; i++) {
                int px = 1 + stack[i].x*scale;
                int py = 1 + stack[i].y*scale;
                image_fill(im, px, py, px + scale, py + scale, 0x007fff);
            }
            draw_walls(im, m, scale, 0x000000);
            image_write(im);
        }
    }

    free(im);
    free(stack);

    return 0xafafaf;
}

struct coord {
    int x;
    int y;
    long d;
};

static struct coord
flood(struct maze *m, int x, int y, int scale, long base)
{
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            *maze_get(m, x, y) &= ~(F_VISITED | F_QUEUED);
        }
    }

    long qlen = m->width * m->height;
    struct coord *queue = malloc(qlen*sizeof(*queue));
    long head = 1;
    long tail = 0;
    queue[0].x = x;
    queue[0].y = y;
    queue[0].d = 0;
    *maze_get(m, x, y) |= F_VISITED | F_QUEUED;

    struct image *im = image_create(m->width*scale + 2, m->height*scale + 2);

    long lastd = 0;
    while (head != tail) {
        int x = queue[tail].x;
        int y = queue[tail].y;
        long d = queue[tail].d;
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

        if (scale && d > lastd) {
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

    struct coord end = queue[tail - 1];

    free(im);
    free(queue);

    return end;
}

static int optind = 1;
static int opterr = 1;
static int optopt;
static char *optarg;

static int
getopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    /* Reset? */
    if (optind == 0) {
        optind = 1;
        optpos = 1;
    }

    arg = argv[optind];
    if (arg && strcmp(arg, "--") == 0) {
        optind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        optopt = arg[optpos];
        if (!opt) {
            if (opterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], optopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                optarg = (char *)arg + optpos + 1;
                optind++;
                optpos = 1;
                return optopt;
            } else if (argv[optind + 1]) {
                optarg = (char *)argv[optind + 1];
                optind += 2;
                optpos = 1;
                return optopt;
            } else {
                if (opterr && *optstring != ':')
                    fprintf(stderr,
                            "%s: option requires an argument: %c\n",
                            argv[0], optopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                optind++;
                optpos = 1;
            }
            return optopt;
        }
    }
}

static int
parseint(char *s, int min, const char *name)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || v < min || v > INT_MAX || *end != 0) {
        fprintf(stderr, "animaze: invalid %s: %s\n", name, optarg);
        exit(EXIT_FAILURE);
    }
    return v;
}

static int
validhex(const char *s)
{
    int valid = 1;
    if (strlen(s) == 18 && s[0] == '0' && s[1] == 'x') {
        for (int i = 2; i < 18; i++) {
            if (!strchr("0123456789abcdef", s[i])) {
                valid = 0;
            }
        }
    } else {
        valid = 0;
    }
    return valid;
}

static unsigned long long
hash(void *buf, size_t len, unsigned long long key)
{
    unsigned char *p = buf;
    unsigned long long h = key;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x25b751109e05be63ULL;
    }
    h &= 0xffffffffffffffffULL;
    h >>= 32;
    h *= 0x2330e1453ed4b9b9ULL;
    return h;
}

static unsigned long long
genseed(void)
{
    unsigned long long seed = 0;

    time_t timeptr = time(0);
    seed = hash(&timeptr, sizeof(timeptr), seed);

    /* PIE */
    unsigned long long (*self)(void) = genseed;
    seed = hash(&self, sizeof(self), seed);

    /* ASLR */
    void *(*mallocptr)() = malloc;
    seed = hash(&mallocptr, sizeof(mallocptr), seed);

    /* Random stack gap */
    void *ptr = &ptr;
    seed = hash(&ptr, sizeof(ptr), seed);

    /* Jitter */
    for (int i = 0; i < 1000; i++) {
        unsigned long counter = 0;
        clock_t start = clock();
        while (clock() == start) {
            counter++;
        }
        seed = hash(&start, sizeof(start), seed);
        seed = hash(&counter, sizeof(counter), seed);
    }

    return seed;
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: animaze [OPTIONS] | ...\n");
    fprintf(f, "  -D         generate with depth first traversal \n");
    fprintf(f, "  -K         generate with Kruskal's algorithm [default]\n");
    fprintf(f, "  -h INT     maze height in cells\n");
    fprintf(f, "  -n INT     number of mazes (default: infinite)\n");
    fprintf(f, "  -q         disable animation\n");
    fprintf(f, "  -s INT     cell size in pixels\n");
    fprintf(f, "  -w INT     maze width in cells\n");
    fprintf(f, "  -x STRING  generation seed\n");
}

int
main(int argc, char *argv[])
{
    int scale = 14;
    int width = 1920/scale;
    int height = 1080/scale;
    int runs = 0;
    int animate = 1;
    long (*generator)(struct maze *, unsigned long long *, int) = kruskal;
    unsigned long long seed = 0;

#ifdef _WIN32
    int _setmode(int, int);
    _setmode(_fileno(stdout), 0x8000);
#endif

    int option;
    while ((option = getopt(argc, argv, "DKh:n:qs:w:x:")) != -1) {
        switch (option) {
        case 'D':
            generator = depthfirst;
            break;
        case 'K':
            generator = kruskal;
            break;
        case 'h':
            height = parseint(optarg, 1, "height");
            break;
        case 'n':
            runs = parseint(optarg, 0, "runs");
            break;
        case 'q':
            animate = 0;
            break;
        case 's':
            scale = parseint(optarg, 1, "scale");
            break;
        case 'w':
            width = parseint(optarg, 1, "width");
            break;
        case 'x':
            if (validhex(optarg)) {
                seed = strtoull(optarg + 2, 0, 16);
            } else {
                seed = hash(optarg, strlen(optarg), 0x4a3fe5e49100be41ULL);
            }
            break;
        default:
            usage(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (argv[optind]) {
        fprintf(stderr, "animaze: too many arguments\n");
        usage(stderr);
        exit(EXIT_FAILURE);
    }

    if (!seed) {
        seed = genseed();
    }

    unsigned long long best_seed = 0;
    long best_dist = 0;

    for (;;) {
        unsigned long long save = seed;
        struct maze *m = maze_create(width, height);
        long final = generator(m, &seed, animate ? scale : 0);

        struct coord beg = flood(m, 0, 0, 0, 0);
        struct coord end = flood(m, beg.x, beg.y, animate ? scale : 0, final);

        if (end.d > best_dist) {
            best_seed = save;
            best_dist = end.d;
            if (!animate) {
                fprintf(stderr, "seed=0x%016llx, dist=%ld, remain=%d\n",
                        save, end.d, runs);
            }
        }

        if (animate) {
            int pw = width*scale + 2;
            int ph = height*scale + 2;
            struct image *im = image_create(pw, ph);
            image_fill(im, 0, 0, im->width, im->height, 0xffffff);
            draw_walls(im, m, scale, 0x000000);
            for (int i = 0; i < 3*60; i++) {
                image_write(im);
            }
            free(im);
        }

        free(m);

        if (runs > 0 && !--runs) {
            break;
        }
    }

    if (!animate) {
        struct maze *m = maze_create(width, height);
        generator(m, &best_seed, 0);
        struct coord beg = flood(m, 0, 0, 0, 0);
        struct coord end = flood(m, beg.x, beg.y, 0, 0);

        struct image *im = image_create(width*scale + 2, height*scale + 2);
        image_fill(im, 0, 0, im->width, im->height, 0xffffff);
        {
            int px = 1 + beg.x*scale;
            int py = 1 + beg.y*scale;
            image_fill(im, px, py, px + scale, py + scale, 0xff7fff);
        }
        {
            int px = 1 + end.x*scale;
            int py = 1 + end.y*scale;
            image_fill(im, px, py, px + scale, py + scale, 0xff7fff);
        }
        draw_walls(im, m, scale, 0x000000);
        image_write(im);
        free(im);
    }
}
