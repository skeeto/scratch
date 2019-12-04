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

/* rng */

static unsigned long long
hash(const void *buf, size_t len, unsigned long long key)
{
    const unsigned char *p = buf;
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

struct rng {
    unsigned long long s;
};

static struct rng
rng_create(void)
{
    unsigned long long seed = 0;

    time_t timeptr = time(0);
    seed = hash(&timeptr, sizeof(timeptr), seed);

    /* PIE */
    struct rng (*self)(void) = rng_create;
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

    return (struct rng){seed};
}

static struct rng
rng_seed(const char *str)
{
    unsigned long long seed = hash(str, strlen(str), 0x4a3fe5e49100be41ULL);
    return (struct rng){seed};
}

static unsigned long
rng_u32(struct rng *rng)
{
    rng->s = rng->s*0x7c3c3267d015ceb5ULL + 0x24bd2d95276253a9ULL;
    unsigned long r = rng->s>>32 & 0xffffffffUL;
    r ^= r>>16;
    r *= 0x60857ba9UL;
    return r & 0xffffffffUL;
}

static unsigned long
rng_range(struct rng *rng, unsigned long r)
{
    unsigned long long x = rng_u32(rng);
    unsigned long long m = x * r;
    unsigned long y = m & 0xffffffffUL;
    if (y < r) {
        unsigned long t = -r % r;
        while (y < t) {
            x = rng_u32(rng);
            m = x * r;
            y = m & 0xffffffffUL;
        }
    }
    return m >> 32;
}

/* image */

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

/* maze */

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

static void
maze_reset(struct maze *m)
{
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            *maze_get(m, x, y) = F_SOUTH | F_EAST;
        }
    }
}

static int
maze_valid(struct maze *m, int x, int y)
{
    return x >= 0 && x < m->width && y >= 0 && y < m->height;
}

/* maze renderer */

struct render {
    struct maze *maze;
    enum {RENDER_NULL, RENDER_PPM} type;
    union {
        struct {
            int scale;
            struct image *image;
        } ppm;
    };
};

static struct render render_null = {0};

static void
render_ppm(struct render *r, struct maze *m, int scale)
{
    r->maze = m;
    r->type = RENDER_PPM;
    r->ppm.scale = scale;
    r->ppm.image = image_create(m->width*scale + 2, m->height*scale + 2);
}

static void
render_free(struct render *r)
{
    switch (r->type) {
    case RENDER_NULL:
        break;
    case RENDER_PPM:
        free(r->ppm.image);
        r->ppm.image = 0;
        break;
    }
}

static void
render_cell(struct render *r, int x, int y, long color)
{
    int scale, px, py;
    switch (r->type) {
    case RENDER_NULL:
        break;
    case RENDER_PPM:
        scale = r->ppm.scale;
        px = 1 + x*scale;
        py = 1 + y*scale;
        image_fill(r->ppm.image, px, py, px + scale, py + scale, color);
        break;
    }
}

static void
render_clear(struct render *r, long color)
{
    struct maze *m = r->maze;
    if (m) {
        for (int y = 0; y < m->height; y++) {
            for (int x = 0; x < m->width; x++) {
                render_cell(r, x, y, color);
            }
        }
    }
}

static void
render_walls_ppm(struct image *im, struct maze *m, int scale, long color)
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
render_walls(struct render *r, long color)
{
    switch (r->type) {
    case RENDER_NULL:
        break;
    case RENDER_PPM:
        render_walls_ppm(r->ppm.image, r->maze, r->ppm.scale, color);
        break;
    }
}

static void
render_flush(struct render *r)
{
    switch (r->type) {
    case RENDER_NULL:
        break;
    case RENDER_PPM:
        image_write(r->ppm.image);
        break;
    }
}

/* disjoint forest */

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

/* maze generators */

static long
kruskal(struct maze *m, struct render *r, struct rng *rng)
{
    struct set *sets = malloc(sizeof(*sets)*m->width*m->height);
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            struct set *s = sets + y*m->width + x;
            s->parent = s;
            s->color = (rng_u32(rng) & 0xffffffUL) | 0x404040UL;
            s->size = 1;
        }
    }

    struct {
        int x;
        int y;
        int which;
    } *walls = malloc(sizeof(*walls)*m->width*m->height*2);
    long nwalls = 0;

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
        long i = rng_range(rng, nwalls);
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
                    render_cell(r, x, y, set_find(s)->color);
                }
            }
            render_walls(r, 0x000000);
            render_flush(r);
        }
    }
    long final = set_find(sets)->color;

    free(walls);
    free(sets);

    return final;
}

static long
depthfirst(struct maze *m, struct render *r, struct rng *rng)
{
    struct {
        int x;
        int y;
    } *stack = malloc(m->width*m->height*sizeof(*stack));
    stack[0].x = rng_range(rng, m->width);
    stack[0].y = rng_range(rng, m->height);
    *maze_get(m, stack[0].x, stack[0].y) |= F_VISITED;
    long nstack = 1;

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

        int tx, ty, roll = 0;
        switch (ndirs) {
        case 4:
        case 3:
        case 2:
            roll = rng_range(rng, ndirs); /* fallthrough */
        case 1:
            tx = stack[nstack].x = x + dir[dirs[roll]*2 + 0];
            ty = stack[nstack].y = y + dir[dirs[roll]*2 + 1];
            nstack++;
            *maze_get(m, tx, ty) |= F_VISITED;
            switch (dirs[roll]) {
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

        for (int y = 0; y < m->height; y++) {
            for (int x = 0; x < m->width; x++) {
                int visited = !!(*maze_get(m, x, y) & F_VISITED);
                long color = visited ? 0xafafaf : 0xffffff;
                render_cell(r, x, y, color);
            }
        }
        for (long i = 0; i < nstack; i++) {
            render_cell(r, x, y, 0x007fff);
        }
        render_walls(r, 0x000000);
        render_flush(r);
    }

    free(stack);

    return 0xafafaf;
}

/* maze solvers */

static void
draw_mask(struct render *r, struct maze *m, int mask, long color)
{
    for (int y = 0; y < m->height; y++) {
        for (int x = 0; x < m->width; x++) {
            if (*maze_get(m, x, y) & mask) {
                render_cell(r, x, y, color);
            }
        }
    }
}

struct coord {
    int x;
    int y;
    long d;
};

static struct coord
flood(struct maze *m, struct render *r, int x, int y, long base)
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
                    int v = 0;
                    switch (i) {
                    case 0: v = !(nw & F_SOUTH); break;
                    case 1: v = !( w & F_EAST ); break;
                    case 2: v = !( w & F_SOUTH); break;
                    case 3: v = !(nw & F_EAST ); break;
                    }
                    if (v) {
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
            render_clear(r, base);
            draw_mask(r, m, F_VISITED, 0xffffff);
            draw_mask(r, m, F_QUEUED, 0xff7f00);
            render_walls(r, 0x000000);
            render_flush(r);
            draw_mask(r, m, F_QUEUED, 0xff0000);
            render_walls(r, 0x000000);
            render_flush(r);
            lastd = d;
        }
    }

    struct coord end = queue[tail - 1];

    free(queue);

    return end;
}

/* option parsing */

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
    int seeded = 0;
    struct rng rng;
    long (*generate)(struct maze *, struct render *, struct rng *) = kruskal;

#ifdef _WIN32
    int _setmode(int, int);
    _setmode(_fileno(stdout), 0x8000);
#endif

    int option;
    while ((option = getopt(argc, argv, "DKh:n:qs:w:x:")) != -1) {
        switch (option) {
        case 'D':
            generate = depthfirst;
            break;
        case 'K':
            generate = kruskal;
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
                rng.s = strtoull(optarg + 2, 0, 16);
            } else {
                rng = rng_seed(optarg);
            }
            seeded = 1;
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

    if (!seeded) {
        rng = rng_create();
    }

    struct maze *maze = maze_create(width, height);

    struct render render = render_null;
    if (animate) {
        render_ppm(&render, maze, scale);
    }

    struct rng best_rng;
    long best_dist = 0;
    for (;;) {
        struct rng save = rng;
        long final = generate(maze, &render, &rng);

        struct coord beg = flood(maze, &render_null, 0, 0, 0);
        struct coord end = flood(maze, &render, beg.x, beg.y, final);

        if (end.d > best_dist) {
            best_rng = save;
            best_dist = end.d;
            if (!animate) {
                fprintf(stderr, "seed=0x%016llx, dist=%ld, remain=%d\n",
                        save.s, end.d, runs);
            }
        }

        if (animate) {
            render_clear(&render, 0xffffff);
            render_walls(&render, 0x000000);
            for (int i = 0; i < 3*60; i++) {
                render_flush(&render);
            }
        }

        if (runs > 0 && !--runs) {
            break;
        }
        maze_reset(maze);
    }

    if (!animate) {
        maze_reset(maze);
        generate(maze, &render_null, &best_rng);

        struct coord beg = flood(maze, &render_null, 0, 0, 0);
        struct coord end = flood(maze, &render_null, beg.x, beg.y, 0);

        struct render ppm;
        render_ppm(&ppm, maze, scale);
        render_clear(&ppm, 0xffffff);
        render_cell(&ppm, beg.x, beg.y, 0xff7fff);
        render_cell(&ppm, end.x, end.y, 0xff7fff);
        render_walls(&ppm, 0x000000);
        render_flush(&ppm);
        render_free(&ppm);
    }

    render_free(&render);
    free(maze);
}
