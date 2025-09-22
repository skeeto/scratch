/* AI race car drivers
 * $ cc -Ofast -march=native -fopenmp -o aidrivers aidrivers.c -lm
 * $ ./aidrivers <map.ppm | mpv --no-correct-pts --fps=60 -
 * $ ./aidrivers <map.ppm | x264 --fps=60 -o out.mp4 --frames 3600 /dev/stdin
 *
 * Input image format: road is black (000000), barriers are white (ffffff),
 * cars start on the green pixel (00ff00) aimed at the blue (0000ff) pixel.
 *
 * Ref: https://nullprogram.com/video/?v=aidrivers
 * Ref: https://nullprogram.com/video/?v=aidrivers2
 * Ref: https://www.youtube.com/watch?v=-sg-GgoFCP0
 */
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PI 0x1.921fb6p+1f

struct sysconf {
    float speedmin, speedmax;
    float control;     /* maximum turn per step */
};

struct config {
    float c[2];
};

struct vehicle {
    float x, y, a;
    long color;
};

struct map {
    int w, h;
    int sx, sy;
    float sa;
    unsigned long d[];
};

struct ppm {
    int w, h;
    unsigned char d[];
};

static const struct sysconf defaultcfg = {
    .speedmin = 0.1f,
    .speedmax = 0.5f,
    .control = PI/128,
};

static unsigned long
u32(unsigned long long *s)
{
    *s = *s*0xbaba2efc33c35f55 + 0xa3761c93eae8450f;
    return *s>>32 & 0xffffffff;
}

static struct ppm *
ppm_create(int w, int h)
{
    struct ppm *f = malloc(sizeof(*f) + 3L*w*h);
    f->w = w;
    f->h = h;
    return f;
}

static struct ppm *
ppm_read(FILE *fin)
{
    int w, h;
    if (fscanf(fin, "P6 %u%u%*d%*c", &w, &h) < 2) {
        return 0;
    }
    struct ppm *f = ppm_create(w, h);
    fread(f->d, 3L*w*h, 1, fin);
    return f;
}

static void
ppm_write(struct ppm *f)
{
    printf("P6\n%d %d\n255\n", f->w, f->h);
    if (!fwrite(f->d, 3L*f->w*f->h, 1, stdout)) exit(EXIT_FAILURE);
}

static void
ppm_copy(struct ppm *dst, struct ppm *src)
{
    memcpy(dst->d, src->d, 3L*dst->w*dst->h);
}

static void
ppm_put(struct ppm *f, int x, int y, long c)
{
    f->d[3L*y*f->w + 3L*x + 0] = c >> 16;
    f->d[3L*y*f->w + 3L*x + 1] = c >>  8;
    f->d[3L*y*f->w + 3L*x + 2] = c >>  0;
}

static long
ppm_get(struct ppm *f, int x, int y)
{
    return (long)f->d[3L*y*f->w + 3L*x + 0] << 16 |
           (long)f->d[3L*y*f->w + 3L*x + 1] <<  8 |
           (long)f->d[3L*y*f->w + 3L*x + 2] <<  0;
}

static int
map_get(struct map *m, int x, int y)
{
    long i = (long)y*m->w + x;
    long b = 8 * sizeof(m->d[0]);
    return m->d[i/b]>>(i % b) & 1;
}

static struct map *
ppm_to_map(struct ppm *f)
{
    struct map *m;
    long b = 8 * sizeof(m->d[0]);
    m = calloc(1, sizeof(*m) + ((long)f->w*f->h + b - 1)/b*sizeof(m->d[0]));
    m->w = f->w;
    m->h = f->h;
    m->sx = m->w / 2;
    m->sy = m->h / 2;
    m->sa = 0;

    for (int y = 0; y < f->h; y++) {
        for (int x = 0; x < f->w; x++) {
            long c = ppm_get(f, x, y);
            if (c == 0x00ff00) {
                m->sx = x;
                m->sy = y;
            }
        }
    }

    for (int y = 0; y < f->h; y++) {
        for (int x = 0; x < f->w; x++) {
            long c = ppm_get(f, x, y);
            if (c == 0x0000ff) {
                m->sa = atan2f(y - m->sy, x - m->sx);
            }
        }
    }

    for (int y = 0; y < f->h; y++) {
        for (int x = 0; x < f->w; x++) {
            long c = ppm_get(f, x, y);
            unsigned long v = c>>16 > 0x7f;
            long i = (long)y*f->w + x;
            m->d[i/b] |= v << (i % b);
        }
    }

    return m;
}

static void
draw_map(struct ppm *f, struct map *m)
{
    int s = f->w / m->w;
    for (int y = 0; y < f->h; y++) {
        for (int x = 0; x < f->w; x++) {
            long c = map_get(m, x/s, y/s) ? 0xffffff : 0x000000;
            ppm_put(f, x, y, c);
        }
    }
}

static void
draw_vehicles(struct ppm *f, struct map *m, struct vehicle *v, int n)
{
    int s = f->w / m->w;
    for (int i = 0; i < n; i++) {
        for (int d = -s*2; d < s*2; d++) {
            for (int j = -s/2; j < s/2; j++) {
                float x = s*v[i].x + j*cosf(v[i].a - PI/2) + d*cosf(v[i].a)/2;
                float y = s*v[i].y + j*sinf(v[i].a - PI/2) + d*sinf(v[i].a)/2;
                ppm_put(f, x, y, v[i].color);
            }
        }
    }
}

static float
sense(float x, float y, float a, struct map *m, struct ppm *f)
{
    float dx = cosf(a);
    float dy = sinf(a);
    int d = 1;
    for (;; d++) {
        float bx = x + dx*d;
        float by = y + dy*d;
        int ix = bx;
        int iy = by;
        if (ix < 0 || ix >= m->w || iy < 0 || iy >= m->h) {
            break;
        }
        if (map_get(m, ix, iy)) {
            break;
        }
        if (f) {
            int s = f->w / m->w;
            for (int py = 0; py < s; py++) {
                for (int px = 0; px < s; px++) {
                    ppm_put(f, ix*s + px, iy*s + py, 0xff0000);
                }
            }
        }
    }
    return sqrtf(d*dx*d*dx + d*dy*d*dy);
}

static int
alive(struct vehicle *v, struct map *m)
{
    return !map_get(m, v->x, v->y);
}

static int
drive(struct vehicle *v, struct config *c, struct map *m, struct sysconf *cfg)
{
    if (!alive(v, m)) return 0;

    float s[3];
    static const float angles[] = {PI/-4, 0, PI/+4};
    for (int i = 0; i < 3; i++) {
        s[i] = sense(v->x, v->y, v->a + angles[i], m, 0);
    }

    float steering = s[2]*c->c[0] - s[0]*c->c[0];
    float throttle = s[1]*c->c[1];
    throttle = throttle < cfg->speedmin ? cfg->speedmin :
               throttle > cfg->speedmax ? cfg->speedmax : throttle;
    v->a += fabsf(steering) > cfg->control ?
                copysignf(cfg->control, steering) : steering;
    v->x += throttle*cosf(v->a);
    v->y += throttle*sinf(v->a);

    return 1;
}

static void
draw_beams(struct ppm *f, struct map *m, struct vehicle *v, int n)
{
    for (int i = 0; i < n; i++) {
        sense(v[i].x, v[i].y, v[i].a - PI/4, m, f);
        sense(v[i].x, v[i].y, v[i].a,        m, f);
        sense(v[i].x, v[i].y, v[i].a + PI/4, m, f);
    }
}

static void
randomize(struct config *c, unsigned long long *rng)
{
    c->c[0] = 1.0f * ldexpf(u32(rng), -32);
    c->c[1] = 0.1f * ldexpf(u32(rng), -32);
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

static void
usage(FILE *f)
{
    fprintf(f, "usage aidrivers <map.ppm [-abcdehkmMnsvx]\n");
    fprintf(f, "  -a INT   simulation steps per frame\n");
    fprintf(f, "  -b       show vehicle vision beams\n");
    fprintf(f, "  -c DIV   control divisor (turning limiter)\n");
    fprintf(f, "  -d INT   initial time steps to skip rendering\n");
    fprintf(f, "  -e       erase crashed vehicles\n");
    fprintf(f, "  -h       print this help information\n");
    fprintf(f, "  -k       kill vehicles when they crash (no reset)\n");
    fprintf(f, "  -m FLOAT minimum speed (%g)\n", defaultcfg.speedmin);
    fprintf(f, "  -M FLOAT maximum speed (%g)\n", defaultcfg.speedmax);
    fprintf(f, "  -n INT   number of vehicles to simulate\n");
    fprintf(f, "  -s INT   input-to-output image scaling\n");
    fprintf(f, "  -v FILE  render on the given overlay\n");
    fprintf(f, "  -x SEED  seed from any string\n");
}

static unsigned long long
hash(void *buf, size_t len, unsigned long long key)
{
    unsigned long long h = 0x838df1d269099c13 ^ key;
    unsigned char *p = buf;
    while (len--) {
        h ^= *p++;
        h *= 0xd467c4c34e0067a1;
    }
    return h ^ h>>32;
}

int
main(int argc, char *argv[])
{
    int scale = 12;
    int nvehicle = 16;
    int frameskip = 1;
    int drop = 0;
    int erase = 0;
    int reset = 1;
    int beams = 0;
    const char *overlayfile = 0;
    struct {time_t a; int (*b)(int, char **); void *c;} seed = {time(0), main, &seed};
    unsigned long long rng[1] = {hash(&seed, sizeof(seed), 0)};
    struct sysconf cfg = defaultcfg;

    int option;
    while ((option = getopt(argc, argv, "a:bc:d:ehkm:M:n:s:v:x:")) != -1) {
        switch (option) {
        case 'a': frameskip = atoi(optarg); break;
        case 'b': beams = 1; break;
        case 'c': cfg.control = PI / atoi(optarg); break;
        case 'd': drop = atoi(optarg); break;
        case 'e': erase = 1; break;
        case 'h': usage(stdout); exit(EXIT_SUCCESS);
        case 'k': reset = 0; break;
        case 'm': cfg.speedmin = atof(optarg); break;
        case 'M': cfg.speedmax = atof(optarg); break;
        case 'n': nvehicle = atoi(optarg); break;
        case 's': scale = atoi(optarg); break;
        case 'v': overlayfile = optarg; break;
        case 'x': *rng = hash(optarg, strlen(optarg), 0); break;
        default: usage (stderr); exit(EXIT_FAILURE);
        }
    }

    struct vehicle *v = malloc(nvehicle*sizeof(*v));
    struct config *c = malloc(nvehicle*sizeof(*c));

#ifdef _WIN32
    /* Set stdin/stdout to binary mode. */
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
#endif

    struct ppm *f = ppm_read(stdin);
    struct map *m = ppm_to_map(f);
    struct ppm *out;
    struct ppm *overlay;
    if (overlayfile) {
        FILE *fin = fopen(overlayfile, "rb");
        if (!fin) {
            fprintf(stderr, "file not found: %s\n", overlayfile);
            exit(EXIT_FAILURE);
        }
        overlay = ppm_read(fin);
        fclose(fin);
        out = ppm_create(overlay->w, overlay->h);
    } else {
        overlay = ppm_create(f->w*scale, f->h*scale);
        draw_map(overlay, m);
        out = ppm_create(f->w*scale, f->h*scale);
    }

    for (int i = 0; i < nvehicle; i++) {
        randomize(c+i, rng);
    }

    for (int i = 0; i < nvehicle; i++) {
        v[i].x = m->sx;
        v[i].y = m->sy;
        v[i].a = m->sa;
        v[i].color = u32(rng)>>8 | 0x404040;
    }

    for (long long t = 0; ; t++) {
        if (t >= drop && t % frameskip == 0) {
            ppm_copy(out, overlay);
            if (beams) {
                draw_beams(out, m, v, nvehicle);
            }
            draw_vehicles(out, m, v, nvehicle);
            ppm_write(out);
        }

        #pragma omp parallel for
        for (int i = 0; i < nvehicle; i++) {
            drive(v+i, c+i, m, &cfg);
        }

        for (int i = 0; i < nvehicle; i++) {
            if (!alive(v+i, m)) {
                if (!erase) {
                    draw_vehicles(overlay, m, v+i, 1);
                }
                if (reset) {
                    randomize(c+i, rng);
                    v[i].x = m->sx;
                    v[i].y = m->sy;
                    v[i].a = m->sa;
                } else {
                    nvehicle--;
                    v[i] = v[nvehicle];
                    c[i] = c[nvehicle];
                    i--;
                }
            }
        }
        if (!nvehicle) {
            break;
        }
    }
}
