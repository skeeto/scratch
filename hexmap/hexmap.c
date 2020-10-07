/* Hexagon grid bitmap renderer
 *   $ cc -Ofast -o hexmap hexmap.c -lm
 *   $ hexmap >output.bmp
 * This is free and unencumbered software released into the public domain.
 */
#define BMP_COMPAT
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "bmp.h"
#include "getopt.h"

static long
blend(long c0, long c1, float a)
{
    float r0 = ((c0 >> 16)       ) / 255.0f;
    float g0 = ((c0 >>  8) & 0xff) / 255.0f;
    float b0 = ((c0 >>  0) & 0xff) / 255.0f;
    float r1 = ((c1 >> 16)       ) / 255.0f;
    float g1 = ((c1 >>  8) & 0xff) / 255.0f;
    float b1 = ((c1 >>  0) & 0xff) / 255.0f;
    float r = r0*a + r1*(1 - a);
    float g = g0*a + g1*(1 - a);
    float b = b0*a + b1*(1 - a);
    return (long)roundf(r*255) << 16 |
           (long)roundf(g*255) <<  8 |
           (long)roundf(b*255) <<  0;
}

static void
swap(float *a, float *b)
{
    float t = *a;
    *a = *b;
    *b = t;
}

static float
fpart(float x)
{
    return x - floorf(x);
}

static float
rfpart(float x)
{
    return 1 - fpart(x);
}

struct image {
    int w;
    int h;
    size_t len;
    unsigned char buf[];
};

struct image *
image_create(int w, int h)
{
    size_t len = bmp_size(w, h);
    if (!len) return 0;
    struct image *m = calloc(1, sizeof(*m) + len);
    if (!m) return 0;
    bmp_init(m->buf, w, h);
    m->w = w;
    m->h = h;
    m->len = len;
    return m;
}

static int
image_dump(struct image *m, FILE *f)
{
    return fwrite(m->buf, m->len, 1, f) && !fflush(f);
}

static void
image_set(struct image *m, int x, int y, long color)
{
    if (x < 0 || x >= m->w || y < 0 || y >= m->h) return;
    bmp_set(m->buf, x, y, color);
}

static long
image_get(struct image *m, int x, int y)
{
    if (x < 0 || x >= m->w || y < 0 || y >= m->h) {
        return 0x000000;
    }
    return bmp_get(m->buf, x, y);
}

static void
image_fill(struct image *m, long color)
{
    int x, y;
    for (y = 0; y < m->h; y++) {
        for (x = 0; x < m->w; x++) {
            bmp_set(m->buf, x, y, color);
        }
    }
}

static void
image_plot(struct image *m, int x, int y, long color, float a)
{
    image_set(m, x, y, blend(color, image_get(m, x, y), a));
}

static void
image_line(struct image *m, float x0, float y0, float x1, float y1, long color)
{
    int steep, xpxl1, ypxl1, xpxl2, ypxl2, x;
    float xend, yend, xgap, dx, dy, gradient, intery;

    steep = fabsf(y1 - y0) > fabsf(x1 - x0);
    if (steep) {
        swap(&x0, &y0);
        swap(&x1, &y1);
    }
    if (x0 > x1) {
        swap(&x0, &x1);
        swap(&y0, &y1);
    }

    dx = x1 - x0;
    dy = y1 - y0;
    gradient = dx == 0.0f ? 1.0f : dy / dx;

    xend = roundf(x0);
    yend = y0 + gradient*(xend - x0);
    xgap = rfpart(x0 + 0.5f);
    xpxl1 = xend;
    ypxl1 = floorf(yend);
    if (steep) {
        image_plot(m, ypxl1,   xpxl1, color, rfpart(yend) * xgap);
        image_plot(m, ypxl1+1, xpxl1, color,  fpart(yend) * xgap);
    } else {
        image_plot(m, xpxl1, ypxl1,   color, rfpart(yend) * xgap);
        image_plot(m, xpxl1, ypxl1+1, color,  fpart(yend) * xgap);
    }
    intery = yend + gradient;

    xend = roundf(x1);
    yend = y1 + gradient*(xend - x1);
    xgap = fpart(x1 + 0.5f);
    xpxl2 = xend;
    ypxl2 = floorf(yend);
    if (steep) {
        image_plot(m, ypxl2  , xpxl2, color, rfpart(yend) * xgap);
        image_plot(m, ypxl2+1, xpxl2, color,  fpart(yend) * xgap);
    } else {
        image_plot(m, xpxl2, ypxl2,   color, rfpart(yend) * xgap);
        image_plot(m, xpxl2, ypxl2+1, color,  fpart(yend) * xgap);
    }

    if (steep) {
        for (x = xpxl1 + 1; x <= xpxl2 - 1; x++) {
            image_plot(m, floorf(intery),   x, color, rfpart(intery));
            image_plot(m, floorf(intery)+1, x, color,  fpart(intery));
            intery += gradient;
        }
    } else {
        for (x = xpxl1 + 1; x <= xpxl2 - 1; x++) {
            image_plot(m, x, floorf(intery),   color, rfpart(intery));
            image_plot(m, x, floorf(intery)+1, color,  fpart(intery));
            intery += gradient;
        }
    }
}

static void
hex_corner(float x, float y, float size, int i, float *cx, float *cy)
{
    float a = 3.14159265359f / 180 * 60 * i;
    *cx = x + size*cosf(a);
    *cy = y + size*sinf(a);
}

static void
image_hex(struct image *m, float x, float y, float size, long color)
{
    float x0, y0, x1, y1;
    hex_corner(x, y, size, 3, &x0, &y0);
    for (int i = 4; i < 7; i++) {
        hex_corner(x, y, size, i%6, &x1, &y1);
        image_line(m, x0, y0, x1, y1, color);
        x0 = x1;
        y0 = y1;
    }
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: hexmap [-f HEX] [-b HEX] [-h] [-s W:H:S]\n");
}

int
main(int argc, char **argv)
{
    int w = 30;
    int h = 20;
    long foreground = 0x000000;
    long background = 0xffffff;
    float size = 25;

    int option;
    while ((option = getopt(argc, argv, "b:f:hs:")) != -1) {
        switch (option) {
        case 'b':
            background = strtol(optarg, 0, 16) & 0xffffff;
            break;
        case 'f':
            foreground = strtol(optarg, 0, 16) & 0xffffff;
            break;
        case 'h':
            usage(stdout);
            exit(0);
            break;
        case 's':
            if (sscanf(optarg, "%d:%d:%f", &w, &h, &size) != 3 ||
                    w <= 0 || h <= 0 || size <= 0) {
                fprintf(stderr, "hexmap: invalid dimensions, %s\n", optarg);
                usage(stdout);
                exit(1);
            }
            break;
        default:
            usage(stderr);
            exit(1);
        }
    }

    int mw = size/2 + w*1.5f*size;
    int mh = sqrtf(3)/2*size + h*sqrtf(3)*size;
    struct image *m = image_create(mw, mh);
    if (!m) {
        fprintf(stderr, "hexmap: image dimensions too large\n");
        exit(1);
    }

    image_fill(m, background);
    for (int x = -1; x < w + 1; x++) {
        float hx = 2*size/2 + x*1.5f*size;
        for (int y = -1; y < h + 1; y++) {
            float hy = sqrtf(3)/2*size + y*sqrtf(3)*size;
            if (x % 2) {
                hy += sqrtf(3)/2*size;
            }
            image_hex(m, hx, hy, size, foreground);
        }
    }

#if defined(_WIN32)
    int _setmode(int, int);
    _setmode(1, 0x8000);
#elif defined(__MSDOS__)
    int setmode(int, int);
    setmode(1, 0x0004);
#endif
    image_dump(m, stdout);

    free(m);
    return 0;
}
