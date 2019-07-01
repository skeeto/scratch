/* Create barcode images from a video
 * $ c99 -O3 -o barcode barcode.c
 * $ ffmpeg -i IN.mp4 -f image2pipe -vcodec ppm pipe:1 | ./barcode > OUT.ppm
 * $ convert OUT.ppm -resize 1920x1080! FINAL.jpg
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
static void io_init(void) { _setmode(_fileno(stdin), _O_BINARY); }
#else
static void io_init(void) {}
#endif

struct frame {
    size_t width;
    size_t height;
    unsigned char data[];
};

static struct frame *
frame_create(size_t width, size_t height)
{
    struct frame *f = malloc(sizeof(*f) + width * height * 3);
    f->width = width;
    f->height = height;
    return f;
}

static struct frame *
frame_read(struct frame *f)
{
    size_t width, height;
    if (scanf("P6 %zu%zu%*d%*c", &width, &height) < 2) {
        free(f);
        return 0;
    }
    if (!f || f->width != width || f->height != height) {
        free(f);
        f = frame_create(width, height);
    }
    fread(f->data, width * height, 3, stdin);
    return f;
}

int
main(void)
{
    size_t width = 0;
    size_t height = 0;
    size_t capacity = 0;
    struct frame *frame = 0;
    unsigned char *barcode = 0;

    /* The barcode image is constructed transposed, which makes growing
     * the image with realloc() trivial. It's transposed into the
     * correct orientation later as it's written out.
     */

    io_init();
    while ((frame = frame_read(frame))) {
        /* Grow barcode image? */
        if (width == capacity) {
            capacity = capacity ? capacity * 2 : 1;
            barcode = realloc(barcode, capacity * frame->height * 3);
        }

        /* Resize frame to 1 pixel wide and append to barcode */
        for (size_t y = 0; y < frame->height; y++) {
            double p[3] = {0};
            int hist[3][256] = {0};
            unsigned char *i = frame->data + y * frame->width * 3;
            unsigned char *o = barcode + width * frame->height * 3 + y * 3;
            for (size_t x = 0; x < frame->width; x++) {
                hist[0][i[x * 3 + 0]]++;
                hist[1][i[x * 3 + 1]]++;
                hist[2][i[x * 3 + 2]]++;
            }
            for (int i = 1; i < 256; i++) {
                p[0] += (double)i * hist[0][i] / frame->width;
                p[1] += (double)i * hist[1][i] / frame->width;
                p[2] += (double)i * hist[2][i] / frame->width;
            }
            o[0] = round(p[0]);
            o[1] = round(p[1]);
            o[2] = round(p[2]);
        }
        width++;
        height = frame->height;
    }

    /* Transpose and write out image */
    printf("P6\n%zu %zu\n255\n", width, height);
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            putchar(barcode[x * height * 3 + y * 3 + 0]);
            putchar(barcode[x * height * 3 + y * 3 + 1]);
            putchar(barcode[x * height * 3 + y * 3 + 2]);
        }
    }
    free(barcode);
}
