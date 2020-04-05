/* Manhattan distance Voronoi diagram animation
 * $ cc -O3 -o voronoi voronoi.c
 * $ ./voronoi | mpv --no-correct-pts --fps=30 -
 * $ ./voronoi | x264 -o voronoi.mp4 /dev/stdin
 * Ref: https://redd.it/fuy6tk
 * Ref: https://nullprogram.com/video/?v=voronoi
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define W 1920
#define H 1080
#define N 256
#define FPS 30

int
main(void)
{
#ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
#endif

    long freelist = 0;
    static struct {
        int16_t x, y;
        int32_t next;
    } nodes[W*H];
    for (long i = 0; i < W*H - 1; i++) nodes[i].next  = i + 1;
    nodes[W*H-1].next = -1;

    srand(time(0) ^ ((uint64_t)clock()*0xfc5434fdb4a9e74d));
    static struct {
        int16_t x, y;
        int32_t head, tail;
        uint32_t color;
    } seeds[N];
    for (int i = 0; i < N; i++) {
        int n = seeds[i].head = seeds[i].tail = freelist;
        freelist = nodes[freelist].next;
        nodes[n].x = seeds[i].x = rand() % W;
        nodes[n].y = seeds[i].y = rand() % H;
        nodes[n].next = -1;
        seeds[i].color = (uint32_t)(rand()&0xff | 0x40) << 16 |
                         (uint32_t)(rand()&0xff | 0x40) <<  8 |
                         (uint32_t)(rand()&0xff | 0x40) <<  0;
    }

    for (long len = 0; ; len++) {
        int count = 0;
        static int map[H][W];
        static unsigned char buf[W*H*3];

        for (int i = 0; i < N; i++) {
            while (seeds[i].head != -1) {
                count++;
                int x = nodes[seeds[i].head].x;
                int y = nodes[seeds[i].head].y;
                long dist = abs(x - seeds[i].x) + abs(y - seeds[i].y);
                if (dist > len) break;

                long dead = seeds[i].head;
                seeds[i].head = nodes[dead].next;
                nodes[dead].next = freelist;
                freelist = dead;
                if (seeds[i].head == -1) seeds[i].tail = -1;

                if (x < 0 || x == W || y < 0 || y == H) {
                    continue;
                } else if (map[y][x]) {
                    if (map[y][x] - 1 != i) {
                        buf[y*W*3 + x*3 + 0] = 0xff;
                        buf[y*W*3 + x*3 + 1] = 0xff;
                        buf[y*W*3 + x*3 + 2] = 0xff;
                    }
                    continue;
                }

                map[y][x] = i + 1;
                buf[y*W*3 + x*3 + 0] = seeds[i].color >> 16;
                buf[y*W*3 + x*3 + 1] = seeds[i].color >>  8;
                buf[y*W*3 + x*3 + 2] = seeds[i].color >>  0;

                static const int dirs[] = {1, 0, 0, 1, -1, 0, 0, -1};
                for (int d = 0; d < 4; d++) {
                    long n = freelist;
                    freelist = nodes[freelist].next;
                    nodes[n].x = x + dirs[d*2+0];
                    nodes[n].y = y + dirs[d*2+1];
                    nodes[n].next = -1;
                    if (seeds[i].tail == -1) {
                        seeds[i].head = seeds[i].tail = n;
                    } else {
                        nodes[seeds[i].tail].next = n;
                        seeds[i].tail = n;
                    }
                }
            }
        }

        for (int y = 0; y < H; y++) {
            for (int x = 0; x < W; x++) {
                int i = map[y][x];
                if (i) {
                }
            }
        }
        for (int i = 0; i < (count ? 1 : 3*FPS); i++) {
            printf("P6\n%d %d\n255\n", W, H);
            if (!fwrite(buf, sizeof(buf), 1, stdout)) {
                return 1;
            }
        }

        if (!count) break; /* no updates, exit */
    }
}
