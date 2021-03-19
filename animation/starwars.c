/* Star Wars cellular automaton (rule 245/2/4)
 * $ cc -O3 -fopenmp -o starwars starwars.c
 * $ ./starwars | mpv --no-correct-pts --fps=15 --fs -
 * $ ./starwars | x264 --frames=900 --fps=15 -o starwars.mp4 /dev/stdin
 * Ref: https://www.conwaylife.com/wiki/OCA:Star_Wars
 */
#include <time.h>
#include <stdio.h>

#define W (1920/S)
#define H (1080/S)
#define S 2
static const long colors[] = {0x111111, 0xffffff, 0xff00ff, 0x0000ff};
#define STATES "02300230123001300130013002300230"

int
main(void)
{
    #ifdef _WIN32
    /* Set stdout to binary mode. */
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    static char state[2][H][W];

    unsigned long long s = time(0);
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            s = s*0x243f6a8885a308d3 + 1;
            state[0][y][x] = (s >> 63) & 1;
        }
    }

    for (int i = 0; ; i = !i) {
        #pragma omp parallel for
        for (int y = 0; y < H; y++) {
            for (int x = 0; x < W; x++) {
                int c0 = state[i][y][x];
                int c1 = (state[i][(y+H+0)%H][(x+W+1)%W] == 1) +
                         (state[i][(y+H+0)%H][(x+W-1)%W] == 1) +
                         (state[i][(y+H+1)%H][(x+W+1)%W] == 1) +
                         (state[i][(y+H+1)%H][(x+W+0)%W] == 1) +
                         (state[i][(y+H+1)%H][(x+W-1)%W] == 1) +
                         (state[i][(y+H-1)%H][(x+W+1)%W] == 1) +
                         (state[i][(y+H-1)%H][(x+W+0)%W] == 1) +
                         (state[i][(y+H-1)%H][(x+W-1)%W] == 1);
                 state[!i][y][x] = STATES[(c1<<2 | c0)&0x1f] - '0';
            }
        }

        static unsigned char ppm[H*S][W*S][3];
        for (int y = 0; y < H*S; y++) {
            for (int x = 0; x < W*S; x++) {
                long c = colors[(int)state[!i][y/S][x/S]];
                ppm[y][x][0] = c >> 16;
                ppm[y][x][1] = c >>  8;
                ppm[y][x][2] = c >>  0;
            }
        }
        printf("P6\n%d %d\n255\n", W*S, H*S);
        if (!fwrite(ppm, sizeof(ppm), 1, stdout)) return 1;
    }
}
