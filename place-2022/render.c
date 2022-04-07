// Place 2022 video renderer
//   $ cc -O3 -o render render.c
//   $ unxz <place.csv.xz | ./render | mpv --no-correct-pts --fps=60 -
//   $ unxz <place.csv.xz | ./render | ffmpeg -framerate 60 -i - place.mp4
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEP 30000  // real-time milliseconds per frame

static const char hdr[17] = "P6\n2000 2000\n255\n";
static const unsigned colors[] = {
    0x000000,0x00756f,0x009eaa,0x00a368,0x00cc78,0x00ccc0,0x2450a4,0x3690ea,
    0x493ac1,0x515252,0x51e9f4,0x6a5cff,0x6d001a,0x6d482f,0x7eed56,0x811e9f,
    0x898d90,0x94b3ff,0x9c6926,0xb44ac0,0xbe0039,0xd4d7d9,0xde107f,0xe4abff,
    0xff3881,0xff4500,0xff99aa,0xffa800,0xffb470,0xffd635,0xfff8b8,0xffffff,
};

int main(void)
{
    static unsigned char buf[2000][2000][3];
    memset(buf, 0xff, sizeof(buf));

    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    int last = 0;
    char line[32];
    fgets(line, sizeof(line), stdin);  // skip header
    while (fgets(line, sizeof(line), stdin) && !ferror(stdout)) {
        int t = atoi(strtok(line, ","));
        int u = atoi(strtok(0, ",")); (void)u;
        int i = atoi(strtok(0, ","));
        int x = atoi(strtok(0, ","));
        int y = atoi(strtok(0, ","));
        if (t > last+STEP) {
            fwrite(hdr, sizeof(hdr), 1, stdout);
            fwrite(buf, sizeof(buf), 1, stdout);
            last = last ? last+STEP : t;
        }
        buf[y][x][0] = colors[i] >> 16;
        buf[y][x][1] = colors[i] >>  8;
        buf[y][x][2] = colors[i] >>  0;
    }
    fwrite(hdr, sizeof(hdr), 1, stdout);
    fwrite(buf, sizeof(buf), 1, stdout);
    return ferror(stdout);
}
