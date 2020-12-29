/* Unique tile renderer
 *   $ cc tiles.c && ./a.out
 *   $ ls tile-*.svg | xargs -P$(nproc) -n1 mogrify -density 32 -format png
 *   $ montage -tile 15x8 -geometry +10+10 tile-*.png tiles.png
 * Ref: https://redd.it/km1gfh
 * Ref: https://i.imgur.com/H6yV2Be.png
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>
#include <stdlib.h>

static int
flipv(int v)
{
    return (v<<6 & 0700) |
           (v    & 0070) |
           (v>>6 & 0007);
}

static int
transpose(int v)
{
    return (v>>2 & 0042) |
           (v>>4 & 0004) |
           (v    & 0421) |
           (v<<2 & 0210) |
           (v<<4 & 0100);
}

static void
render(int v)
{
    char name[16];
    snprintf(name, sizeof(name), "tile-%03d.svg", v);
    FILE *f = fopen(name, "wb");
    if (!f) {
        printf("fatal: count not open %s\n", name);
        exit(EXIT_FAILURE);
    }

    int scale = 100;
    fprintf(f, "<svg version='1.1' xmlns='http://www.w3.org/2000/svg' ");
    fprintf(f, "width='%d' height='%d'>\n", scale*3, scale*3);
    fprintf(f, "<rect width='100%%' height='100%%' fill='white'/>\n");
    for (int y = 0; y < 3; y++) {
        for (int x = 0; x < 3; x++) {
            int i = y*3 + x;
            char *fill = v>>i & 1 ? "" : "fill:white;";
            fprintf(f, "<circle cx='%d' cy='%d' r='%d' "
                       "style='%sstroke:black;stroke-width:%dpx'/>\n",
                    scale/2 + x*scale, scale/2 + y*scale,
                    scale*4/10, fill, scale/15);
        }
    }
    fprintf(f, "</svg>\n");

    fclose(f);
}

int
main(void)
{
    int t;
    char seen[512] = {0};
    for (int i = 0; i < 512; i++) {
        if (seen[i]) continue; else seen[i] = 1;
        t = transpose(flipv(i));
        if (seen[t]) continue; else seen[t] = 1;
        t = transpose(flipv(t));
        if (seen[t]) continue; else seen[t] = 1;
        t = transpose(flipv(t));
        if (seen[t]) continue; else seen[t] = 1;
        render(i);
    }
}
