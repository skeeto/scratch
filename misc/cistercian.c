/* Cistercian Number System -- renders all 0-9999
 * $ cc -Os cistercian.c
 * $ ./a.out | convert pgm:- cistercian.png
 * Ref: https://www.youtube.com/watch?v=9p55Qgt7Ciw
 */
#include <stdio.h>
#include <string.h>

#define W 200
#define H  50
static unsigned char image[1+H*32][1+W*20];

static void
set(int x, int y)
{
    image[y+1][x+1] = 0;
}

static void
dump(void)
{
    printf("P5\n%d %d\n1\n", 1+W*20, 1+H*32);
    fwrite(image, sizeof(image), 1, stdout);
}

static void
diag0(int x, int y)
{
    for (int i = 0; i < 8; i++) {
        set(x+i, y+i+0);
        set(x+i, y+i+1);
        set(x+i, y+i+2);
    }
}

static void
diag1(int x, int y)
{
    for (int i = 0; i < 8; i++) {
        set(x+i, y+(7-i)+0);
        set(x+i, y+(7-i)+1);
        set(x+i, y+(7-i)+2);
    }
}

static void
linev(int x, int y)
{
    for (int i = 0; i < 8; i++) {
        set(x+0, y+i);
        set(x+1, y+i);
    }
}

static void
lineh(int x, int y)
{
    for (int i = 0; i < 8; i++) {
        set(x+i, y+0);
        set(x+i, y+1);
    }
}

static void
draw(int x, int y, int v)
{
    for (int i = 0; i < 31; i++) {
        set(x+8, y+i);
        set(x+9, y+i);
    }

    switch (v % 10) {
    case 1: lineh(x + 10, y);
            break;
    case 2: lineh(x + 10, y+8);
            break;
    case 3: diag0(x + 10, y);
            break;
    case 4: diag1(x + 10, y);
            break;
    case 5: lineh(x + 10, y);
            diag1(x + 10, y);
            break;
    case 6: linev(x + 16, y);
            break;
    case 7: lineh(x + 10, y);
            linev(x + 16, y);
            break;
    case 8: lineh(x + 10, y+8);
            linev(x + 16, y);
            break;
    case 9: lineh(x + 10, y);
            lineh(x + 10, y+8);
            linev(x + 16, y);
            break;
    }

    switch (v / 10 % 10) {
    case 1: lineh(x, y);
            break;
    case 2: lineh(x, y+8);
            break;
    case 3: diag1(x, y);
            break;
    case 4: diag0(x, y);
            break;
    case 5: lineh(x, y);
            diag0(x, y);
            break;
    case 6: linev(x, y);
            break;
    case 7: lineh(x, y);
            linev(x, y);
            break;
    case 8: lineh(x, y+8);
            linev(x, y);
            break;
    case 9: lineh(x, y);
            lineh(x, y+8);
            linev(x, y);
            break;
    }

    switch (v / 100 % 10) {
    case 1: lineh(x + 10, y+29);
            break;
    case 2: lineh(x + 10, y+21);
            break;
    case 3: diag1(x + 10, y+21);
            break;
    case 4: diag0(x + 10, y+21);
            break;
    case 5: lineh(x + 10, y+29);
            diag0(x + 10, y+21);
            break;
    case 6: linev(x + 16, y+21);
            break;
    case 7: lineh(x + 10, y+29);
            linev(x + 16, y+21);
            break;
    case 8: lineh(x + 10, y+21);
            linev(x + 16, y+21);
            break;
    case 9: lineh(x + 10, y+29);
            lineh(x + 10, y+21);
            linev(x + 16, y+21);
            break;
    }

    switch (v / 1000 % 10) {
    case 1: lineh(x, y+29);
            break;
    case 2: lineh(x, y+21);
            break;
    case 3: diag1(x, y+21);
            break;
    case 4: diag0(x, y+21);
            break;
    case 5: lineh(x, y+29);
            diag0(x, y+21);
            break;
    case 6: linev(x, y+21);
            break;
    case 7: lineh(x, y+29);
            linev(x, y+21);
            break;
    case 8: lineh(x, y+21);
            linev(x, y+21);
            break;
    case 9: lineh(x, y+29);
            lineh(x, y+21);
            linev(x, y+21);
            break;
    }
}

static unsigned long
u32(void)
{
    static unsigned long long s = 0;
    return (s = s*0xac3a183f8a3c0b8d + 0xf53703c71ce3cf19) >> 32;
}

int
main(void)
{

    static short vals[10000];
    for (int i = 0; i < 10000; i++) {
        vals[i] = i;
    }
#if 1
    for (int i = 9999; i > 0; i--) {
        int j = u32() % (i + 1);
        int tmp = vals[i];
        vals[i] = vals[j];
        vals[j] = tmp;
    }
#endif

    memset(image, 1, sizeof(image));
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            draw(x*20, y*32, vals[y*W + x]);
        }
    }
    dump();
}
