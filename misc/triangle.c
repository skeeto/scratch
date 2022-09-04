// Triangle maze generator
//   $ cc -O -o triangle triangle.c
//   $ ./triangle >maze.pgm
// Ref: https://www.youtube.com/watch?v=_h65x15ULXE
// Ref: https://old.reddit.com/r/programming/comments/x52502
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <string.h>
#include <time.h>

#define W 800           // image width
#define H 800           // image height
#define N 64            // number of maze rows
#define PX (W/2)        // horizontal bias
#define PY 25           // vertical bias
#define SX (SY/2)       // cell width
#define SY ((H-PY)/N)   // cell height

// Output PGM, operated on by point, line, and pgmout.
static unsigned char pgm[H][W];

struct p2 { short x, y; };

struct node {
    struct p2 p;
    short n, e, s, w;
    #define FN (1<<0)
    #define FE (1<<1)
    #define FS (1<<2)
    #define FW (1<<3)
    #define FV (1<<4)
    short flags;
};

// Return true if the point is inside the image.
static int
valid(struct p2 p)
{
    return p.x>=0 && p.x<W && p.y>=0 && p.y<H;
}

// Draw a point, doing nothing if outside the image.
static void
point(struct p2 p)
{
    if (valid(p)) {
        pgm[p.y][p.x] = 0;
    }
}

// Translate cell coordinate to image coordinates.
static struct p2
xlate(struct p2 p)
{
    p.x = PX + SX*p.x;
    p.y = PY + SY*p.y;
    return p;
}

// Draw a line between two points, clipping if necessary.
static void
line(struct p2 a, struct p2 b)
{
    int dx = b.x>a.x ? b.x-a.x : a.x-b.x;
    int dy = b.y>a.y ? b.y-a.y : a.y-b.y;
    int sx = b.x<a.x ? -1 : +1;
    int sy = b.y<a.y ? -1 : +1;
    if (dx > dy) {
        int d = 2*dy - dx;
        struct p2 p = {0, a.y};
        for (p.x = a.x; p.x != b.x; p.x += sx) {
            point(p);
            if (d > 0) {
                p.y += sy;
                d -= 2*dx;
            }
            d += 2*dy;
        }
    } else {
        int d = 2 * dx - dy;
        struct p2 p = {a.x, 0};
        for (p.y = a.y; p.y != b.y; p.y += sy) {
            point(p);
            if (d > 0) {
                p.x += sx;
                d -= 2*dy;
            }
            d += 2*dx;
        }
    }
    point(b);
}

// Write the PGM to standard output.
static void
pgmout(void)
{
    #define X(s) #s
    #define S(s) X(s)
    static const char hdr[] = "P5 "S(W)" "S(H)" 255\n";
    fwrite(hdr, sizeof(hdr)-1, 1, stdout);
    fwrite(pgm, sizeof(pgm), 1, stdout);
}

int main(void)
{
    struct node nodes[N*N];
    memset(nodes, 0, sizeof(nodes));

    // Populate the graph in the shape of a triangle.
    int y = 0, x = 0, n = 1;
    for (int i = 0; i < N*N; i++) {
        nodes[i].p.x = x - n/2;
        nodes[i].p.y = y;
        if (x > 0) {
            int j = i - 1;
            nodes[i].w = 1 + j;
            nodes[j].e = 1 + i;
            nodes[i].flags |= FW;
            nodes[j].flags |= FE;
        }
        if (x % 2) {
            int j = i - n + 1;
            nodes[i].n = 1 + j;
            nodes[j].s = 1 + i;
            nodes[i].flags |= FN;
            nodes[j].flags |= FS;
        }
        if (++x == n) {
            x = 0;
            y++;
            n += 2;
        }
    }

    // Seed the PRNG
    unsigned long long rng = time(0);
    clock_t end, beg = clock();
    do {
        rng *= 1111111111111111111;
        rng ^= rng >> 33;
        rng += beg;
    } while ((end = clock()) == beg);
    rng *= 1111111111111111111;
    rng ^= rng >> 33;
    rng += end;

    // Initialize a stack
    int top = 0;
    short stack[N*N];
    stack[top] = 0;
    nodes[stack[top]].flags |= FV;

    // Random depth first traversal
    while (top >= 0) {
        int i = stack[top];
        if (!(nodes[i].flags & 15)) {
            top--;
            continue;  // dead end
        }

        // Determine valid edges
        int n = 0;
        int opt[4];
        for (int d = 0; d < 4; d++) {
            int j = (&nodes[i].n)[d];
            if (j && !(nodes[j-1].flags&FV)) {
                opt[n++] = d;
            }
        }

        if (!n) {
            top--;  // no valid edges
        } else {
            // Pick a random edge
            rng = rng*0x3243f6a8885a308d + 1;
            int d = opt[(rng >> 32) % n];
            int b = 1 << d;
            int j = (&nodes[i].n)[d] - 1;

            // Tear down walls
            nodes[i].flags &= ~b;
            nodes[j].flags &= ~(1 << ((d + 2)%4));

            // Mark visited and push onto the stack
            nodes[j].flags |= FV;
            stack[++top] = j;
        }
    }

    // Draw all the walls
    memset(pgm, 255, sizeof(pgm));
    for (int i = 0; i < N*N; i++) {
        if (!nodes[i].e || nodes[i].flags&FE) {
            struct p2 a = xlate(nodes[i].p);
            struct p2 b = {nodes[i].p.x+1, nodes[i].p.y};
            b = xlate(b);
            if (nodes[i].n) {
                a.y += SY/2;
                b.y -= SY/2;
            } else {
                a.y -= SY/2;
                b.y += SY/2;
            }
            line(a, b);
        }
        if (!nodes[i].w) {
            struct p2 a = xlate(nodes[i].p);
            struct p2 b = {nodes[i].p.x-1, nodes[i].p.y};
            b = xlate(b);
            a.y -= SY/2;
            b.y += SY/2;
            line(a, b);
        }
        if (nodes[i].flags&FN) {
            int j = nodes[i].n - 1;
            struct p2 a = xlate(nodes[i].p);
            struct p2 b = xlate(nodes[j].p);
            a.x += SX; a.y -= SY/2;
            b.x -= SX; b.y += SY/2;
            line(a, b);
        }
        if (!nodes[i].s && !nodes[i].n) {
            struct p2 a = xlate(nodes[i].p);
            struct p2 b = a;
            a.x += SX; a.y += SY/2;
            b.x -= SX; b.y += SY/2;
            line(a, b);
        }
    }

    pgmout();
    fflush(stdout);
    return ferror(stdout);
}
