// Colored "sixteen puzzle" solver
//
// A variation of the Sixteen puzzle where tiles are colored (1, 2, 3) rather
// than numbered. There are four tiles colored 1 and four colored 2. The goal
// is to align the tiles colored 1 and 2 into their own rows. In this program,
// zero represents empty spaces.
//
// There are 16 tiles with two bits of information apiece, so any state can be
// represented as a 32-bit integer. New states are derived by bit manipulation.
// This program doesn't exploit reflection, and it could be made faster by
// canonicalizing the state reflection before consulting the "seen" table,
// which would avoid wasted time exploring reflections. The terminal condition
// locks in rotation, so 90 degree rotations are distinct states.
//
// Ref: https://old.reddit.com/r/algorithms/comments/wkkw81
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <stdint.h>

// Bit array tracking states already visited.
static uint32_t seen[1L<<27];

// Try to mark a state as visited, returning 1 if unvisited.
static int
mark(uint32_t s)
{
    uint32_t b = (uint32_t)1 << (s&31);
    uint32_t x = seen[s>>5];
    if (x & b) {
        return 0;
    }
    seen[s>>5] = x | b;
    return 1;
}

// Decode a 16-character string representation of a state.
static uint32_t
decode(char *p)
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t v = p[i] - '0';
        s |= v << (i*2);
    }
    return s;
}

// Print a human-friendly 4x4 grid of a state.
static void
print(uint32_t s)
{
    for (int i = 0; i < 16; i++) {
        printf("%d%c", (s>>(i*2))&3, " \n"[i%4==3]);
    }
}

// Populate m with the available moves, returning the count.
static int
moves(uint32_t *m, uint32_t s)
{
    int n = 0;
    m[n] = (s&0xfffffffc) | ((s&0x00000003)<<8);
    n += !!(s&0x00000003) & !(s&0x00000300);
    m[n] = (s&0xfffffffc) | ((s&0x00000003)<<2);
    n += !!(s&0x00000003) & !(s&0x0000000c);
    m[n] = (s&0xfffffff3) | ((s&0x0000000c)<<8);
    n += !!(s&0x0000000c) & !(s&0x00000c00);
    m[n] = (s&0xfffffff3) | ((s&0x0000000c)<<2);
    n += !!(s&0x0000000c) & !(s&0x00000030);
    m[n] = (s&0xfffffff3) | ((s&0x0000000c)>>2);
    n += !!(s&0x0000000c) & !(s&0x00000003);
    m[n] = (s&0xffffffcf) | ((s&0x00000030)<<8);
    n += !!(s&0x00000030) & !(s&0x00003000);
    m[n] = (s&0xffffffcf) | ((s&0x00000030)<<2);
    n += !!(s&0x00000030) & !(s&0x000000c0);
    m[n] = (s&0xffffffcf) | ((s&0x00000030)>>2);
    n += !!(s&0x00000030) & !(s&0x0000000c);
    m[n] = (s&0xffffff3f) | ((s&0x000000c0)<<8);
    n += !!(s&0x000000c0) & !(s&0x0000c000);
    m[n] = (s&0xffffff3f) | ((s&0x000000c0)>>2);
    n += !!(s&0x000000c0) & !(s&0x00000030);
    m[n] = (s&0xfffffcff) | ((s&0x00000300)<<8);
    n += !!(s&0x00000300) & !(s&0x00030000);
    m[n] = (s&0xfffffcff) | ((s&0x00000300)>>8);
    n += !!(s&0x00000300) & !(s&0x00000003);
    m[n] = (s&0xfffffcff) | ((s&0x00000300)<<2);
    n += !!(s&0x00000300) & !(s&0x00000c00);
    m[n] = (s&0xfffff3ff) | ((s&0x00000c00)<<8);
    n += !!(s&0x00000c00) & !(s&0x000c0000);
    m[n] = (s&0xfffff3ff) | ((s&0x00000c00)>>8);
    n += !!(s&0x00000c00) & !(s&0x0000000c);
    m[n] = (s&0xfffff3ff) | ((s&0x00000c00)<<2);
    n += !!(s&0x00000c00) & !(s&0x00003000);
    m[n] = (s&0xfffff3ff) | ((s&0x00000c00)>>2);
    n += !!(s&0x00000c00) & !(s&0x00000300);
    m[n] = (s&0xffffcfff) | ((s&0x00003000)<<8);
    n += !!(s&0x00003000) & !(s&0x00300000);
    m[n] = (s&0xffffcfff) | ((s&0x00003000)>>8);
    n += !!(s&0x00003000) & !(s&0x00000030);
    m[n] = (s&0xffffcfff) | ((s&0x00003000)<<2);
    n += !!(s&0x00003000) & !(s&0x0000c000);
    m[n] = (s&0xffffcfff) | ((s&0x00003000)>>2);
    n += !!(s&0x00003000) & !(s&0x00000c00);
    m[n] = (s&0xffff3fff) | ((s&0x0000c000)<<8);
    n += !!(s&0x0000c000) & !(s&0x00c00000);
    m[n] = (s&0xffff3fff) | ((s&0x0000c000)>>8);
    n += !!(s&0x0000c000) & !(s&0x000000c0);
    m[n] = (s&0xffff3fff) | ((s&0x0000c000)>>2);
    n += !!(s&0x0000c000) & !(s&0x00003000);
    m[n] = (s&0xfffcffff) | ((s&0x00030000)<<8);
    n += !!(s&0x00030000) & !(s&0x03000000);
    m[n] = (s&0xfffcffff) | ((s&0x00030000)>>8);
    n += !!(s&0x00030000) & !(s&0x00000300);
    m[n] = (s&0xfffcffff) | ((s&0x00030000)<<2);
    n += !!(s&0x00030000) & !(s&0x000c0000);
    m[n] = (s&0xfff3ffff) | ((s&0x000c0000)<<8);
    n += !!(s&0x000c0000) & !(s&0x0c000000);
    m[n] = (s&0xfff3ffff) | ((s&0x000c0000)>>8);
    n += !!(s&0x000c0000) & !(s&0x00000c00);
    m[n] = (s&0xfff3ffff) | ((s&0x000c0000)<<2);
    n += !!(s&0x000c0000) & !(s&0x00300000);
    m[n] = (s&0xfff3ffff) | ((s&0x000c0000)>>2);
    n += !!(s&0x000c0000) & !(s&0x00030000);
    m[n] = (s&0xffcfffff) | ((s&0x00300000)<<8);
    n += !!(s&0x00300000) & !(s&0x30000000);
    m[n] = (s&0xffcfffff) | ((s&0x00300000)>>8);
    n += !!(s&0x00300000) & !(s&0x00003000);
    m[n] = (s&0xffcfffff) | ((s&0x00300000)<<2);
    n += !!(s&0x00300000) & !(s&0x00c00000);
    m[n] = (s&0xffcfffff) | ((s&0x00300000)>>2);
    n += !!(s&0x00300000) & !(s&0x000c0000);
    m[n] = (s&0xff3fffff) | ((s&0x00c00000)<<8);
    n += !!(s&0x00c00000) & !(s&0xc0000000);
    m[n] = (s&0xff3fffff) | ((s&0x00c00000)>>8);
    n += !!(s&0x00c00000) & !(s&0x0000c000);
    m[n] = (s&0xff3fffff) | ((s&0x00c00000)>>2);
    n += !!(s&0x00c00000) & !(s&0x00300000);
    m[n] = (s&0xfcffffff) | ((s&0x03000000)>>8);
    n += !!(s&0x03000000) & !(s&0x00030000);
    m[n] = (s&0xfcffffff) | ((s&0x03000000)<<2);
    n += !!(s&0x03000000) & !(s&0x0c000000);
    m[n] = (s&0xf3ffffff) | ((s&0x0c000000)>>8);
    n += !!(s&0x0c000000) & !(s&0x000c0000);
    m[n] = (s&0xf3ffffff) | ((s&0x0c000000)<<2);
    n += !!(s&0x0c000000) & !(s&0x30000000);
    m[n] = (s&0xf3ffffff) | ((s&0x0c000000)>>2);
    n += !!(s&0x0c000000) & !(s&0x03000000);
    m[n] = (s&0xcfffffff) | ((s&0x30000000)>>8);
    n += !!(s&0x30000000) & !(s&0x00300000);
    m[n] = (s&0xcfffffff) | ((s&0x30000000)<<2);
    n += !!(s&0x30000000) & !(s&0xc0000000);
    m[n] = (s&0xcfffffff) | ((s&0x30000000)>>2);
    n += !!(s&0x30000000) & !(s&0x0c000000);
    m[n] = (s&0x3fffffff) | ((s&0xc0000000)>>8);
    n += !!(s&0xc0000000) & !(s&0x00c00000);
    m[n] = (s&0x3fffffff) | ((s&0xc0000000)>>2);
    n += !!(s&0xc0000000) & !(s&0x30000000);
    return n;
}

// Indicate if the given state is terminal. A terminal state has exactly two
// rows of either "1" or "2" tiles.
static int
done(uint32_t s)
{
    int score = 0;
    score += (s & 0x000000ff) == 0x00000055;
    score += (s & 0x0000ff00) == 0x00005500;
    score += (s & 0x00ff0000) == 0x00550000;
    score += (s & 0xff000000) == 0x55000000;
    score += (s & 0x000000ff) == 0x000000aa;
    score += (s & 0x0000ff00) == 0x0000aa00;
    score += (s & 0x00ff0000) == 0x00aa0000;
    score += (s & 0xff000000) == 0xaa000000;
    return score == 2;
}

int
main(void)
{
    uint32_t start = decode("1332022030311132");
    int32_t head = 0, tail = 0;
    static uint32_t queue[1L<<26];  // BFS queue, fixed size is an estimate
    static int32_t link[1L<<26];    // linked lists (tree) to the root state

    queue[head++] = start;
    mark(start);
    while (tail != head) {
        uint32_t c = queue[tail];
        if (done(c)) {
            break;
        }
        int32_t parent = tail++;

        uint32_t m[32];
        int len = moves(m, c);
        for (int i = 0; i < len; i++) {
            if (mark(m[i])) {
                link[head] = parent;
                queue[head++] = m[i];
            }
        }
    }

    // Reverse the linked list in place
    int32_t child = tail;
    for (int32_t i = tail;;) {
        int32_t parent = link[i];
        link[i] = child;
        child = i;
        if (i == 0) {
            break;
        }
        i = parent;
    }

    // Walk the reversed linked list to produce a solution
    for (int32_t p = 0, i = 0;; i++) {
        printf("M%d\n", (int)i);
        print(queue[p]);
        if (link[p] == p) {
            break;
        }
        p = link[p];
    }
}
