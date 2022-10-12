// Perfect minimax player for the Dandelions paper-and-pencil game
//   $ cc -O3 -o dandelions dandelions.c
//   $ cl /O2 dandelions.c
//
// Wait for the ">>" prompt after startup. It takes a few seconds to
// explore and populate the initial game tree.
//
// Ref: https://mathwithbaddrawings.com/dandelions/
// Ref: http://nullprogram.com/blog/2022/10/12/
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _MSC_VER
#  define ASSERT(c) if (!(c)) __debugbreak();
#  define POPCOUNT64(x) __popcnt64(x)
#elif __GNUC__
#  define ASSERT(c) if (!(c)) __builtin_trap();
#  define POPCOUNT64(x) __builtin_popcountll(x)
#else
#  define ASSERT(c) if (!(c)) *(volatile int *)0 = 0;
#endif

#define GAME_INIT ((uint64_t)255 << 50)
typedef uint64_t game;

#define MEMOIZE_EXP 28
#define MEMOIZE_CAP (1L << MEMOIZE_EXP)
#define FLAG_FULL (1 << 0)  // fully explore the game tree (debug only!)
struct memoize {
    uint32_t len;
    int flags;
    game *slots;
};

// Initialize a new memozation table.
struct memoize memoize(void)
{
    struct memoize mt = {0, 0, calloc(sizeof(game), MEMOIZE_CAP)};
    return mt;
}

// Extract the turn counter (0-14).
static int turn(game g)
{
    return POPCOUNT64((g & 0x3fffffffe000000) ^ GAME_INIT);
}

// True if the position (0-24) has no flower.
static int empty(game g, int i)
{
    return !((g >> (25 + i)) & 1);
}

// True if the position has a seed.
static int seeded(game g, int i)
{
    return g>>i & 1;
}

// True if the direction (0-7) has seen no wind.
static int calm(game g, int d)
{
    return (g >> (50 + d)) & 1;
}

// True if this is the null game state.
static int null(game g)
{
    return !g;
}

// Compute the score for this field. Positives (number of gaps in the
// field) mean wind wins, otherwise dandelions win (more negative means
// fewer dandelions to win).
static int score(game g)
{
    int gaps = 25 - POPCOUNT64(g&0x1ffffff);
    return gaps ? gaps : POPCOUNT64(g & 0x3fffffe000000)-7;
}

// Plant a flower at a position (0-24).
static game plant(game g, int i)
{
    return g | (uint64_t)1<<(i + 25) | (uint64_t)1<<i;
}

// Zero the spare 6-bit value.
static game clean(game g)
{
    return g & 0x3ffffffffffffff;
}

// Store the spare signed, 6-bit value.
static game store(game g, int v)
{
    return g | (uint64_t)(v+32)<<58;
}

// Load the spare 6-bit value.
static int load(game g)
{
    return (int)(g >> 58) - 32;
}

// Blow the wind and spread the seeds.
static game blow(game g, int dir)
{
    // Instead of shifting left or right, use a rotation so that either
    // direction can be reached without a negative shift, i.e. a large
    // rotation is the same as a small rotation in the other direciton.
    static uint8_t rotate[] = {31, 26, 27, 28, 1, 6, 5, 4};
    static uint32_t mask[] = {
        0x0f7bdef, 0x007bdef, 0x00fffff, 0x00f7bde,
        0x1ef7bde, 0x1ef7bc0, 0x1ffffe0, 0x0f7bde0
    };
    uint32_t s = g & 0x1ffffff;
    uint32_t f = g >> 25;
    uint32_t m = mask[dir];
    int r = rotate[dir];
    f &= m;  f = f>>r | f<<(32-r);  s |= f;
    f &= m;  f = f>>r | f<<(32-r);  s |= f;
    f &= m;  f = f>>r | f<<(32-r);  s |= f;
    f &= m;  f = f>>r | f<<(32-r);  s |= f;
    return (g ^ (uint64_t)1<<(dir + 50)) | s;
}

// Reverse bits, then rotate right.
static unsigned char revrot(unsigned char b, int r)
{
    static unsigned char t[] = {0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
    b = t[b&15]<<4 | t[b>>4];
    b = b>>r | b<<(8-r);
    return b;
}

// Transpose the game state along the diagonal.
static game transpose(game g)
{
    unsigned char b = revrot(g>>50, 5);
    return (uint64_t)b<<50 |
           ((g >> 16) & 0x0000020000010) |
           ((g >> 12) & 0x0000410000208) |
           ((g >>  8) & 0x0008208004104) |
           ((g >>  4) & 0x0104104082082) |
           ((g >>  0) & 0x2082083041041) |
           ((g <<  4) & 0x1041040820820) |
           ((g <<  8) & 0x0820800410400) |
           ((g << 12) & 0x0410000208000) |
           ((g << 16) & 0x0200000100000);
}

// Flip the game state along the horizontal.
static game flipv(game g)
{
    unsigned char b = revrot(g>>50, 7);
    return (uint64_t)b<<50 |
           ((g >> 20) & 0x000003e00001f) |
           ((g >> 10) & 0x00007c00003e0) |
           ((g >>  0) & 0x000f800007c00) |
           ((g << 10) & 0x01f00000f8000) |
           ((g << 20) & 0x3e00001f00000);
}

// Return the canonical representation of the game state.
static game canonicalize(game g)
{
    uint64_t c = g;
    g = transpose(g); c = c < g ? c : g;
    g = flipv(g);     c = c < g ? c : g;
    g = transpose(g); c = c < g ? c : g;
    g = flipv(g);     c = c < g ? c : g;
    g = transpose(g); c = c < g ? c : g;
    g = flipv(g);     c = c < g ? c : g;
    g = transpose(g); c = c < g ? c : g;
    return c;
}

// Compute a 64-bit hash for this game state.
static uint64_t hash(game g)
{
    return g ^ g>>32;
}

// Display the game state.
static void display(game g)
{
    int b = g >> 50;
    for (int d = 0; d < 8; d++) {
        putchar(1<<d&b ? '-' : "012345678"[d]);
    }
    putchar('\n');

    int32_t s = g & 0x1ffffff;
    int32_t f = g >> 25;
    for (int i = 0; i < 25; i++) {
        int32_t b = (int32_t)1 << i;
        putchar("_.*"[!!(f&b)+!!(s&b)]);
        if (i%5 == 4) {
            putchar('\n');
        }
    }
}

static double usage(struct memoize *mt)
{
    return 100.0 * mt->len / MEMOIZE_CAP;
}

// Get the memoization slot for a canonical game state.
static game *lookup(struct memoize *mt, game g)
{
    uint64_t h = hash(g);
    size_t m = MEMOIZE_CAP - 1;
    size_t s = h>>(64 - MEMOIZE_EXP) | 1;
    for (size_t i = h;;) {
        i = (i + s)&m;
        if (null(mt->slots[i])) {
            mt->len++;
            ASSERT(mt->len < MEMOIZE_CAP);
            return mt->slots + i;
        }
        if (clean(mt->slots[i]) == g) {
            return mt->slots + i;
        }
    }
}

// Determine the dandelions score lower bound. That is, dandelions can
// do at least this well.
static int eval(struct memoize *mt, game g)
{
    g = canonicalize(g);
    game *k = lookup(mt, g);

    if (!null(*k)) {
        return load(*k);
    }

    int s = score(g);
    if (s <= 0) {
        *k = store(g, s);
        return s;
    }

    int t = turn(g);
    if (t == 14) {
        int s = score(g);
        *k = store(g, s);
        return s;
    }

    int result;
    *k = g;
    if (t & 1) {
        // Search for a branch where wind always wins
        result = 0;
        for (int i = 0; i < 8; i++) {
            if (calm(g, i)) {
                int r = eval(mt, blow(g, i));
                if (r > result) {
                    result = r;
                    *k = store(g, r);
                    if (!(mt->flags & FLAG_FULL)) {
                        return r;
                    }
                }
            }
        }

    } else {
        // Search for a branch where dandelions alway wins. Iterating in
        // a random order is slower but may make for a more interesting
        // "opponent."
        result = 31;
        for (int i = 0; i < 25; i++) {
            if (empty(g, i)) {
                int r = eval(mt, plant(g, i));
                if (r < result) {
                    result = r;
                    *k = store(g, r);
                    if (!r && !(mt->flags & FLAG_FULL)) {
                        return 0;
                    }
                }
            }
        }
    }

    *k = store(g, result);
    return result;
}

static int prompt(char *s)
{
    fputs(s, stdout);
    fflush(stdout);
    int r;
    return scanf("%d", &r) != 1 ? -1 : r;
}

struct option {
    int move;
    int delta;
};

static int cmp(const void *p0, const void *p1)
{
    const struct option *a = p0, *b = p1;
    if (a->delta == b->delta) {
        return a->move - b->move;
    }
    return a->delta - b->delta;
}

// Compute the winning options, sorted by descending by quality.
static int options(struct memoize *mt, struct option *opts, game g)
{
    int len = 0;
    if (turn(g) & 1) {
        for (int i = 0; i < 8; i++) {
            if (calm(g, i)) {
                int s = eval(mt, blow(g, i));
                if (s > 0) {
                    opts[len].move = i;
                    opts[len].delta = -s;
                    len++;
                }
            }
        }
    } else {
        for (int i = 0; i < 25; i++) {
            if (empty(g, i)) {
                int s = eval(mt, plant(g, i));
                if (s <= 0) {
                    opts[len].move = i;
                    opts[len].delta = s;
                    len++;
                }
            }
        }
    }
    qsort(opts, len, sizeof(*opts), cmp);
    return len;
}

// Crude user interface for manually exploring the game tree. The game must
// be on dandelions turn.
static int play(struct memoize *mt, game init)
{
    int r;
    game g = init;
    int flags = mt->flags;

    for (int t = turn(g)>>1; t < 7; t++) {
        int nopts;
        struct option opts[25];

        // Use a full search for dandelions once down the tree a bit
        if (t > 1) {
            mt->flags |= FLAG_FULL;
        } else {
            mt->flags = flags;
        }

        display(g);
        for (int i = 0; i < 25; i++) {
            if (empty(g, i)) {
                printf("%3d", i);
            } else {
                printf(" --");
            }
            if (i%5 == 4) {
                putchar('\n');
            }
        }

        nopts = options(mt, opts, g);
        fputs("best: ", stdout);
        for (int i = 0; i < nopts; i++) {
            printf("%s%d", i?", ":"", opts[i].move);
            if (opts[i].delta) {
                printf("[%d short]", -opts[i].delta);
            }
        }
        puts(nopts ? "" : "(unwinnable)");

        // Never use full search for wind (too slow when losing)
        mt->flags = flags;

        for (;;) {
            r = prompt("dandelions [0-24] >> ");
            if (r < 0) {
                return -1;
            } else if (r < 25 && empty(g, r)) {
                break;
            }
            puts("invalid move");
        }
        putchar('\n');
        g = plant(g, r);
        if (score(g) <= 0) {
            break;
        }

        display(g);
        printf("%c  %c  %c\n \\ | / \n%c--*--%c\n / | \\ \n%c  %c  %c\n",
               "-5"[calm(g, 5)], "-6"[calm(g, 6)], "-7"[calm(g, 7)],
               "-4"[calm(g, 4)], "-0"[calm(g, 0)], "-3"[calm(g, 3)],
               "-2"[calm(g, 2)], "-1"[calm(g, 1)]);

        nopts = options(mt, opts, g);
        fputs("best: ", stdout);
        for (int i = 0; i < nopts; i++) {
            printf("%s%d", i?", ":"", opts[i].move);
            if (opts[i].delta < -1) {
                printf("[%d gaps]", -opts[i].delta);
            }
        }
        puts(nopts ? "" : "(unwinnable)");

        for (;;) {
            r = prompt("wind [0-7] >> ");
            if (r < 0) {
                return -1;
            } else if (r < 8 && calm(g, r)) {
                break;
            }
            puts("invalid move");
        }
        putchar('\n');
        g = blow(g, r);
        if (score(g) <= 0) {
            break;
        }
    }

    display(g);
    int s = score(g);
    if (s > 0) {
        puts("Wind wins");
    } else {
        puts("Dandelions win");
    }
    return s;
}

#ifndef PUZZLE
int main(void)
{
    struct memoize mt = memoize();
    for (;;) {
        play(&mt, GAME_INIT);
        int r = prompt("Play again? (0/1) ");
        if (r != 1) {
            break;
        }
    }
}

#else
#include <time.h>

// Generate a puzzle for dandelions.
static game puzzle(struct memoize *mt, uint64_t seed)
{
    for (;;) {
        game g = GAME_INIT;
        struct option opts[25];
        int wind[] = {0, 1, 2, 3, 4, 5, 6, 7};
        for (int i = 0; i < 5; i++) {
            seed = seed*0x3243f6a8885a308d + 1;

            int len = options(mt, opts, g);
            int opt = ((uint32_t)(seed >> 48)*len)>>16;
            ASSERT(empty(g, opts[opt].move));
            g = plant(g, opts[opt].move);

            opt = ((uint32_t)(seed>>32 & 0xffff)*(8 - i))>>16;
            ASSERT(calm(g, wind[opt]));
            g = blow(g, wind[opt]);
            wind[opt] = wind[7-i];
        }
        if (options(mt, opts, g) == 1 && seeded(g, opts[0].move)) {
            return g;
        }
        printf("Searching, %.1f%% table used, seed 0x%016llx\n",
               usage(mt), (unsigned long long)seed);
        if (usage(mt) > 60) {
            mt->len = 0;
            memset(mt->slots, 0, sizeof(mt->slots[0])*MEMOIZE_CAP);
        }
    }
}

int main(void)
{
    struct memoize mt = memoize();
    uint64_t seed = time(0);
    game g = puzzle(&mt, seed);
    while (play(&mt, g) != -1);
}
#endif
