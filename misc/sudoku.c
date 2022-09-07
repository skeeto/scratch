// Sudoku solver and generator
//   $ cc -fopenmp -O3 -o sudoku sudoku.c
//   $ ./sudoku -5
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define POPCNT(x)  __builtin_popcount(x)
#define FFS(x)     (__builtin_ffs(x) - 1)

// Norvig
#define S0 \
"4.....8.5"\
".3......."\
"...7....."\
".2.....6."\
"....8.4.."\
"....1...."\
"...6.3.7."\
"5..2....."\
"1.4......"

// Pathological
#define S1 \
"........."\
".....3.85"\
"..1.2...."\
"...5.7..."\
"..4...1.."\
".9......."\
"5......73"\
"..2.1...."\
"....4...9"

// More Pathological
#define S2 \
"........."\
"92..7...."\
".....3..."\
"3........"\
"1...97..."\
".....57.."\
"......2.."\
"4....2..."\
"..6......"

// Extremely easy
#define P0 \
".67425..9"\
"...18..6."\
"89.6.7.52"\
"4...6.913"\
"6.239457."\
"9738.162."\
"...243795"\
".249768.."\
".3.5182.."

// Easy
#define P1 \
"2...57389"\
".3.891..."\
"7.9..3.16"\
".73.8926."\
"..25.6..."\
".9.3.4.57"\
".5.9.8.2."\
"9287.56.."\
"....3...."

// Medium
#define P2 \
".9.6.1..."\
"....3.9.1"\
".3.2.8..."\
"7.9.....4"\
".4.3.7.9."\
"8.3.1.5.7"\
".5.7.2.1."\
"9.4.5.7.6"\
".1.9.6.58"

// Difficult
#define P3 \
".......32"\
"36......."\
"......5.8"\
"87......."\
".9...3.4."\
"6..8....."\
".....2..3"\
"5.163.4.."\
".39148756"

// Evil
#define P4 \
"........."\
"......523"\
".......18"\
"........."\
"..9.74.6."\
"..461...7"\
".58.43..."\
".4..2..3."\
".67.81.94"

struct sudoku { uint16_t s[9*9]; };

// Assign a square to a specific symbol and propagate the constraints.
// If a contraction was discovered, returns zero and leaves the Sudoku
// state undefined.
static int
assign(struct sudoku *s, int idx, int symbol)
{
    static const int8_t checks[9*9][20] = {
        {1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,18,19,20,27,36,45,54,63,72},
        {0, 2, 3, 4, 5, 6, 7, 8, 9,10,11,18,19,20,28,37,46,55,64,73},
        {0, 1, 3, 4, 5, 6, 7, 8, 9,10,11,18,19,20,29,38,47,56,65,74},
        {0, 1, 2, 4, 5, 6, 7, 8,12,13,14,21,22,23,30,39,48,57,66,75},
        {0, 1, 2, 3, 5, 6, 7, 8,12,13,14,21,22,23,31,40,49,58,67,76},
        {0, 1, 2, 3, 4, 6, 7, 8,12,13,14,21,22,23,32,41,50,59,68,77},
        {0, 1, 2, 3, 4, 5, 7, 8,15,16,17,24,25,26,33,42,51,60,69,78},
        {0, 1, 2, 3, 4, 5, 6, 8,15,16,17,24,25,26,34,43,52,61,70,79},
        {0, 1, 2, 3, 4, 5, 6, 7,15,16,17,24,25,26,35,44,53,62,71,80},
        {0, 1, 2,10,11,12,13,14,15,16,17,18,19,20,27,36,45,54,63,72},
        {0, 1, 2, 9,11,12,13,14,15,16,17,18,19,20,28,37,46,55,64,73},
        {0, 1, 2, 9,10,12,13,14,15,16,17,18,19,20,29,38,47,56,65,74},
        {3, 4, 5, 9,10,11,13,14,15,16,17,21,22,23,30,39,48,57,66,75},
        {3, 4, 5, 9,10,11,12,14,15,16,17,21,22,23,31,40,49,58,67,76},
        {3, 4, 5, 9,10,11,12,13,15,16,17,21,22,23,32,41,50,59,68,77},
        {6, 7, 8, 9,10,11,12,13,14,16,17,24,25,26,33,42,51,60,69,78},
        {6, 7, 8, 9,10,11,12,13,14,15,17,24,25,26,34,43,52,61,70,79},
        {6, 7, 8, 9,10,11,12,13,14,15,16,24,25,26,35,44,53,62,71,80},
        {0, 1, 2, 9,10,11,19,20,21,22,23,24,25,26,27,36,45,54,63,72},
        {0, 1, 2, 9,10,11,18,20,21,22,23,24,25,26,28,37,46,55,64,73},
        {0, 1, 2, 9,10,11,18,19,21,22,23,24,25,26,29,38,47,56,65,74},
        {3, 4, 5,12,13,14,18,19,20,22,23,24,25,26,30,39,48,57,66,75},
        {3, 4, 5,12,13,14,18,19,20,21,23,24,25,26,31,40,49,58,67,76},
        {3, 4, 5,12,13,14,18,19,20,21,22,24,25,26,32,41,50,59,68,77},
        {6, 7, 8,15,16,17,18,19,20,21,22,23,25,26,33,42,51,60,69,78},
        {6, 7, 8,15,16,17,18,19,20,21,22,23,24,26,34,43,52,61,70,79},
        {6, 7, 8,15,16,17,18,19,20,21,22,23,24,25,35,44,53,62,71,80},
        {0, 9,18,28,29,30,31,32,33,34,35,36,37,38,45,46,47,54,63,72},
        {1,10,19,27,29,30,31,32,33,34,35,36,37,38,45,46,47,55,64,73},
        {2,11,20,27,28,30,31,32,33,34,35,36,37,38,45,46,47,56,65,74},
        {3,12,21,27,28,29,31,32,33,34,35,39,40,41,48,49,50,57,66,75},
        {4,13,22,27,28,29,30,32,33,34,35,39,40,41,48,49,50,58,67,76},
        {5,14,23,27,28,29,30,31,33,34,35,39,40,41,48,49,50,59,68,77},
        {6,15,24,27,28,29,30,31,32,34,35,42,43,44,51,52,53,60,69,78},
        {7,16,25,27,28,29,30,31,32,33,35,42,43,44,51,52,53,61,70,79},
        {8,17,26,27,28,29,30,31,32,33,34,42,43,44,51,52,53,62,71,80},
        {0, 9,18,27,28,29,37,38,39,40,41,42,43,44,45,46,47,54,63,72},
        {1,10,19,27,28,29,36,38,39,40,41,42,43,44,45,46,47,55,64,73},
        {2,11,20,27,28,29,36,37,39,40,41,42,43,44,45,46,47,56,65,74},
        {3,12,21,30,31,32,36,37,38,40,41,42,43,44,48,49,50,57,66,75},
        {4,13,22,30,31,32,36,37,38,39,41,42,43,44,48,49,50,58,67,76},
        {5,14,23,30,31,32,36,37,38,39,40,42,43,44,48,49,50,59,68,77},
        {6,15,24,33,34,35,36,37,38,39,40,41,43,44,51,52,53,60,69,78},
        {7,16,25,33,34,35,36,37,38,39,40,41,42,44,51,52,53,61,70,79},
        {8,17,26,33,34,35,36,37,38,39,40,41,42,43,51,52,53,62,71,80},
        {0, 9,18,27,28,29,36,37,38,46,47,48,49,50,51,52,53,54,63,72},
        {1,10,19,27,28,29,36,37,38,45,47,48,49,50,51,52,53,55,64,73},
        {2,11,20,27,28,29,36,37,38,45,46,48,49,50,51,52,53,56,65,74},
        {3,12,21,30,31,32,39,40,41,45,46,47,49,50,51,52,53,57,66,75},
        {4,13,22,30,31,32,39,40,41,45,46,47,48,50,51,52,53,58,67,76},
        {5,14,23,30,31,32,39,40,41,45,46,47,48,49,51,52,53,59,68,77},
        {6,15,24,33,34,35,42,43,44,45,46,47,48,49,50,52,53,60,69,78},
        {7,16,25,33,34,35,42,43,44,45,46,47,48,49,50,51,53,61,70,79},
        {8,17,26,33,34,35,42,43,44,45,46,47,48,49,50,51,52,62,71,80},
        {0, 9,18,27,36,45,55,56,57,58,59,60,61,62,63,64,65,72,73,74},
        {1,10,19,28,37,46,54,56,57,58,59,60,61,62,63,64,65,72,73,74},
        {2,11,20,29,38,47,54,55,57,58,59,60,61,62,63,64,65,72,73,74},
        {3,12,21,30,39,48,54,55,56,58,59,60,61,62,66,67,68,75,76,77},
        {4,13,22,31,40,49,54,55,56,57,59,60,61,62,66,67,68,75,76,77},
        {5,14,23,32,41,50,54,55,56,57,58,60,61,62,66,67,68,75,76,77},
        {6,15,24,33,42,51,54,55,56,57,58,59,61,62,69,70,71,78,79,80},
        {7,16,25,34,43,52,54,55,56,57,58,59,60,62,69,70,71,78,79,80},
        {8,17,26,35,44,53,54,55,56,57,58,59,60,61,69,70,71,78,79,80},
        {0, 9,18,27,36,45,54,55,56,64,65,66,67,68,69,70,71,72,73,74},
        {1,10,19,28,37,46,54,55,56,63,65,66,67,68,69,70,71,72,73,74},
        {2,11,20,29,38,47,54,55,56,63,64,66,67,68,69,70,71,72,73,74},
        {3,12,21,30,39,48,57,58,59,63,64,65,67,68,69,70,71,75,76,77},
        {4,13,22,31,40,49,57,58,59,63,64,65,66,68,69,70,71,75,76,77},
        {5,14,23,32,41,50,57,58,59,63,64,65,66,67,69,70,71,75,76,77},
        {6,15,24,33,42,51,60,61,62,63,64,65,66,67,68,70,71,78,79,80},
        {7,16,25,34,43,52,60,61,62,63,64,65,66,67,68,69,71,78,79,80},
        {8,17,26,35,44,53,60,61,62,63,64,65,66,67,68,69,70,78,79,80},
        {0, 9,18,27,36,45,54,55,56,63,64,65,73,74,75,76,77,78,79,80},
        {1,10,19,28,37,46,54,55,56,63,64,65,72,74,75,76,77,78,79,80},
        {2,11,20,29,38,47,54,55,56,63,64,65,72,73,75,76,77,78,79,80},
        {3,12,21,30,39,48,57,58,59,66,67,68,72,73,74,76,77,78,79,80},
        {4,13,22,31,40,49,57,58,59,66,67,68,72,73,74,75,77,78,79,80},
        {5,14,23,32,41,50,57,58,59,66,67,68,72,73,74,75,76,78,79,80},
        {6,15,24,33,42,51,60,61,62,69,70,71,72,73,74,75,76,77,79,80},
        {7,16,25,34,43,52,60,61,62,69,70,71,72,73,74,75,76,77,78,80},
        {8,17,26,35,44,53,60,61,62,69,70,71,72,73,74,75,76,77,78,79},
    };

    int fail = 0;
    int head = 1, tail = 0;
    struct { int8_t i, v; } queue[9*9];
    queue[0].i = idx;
    queue[0].v = symbol;

    // When propagation narrows a square to a single possibility, that
    // square is enqueued for an additional assignment.
    while (head != tail) {
        int n = queue[tail].i;
        int v = queue[tail++].v;
        uint16_t m = ~(1 << v);
        s->s[n] = 1 << v;
        for (int i = 0; i < 20; i++) {
            int prev = s->s[checks[n][i]];
            int next = s->s[checks[n][i]] &= m;
            queue[head].i = checks[n][i];
            queue[head].v = FFS(next);
            head += prev != next && POPCNT(next) == 1;
            fail += !next;
        }
    }
    return !fail;
}

// Initialize to an empty board
static void
empty(struct sudoku *s)
{
    for (int i = 0; i < 9*9; i++) {
        s->s[i] = 0x1ff;
    }

}

// Parse a string representation of a Sudoku. Return zero for bad input.
static int
decode(struct sudoku *s, char p[9*9])
{
    empty(s);
    for (int i = 0; i < 9*9; i++) {
        switch (p[i]) {
        default:
            return 0;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            if (!assign(s, i, p[i] - '1')) {
                return 0;
            }
            break;
        case '.':
            break;
        }
    }
    return 1;
}

// Find the squares with the narrowest constraints. Fills dst with their
// indices and returns the square count.
static int
narrowest(int8_t dst[9*9], struct sudoku *s)
{
    int len = 0;
    int best = 11;
    for (int i = 0; i < 9*9; i++) {
        int c = POPCNT(s->s[i]);
        if (c == best) {
            dst[len++] = i;
        } else if (c > 1 && c < best) {
            best = c;
            dst[0] = i;
            len = 1;
        }
    }
    return len;
}

// Return the first "narrowest" square, as a convenience.
static int
narrow(struct sudoku *s)
{
    int8_t d[9*9];
    return narrowest(d, s) ? d[0] : -1;
}

static void
printstate(struct sudoku *s)
{
    static char t[1<<9] = {
        [1<<0] = '1', [1<<1] = '2', [1<<2] = '3',
        [1<<3] = '4', [1<<4] = '5', [1<<5] = '6',
        [1<<6] = '7', [1<<7] = '8', [1<<8] = '9',
    };
    for (int i = 0; i < 9*9; i++) {
        char c = t[s->s[i]];
        putchar(c ? c : '.');
        switch (i % 27) {
        case  2: case  5: case 11: case 14: case 20: case 23:
            putchar(' ');
            break;
        case 26:
            putchar('\n');
            // fallthrough
        case  8: case 17:
            putchar('\n');
            break;
        }
    }
}

static void
print(char p[9*9])
{
    printf("%.3s %.3s %.3s\n%.3s %.3s %.3s\n%.3s %.3s %.3s\n\n"
           "%.3s %.3s %.3s\n%.3s %.3s %.3s\n%.3s %.3s %.3s\n\n"
           "%.3s %.3s %.3s\n%.3s %.3s %.3s\n%.3s %.3s %.3s\n",
           p+ 0, p+ 3, p+ 6, p+ 9, p+12, p+15, p+18, p+21, p+24,
           p+27, p+30, p+33, p+36, p+39, p+42, p+45, p+48, p+51,
           p+54, p+57, p+60, p+63, p+66, p+69, p+72, p+75, p+78);
}

// Attempt to solve the Sudoku, populating it with a solution if found.
// Return value indicates the solvable state of the Sudoku.
static enum {UNSOLVABLE, VALID, MULTIPLE}
solve(struct sudoku *s, int64_t limit)
{
    // Use a stack to implement a guess and backtrack approach
    struct {
        struct sudoku s;
        int8_t i;  // index to manipulate
        int8_t v;  // symbol to attempt next
    } stack[9*9];
    int top = 0;
    int status = UNSOLVABLE;
    int64_t count = 0;

    stack[0].s = *s;
    stack[0].i = narrow(&stack[top].s);
    stack[0].v = 0;

    while (top >= 0) {
        if (limit && ++count > limit) {
            return UNSOLVABLE;
        }

        if (stack[top].i < 0) {
            switch (status) {
            case UNSOLVABLE:
                status = VALID;
                *s = stack[top--].s;
                continue;  // keep looking
            case VALID:
                return MULTIPLE;
            }
        }

        if (stack[top].v == 9) {
            top--;
            continue;  // backtrack
        }

        int i = stack[top].i;
        while (stack[top].v < 9) {
            int v = stack[top].v++;
            uint16_t b = 1 << v;
            if (stack[top].s.s[i] & b) {
                stack[top+1].s = stack[top].s;
                if (assign(&stack[top+1].s, i, v)) {
                    stack[top+1].i = narrow(&stack[top+1].s);
                    stack[top+1].v = 0;
                    top++;
                    break;  // "recurse"
                }
            }
        }
    }
    return status;
}

// Compute a difficulty score 1-5 of the given puzzle.
static int
score(char p[9*9])
{
    int givens = 0;
    for (int i = 0; i < 9*9; i++) {
        givens += p[i] != '.';
    }
    givens = 5 - (givens>27) - (givens>31) - (givens>35) - (givens>49);

    int min = 9;
    for (int i = 0; i < 9; i++) {
        int x = i%3*3, y = i/3*3;
        int v = 0, h = 0, b = 0;
        for (int j = 0; j < 9; j++) {
            v += p[j*9+i] != '.';
            h += p[i*9+j] != '.';
            b += p[(y+j/3)*9+x+j%3] != '.';
        }
        min = v<min ? v : min;
        min = h<min ? h : min;
        min = b<min ? b : min;
    }
    min = 5 - (min>4) - (min>3) - (min>2) - (min>0);

    return (givens*2 + min) / 3;
}

static uint64_t
hash64(uint64_t x)
{
    x += 1111111111111111111; x ^= x >> 33;
    x *= 1111111111111111111; x ^= x >> 33;
    x *= 1111111111111111111; x ^= x >> 33;
    return x;
}

static int32_t
rand31(uint64_t s[1])
{
    *s = *s*0x3243f6a8885a308d + 1;
    return *s >> 33;
}

// Generate a new puzzle at a target difficulty (1-5).
static void
generate(char p[9*9], int target, uint64_t seed)
{
    int8_t order[9*9];
    for (int i = 0; i < 9*9; i++) {
        order[i] = i;
    }

    seed = hash64(seed);
    for (int i = 9*9-1; i > 0; i--) {
        int j = rand31(&seed) % (i + 1);
        int8_t t = order[i];
        order[i] = order[j];
        order[j] = t;
    }

    for (;;) {
        struct sudoku s, t;
        empty(&s);

        for (int i = 0; i < 9*9; i++) {
            p[i] = '.';
        }

        for (int i = 0; i < 9*9; i++) {
            // Will this placement hurt the score too badly?
            p[order[i]] = '0';
            int r = score(p);
            p[order[i]] = '.';
            if (r < target) {
                continue;
            }

            // What symbols are available
            int n = 0, opt[9];
            uint16_t b = s.s[order[i]];
            for (int v = 0; v < 9; v++) {
                if (b & (1 << v)) {
                    opt[n++] = v;
                }
            }

            // Pick the first symbol that isn't a contradiction
            while (n) {
                int j = rand31(&seed) % n;
                t = s;
                if (assign(&t, order[i], opt[j])) {
                    s = t;
                    p[order[i]] = '1' + opt[j];
                    break;
                }
                opt[j] = opt[--n];
            }
            if (!n) {
                break;
            }

            if (i >= 16) {
                t = s;
                int r = solve(&t, 1000000);
                if (r == UNSOLVABLE) {
                    break;
                } else if (r == VALID) {
                    int actual = score(p);
                    if (actual == target) {
                        return;
                    } else if (actual > target) {
                        break;
                    }
                }
            }
        }
    }
}

// Generate a unique 64-bit seed.
static uint64_t
genseed(void)
{
    uint64_t seed = hash64(time(0));
    clock_t end, beg = clock();
    do {
        seed = hash64(seed + beg);
    } while ((end = clock()) == beg);
    seed = hash64(seed + end);
    return seed;
}

int
main(int argc, char **argv)
{
    int target = 3;
    uint64_t seed = genseed();

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            fprintf(stderr, "sudoku: invalid argument, %s\n", argv[i]);
        }
        switch (argv[i][1]) {
        case 'h':
            fprintf(stderr, "usage: sudoku [-12345]\n");
            return 0;
        case '1': case '2': case '3': case '4': case '5':
            target = argv[i][1] - '0';
            break;
        default:
            fprintf(stderr, "sudoku: invalid difficulty, %s\n", argv[i]);
            return 1;
        }
    }

    // Quick and dirty multithreaded generation
    #pragma omp parallel for
    for (int i = 0; i < 256; i++) {
        char p[9*9];
        generate(p, target, hash64(seed + i));
        #pragma omp critical
        {
            print(p);
            fflush(stdout);
            exit(ferror(stdout));
        }
    }
}
