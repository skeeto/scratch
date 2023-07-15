// Solver for "Ada and Friends" (ADAFRIEN)
//
// Ada the Ladybug has many friends. They constantly celebrate, and Ada
// must buy them gifts. This is costly, so she has decided to unfriend
// some friends. What is the maximum amount of money she can save?
//
// Input: The first line is two integers 1 <= Q <= K <= 1e5, the number
// of celebrations, Q, and the maximum number of friends Ada wants to
// unfriend, K. The next Q lines contain the name of friend to whom Ada
// will buy gift and the cost, 1 <= E <= 1e9+1. Names contain at most 40
// lowercase ASCII letters.
//
// Note: The solver below does not validate input, assuming it is in the
// correct format, e.g. from the included input generator.
//
// Ref: https://www.spoj.com/problems/ADAFRIEN/
// Ref: https://old.reddit.com/r/C_Programming/comments/14xe2sq
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

typedef struct {
    char *end;
    int32_t value;
} Parsed;

static Parsed parse(char *s)
{
    Parsed r = {s, 0};
    do {
        r.value = r.value*10 + *r.end++ - '0';
    } while ((unsigned)(*r.end-'0') <= 9);
    return r;
}

typedef struct {
    uint64_t name[5];  // zero-padded 40 characters
} Name;

static Name makename(char *s, int len)
{
    Name n = {0};
    char *p = (char *)n.name;
    for (int i = 0; i < len; i++) {
        p[i] = s[i];
    }
    return n;
}

static int equal(Name a, Name b)
{
    return 5 == (a.name[0] == b.name[0]) +
                (a.name[1] == b.name[1]) +
                (a.name[2] == b.name[2]) +
                (a.name[3] == b.name[3]) +
                (a.name[4] == b.name[4]);
}

static uint64_t hash(Name n)
{
    uint64_t r = 0;
    for (int i = 0; i < 5; i++) {
        r ^= n.name[i];
        r *= 1111111111111111111;
    }
    return r ^ r>>32;
}

// Solver state, zero-initialize
typedef struct {
    Name names[100000];
    int64_t costs[100000];
    int32_t lookup[1<<17];
    int32_t count;
    int32_t unfriend;
    int32_t remaining;
} Solver;

// Call with the first line, then continue calling with each line until
// "remaining" is zero. Lines are newline-terminated, null-termination
// is optional.
static void insert(Solver *s, char *line)
{
    if (--s->remaining < 0) {  // first line?
        Parsed p = parse(line);
        s->remaining = p.value;
        s->unfriend = parse(p.end+1).value;
        return;
    }

    int length = 0;
    for (; line[length] != ' '; length++) {}
    Name name = makename(line, length);
    int32_t cost = parse(line+length+1).value;

    // MSI hash table (https://nullprogram.com/blog/2022/08/08/)
    uint64_t h    = hash(name);
    unsigned mask = (unsigned)(1<<17) - 1;
    unsigned step = (unsigned)(h>>16) | 1;
    for (unsigned index = (unsigned)h;;) {
        index = (index + step)&mask;
        int32_t i = s->lookup[index] - 1;  // unbias
        if (i < 0) {
            int32_t dest = s->count++;
            s->lookup[index] = dest + 1;  // bias
            s->names[dest] = name;
            s->costs[dest] = cost;
            return;
        } else if (equal(name, s->names[i])) {
            s->costs[i] += cost;
            return;
        }
    }
}

// In-place base-2 MSB radix sort
static void sort(int64_t *beg, int64_t *end, int shift)
{
    if (end-beg < 2) {
        return;
    }

    int64_t *p = beg;
    int64_t *e = end;
    while (p < e) {
        if ((*p>>shift) & 1) {
            p++;
        } else {
            int64_t swap = *--e;
            *e = *p;
            *p = swap;
        }
    }
    if (shift) {
        sort(beg, p, shift-1);
        sort(p, end, shift-1);
    }
}

// Compute final result, destroying the solver state.
static int64_t finalize(Solver *s)
{
    // Only need to sort on 47 bits: log2((1e9+1)*1e5) < 47
    sort(s->costs, s->costs+s->count, 46);
    int64_t savings = 0;
    for (int32_t i = 0; i < s->unfriend; i++) {
        savings += s->costs[i];
    }
    return savings;
}


#if defined(GENERATE)
// $ cc -DGENERATE -o generate adafrien.c
// $ cl /DGENERATE /Fe:generate.exe adafrien.c
// $ ./generate my custom seed | ./adafrien
#include <stdio.h>

static int randint(uint64_t *rng, int min, int max)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    uint32_t range = max - min + 1;
    return (int)(((*rng >> 32)*range) >> 32) + min;
}

int main(int argc, char **argv)
{
    static struct {
        char name[40];
        int length;
    } names[100000];

    uint64_t rng[1] = {0x100};
    for (int i = 1; i < argc; i++) {
        for (char *s = argv[i]; *s; s++) {
            *rng ^= *s & 255;
            *rng *= 1111111111111111111;
        }
        *rng ^= *rng >> 32;
    }

    int count = randint(rng, 1, 100000);
    for (int i = 0; i < count; i++) {
        int length = names[i].length = randint(rng, 1, 40);
        for (int j = 0; j < length; j++) {
            names[i].name[j] = (char)randint(rng, 'a', 'z');
        }
    }

    printf("100000 %d\n", randint(rng, 1, (count+1)/2));
    for (int i = 0; i < 100000; i++) {
        int who = randint(rng, 0, count-1);
        fwrite(names[who].name, names[who].length, 1, stdout);
        printf(" %d\n", randint(rng, 1, 1000000001));
    }
    fflush(stdout);
    return ferror(stdout);
}

#elif defined(_WIN32) && !defined(STDIO)
// Win32 implementation
// $ cc -nostartfiles -o adafrien.exe adafrien.c
// $ cl /GS- adafrien.c /link /subsystem:console kernel32.lib
__declspec(dllimport) void *__stdcall GetStdHandle(int);
__declspec(dllimport) int __stdcall ReadFile(void*, char*, int, int*, void*);
__declspec(dllimport) int __stdcall WriteFile(void*, char*, int, int*, void*);

int mainCRTStartup(void)
{
    static Solver solver[1] = {0};
    static char buf[10+1+10+2 + 100000*(40+1+10+2)];  // worst case

    void *stdin = GetStdHandle(-10);
    for (int len = 0;;) {
        int count;
        ReadFile(stdin, buf+len, (int)sizeof(buf)-len, &count, 0);
        if (!count) {
            break;
        }
        len += count;
    }

    char *line = buf;
    do {
        insert(solver, line);
        while (*line++ != '\n') {}
    } while (solver->remaining);
    int64_t total = finalize(solver);

    void *stdout = GetStdHandle(-11);
    char out[32];
    char *p = out + sizeof(out);
    int len = 0;
    p[-++len] = '\n';
    do {
        p[-++len] = (char)(total%10) + '0';
    } while (total /= 10);
    return !WriteFile(stdout, p-len, len, &len, 0);
}

#else
// stdio implementation
// $ cc -o adafrien adafrien.c
// $ cl /DSTDIO adafrien.c
#include <stdio.h>

int main(void)
{
    char line[64] = {0};
    static Solver solver[1] = {0};
    do {
        fgets(line, sizeof(line), stdin);
        insert(solver, line);
    } while (solver->remaining);
    printf("%lld\n", (long long)finalize(solver));
    fflush(stdout);
    return ferror(stdout) || ferror(stdin);
}
#endif
