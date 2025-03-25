// Water Sort Puzzle Game
// $ eval cc -O water-sort-puzzle.c $(pkg-config --cflags --libs sdl2)
//
// User interface:
// * Left-click the "bottles" to make moves
// * Middle-click to get a hint
// * Right-click to undo
// * h: hint move
// * q: quit the game
// * r: reset puzzle
// * u: undo last move
// * 1-5: generate a new puzzle (0=easy, 4=hard)
//
// TODO: Add on-screen buttons, then build web version with empscripten.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define affirm(c)       while (!(c)) *(volatile int *)0 = 0

typedef int8_t      i8;
typedef uint16_t    u16;
typedef int32_t     b32;
typedef int32_t     i32;
typedef uint64_t    u64;
typedef ptrdiff_t   iz;
typedef size_t      uz;

enum {
    SOLVE_MEM = 1<<25,
};

typedef struct {
    char *beg;
    char *end;
} Arena;

static void *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (uz)a->end & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    char *r = a->end -= pad + count*size;
    for (iz i = 0; i < count*size; i++) {
        r[i] = 0;
    }
    return r;
}

enum { MAXBOTTLE = 14 };
typedef struct {
    u16 s[MAXBOTTLE];
} State;

static b32 null(State s)
{
    return !s.s[0] && !s.s[1] && !s.s[2];
}

static b32 equals(State a, State b, i32 nbottle)
{
    for (i32 i = 0; i < nbottle; i++) {
        if (a.s[i] != b.s[i]) {
            return 0;
        }
    }
    return 1;
}

static u64 hash64(State s, i32 nbottle)
{
    u64 h = 0;
    for (i32 i = 0; i < nbottle; i++) {
        h ^= s.s[i];
        h *= 1111111111111111111u;
    }
    return h;
}

typedef struct {
    State *slots;
    iz     len;
    i32    exp;
} StateSet;

static StateSet newset(Arena *a, i32 exp)
{
    StateSet s = {0};
    s.slots = new(a, (iz)1<<exp, State);
    s.exp   = exp;
    return s;
}

static void sort(u16 *nums, i32 len)
{
    for (i32 i = 1; i < len; i++) {
        for (i32 j = i; j>0 && nums[j-1]>nums[j]; j--) {
            u16 swap  = nums[j-1];
            nums[j-1] = nums[j];
            nums[j]   = swap;
        }
    }
}

static State normalize(State s, i32 nbottle)
{
    sort(s.s, nbottle);
    return s;
}

static b32 insert(StateSet *t, State s, i32 nbottle)
{
    affirm(t->len < ((iz)1<<t->exp) - ((iz)1<<(t->exp-2)));
    State norm = normalize(s, nbottle);
    u64   hash = hash64(norm, nbottle);
    uz    mask = ((uz)1 << t->exp) - 1;
    uz    step = (hash >> (64 - t->exp)) | 1;
    for (iz i = (iz)hash;;) {
        i = (i + step) & mask;
        if (null(t->slots[i])) {
            t->slots[i] = norm;
            t->len++;
            return 1;
        } else if (equals(t->slots[i], norm, nbottle)) {
            return 0;
        }
    }
}

static i32 height(u16 x)
{
    i32 r = 0;
    if (x) {
        u16 c = x&15;
        do {
            r++;
            x >>= 4;
        } while (c == (x&15));
    }
    return r;
}

static i32 space(u16 x)
{
    i32 r = 4;
    while (x) {
        r--;
        x >>= 4;
    }
    return r;
}

typedef struct {
    i32 src;
    i32 dst;
} Move;

static State apply(State s, Move e)
{
    i32 h = height(s.s[e.src]);
    u16 m = (u16)((1 << (h*4)) - 1);
    s.s[e.dst] = (u16)(s.s[e.dst]<<(4*h) | (s.s[e.src] & m));
    s.s[e.src] = (u16)(s.s[e.src]>>(4*h)                   );
    return s;
}

static b32 solved(State s, i32 nbottle)
{
    for (i32 i = 0; i < nbottle; i++) {
        u16 v = s.s[i];
        u16 r = (u16)(s.s[i]>>4 | s.s[i]<<4);
        if (v ^ r) {
            return 0;
        }
    }
    return 1;
}

static i32 getmoves(State s, i32 nbottle, Move *e)
{
    enum { MAXCOLOR = MAXBOTTLE-2 };
    i8  lens[MAXCOLOR+1]    = {0};
    i8  hist[MAXCOLOR+1][4] = {0};
    i8  empty[MAXBOTTLE]    = {0};
    i32 nempty              = 0;
    for (i32 i = 0; i < nbottle; i++) {
        u16 v = s.s[i]&15;
        if (v) {
            hist[v][lens[v]++] = (i8)i;
        } else {
            empty[nempty++] = (i8)i;
        }
    }

    i32 r = 0;
    for (i32 src = 0; src < nbottle; src++) {
        u16 v = s.s[src]&15;
        if (!v) continue;

        i32 h = height(s.s[src]);
        for (i32 i = 0; i < lens[v]; i++) {
            i32 dst = hist[v][i];
            i32 spc = space(s.s[dst]);
            if (dst!=src && spc>=h) {
                e[r].src = src;
                e[r].dst = dst;
                r++;
            }
        }

        for (i32 i = 0; i < nempty; i++) {
            e[r].src = src;
            e[r].dst = empty[i];
            r++;
        }
    }
    return r;
}

typedef struct {
    State *states;
    i32    len;
} Solution;

static Solution solve(State init, i32 nbottle, Arena *a)
{
    Solution r = {0};

    i32      exp  = 19;
    StateSet seen = newset(a, exp);
    insert(&seen, init, nbottle);

    typedef struct {
        State s;
        i32   delta;
    } Node;

    iz    cap   = (iz)1<<exp;
    Node *queue = new(a, cap, Node);
    i32   head  = 0;
    i32   tail  = 0;
    queue[head++].s = init;

    while (tail < head) {
        Node n = queue[tail++];
        Move moves[64];
        i32 nmoves = getmoves(n.s, nbottle, moves);

        for (i32 i = 0; i < nmoves; i++) {
            State next = apply(n.s, moves[i]);
            if (insert(&seen, next, nbottle)) {
                affirm(head - tail < 0x7fffffff);
                queue[head].s     = next;
                queue[head].delta = head - tail + 1;
                if (solved(next, nbottle)) {
                    r.len = 1;
                    for (i32 i = head; queue[i].delta; i -= queue[i].delta) {
                        r.len++;
                    }
                    r.states = new(a, r.len, State);

                    i32 len = r.len;
                    for (i32 i = head; queue[i].delta; i -= queue[i].delta) {
                        r.states[--len] = queue[i].s;
                    }
                    r.states[--len] = init;
                    return r;
                }
                head++;
                affirm(head < cap);
            }
        }
    }
    return r;
}

static i32 randint(u64 *rng, i32 lo, i32 hi)
{
    u64 x = *rng = *rng*0x3243f6a8885a308d + 1;
    return (i32)((x>>32)*(hi - lo)>>32) + lo;
}

// Distribution (0.34% unsolvable):
//   steps freq. diff.
//   30    0.01%
//   31    0.00%
//   32    0.04%
//   33    0.27%
//   34    0.82%
//   35    2.32%
//   36    5.11%
//   37   11.23%
//   38   17.53%
//   39   22.06%
//   40   20.90%     1
//   41   13.31%     2
//   42    4.93%     3
//   43    1.07%     4
//   44    0.06%     5
static State genpuzzle(u64 seed, i32 nbottle)
{
    affirm(nbottle>=4 && nbottle<=MAXBOTTLE);

    enum { MAXCOLOR = MAXBOTTLE-2 };
    i32 ncolor = nbottle - 2;

    i8 colors[MAXCOLOR*4];
    for (i32 c = 0; c < ncolor; c++) {
        for (i32 i = 0; i < 4; i++) {
            colors[4*c+i] = (i8)(c + 1);
        }
    }

    State s   = {0};
    i32   len = ncolor * 4;
    for (i32 b = 0; b < nbottle-2; b++) {
        for (i32 h = 0; h < 4; h++) {
            i32 i = randint(&seed, 0, len);
            u16 c = colors[i];
            colors[i] = colors[--len];
            s.s[b] |= (u16)(c<<(h*4));
        }
    }
    return s;
}


// UI

#if 1
#include "SDL.h"

enum {
    MAXUNDO   = 256,
    BORDER_MS = 500,
    STEP_BASE = 39,
    NTHREADS  = (i32)sizeof(uz),
};

typedef uint8_t u8;
typedef int64_t i64;
typedef float   f32;

static i32 colors[] = {
    0x222222,
    0x8b4513, 0x228b22, 0x4682b4,
    0x4b0082, 0xff0000, 0xffd700,
    0x7fff00, 0x00ffff, 0x0000ff,
    0xff00ff, 0x2f4f4f, 0xf0f8ff,
};

enum {
    STATUS_GENERATING,
    STATUS_UNKNOWN,
    STATUS_SOLVED,
    STATUS_SOLVABLE,
    STATUS_UNSOLVABLE,
};

typedef struct {
    i64   success;
    i64   error;
    i32   border;

    i32   nbottle;
    State states[MAXUNDO];
    i32   head;
    i32   tail;
    i32   status;

    i32   width;
    i32   height;

    b32   click;
    i32   mousex;
    i32   mousey;
    i32   select;
    i32   active;
    i32   slot;
} UI;

static void push(UI *ui, State s)
{
    ui->status = STATUS_UNKNOWN;
    ui->states[ui->head++%MAXUNDO] = s;
    ui->tail += ui->head-ui->tail > MAXUNDO;
}

static b32 pop(UI *ui)
{
    ui->status = STATUS_UNKNOWN;
    if (ui->head-1 > ui->tail) {
        ui->head--;
        return 1;
    }
    return 0;
}

static State top(UI *ui)
{
    State r = {0};
    if (ui->head > ui->tail) {
        r = ui->states[(ui->head-1)%MAXUNDO];
    }
    return r;
}

static void undo(UI *ui, i64 now)
{
    ui->success = ui->error = 0;
    if (!pop(ui)) {
        ui->error = now + BORDER_MS;
    }
}

static void hint(UI *ui, i64 now, Arena a)
{
    Arena    tmp = a;
    Solution ok  = solve(top(ui), ui->nbottle, &tmp);
    if (ok.len > 1) {
        push(ui, ok.states[1]);
    } else {
        ui->error = now + BORDER_MS;
    }
}

static void draw(SDL_Renderer *r, UI *ui)
{
    // TODO: on-screen buttons for reset, undo, hint, generate
    // TODO: puzzle editor, to turn it into a solver

    if (ui->border) {
        i32 c = ui->border;
        SDL_SetRenderDrawColor(r, (u8)(c>>16), (u8)(c>>8), (u8)(c>>0), 0xff);
        SDL_RenderClear(r);

        i32 pad = ui->width / 75;
        SDL_Rect bg = {pad, pad, ui->width-1-pad*2, ui->height-1-pad*2};
        c = colors[0];
        SDL_SetRenderDrawColor(r, (u8)(c>>16), (u8)(c>>8), (u8)(c>>0), 0xff);
        SDL_RenderFillRect(r, &bg);
    } else {
        i32 c = colors[0];
        SDL_SetRenderDrawColor(r, (u8)(c>>16), (u8)(c>>8), (u8)(c>>0), 0xff);
        SDL_RenderClear(r);
    }

    i32 bw   = ui->width  / 7;
    i32 bh   = ui->height / 2;
    i32 xpad = bw / 6;
    i32 ypad = bh / 8;
    i32 ww   =  bw - 2*xpad;
    i32 wh   = (bh - 2*ypad)/4;

    if (ui->select >= 0) {
        SDL_Rect bottle = {
            (ui->select%7)*bw,
            ypad/2 + (ui->select/7)*bh,
            bw, bh - ypad
        };
        SDL_SetRenderDrawColor(r, 0x7f, 0x7f, 0x7f, 0xff);
        SDL_RenderFillRect(r, &bottle);
    }

    State s = top(ui);
    if (null(s)) {
        return;
    }

    ui->active = -1;
    for (i32 i = 0; i < ui->nbottle; i++) {
        u16 v = s.s[i];
        for (; v && !(v&0xf000); v = (u16)(v<<4)) {}
        for (i32 y = 0; y < 4; y++) {
            u16 c = (v>>(y*4)) & 15;
            i32 color = colors[c];
            SDL_SetRenderDrawColor(
                r, (u8)(color>>16), (u8)(color>>8), (u8)(color>>0), 0xff
            );

            SDL_Rect water = {
                xpad + (i%7)*bw,
                ypad + (i/7)*bh + y*wh,
                ww+1, wh+1
            };
            SDL_RenderFillRect(r, &water);
            SDL_SetRenderDrawColor(r, 0xff, 0xff, 0xff, 0xff);
            SDL_RenderDrawRect(r, &water);

            SDL_Point click = {ui->mousex, ui->mousey};
            if (SDL_PointInRect(&click, &water)) {
                ui->active = i;
                ui->slot   = y;
            }
        }
    }
}

static b32 valid(State s, i32 nbottle, Move e)
{
    Move moves[64];
    i32 len = getmoves(s, nbottle, moves);
    for (i32 i = 0; i < len; i++) {
        if (moves[i].src==e.src && moves[i].dst==e.dst) {
            return 1;
        }
    }
    return 0;
}

static u64 compress(u64 a, u64 b)
{
    return (a + b) * 1111111111111111111u;
}

typedef struct {
    u64        seed;
    SDL_mutex *lock;
    SDL_cond  *cv;
    Arena      scratch;
    State      puzzles[5];
    i32        nbottle;
    i32        id;
} Worker;

static int worker(void *arg)
{
    Worker *w    = arg;
    u64     seed = w->seed;

    SDL_SetThreadPriority(SDL_THREAD_PRIORITY_LOW);
    SDL_LockMutex(w->lock);

    for (;;) {
        i32 needed = 0;
        for (i32 i = 0; i < 5; i++) {
            if (null(w->puzzles[i])) {
                needed |= 1<<i;
            }
        }

        if (!needed) {
            SDL_Log("thread %d: sleep", w->id);
            SDL_CondWait(w->cv, w->lock);
            SDL_Log("thread %d: woken", w->id);
            continue;
        }

        SDL_UnlockMutex(w->lock);
        for (;;) {
            seed = compress(seed, SDL_GetTicks64());
            seed = compress(seed, w->id);
            seed = compress(seed, needed);

            Arena scratch = w->scratch;
            State s = genpuzzle(seed, w->nbottle);
            Solution r = solve(s, w->nbottle, &scratch);
            i32 difficulty = r.len - STEP_BASE;
            i32 i = difficulty - 1;

            if (difficulty>=1 && difficulty<=5 && (needed&(1<<i))) {
                SDL_Log("thread %d: difficulty=%d", w->id, difficulty);
                SDL_LockMutex(w->lock);
                w->puzzles[i] = s;
                break;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char *mem = SDL_malloc(SOLVE_MEM);
    Arena a   = {mem, mem+SOLVE_MEM};

    UI *ui      = new(&a, 1, UI);
    ui->width   = 600;
    ui->height  = 600;
    ui->nbottle = MAXBOTTLE;
    ui->select  = -1;

    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *w = SDL_CreateWindow(
        "Water Sort Puzzle",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        ui->width, ui->height, 0
    );
    SDL_Renderer *r     = SDL_CreateRenderer(w, -1, SDL_RENDERER_PRESENTVSYNC);
    SDL_Cursor   *arrow = SDL_CreateSystemCursor(SDL_SYSTEM_CURSOR_ARROW);
    SDL_Cursor   *hand  = SDL_CreateSystemCursor(SDL_SYSTEM_CURSOR_HAND);

    u64 seed = 0;
    seed = compress(seed, (uz)a.beg);
    seed = compress(seed, SDL_GetTicks64());
    #if __amd64
    asm volatile ("rdrand %0" : "=r"(seed));
    #endif

    SDL_mutex *lock    = SDL_CreateMutex();
    Worker    *workers = new(&a, NTHREADS, Worker);
    for (i32 i = 0; i < NTHREADS; i++) {
        char *mem = SDL_malloc(SOLVE_MEM);
        workers[i].seed    = compress(seed, (uz)mem);
        workers[i].lock    = lock;
        workers[i].cv      = SDL_CreateCond();
        workers[i].scratch = (Arena){mem, mem+SOLVE_MEM};
        workers[i].nbottle = ui->nbottle;
        workers[i].id      = i + 1;
        SDL_Thread *t = SDL_CreateThread(worker, "worker", workers+i);
        SDL_DetachThread(t);
    }

    State puzzle     = {0};
    i32   difficulty = 2;
    for (;;) {
        i64 now = SDL_GetTicks64();

        if (null(puzzle)) {
            SDL_LockMutex(lock);
            for (i32 i = 0; i < NTHREADS; i++) {
                State *s = workers[i].puzzles + difficulty - 1;
                if (!null(*s)) {
                    puzzle = *s;
                    *s = (State){0};
                    ui->head = ui->tail = 0;
                    push(ui, puzzle);
                    SDL_CondSignal(workers[i].cv);
                    break;
                }
            }
            SDL_UnlockMutex(lock);
        }

        if (ui->status == STATUS_UNKNOWN) {
            if (solved(top(ui), ui->nbottle)) {
                ui->status = STATUS_SOLVED;
            } else {
                Arena    tmp = a;
                Solution ok  = solve(top(ui), ui->nbottle, &tmp);
                ui->status = ok.len ? STATUS_SOLVABLE : STATUS_UNSOLVABLE;
            }
        }

        switch (ui->status) {
        case STATUS_GENERATING:
            i32 green = SDL_GetTicks64() / 4 % 512;
            green = green>255 ? 511-green : green;
            ui->border = green<<8 | 0xff;
            ui->success = ui->error = 0;
            break;
        case STATUS_UNKNOWN:
        case STATUS_SOLVABLE:
            ui->border = 0;
            break;
        case STATUS_SOLVED:
            ui->success = now + BORDER_MS;
            break;
        case STATUS_UNSOLVABLE:
            ui->error = now + BORDER_MS;
            break;
        }

        ui->border = ui->success>now ? 0x00ff00 : ui->border;
        ui->border = ui->error>now   ? 0xff0000 : ui->border;
        ui->click  = 0;

        SDL_Event e = {0};
        while (SDL_PollEvent(&e)) {
            switch (e.type) {
            case SDL_QUIT:
                return 0;

            case SDL_KEYDOWN:
                switch (e.key.keysym.sym) {
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':;  // generate a new puzzle
                    difficulty = e.key.keysym.sym - '0';
                    puzzle = (State){0};
                    ui->head = ui->tail = 0;
                    ui->success = ui->error = 0;
                    ui->status = STATUS_GENERATING;
                    ui->select = -1;
                    break;
                case 'h':;  // hint
                    hint(ui, now, a);
                    break;
                case 'q':  // quit
                    return 0;
                case 'r':  // reset
                    ui->head = ui->tail = 0;
                    push(ui, puzzle);
                    ui->success = ui->error = 0;
                    break;
                case 'u':  // undo
                    undo(ui, now);
                    break;
                }
                break;

            case SDL_MOUSEBUTTONDOWN:
                switch (e.button.button) {
                case 1:
                    ui->mousex = e.button.x;
                    ui->mousey = e.button.y;
                    ui->click  = 1;
                    break;
                case 2:
                    hint(ui, now, a);
                    break;
                case 3:
                    undo(ui, now);
                    break;
                }
                break;

            case SDL_MOUSEMOTION:
                ui->mousex = e.motion.x;
                ui->mousey = e.motion.y;
                break;
            }
        }

        draw(r, ui);

        if (ui->active >= 0) {
            SDL_SetCursor(hand);
        } else {
            SDL_SetCursor(arrow);
        }

        if (ui->click) {
            if (ui->select >= 0) {
                if (ui->select == ui->active) {
                    ui->select = -1;
                } else {
                    State s = top(ui);
                    Move  m = {ui->select, ui->active};
                    if (valid(s, ui->nbottle, m)) {
                        push(ui, apply(s, m));
                        ui->select = -1;
                    } else {
                        ui->select = ui->active;
                    }
                }
            } else {
                ui->select = ui->active;
            }
        }

        SDL_RenderPresent(r);
    }
}


#else
#include <stdlib.h>
#include <stdio.h>

static void print(State s, i32 nbottle)
{
    for (i32 y = 0; y < 4; y++) {
        for (i32 x = 0; x < nbottle; x++) {
            i32 v = s.s[x];
            for (; v && !(v&0xf000); v <<= 4) {}
            v >>= y*4;
            printf("%3d", v&15);
        }
        putchar('\n');
    }
}

int main(void)
{
    char *mem = malloc(SOLVE_MEM);
    Arena a   = {mem, mem+SOLVE_MEM};
    for (i32 i = 0; i < 1000; i++) {
        Arena scratch = a;
        i32   nbottle = 14;
        State s       = genpuzzle(i+1, nbottle);
        print(s, nbottle);
        printf("%d steps\n", solve(s, nbottle, &scratch).len);
    }
}
#endif
