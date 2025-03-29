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
// TODO: Add on-screen buttons, then compile to WASM with Clang
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define affirm(c)       while (!(c)) *(volatile int *)0 = 0

typedef int8_t      i8;
typedef uint8_t     u8;
typedef uint16_t    u16;
typedef int32_t     b32;
typedef int32_t     i32;
typedef int64_t     i64;
typedef uint64_t    u64;
typedef float       f32;
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

enum {
    MAXUNDO   = 256,
    BORDER_MS = 500,
};

static i32 colors[] = {
    0x222222,
    0x8b4513, 0x228b22, 0x4682b4,
    0x4b0082, 0xff0000, 0xffd700,
    0x7fff00, 0x00ffff, 0x0000ff,
    0xff00ff, 0x2f4f4f, 0xf0f8ff,
};

enum {
    DRAW_BOX,
    DRAW_FILL,
};

typedef struct {
    i32 mode;
    i32 color;
    i32 x, y, w, h;
} DrawOp;

typedef struct {
    DrawOp *ops;
    i32     len;
} DrawList;

typedef struct {
    i32 border;
    i32 width;
    i32 height;
    i32 select;
    i32 active;
    i32 mousex;
    i32 mousey;
} UI;

static DrawList renderui(State state, i32 nbottle, UI *ui, Arena *a)
{
    // TODO: on-screen buttons for reset, undo, hint, generate
    // TODO: puzzle editor, to turn it into a solver

    DrawList r = {0};
    r.ops = new(a, 256, DrawOp);

    if (ui->border) {
        r.ops[r.len++] = (DrawOp){
            .mode  = DRAW_FILL,
            .color = ui->border,
            .x     = 0,
            .y     = 0,
            .w     = ui->width,
            .h     = ui->height,
        };

        i32 pad = ui->width / 75;
        r.ops[r.len++] = (DrawOp){
            .mode  = DRAW_FILL,
            .color = colors[0],
            .x     = pad,
            .y     = pad,
            .w     = ui->width  - 1 - pad * 2,
            .h     = ui->height - 1 - pad * 2,
        };
    } else {
        r.ops[r.len++] = (DrawOp){
            .mode  = DRAW_FILL,
            .color = colors[0],
            .x     = 0,
            .y     = 0,
            .w     = ui->width,
            .h     = ui->height,
        };
    }

    i32 bw   = ui->width  / 7;
    i32 bh   = ui->height / 2;
    i32 xpad = bw / 6;
    i32 ypad = bh / 8;
    i32 ww   =  bw - 2*xpad;
    i32 wh   = (bh - 2*ypad)/4;

    if (ui->select >= 0) {
        r.ops[r.len++] = (DrawOp){
            .mode  = DRAW_FILL,
            .color = 0x7f7f7f,
            .x     = (ui->select%7)*bw,
            .y     = ypad/2 + (ui->select/7)*bh,
            .w     = bw,
            .h     = bh - ypad,
        };
    }

    if (null(state)) {
        return r;
    }

    ui->active = -1;
    for (i32 i = 0; i < nbottle; i++) {
        u16 v = state.s[i];
        for (; v && !(v&0xf000); v = (u16)(v<<4)) {}
        for (i32 y = 0; y < 4; y++) {
            DrawOp water = (DrawOp){
                .mode  = DRAW_FILL,
                .color = colors[(v>>(y*4)) & 15],
                .x     = xpad + (i%7)*bw,
                .y     = ypad + (i/7)*bh + y*wh,
                .w     = ww+1,
                .h     = wh+1,
            };
            r.ops[r.len++] = water;

            water.mode  = DRAW_BOX;
            water.color = 0xffffff;
            r.ops[r.len++] = water;

            if (ui->mousex >= water.x &&
                ui->mousey >= water.y &&
                ui->mousex <  water.x+water.w &&
                ui->mousey <  water.y+water.h) {
                ui->active = i;
            }
        }
    }

    return r;
}

enum {
    STATUS_GENERATING,
    STATUS_UNKNOWN,
    STATUS_SOLVED,
    STATUS_SOLVABLE,
    STATUS_UNSOLVABLE,
};

enum {
    INPUT_NONE,
    INPUT_CLICK,
    INPUT_HINT,
    INPUT_RESET,
    INPUT_UNDO,
};

typedef struct {
    i64   success;
    i64   error;

    UI    ui;

    i32   input;

    i32   nbottle;
    State puzzle;
    State states[MAXUNDO];
    i32   head;
    i32   tail;
    i32   status;
} Game;

static void push(Game *g, State s)
{
    g->status = STATUS_UNKNOWN;
    g->states[g->head++%MAXUNDO] = s;
    g->tail += g->head-g->tail > MAXUNDO;
}

static b32 pop(Game *g)
{
    g->status = STATUS_UNKNOWN;
    if (g->head-1 > g->tail) {
        g->head--;
        return 1;
    }
    return 0;
}

static State top(Game *g)
{
    State r = {0};
    if (g->head > g->tail) {
        r = g->states[(g->head-1)%MAXUNDO];
    }
    return r;
}

static void undo(Game *g, i64 now)
{
    g->success = g->error = 0;
    if (!pop(g)) {
        g->error = now + BORDER_MS;
    }
}

static void hint(Game *g, i64 now, Arena a)
{
    Arena    tmp = a;
    Solution ok  = solve(top(g), g->nbottle, &tmp);
    if (ok.len > 1) {
        push(g, ok.states[1]);
    } else {
        g->error = now + BORDER_MS;
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

static void update(Game *game, i64 now, Arena scratch)
{
    if (game->status == STATUS_UNKNOWN) {
        if (solved(top(game), game->nbottle)) {
            game->status = STATUS_SOLVED;
        } else {
            Solution ok  = solve(top(game), game->nbottle, &scratch);
            game->status = ok.len ? STATUS_SOLVABLE : STATUS_UNSOLVABLE;
        }
    }

    switch (game->status) {
    case STATUS_GENERATING:
        i32 green = (i32)(now / 4 % 512);
        green = green>255 ? 511-green : green;
        game->ui.border = green<<8 | 0xff;
        game->success = game->error = 0;
        break;
    case STATUS_UNKNOWN:
    case STATUS_SOLVABLE:
        game->ui.border = 0;
        break;
    case STATUS_SOLVED:
        game->success = now + BORDER_MS;
        break;
    case STATUS_UNSOLVABLE:
        game->error = now + BORDER_MS;
        break;
    }

    game->ui.border = game->success>now ? 0x00ff00 : game->ui.border;
    game->ui.border = game->error>now   ? 0xff0000 : game->ui.border;

    switch (game->input) {
    case INPUT_HINT:
        hint(game, now, scratch);
        break;
    case INPUT_RESET:
        game->head = game->tail = 0;
        push(game, game->puzzle);
        game->success = game->error = 0;
        break;
    case INPUT_UNDO:
        undo(game, now);
        break;
    }

    if (game->input == INPUT_CLICK) {
        if (game->ui.select >= 0) {
            if (game->ui.select == game->ui.active) {
                game->ui.select = -1;
            } else {
                State s = top(game);
                Move  m = {game->ui.select, game->ui.active};
                if (valid(s, game->nbottle, m)) {
                    push(game, apply(s, m));
                    game->ui.select = -1;
                } else {
                    game->ui.select = game->ui.active;
                }
            }
        } else {
            game->ui.select = game->ui.active;
        }
    }
}


#ifdef SDL
#include "SDL.h"

enum {
    STEP_BASE = 39,
    NTHREADS  = (i32)sizeof(uz),
};

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

    Game *game  = new(&a, 1, Game);
    game->nbottle = MAXBOTTLE;
    game->ui.width   = 600;
    game->ui.height  = 600;
    game->ui.select  = -1;

    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *w = SDL_CreateWindow(
        "Water Sort Puzzle",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        game->ui.width, game->ui.height, 0
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
        workers[i].nbottle = game->nbottle;
        workers[i].id      = i + 1;
        SDL_Thread *t = SDL_CreateThread(worker, "worker", workers+i);
        SDL_DetachThread(t);
    }

    State puzzle     = {0};
    i32   difficulty = 2;
    for (;;) {
        Arena scratch = a;
        i64   now     = SDL_GetTicks64();

        if (null(puzzle)) {
            SDL_LockMutex(lock);
            for (i32 i = 0; i < NTHREADS; i++) {
                State *s = workers[i].puzzles + difficulty - 1;
                if (!null(*s)) {
                    puzzle = *s;
                    *s = (State){0};
                    game->head = game->tail = 0;
                    push(game, puzzle);
                    SDL_CondSignal(workers[i].cv);
                    break;
                }
            }
            SDL_UnlockMutex(lock);
        }

        game->input = INPUT_NONE;
        SDL_Event e = {0};
        while (SDL_PollEvent(&e)) {
            switch (e.type) {
            case SDL_QUIT:
                return 0;

            case SDL_KEYDOWN:
                switch (e.key.keysym.sym) {
                case '1': case '2': case '3': case '4': case '5':
                    // generate a new puzzle
                    difficulty = e.key.keysym.sym - '0';
                    puzzle = (State){0};
                    game->head = game->tail = 0;
                    game->success = game->error = 0;
                    game->status = STATUS_GENERATING;
                    game->ui.select = -1;
                    break;
                case 'h':
                    game->input = INPUT_HINT;
                    break;
                case 'q':
                    return 0;
                case 'r':
                    game->input = INPUT_RESET;
                    break;
                case 'u':
                    game->input = INPUT_UNDO;
                    break;
                }
                break;

            case SDL_MOUSEBUTTONDOWN:
                switch (e.button.button) {
                case 1:
                    game->ui.mousex = e.button.x;
                    game->ui.mousey = e.button.y;
                    game->input = INPUT_CLICK;
                    break;
                case 2:
                    game->input = INPUT_HINT;
                    break;
                case 3:
                    game->input = INPUT_UNDO;
                    break;
                }
                break;

            case SDL_MOUSEMOTION:
                game->ui.mousex = e.motion.x;
                game->ui.mousey = e.motion.y;
                break;
            }
        }

        DrawList dl = renderui(top(game), game->nbottle, &game->ui, &scratch);
        for (i32 i = 0; i < dl.len; i++) {
            i32 c = dl.ops[i].color;
            SDL_SetRenderDrawColor(r, (u8)(c>>16), (u8)(c>>8), (u8)c, 0xff);
            switch (dl.ops[i].mode) {
            case DRAW_FILL:
                SDL_RenderFillRect(r, (void *)&dl.ops[i].x);
                break;
            case DRAW_BOX:
                SDL_RenderDrawRect(r, (void *)&dl.ops[i].x);
                break;
            }
        }

        if (game->ui.active >= 0) {
            SDL_SetCursor(hand);
        } else {
            SDL_SetCursor(arrow);
        }

        update(game, now, scratch);
        SDL_RenderPresent(r);
    }
}
#endif
