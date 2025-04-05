#include "water-sort.c"
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

        DrawList *dl = renderui(top(game), game->nbottle, &game->ui, &scratch);
        for (i32 i = 0; i < dl->len; i++) {
            i32 c = dl->ops[i].color;
            SDL_SetRenderDrawColor(r, (u8)(c>>16), (u8)(c>>8), (u8)c, 0xff);
            switch (dl->ops[i].mode) {
            case DRAW_FILL:
                SDL_RenderFillRect(r, (void *)&dl->ops[i].x);
                break;
            case DRAW_BOX:
                SDL_RenderDrawRect(r, (void *)&dl->ops[i].x);
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
