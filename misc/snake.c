// SDL2 snake game
//   $ cc -o snake snake.c $(sdl2-config --cflags --libs)
// This is free and unencumbered software released into the public domain.
#include <SDL.h>

#if MINI && _WIN32
// Minimalist Windows build:
//   $ cc -DMINI -mno-stack-arg-probe -fno-asynchronous-unwind-tables
//        -Os -s -nostdlib -Wl,--gc-sections -o snake snake.c
//        -lkernel32 $(sdl2-config --cflags --libs)
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
void WinMainCRTStartup(void) { ExitProcess(SDL_main(0, 0)); }
#endif

#define WIDTH  50
#define HEIGHT 40
#define SCALE  15
#define PERIOD 100  // ms per game step
#define DROP   50   // mean-ish period in ms for extra apples
#define MAXLEN (WIDTH*HEIGHT)

enum dir {DIR_RIGHT, DIR_DOWN, DIR_LEFT, DIR_UP};

// 0:empty, #:wall, @:snake part, $:food
#define MAP_INIT {0}
struct map {
    int napples;
    unsigned char map[HEIGHT][WIDTH];
};

#define SNAKE_INIT {0, 1, 1, MAXLEN-1, {{WIDTH/2,HEIGHT/2},{WIDTH/2,HEIGHT/2}}}
struct snake {
    int dx, dy;
    int head, tail;
    struct {
        short x, y;
    } parts[MAXLEN];
};

// Mix entropy into the random number state.
static void randmix(Uint64 *rng, Uint64 x)
{
    *rng = *rng*1111111111111111111 + x;
}

// Draw a random number in [lo, hi).
static int randint(Uint64 *rng, int lo, int hi)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (int)(((*rng>>32)*(hi - lo))>>32) + lo;
}

// Get the tile at (x, y), with out-of-bounds as a wall.
static int map_get(struct map *m, int x, int y)
{
    if (x<0 || x>=WIDTH || y<0 || y>=HEIGHT) {
        return '#';
    }
    return m->map[y][x];
}

// Randomly drop a new apple in an empty position.
static void map_newapple(struct map *m, struct snake *s, Uint64 *rng)
{
    int x, y;
    do {
        x = randint(rng, 0, WIDTH);
        y = randint(rng, 0, HEIGHT);
    } while (m->map[y][x]);
    m->map[y][x] = '$';
    m->napples++;
}

// Try to advance the head but leave the tail, returning the tile that
// was/would be consumed.
static int snake_grow(struct snake *s, struct map *m)
{
    int prev = s->head;
    int x = s->parts[prev].x + s->dx;
    int y = s->parts[prev].y + s->dy;
    int t = map_get(m, x, y);
    switch (t) {
    case '#':
    case '@': return t;
    }
    m->map[y][x] = '@';
    s->head = (s->head + 1) % MAXLEN;
    s->parts[s->head].x = x;
    s->parts[s->head].y = y;
    return t;
}

// Try to advance both the head and tail, returning the tile that
// was/would be consumed.
static int snake_step(struct snake *s, struct map *m)
{
    int t = snake_grow(s, m);
    switch (t) {
    case '#':
    case '$':
    case '@': return t;
    }
    s->tail = (s->tail + 1) % MAXLEN;
    int x = s->parts[s->tail].x;
    int y = s->parts[s->tail].y;
    m->map[y][x] = 0;
    return t;
}

// Return the snake's current length.
static int snake_length(struct snake *s)
{
    return (s->head - s->tail + MAXLEN) % MAXLEN;
}

// Try to turn the snake in the given direction.
static void snake_turn(struct snake *s, enum dir dir)
{
    static const int dirs[] = {1,0, 0,1, -1,0, 0,-1};
    int dx = dirs[dir*2+0];
    int dy = dirs[dir*2+1];
    int nx = s->parts[s->head].x + dx;
    int ny = s->parts[s->head].y + dy;
    int prev = (s->head + MAXLEN - 1) % MAXLEN;
    int px = s->parts[prev].x;
    int py = s->parts[prev].y;
    if (px!=nx || py!=ny) {  // forbid turning back on itself
        s->dx = dx;
        s->dy = dy;
    }
}

int main(int argc, char **argv)
{
    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *w = SDL_CreateWindow(
        "Snake", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        WIDTH*SCALE, HEIGHT*SCALE, 0
    );
    SDL_Renderer *r = SDL_CreateRenderer(w, -1, SDL_RENDERER_PRESENTVSYNC);

    Uint64 rng = 0;
    int bg = 0xffffff;
    struct map map = MAP_INIT;
    struct snake snake = SNAKE_INIT;
    Uint32 laststep = SDL_GetTicks();

    // Render a simple map with two inner walls
    for (int y = HEIGHT/6; y < HEIGHT-HEIGHT/6; y++) {
        map.map[y][WIDTH/5] = map.map[y][WIDTH-WIDTH/5] = '#';
    }

    for (SDL_Event e = {0};; randmix(&rng, e.common.timestamp)) {
        while (SDL_PollEvent(&e)) {
            switch (e.type) {
            case SDL_QUIT:
                return 0;
            case SDL_KEYDOWN:
                // TODO: maybe buffer inputs a bit?
                switch (e.key.keysym.sym) {
                case 'q':
                    return 0;
                case ' ':
                    snake_grow(&snake, &map);
                    break;
                case SDLK_UP: case 'w':
                    snake_turn(&snake, DIR_UP);
                    break;
                case SDLK_DOWN: case 's':
                    snake_turn(&snake, DIR_DOWN);
                    break;
                case SDLK_RIGHT: case 'd':
                    snake_turn(&snake, DIR_RIGHT);
                    break;
                case SDLK_LEFT: case 'a':
                    snake_turn(&snake, DIR_LEFT);
                    break;
                }
                break;
            }
        }

        // TODO: speed up game over time?
        Uint32 now = SDL_GetTicks();
        randmix(&rng, now);
        if (now-laststep >= PERIOD) {
            if (!map.napples || !randint(&rng, 0, DROP*map.napples)) {
                map_newapple(&map, &snake, &rng);
            }
            bg = 0xffffff;
            switch (snake_step(&snake, &map)) {
            case '$': map.napples--;
                      break;
            case '@':
            case '#': SDL_Log("game over length=%d", snake_length(&snake));
                      bg = 0xff7f7f;  // TODO: implement game over
            }
            laststep = now;
        }

        SDL_SetRenderDrawColor(r, bg>>16, bg>>8, bg, 255);
        SDL_RenderClear(r);
        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                static const int colors[] = {
                    ['#'] = 0x333333,
                    ['$'] = 0xff0000,
                    ['@'] = 0x00aa00,
                };
                int c = colors[map.map[y][x]];
                if (c) {
                    SDL_SetRenderDrawColor(r, c>>16, c>>8, c, 255);
                    SDL_Rect tile = {x*SCALE, y*SCALE, SCALE, SCALE};
                    SDL_RenderFillRect(r, &tile);
                }
            }
        }
        SDL_RenderPresent(r);
    }
}
