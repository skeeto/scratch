// SDL2 version, mainly for debugging and development
#include "maze.c"
#include "SDL.h"

enum {
    WIDTH       = 45,
    HEIGHT      = 30,
    CELL_SIZE   = 24,
};

static void draw_circle(SDL_Renderer *r, i32 cx, i32 cy, i32 radius)
{
    for (i32 w = 0; w < radius * 2; w++) {
        for (i32 h = 0; h < radius * 2; h++) {
            i32 dx = radius - w;
            i32 dy = radius - h;
            if (dx*dx + dy*dy < radius*radius) {
                SDL_RenderDrawPoint(r, cx+dx, cy+dy);
            }
        }
    }
}

static void render(SDL_Renderer *r, Animation *ani)
{
    SDL_SetRenderDrawColor(r, 255, 255, 255, 255);
    SDL_RenderClear(r);

    SDL_SetRenderDrawColor(r, 0, 0, 0, 255);
    SDL_RenderDrawLine(r, 0, 0, 0, HEIGHT*CELL_SIZE);

    for (i32 y = 0; y < ani->maze.height; y++) {
        Row *row = get_row(&ani->maze, ani->maze.top+y);
        for (i32 x = 0; x < ani->gen.width; x++) {
            if (has_wall(*row, x)) {
                i32 x1 = (x + 1)*CELL_SIZE;
                i32 y1 = y * CELL_SIZE;
                i32 y2 = (y + 1)*CELL_SIZE;
                SDL_RenderDrawLine(r, x1, y1, x1, y2);
            }
            if (has_floor(*row, x)) {
                i32 x1 = x * CELL_SIZE;
                i32 x2 = (x + 1)*CELL_SIZE;
                i32 y1 = (y + 1)*CELL_SIZE;
                SDL_RenderDrawLine(r, x1, y1, x2, y1);
            }
        }
    }

    i32 y  = (i32)(ani->maze.position.y - ani->maze.top);
    i32 rx = ani->maze.position.x*CELL_SIZE + CELL_SIZE/2;
    i32 ry = y*CELL_SIZE + CELL_SIZE/2;
    SDL_SetRenderDrawColor(r, 0x44, 0x44, 0xff, 255);
    draw_circle(r, rx, ry, CELL_SIZE/2);

    SDL_SetRenderDrawColor(r, 0xff, 0x00, 0x00, 255);
    i32 dx =      dirs[ani->bearing].x * CELL_SIZE*2/3;
    i32 dy = (i32)dirs[ani->bearing].y * CELL_SIZE*2/3;
    SDL_RenderDrawLine(r, rx, ry, rx+dx, ry+dy);
}

int main(int, char **)
{
    static u8 mem[1<<19];
    Arena perm = {mem, mem+lenof(mem)};

    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *w = SDL_CreateWindow(
        "Infinite maze walker",
        SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED,
        WIDTH*CELL_SIZE,
        HEIGHT*CELL_SIZE,
        0
    );
    SDL_Renderer *r = SDL_CreateRenderer(w, -1, 0);

    u64 seed = (uz)mem;  // ASLR (maybe)
    Animation ani = new_animation(&perm, WIDTH, HEIGHT, seed);
    for (;;) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            switch (event.type) {
            case SDL_QUIT:
                return 0;
            }
        }
        step(&ani);
        render(r, &ani);
        SDL_RenderPresent(r);
        SDL_Delay(100);
    }
}
