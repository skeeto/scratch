#include "water-sort.c"

static Game *game;
static Arena perm;

__attribute((export_name("game_init")))
void game_init(i32 seed)
{
    static char heap[SOLVE_MEM];
    perm.beg = heap;
    perm.end = heap + SOLVE_MEM;

    game = new(&perm, 1, Game);
    game->nbottle   = MAXBOTTLE;
    game->ui.select = -1;
    game->puzzle    = genpuzzle(seed, game->nbottle);
    push(game, game->puzzle);
}

__attribute((export_name("game_render")))
DrawList *game_render(i32 width, i32 height, i32 mousex, i32 mousey)
{
    game->ui.width  = width;
    game->ui.height = height;
    game->ui.mousex = mousex;
    game->ui.mousey = mousey;
    Arena scratch   = perm;
    return renderui(top(game), game->nbottle, &game->ui, &scratch);
}

__attribute((export_name("game_update")))
void game_update(i32 input, i32 x, i32 y, i32 now)
{
    game->input     = input;
    game->ui.mousex = x;
    game->ui.mousey = y;
    update(game, now, perm);
}
