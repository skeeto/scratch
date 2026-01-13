// WebAssembly version for use in index.html
#include "maze.c"

[[clang::export_name("init")]]
Animation *wasm_init(i32 width, i32 height, u64 seed)
{
    affirm(width>0 && width<=64);
    affirm(height>0);

    static u8 mem[1<<20];
    Arena perm = {mem, mem+lenof(mem)};
    Animation *ani = new(&perm, 1, Animation);
    *ani = new_animation(&perm, width, height, seed);
    return ani;
}

[[clang::export_name("step")]]
void wasm_step(Animation *ani)
{
    step(ani);
}

typedef struct {
    i32 x;
    i32 y;
    i32 bearing;
    i32 width;
    i32 height;
    i32 nops;
    u8 *maze;
    u8 *ops;
} Info;

[[clang::export_name("render")]]
Info *wasm_render(Animation *ani)
{
    Arena a = ani->active;
    Info *info    = new(&a, 1, Info);
    info->x       = ani->maze.position.x;
    info->y       = (i32)(ani->maze.position.y - ani->maze.top);
    info->bearing = ani->bearing;
    info->width   = ani->gen.width;
    info->height  = ani->maze.height;
    info->nops    = ani->program.len - ani->ip;
    info->maze    = new(&a, info->width*info->height, u8);
    info->ops     = new(&a, info->nops,  u8);

    iz  i = 0;
    i32 h = ani->maze.height;
    i32 w = ani->gen.width;
    for (i32 y = 0; y < h; y++) {
        Row r = *get_row(&ani->maze, ani->maze.top+y);
        for (i32 x = 0; x < w; x++) {
            i32 bw = has_wall(r, x);
            i32 bf = has_floor(r, x);
            info->maze[i++] = (u8)(bf<<1 | bw);
        }
    }

    i = 0;
    for (i32 ip = ani->ip; ip < ani->program.len; ip++) {
        info->ops[i++] = (u8)(ani->program.data[ip] + 1);
    }
    return info;
}
