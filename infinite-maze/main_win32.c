// Windows console version, mainly for debugging and development
#include "maze.c"
#include <stdio.h>

#define W32 [[gnu::stdcall, gnu::dllimport]]
W32 void Sleep(i32);
W32 uz   GetStdHandle(i32);
W32 i32  WriteFile(uz, u8 *, i32, i32 *, uz);

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, r.len, u8);
    __builtin_memcpy(r.data, s.data, touz(r.len));
    return r;
}

static Str concat(Arena *a, Str head, Str tail)
{
    if (a->beg != head.data+head.len) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static Str sprint(Arena *a, Str dst, char *fmt, ...)
{
    __builtin_va_list va;

    __builtin_va_start(va, fmt);
    i32 len = vsnprintf(0, 0, fmt, va);
    __builtin_va_end(va);
    affirm(len > 0);

    if (a->beg != dst.data+dst.len) {
        dst = clone(a, dst);
    }
    u8 *buf = new(a, len+1, u8);

    __builtin_va_start(va, fmt);
    vsnprintf((char *)buf, touz(len+1), fmt, va);
    __builtin_va_end(va);

    dst.len += len;
    return dst;
}

static Str put(Arena *a, Str s, u8 c)
{
    return concat(a, s, (Str){&c, 1});
}

static Str print(Arena *a, Str dst, Gen *g, Row r)
{
    dst = put(a, dst, '|');
    for (i32 i = 0; i < g->width; i++) {
        dst = put(a, dst, marked(r, i) ? '#' : ' ');
        dst = put(a, dst, has_wall(r, i) ? '|' : ' ');
    }
    dst = put(a, dst, '\n');

    dst = put(a, dst, '+');
    for (i32 i = 0; i < g->width; i++) {
        dst = put(a, dst, has_floor(r, i) ? '-' : ' ');
        dst = put(a, dst, '+');
    }
    return dst;
}


int main()
{
    static u8 mem[1<<18];
    Arena perm = {mem, mem+lenof(mem)};

    u64 seed = 12345;
    asm volatile ("rdrand %0" : "=r"(seed));
    Animation ani = new_animation(&perm, 25, 41, seed);

    for (;;) {
        step(&ani);

        Arena scratch = ani.active;
        Str output = {};
        output = sprint(
            &scratch, output,
            "%d,%lld  %d,%lld  %td/%td %c\n",
            ani.maze.position.x, ani.maze.position.y,
            ani.maze.target.x, ani.maze.target.y,
            ani.ip, ani.program.len,
            ">V<^"[ani.bearing]
        );
        for (i32 i = 0; i < ani.maze.height; i++) {
            output = print(
                &scratch,
                output,
                &ani.gen,
                ani.maze.rows[(i+ani.maze.top)%ani.maze.height]
            );
            if (i+ani.ip < ani.program.len) {
                static Str names[] = {
                    [1+Op_LEFT]  = S("LEFT"),
                    [1+Op_MOVE]  = S("MOVE"),
                    [1+Op_RIGHT] = S("RIGHT"),
                    [1+Op_DIG]   = S("DIG"),
                };
                Str name = names[1+ani.program.data[i+ani.ip]];
                output = concat(&scratch, output, S("  "));
                output = concat(&scratch, output, name);
            }
            output = put(&scratch, output, '\n');
        }

        // I initially used fwrite, but larger mazes flicker because msvcrt
        // flushes around 4kB even with IOFBF on a large buffer. Must avoid
        // stdio in order to fix it.
        WriteFile(GetStdHandle(-11), output.data, (i32)output.len, 0, 0);

        Sleep(10);
    }
}
