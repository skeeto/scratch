// $ cc -o aoc2509 aoc2509.c
// $ ./aoc2509 <input.txt
#include "aoc2509.c"
#include <stdio.h>

static Str slurp(Arena *a)
{
    Str r = {};
    r.data = a->beg;
    r.len = a->end - a->beg;
    r.len = (ptrdiff_t)fread(r.data, 1, (size_t)r.len, stdin);
    a->beg += r.len;
    return r;
}

int main()
{
    static char mem[1<<22];
    Arena a  = {mem, 1[&mem]};
    Str   s  = slurp(&a);
    V2s   vs = parse(&a, s);
    printf("%lld\n", (long long)part1(vs));
    printf("%lld\n", (long long)part2(vs));
    printf("%lld\n", (long long)part2_raster(vs, a));
}
