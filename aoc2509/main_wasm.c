// $ clang -std=gnu23 --target=wasm32 -nostdlib -Oz -s -mbulk-memory
//     -mmultivalue -Xclang -target-abi -Xclang experimental-mv
//     -Wl,--no-entry -Wl,--stack-first -z stack-size=4096
//     -o aoc2509.wasm main_wasm.c
#include "generate.c"

typedef struct { int64_t _[3]; } Solution;

[[clang::export_name("solve")]]
Solution wasm_solve(char *src, ptrdiff_t len, ptrdiff_t cap)
{
    Arena a  = {src+len, src+cap};
    Str   s  = {src, len};
    V2s   vs = parse(&a, s);
    return (Solution){{part1(vs), part2(vs), part2_raster(vs, a)}};
}

[[clang::export_name("generate")]]
V2s wasm_generate(uint64_t seed, char *mem, ptrdiff_t cap)
{
    return generate(seed, &(Arena){mem, mem+cap});
}
