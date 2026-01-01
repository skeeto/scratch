#include <stddef.h>
#include <stdint.h>

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define assert(c)       while (!(c)) __builtin_trap()

typedef struct {
    char *beg;
    char *off;
    char *end;
} Arena;

[[clang::export_name("alloc")]]
void *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = -(uintptr_t)a->off & (align - 1);
    assert(count < (a->end - a->off - pad)/size);
    char *r = a->off + pad;
    a->off += pad + count*size;
    return __builtin_memset(r, 0, count*size);
}

[[clang::export_name("reset")]]
void reset(Arena *a)
{
    a->off = a->beg;
}

[[clang::export_name("newarena")]]
Arena *newarena(ptrdiff_t cap)
{
    size_t old = __builtin_wasm_memory_grow(0, (cap + 0xffffu)>>16);
    assert(old != (size_t)-1);

    char *mem = (char *)(old << 16);
    Arena tmp = {mem, mem, mem+cap};
    Arena *r = new(&tmp, 1, Arena);
    *r = (Arena){tmp.off, tmp.off, tmp.end};
    return r;
}

typedef struct {
    int32_t i;
    int32_t j;
} Solution;

[[clang::export_name("twosum")]]
Solution *twosum(int32_t *nums, int32_t count, int32_t target, Arena *a)
{
    Solution *ret = new(a, 1, Solution);

    int32_t exp = 32 - __builtin_clz(count);

    Arena scratch = *a;
    int32_t *seen = new(&scratch, 1<<exp, int32_t);

    for (int32_t n = 0; n < count; n++) {
        int32_t  number = nums[n];
        int32_t  complement = target - number;
        int32_t  key = complement>number ? complement : number;
        uint32_t hash = key * 489183053u;
        uint32_t mask = (1<<exp) - 1;
        uint32_t step = hash>>(32 - exp) | 1;
        for (int32_t i = hash;;) {
            i = (i + step) & mask;
            int32_t j = seen[i] - 1;
            if (j < 0) {
                seen[i] = n + 1;
                break;
            } else if (nums[j] == complement) {
                ret->i = j;
                ret->j = n;
                return ret;
            }
        }
    }
    return 0;  // no solution
}
