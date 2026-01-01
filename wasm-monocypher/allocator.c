// $ clang --target=wasm32 -nostdlib -O2 -Wl,--no-entry -Wl,--export-all
//     -o monocypher.wasm allocator.c
#include "monocypher.c"

extern char  __heap_base[];
static char *heap_used;
static char *heap_high;

static void *bump_sbrk(ptrdiff_t size)
{
    size_t addpages = (size + 0xffffu) >> 16;  // round up
    size_t oldpages = __builtin_wasm_memory_grow(0, addpages);
    if (oldpages == (size_t)-1) {
        __builtin_trap();
    }
    return (void *)(oldpages << 16);
}

void *bump_alloc(ptrdiff_t size)
{
    if (!heap_high) {  // init?
        heap_used = heap_high = __heap_base;
    }

    ptrdiff_t align     = -(size_t)heap_used & 15;
    ptrdiff_t available = heap_high - heap_used;
    if (size > available - align) {
        heap_high = bump_sbrk(size - (available - align));
    }

    char *r = heap_used + align;
    heap_used += size + align;
    return r;
}

void bump_reset(void)
{
    ptrdiff_t len = heap_used - __heap_base;
    __builtin_memset(__heap_base, 0, len);
    heap_used = __heap_base;
}
