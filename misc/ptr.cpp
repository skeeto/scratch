// Compressed relative pointers (experiment)
// Ref: https://www.youtube.com/watch?v=Z0tsNFZLxSU
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

#define assert(c) while (!(c)) __builtin_unreachable()

template<typename T, typename I>
struct ptr {
    I rel;

    ptr() { rel = 0; }
    ptr(T *p) { *this = p; }
    ptr(ptr<T, I> &p) { *this = p; }

    T *operator->()
    {
        assert(rel);
        return (T *)((char *)this + rel);
    }

    T &operator*()
    {
        assert(rel);
        return *(T *)((char *)this + rel);
    }

    operator T*()
    {
        return rel ? (T *)((char *)this + rel) : 0;
    }

    void operator=(T *p)
    {
        rel = 0;
        if (p) {
            auto delta = (char *)p - (char *)this;
            assert((I)delta == delta);
            rel = (I)delta;
        }
    }

    void operator=(ptr<T, I> &p)
    {
        rel = 0;
        if (p.rel) {
            *this = &*p;
        }
    }
};

template<typename T> using ptr8  = ptr<T, int8_t>;
template<typename T> using ptr16 = ptr<T, int16_t>;
template<typename T> using ptr32 = ptr<T, int32_t>;


// Demo/test
#include <stdio.h>

struct node {
    ptr16<node> next;
    int16_t     value;
};

int main()
{
    enum { N = 8 };
    node nodes[N] = {};
    for (int16_t i = 0; i < N; i++) {
        nodes[i].next  = nodes + i + 1;
        nodes[i].value = -i-1;
    }
    nodes[N-1].next = 0;

    // Alternative first element (test relative copying)
    node altfirst = nodes[0];
    altfirst.value = 100;

    for (node *p = &altfirst; p; p = p->next) {
        printf("%p %d\n", p, p->value);
    }
}
