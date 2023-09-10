// memset, memcpy, memmove via x86 string instructions
// $ cc -c -O -fno-builtin -fno-asynchronous-unwind-tables -fno-ident memory.c
//
// Supports x86-32 and x86-64 on any operating systems. Useful when a
// compiler (GCC, Clang, MSVC, tcc) inserts calls to these functions,
// making their definitions mandatory. While this file must be compiled
// with a GNU C implementation (GCC, Clang), the resulting object file
// can be used in any toolchain.
//
// This is free and unencumbered software released into the public domain.

typedef __SIZE_TYPE__ size_t;

__attribute((section(".text.memset, \"x0\" #")))
void *memset(void *dst, int c, size_t len)
{
    void *r = dst;
    asm volatile (
        "rep stosb"
        : "+D"(dst), "+c"(len)
        : "a"(c)
        : "memory"
    );
    return r;
}

__attribute((section(".text.memcpy, \"x0\" #")))
void *memcpy(void *restrict dst, void *restrict src, size_t len)
{
    void *r = dst;
    asm volatile (
        "rep movsb"
        : "+D"(dst), "+S"(src), "+c"(len)
        :
        : "memory"
    );
    return r;
}

__attribute((section(".text.memmove, \"x0\" #")))
void *memmove(void *dst, void *src, size_t len)
{
    void *r = dst;
    if ((size_t)dst > (size_t)src) {
        dst += len - 1;
        src += len - 1;
        asm ("std");
    }
    asm volatile (
        "rep movsb; cld"
        : "+D"(dst), "+S"(src), "+c"(len)
        :
        : "memory"
    );
    return r;
}
