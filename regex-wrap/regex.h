#pragma once
#include <stddef.h>

#define S(s) (str){s, sizeof(s)-1}

typedef struct {
    char     *data;
    ptrdiff_t len;
} str;

typedef struct {
    char *beg;
    char *end;
} arena;

typedef struct regex regex;

typedef struct {
    str      *data;
    ptrdiff_t len;
} strlist;

regex  *regex_new(str, arena *);
strlist regex_match(regex *, str, arena *);
