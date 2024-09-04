#include <stdio.h>
#include <stdlib.h>
#include "regex.h"

int main(void)
{
    int   cap = 1<<21;
    char *mem = malloc(cap);
    arena a   = {mem, mem+cap};

    regex  *re = regex_new(S("(\\w+)"), &a);
    str     s  = S("Hello, world! This is a test.");
    strlist m  = regex_match(re, s, &a);
    for (ptrdiff_t i = 0; i < m.len; i++) {
        printf("%2td = %.*s\n", i, (int)m.data[i].len, m.data[i].data);
    }

    #if 0
    for (int i = 0; i < 30000; i++) {
        arena scratch = a;
        regex_match(re, s, &scratch);
    }
    #endif
}
