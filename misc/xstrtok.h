/* xstrtok: drop-in, portable strtok_r(3)
 * This is free and unencumbered software released into the public domain.
 */
#include <string.h>

static char *
xstrtok(char *str, const char *delim, char **saveptr)
{
    char *r, *p = str ? str : *saveptr;

    r = p += strspn(p, delim);
    if (!*p) {
        return (*saveptr = 0);
    }

    *saveptr = p += strcspn(p, delim);
    if (*p) {
        *p = 0;
        (*saveptr)++;
    }

    return r;
}
