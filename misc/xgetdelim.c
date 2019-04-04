#include <stdio.h>
#include <stdlib.h>
#include "xgetdelim.h"

size_t
xgetdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    int c;
    char *line = *lineptr;
    size_t len = *n;
    size_t nread = 0;

    if (len < 2) {
        if (len)
            line[0] = 0;
        len = 256;
        if (!(line = realloc(line, len)))
            return 0;
        *lineptr = line;
        *n = len;
    }

    for (;;) {
        if (nread == len - 2) {
            /* Need space for at least two characters before fgetc(). */
            line[nread] = 0;
            if (len * 2 < len)
                return 0;
            if (!(line = realloc(line, len *= 2)))
                return 0;
            *lineptr = line;
            *n = len;
        }

        c = fgetc(stream);
        if (c == EOF) {
            line[nread] = 0;
            return nread;
        }
        line[nread++] = c;
        if (c == delim) {
            line[nread] = 0;
            return nread;
        }
    }
}

size_t
xgetline(char **lineptr, size_t *n, FILE *stream)
{
    return xgetdelim(lineptr, n, '\n', stream);
}
