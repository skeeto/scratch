/* ANSI C implementation of getline(3) and getdelim(3) */
#include <stdio.h>

/**
 * Returns the number of bytes read, or 0 on error or EOF.
 *
 * The two kinds of errors: input error, out of memory. To distinguish
 * between EOF, input error, and out of memory use ferror() and feof()
 * on the stream. If an out of memory error occurs, the buffer contains
 * the entire NUL-terminated stream, though with a possibly ambiguous
 * length.
 *
 * This function properly handles inputs containing NUL bytes. It is the
 * caller's responsibility to free the buffer when done.
 */
size_t xgetdelim(char **lineptr, size_t *n, int delim, FILE *stream);

/**
 * Same as xgetdelim(lineptr, n, '\n', stream).
 */
size_t xgetline(char **lineptr, size_t *n, FILE *stream);