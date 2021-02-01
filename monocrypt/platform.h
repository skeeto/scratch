#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdint.h>

/* Set standard input and output to binary. */
void binary_stdio(void);

/* Fill buf with system entropy. */
int fillrand(void *buf, int len);

/* Display prompt then read zero-terminated, UTF-8 password.
 * Return password length with terminator, zero on input error, negative if
 * the buffer was too small.
 */
int read_password(uint8_t *buf, int len, char *prompt);

#endif
