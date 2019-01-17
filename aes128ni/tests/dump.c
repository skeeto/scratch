/* AES-NI benchmark
 *
 * This program dumps AES-NI output as fast as possible to measure its
 * speed. The output buffer has been tuned to maximize performance.
 */
#define _POSIX_C_SOURCE 200112L
#include "../aes128ni.h"
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

int
main(void)
{
    struct aes128 ctx[1];
    unsigned char buf[1 << 14];
    uint64_t counter[2] = {0, 0};
    const unsigned char key[AES128_KEYLEN] = {0};

    aes128_init(ctx, key);
    for (;;) {
        for (size_t i = 0; i < sizeof(buf); i += 16) {
            aes128_encrypt(ctx, buf + i, counter);
            if (!++counter[0]) counter[1]++;
        }
        if (write(1, buf, sizeof(buf)) != sizeof(buf))
            break;
    }
    (void)aes128_decrypt; /* unused */
}
