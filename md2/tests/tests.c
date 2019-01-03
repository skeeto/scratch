#include <stdio.h>
#include <string.h>
#include "../md2.h"

static int
test(const char *buf, const char *hexdigest)
{
    int i;
    struct md2 ctx[1];
    unsigned char digest[MD2_BLOCK_SIZE];

    md2_init(ctx);
    md2_append(ctx, buf, strlen(buf));
    md2_finish(ctx, digest);

    for (i = 0; i < MD2_BLOCK_SIZE; i++) {
        static const char hex[16] = "0123456789abcdef";
        if (hexdigest[i * 2 + 0] != hex[digest[i] >> 4])
            return 0;
        if (hexdigest[i * 2 + 1] != hex[digest[i] & 0xf])
            return 0;
    }
    return 1;
}

int
main(void)
{
    static const char *const tests[] = {
        "", "8350e5a3e24c153df2275c9f80692773",
        "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1",
        "abc", "da853b0d3f88d99b30283a69e6ded6bb",
        "message digest", "ab4f496bfb2a530b219ff33031fe06b0",
        "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "da33def2a42df13975352846c30338cd",
        "123456789012345678901234567890123456789012345678901234567890123"
            "45678901234567890", "d5976f79d83d3a0dc9806c3c66f3efd8"
    };
    int i;
    int pass = 0;
    int n = sizeof(tests) / sizeof(tests[0]) / 2;

    for (i = 0; i < n; i++) {
        const char *buf = tests[i * 2 + 0];
        const char *digest = tests[i * 2 + 1];
        if (!test(buf, digest))
            printf("FAIL: %s\n", buf);
        else
            pass++;
    }

    printf("Passed %d / %d\n", pass, n);
    return !(pass == n);
}
