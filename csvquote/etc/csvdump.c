// Benchmark/test for csvquote
//   $ cc -O3 -o csvdump csvdump.c
//   $ ./csvdump | ./csvquote >/dev/null
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <time.h>

int rng(int n)
{
    static unsigned long long s = 1;
    return ((s = s*0x3243f6a8885a308dU + 1) >> 33) % n;
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    static char buf[1L<<17];

    // Fill buf with random CSV content
    char *p = buf;
    for (int r = 0;; r++) {
        for (int i = 0; i < 16; i++) {
            int len = 0 + rng(20);

            if (i > 0) *p++ = ',';

            if (rng(10)) {
                for (int j = 0; j < len; j++) {
                    int c = ' ' + rng('~' - ' ' + 1);
                    switch (c) {
                    case '"' :
                    case ',' :
                    case '\n': break;
                    default  : *p++ = c;
                    }
                }

            } else {
                *p++  = '"';
                for (int j = 0; j < len; j++) {
                    int c = ' ' + rng('~' - ' ' + 2);
                    if (c == 127) c = '\n';
                    switch (c) {
                    case '"' : *p++ = c; // fallthrough
                    default  : *p++ = c;
                    }
                }
                *p++  = '"';
            }
        }
        *p++ = '\n';

        if ((size_t)(p-buf) > sizeof(buf)/2) {
            break;
        }
    }
    size_t len = p - buf;

    // Endlessly repeat the buffer, printing output speed to stderr
    long t = 0;
    time_t last = time(0);
    for (long c = 1; ; c++) {
        if (!fwrite(buf, len, 1, stdout)) {
            return 1;
        }

        time_t now = time(0);
        if (now != last) {
            if (t++) {
                double r = len / 1048576.0 * c;
                fprintf(stderr, "%-8.6f MiB/s\n", r / (now - last));
            }
            last = now;
            c = 0;
        }
    }
}
