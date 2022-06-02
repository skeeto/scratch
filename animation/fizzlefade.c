// LCG fizzlefade with randomly-selected parameters
// Shows many obvious patterns resulting from poorly-chosen parameters.
//   $ cc -O3 -o fizzlefade fizzlefade.c
//   $ ./fizzlefade | mpv --no-correct-pts --fps=60 --fs -
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <time.h>

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    for (unsigned long long rng = time(0);;) {
        // Randomly generate LCG parameters
        long m, a, c, s;
        do {
            rng = rng*0x3243f6a8885a308dU + 1;
            s = (rng >>  0) & 0xff;
            c = (rng >>  8) & 0xffffff;
            m = (rng >> 32) % (1920L * 1080);
            a = (rng >> 53);
            while (!(a%2 && a%3 && a%5)) a++;
        } while ((m-1)%2 || (m-1)%3 || (m-1)%4 || (m-1)%5);

        // Use LCG to permute all pixels
        static unsigned char image[1920L*1080][3];
        for (long i = 0; i < 1920L*1080; i++) {
            s = ((long long)s*m + a) % (1920L * 1080);
            image[s][0] = c >>  0;
            image[s][1] = c >>  8;
            image[s][2] = c >> 16;
            if (!(i%8100)) {
                puts("P6\n1920 1080\n255");
                if (!fwrite(image, sizeof(image), 1, stdout)) {
                    return 1;
                }
            }
        }
    }
}
