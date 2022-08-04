// Five five-letter words with 25 unique letters
//   $ cc -fopenmp -O3 -o fivefive fivefive.c
//   $ ./fivefive <words
// Ref: https://www.youtube.com/watch?v=_-AfhLQfb6w
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX (1<<16)

int main(void)
{
    char word[8];
    int nwords = 0;
    static int32_t sets[MAX];
    static char words[MAX][5];
    static uint32_t seen[1<<21] = {0};

    while (nwords<MAX && fgets(word, sizeof(word), stdin)) {
        // Convert word into a bitset
        int n = 0;
        int32_t c = 0;
        for (int i = 0; i < 5; i++) {
            int32_t b = (int32_t)1 << (word[i] - 'a');
            n += !(c & b);
            c |= b;
        }

        // Only keep words with 5 unique letters with unique sets
        if (n == 5 && !(seen[c>>5] & ((uint32_t)1 << (c&31)))) {
            seen[c>>5] |= (uint32_t)1 << (c&31);
            sets[nwords] = c;
            memcpy(words[nwords++], word, 5);
        }
    }

    #pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < nwords; i++) {
        int n = 0;
        int32_t c = 0;
        int stack[5] = {i};

        for (;;) {
            if (n == 5) {
                // Solution found
                #pragma omp critical
                printf("%.5s %.5s %.5s %.5s %.5s\n",
                        words[stack[0]], words[stack[1]],
                        words[stack[2]], words[stack[3]],
                        words[stack[4]]);
                c ^= sets[stack[--n]++];

            } else if (stack[n] == nwords) {
                // This cursor is exhausted, pop
                if (!--n) {
                    break; // bottomed out
                }
                c ^= sets[stack[n]];
                stack[n]++;

            } else if ((c & sets[stack[n]])) {
                // This word is invalid, advance
                stack[n]++;

            } else {
                // Keep this word and push
                c |= sets[stack[n]];
                if (++n < 5) {
                    stack[n] = stack[n-1]+1;
                }
            }
        }
    }
}
