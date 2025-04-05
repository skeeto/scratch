// Used to generate a seed list for WASM build.
#include "water-sort.c"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    #pragma omp parallel for
    for (int seed = 0; seed <= 1<<24; seed++) {
        char *mem = malloc(SOLVE_MEM);
        Arena a   = {mem, mem+SOLVE_MEM};
        State s = genpuzzle(seed, MAXBOTTLE);
        Solution r = solve(s, MAXBOTTLE, &a);
        if (r.len >= 44) {
            #pragma omp critical
            {
                printf("%8d%3d%6d\n", seed, r.len, r.width);
                fflush(stdout);
            }
        }
        free(mem);
    }
}
