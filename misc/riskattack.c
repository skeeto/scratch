/* This is free and unencumbered software released into the public domain. */

#include <stdint.h>
#include <stdlib.h>

// Simulate a Risk attack roll and return the number of attackers lost.
// Attack dice count must be from 1 to 3, and defense from 1 to 2. Defender
// loss can be computed from attacker loss: dloss = min(att, def) - aloss
//
// Seed the PRNG *state to any value.
int risk_attack(uint64_t *state, int attack, int defense)
{
    for (;;) {
        // Custom 64-bit PCG producing a high-quality 32-bit result
        uint32_t r = *state >> 32;
        *state = *state*0x7c3c3267d015ceb5 + 1;
        r ^= r >> 16;
        r *= 0x60857ba9;
        r ^= r >> 16;
        // Rather than generate individual rolls, draw from the result
        // distribution, without biases (rejection sampling).
        switch ((attack - 1)<<1 | (defense - 1)) {
        case 0: if (r >= 0xfffffffc) continue;  /* 1v1 */
                return r%12 >= 5;
        case 1: if (r >= 0xffffff48) continue;  /* 1v2 */
                return r%216 >= 55;
        case 2: if (r >= 0xffffff48) continue;  /* 2v1 */
                return r%216 >= 125;
        case 3: if (r >= 0xfffffb10) continue;  /* 2v2 */
                return (r%1296 >= 295) + (r%1296 >= 715);
        case 4: if (r >= 0xffffff90) continue;  /* 3v1 */
                return r%144 >= 95;
        case 5: if (r >= 0xfffff600) continue;  /* 3v2 */
                return (r%7776 >= 2890) + (r%7776 >= 5501);
        }
        abort();
    }
}
