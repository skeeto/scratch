// Codename generator via permutation
//
// Ref: https://nullprogram.com/blog/2021/09/14/
// Ref: https://possiblywrong.wordpress.com/2021/09/13/code-name-generator/
// Ref: https://www.ufopaedia.org/index.php/Mission_Names_(EU2012)
// Ref: https://en.wikipedia.org/wiki/Secret_Service_code_name
// Ref: https://en.wikipedia.org/wiki/Linear_congruential_generator
// Ref: https://andrew-helmer.github.io/permute/
// Ref: https://nullprogram.com/blog/2018/07/31/
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define COUNTOF(a) (int)(sizeof(a) / sizeof(*(a)))

static const char adjvs[][10] = {
    "SWINGING", "RADIANT", "BRONZE", "RED", "GREEN", "PINK", "STONE",
    "PURPLE", "NAVY", "SCARLET", "FALLEN", "FUCHSIA", "EMERALD", "DESERT",
    "SACRED", "FROZEN", "CELTIC", "SWOOPING", "LEAD", "TURQUOISE", "GRAY",
    "BEIGE", "OLIVE", "SILENT", "MAROON", "GLASS", "FADING", "CRIMSON",
    "BLUE", "AMBER", "TEAL", "BLACK", "FLYING", "COPPER", "LIME", "GOLDEN",
    "VENGEFUL", "AGING", "EMPTY", "STEEL", "IRON", "SPECTRAL", "LOST",
    "WHITE", "FROWNING", "YELLOW", "FORGOTTEN", "AQUA", "PLASTIC", "LAZY",
    "SILVER", "SWIFT", "CHASING",
};

static const char nouns[][12] = {
    "COPPERTONE", "JOCKEY", "TIMBERWOLF", "SAWHORSE", "PANDA", "SANDSTORM",
    "SEARCHLIGHT", "RAINBOW", "RENAISSANCE", "SPEEDWAY", "VOLUNTEER",
    "PHOENIX", "MARVEL", "SUNBURN", "DRILLER", "MARKSMAN", "DASHER",
    "JAVELIN", "SNOWBANK", "HUMMINGBIRD", "RADIANCE", "RIBBON", "INSTRUCTOR",
    "ROSEBUD", "THUNDER", "RAMROD", "ALPINE", "AUTHOR", "DOGWOOD",
    "CORNERSTONE", "RAINDANCE", "LANCER", "SUNDANCE", "EAGLE", "DAREDEVIL",
    "ROVER", "MIRACLE", "TRANQUILITY", "STARBURST", "PROFESSOR", "APOLLO",
    "SUNSHINE", "DUSTER", "PATHFINDER", "SWORDFISH", "MAHOGANY", "PHOTOGRAPH",
    "DERBY", "STARDUST", "DYNAMO", "CENTURION", "MECHANIC", "STARLIGHT",
    "RHYME", "LASER", "PIONEER", "GRANDMA", "DANCER", "PEBBLES",
    "SCREWDRIVER", "SCORECARD", "WITNESS", "DIAMOND", "VELVET", "DASHBOARD",
    "SUPERVISOR", "PASSKEY", "SILHOUETTE", "RENEGADE", "SUGARFOOT", "VENUS",
    "PROVIDENCE", "DEACON", "DRAGON", "SAHARA", "CHAMPION",
};

static uint32_t
hash32(uint32_t x)
{
    x += 0x3243f6a8U; x ^= x >> 15;
    x *= 0xd168aaadU; x ^= x >> 15;
    x *= 0xaf723597U; x ^= x >> 15;
    return x;
}

// Generate a code name and return the next generator state. The destination
// buffer size must be at least 22 bytes.
uint32_t
codename(uint32_t state, char *buf)
{
    long a = (state <<  3 | 5) & 0xfff;  //  9 bits
    long c = (state >>  8 | 1) & 0xfff;  // 11 bits
    long s =  state >> 20;               // 12 bits

    do {
        s = (s*a + c) & 0xfff;
    } while (s >= COUNTOF(adjvs)*COUNTOF(nouns));

    int i = s % COUNTOF(adjvs);
    int j = s / COUNTOF(adjvs);
    snprintf(buf, 22, "%s %s", adjvs[i], nouns[j]);
    return (state & 0xfffff) | (uint32_t)s<<20;
}

// Generate the nth code name for this seed. The destination buffer size
// must be at least 22 bytes. Returns the actual code name length.
int
codename_n(char *buf, uint32_t seed, int n)
{
    uint32_t i = n;
    do {
        i ^= i >> 6; i ^= seed >>  0; i *= 0x325; i &= 0xfff;
        i ^= i >> 6; i ^= seed >>  8; i *= 0x3f5; i &= 0xfff;
        i ^= i >> 6; i ^= seed >> 16; i *= 0xa89; i &= 0xfff;
        i ^= i >> 6; i ^= seed >> 24; i *= 0x85b; i &= 0xfff;
        i ^= i >> 6;
    } while (i >= COUNTOF(adjvs)*COUNTOF(nouns));

    int a = i % COUNTOF(adjvs);
    int b = i / COUNTOF(adjvs);
    return snprintf(buf, 22, "%s %s", adjvs[a], nouns[b]);
}

int
main(int argc, char **argv)
{
    uint32_t seed = hash32(time(0));
    if (argc > 1) {
        seed = strtoul(argv[1], 0, 16);
    }

    #if 1
    uint32_t state = seed;
    for (int i = 0; i < 4028; i++) {
        char buf[32];
        state = codename(state, buf);
        puts(buf);
    }
    #else
    for (int i = 0; i < 4028; i++) {
        char buf[32];
        codename_n(buf, seed, i);
        puts(buf);
    }
    #endif
}
