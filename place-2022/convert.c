// 2022 r/place placement data converter
// Ref: https://old.reddit.com/r/place/comments/txvk2d/
// This is free and unencumbered software released into the public domain.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Convert a base64-encoded SHA-512 hash into a 64-bit key. This key is more
// efficient and manageable, but still unique in the dataset.
static uint64_t
decode(const char *hash)
{
    static const unsigned char t[256] = {
        ['A']= 0, ['B']= 1, ['C']= 2, ['D']= 3, ['E']= 4, ['F']= 5,
        ['G']= 6, ['H']= 7, ['I']= 8, ['J']= 9, ['K']=10, ['L']=11,
        ['M']=12, ['N']=13, ['O']=14, ['P']=15, ['Q']=16, ['R']=17,
        ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
        ['Y']=24, ['Z']=25, ['a']=26, ['b']=27, ['c']=28, ['d']=29,
        ['e']=30, ['f']=31, ['g']=32, ['h']=33, ['i']=34, ['j']=35,
        ['k']=36, ['l']=37, ['m']=38, ['n']=39, ['o']=40, ['p']=41,
        ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47,
        ['w']=48, ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53,
        ['2']=54, ['3']=55, ['4']=56, ['5']=57, ['6']=58, ['7']=59,
        ['8']=60, ['9']=61, ['+']=62, ['/']=63,
    };
    return (uint64_t)t[hash[ 0]&255] << 58 | (uint64_t)t[hash[ 1]&255] << 52 |
           (uint64_t)t[hash[ 2]&255] << 46 | (uint64_t)t[hash[ 3]&255] << 40 |
           (uint64_t)t[hash[ 4]&255] << 34 | (uint64_t)t[hash[ 5]&255] << 28 |
           (uint64_t)t[hash[ 6]&255] << 22 | (uint64_t)t[hash[ 7]&255] << 16 |
           (uint64_t)t[hash[ 8]&255] << 10 | (uint64_t)t[hash[ 9]&255] <<  4 |
           (uint64_t)t[hash[10]&255] >>  2;
}

// Get/invent a short user ID for a hash.
static int32_t
lookup(const char *hash)
{
    #define HTLEN 24
    static uint64_t keys[1L<<HTLEN];
    static int32_t  vals[1L<<HTLEN];
    static int32_t  count = 0;

    // Input is already uniformly distributed so no need to hash it.
    uint64_t key = decode(hash);
    uint32_t m = (1L << HTLEN) - 1;
    uint32_t i = key & m;
    uint32_t s = key>>HTLEN | 1;
    for (;;) {
        if (!vals[i]) {
            keys[i] = key;
            vals[i] = ++count;
            break;
        } else if (keys[i] == key) {
            break;
        }
        i = (i + s) & m;
    }
    return vals[i] - 1;
}

// Parse a color string into an integer.
static int32_t
parse_color(const char *c)
{
    static const unsigned char t[256] = {
        ['0'] =  0, ['1'] =  1, ['2'] =  2, ['3'] =  3, ['4'] =  4, ['5'] =  5,
        ['6'] =  6, ['7'] =  7, ['8'] =  8, ['9'] =  9, ['A'] = 10, ['B'] = 11,
        ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    };
    return (int32_t)t[c[0]&255] << 20 | (int32_t)t[c[1]&255] << 16 |
           (int32_t)t[c[2]&255] << 12 | (int32_t)t[c[3]&255] <<  8 |
           (int32_t)t[c[4]&255] <<  4 | (int32_t)t[c[5]&255] <<  0;
}

// Convert a color into a palette index.
static int
to_index(int32_t color)
{
    // palette:
    //   000000 00756f 009eaa 00a368 00cc78 00ccc0 2450a4 3690ea
    //   493ac1 515252 51e9f4 6a5cff 6d001a 6d482f 7eed56 811e9f
    //   898d90 94b3ff 9c6926 b44ac0 be0039 d4d7d9 de107f e4abff
    //   ff3881 ff4500 ff99aa ffa800 ffb470 ffd635 fff8b8 ffffff
    static const unsigned char t[64] = {
        +0, 19,  0,  0, 11,  0, 24,  0, 29,  0,  4, 13, 12,  0, 31, 10,
        +0, 28,  0,  0,  1,  0,  0, 20,  0,  0, 14,  0, 23,  0,  0, 26,
        +0, 15,  0,  0,  0, 30,  0, 18,  0,  0, 22, 25, 27,  0,  5,  2,
        17,  9,  3, 21,  0,  8,  0, 16,  6,  0,  0,  0,  0,  7,  0,  0,
    };
    return t[(color * UINT32_C(0x775d1eb3)) >> 26];
}

// Parse an image coordinate pair. Input pointer must be just inside the
// first quote.
static void
parse_coord(const char *c, int16_t *xy)
{
    xy[0] = xy[1] = 0;
    for (int i = 0; i < 2; i++) {
        for (;; c++) {
            unsigned v = *c - '0';
            if (v > 9) {
                c++;
                break;
            }
            xy[i] = xy[i]*10 + v;
        }
    }
}

// Sort function for int32_t for qsort().
static int
int32_cmp(const void *p0, const void *p1)
{
    int32_t i0 = *(const int32_t *)p0;
    int32_t i1 = *(const int32_t *)p1;
    return (i0 > i1) - (i0 < i1);
}

int
main(void)
{
    struct {
        int32_t ts;     // ~29 bits
        int32_t user;   // ~24 bits
        int16_t x;      //  11 bits
        int16_t y;      //  11 bits
        int8_t color;   //   5 bits
    } *events = malloc((1L<<28) * sizeof(*events));
    int32_t nevents = 0;

    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    char line[256];
    fgets(line, sizeof(line), stdin);  // skip header
    while (fgets(line, sizeof(line), stdin)) {
        int32_t i = nevents++;
        int tlen = strchr(line, ',') - line;

        int32_t d = line[9] - '1';
        int32_t h = 10*(line[11]-'0') + line[12] - '0';
        int32_t m = 10*(line[14]-'0') + line[15] - '0';
        int32_t s = 10*(line[17]-'0') + line[18] - '0';
        int32_t f = 0;
        switch (tlen) {
        case 23: break;
        case 25: f = 100*(line[20]-'0'); break;
        case 26: f = 100*(line[20]-'0') + 10*(line[21]-'0'); break;
        case 27: f = 100*(line[20]-'0') + 10*(line[21]-'0') + line[22] - '0';
        }
        events[i].ts = d*(24*60*60*1000) +
                       h*(60*60*1000) +
                       m*(60*1000) +
                       s*(1000) +
                       f;

        events[i].user = lookup(line + tlen + 1);

        events[i].color = to_index(parse_color(line + tlen + 1 + 88 + 1 + 1));

        int16_t xy[2];
        parse_coord(line + tlen + 1 + 88 + 1 + 7 + 1 + 1, xy);
        events[i].x = xy[0];
        events[i].y = xy[1];
    }

    qsort(events, nevents, sizeof(*events), int32_cmp);

    puts("timestamp,user,color,x,y");
    for (int32_t i = 0; i < nevents; i++) {
        printf("%" PRIi32 ",%" PRIi32 ",%d,%d,%d\n",
               events[i].ts,
               events[i].user,
               events[i].color,
               events[i].x,
               events[i].y);
    }

    free(events);
    fflush(stdout);
    return ferror(stdout);
}
