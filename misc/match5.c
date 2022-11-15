// State machine matching 5-letter words
//   $ cc -o match5 match5.c
//   $ ./match5 <match5.c
// This is free and unencumbered software released into the public domain.
#include <assert.h>
#include <stdint.h>

#define MATCHER_INIT {0, 0}
struct matcher {
    uint64_t buf;
    int state;
};

// If C completes a match, write the 5-letter match into WORD and return
// true. Otherise return false;
static int next(struct matcher *m, char *word, unsigned char c)
{
    static const uint32_t alpha[8] = {0x0000,0x00000000,0x07fffffe,0x07fffffe};
    static const uint32_t alnum[8] = {0x0000,0x03ff0000,0x07fffffe,0x07fffffe};
    static const uint32_t split[8] = {0x3e00,0xfc00ffff,0xf8000001,0x78000001};
    m->buf = m->buf<<8 | c;
    switch (m->state) {
    case 0: if (alpha[c>>5]&(uint32_t)1<<(c&31)) {
                m->state = 1;
            } else if (!(split[c>>5]&(uint32_t)1<<(c&31))) {
                m->state = 6;
            }
            return 0;
    case 1:
    case 2:
    case 3:
    case 4: m->state = alnum[c>>5]&(uint32_t)1<<(c&31) ? m->state+1 : 0;
            return 0;
    case 5: if (split[c>>5]&(uint32_t)1<<(c&31)) {
                m->state = 0;
                word[0] = m->buf >> 40;
                word[1] = m->buf >> 32;
                word[2] = m->buf >> 24;
                word[3] = m->buf >> 16;
                word[4] = m->buf >>  8;
                return 1;
            }
            m->state = 6;
            return 0;
    case 6: m->state = split[c>>5]&(uint32_t)1<<(c&31) ? 0 : 6;
            return 0;
    }
    assert(0);
}


// Demo / Test
#include <stdio.h>

int main(void)
{
    char buf[6] = ".....\n";
    struct matcher m = MATCHER_INIT;
    for (int c = getchar(); c != EOF; c = getchar()) {
        if (next(&m, buf, c)) {
            fwrite(buf, sizeof(buf), 1, stdout);
        }
    }
    fflush(stdout);
    return ferror(stdout);
}
