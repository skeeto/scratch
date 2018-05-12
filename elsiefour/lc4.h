/* ANSI C implementation of ElsieFour (LC4)
 * This is free and unencumbered software released into the public domain.
 */
#ifndef LC4_H
#define LC4_H

struct lc4 {
    int i;
    int j;
    char s[6][6];
    char rev[36];
};

static int
lc4_value(int c)
{
    static const signed char table[] = {
          -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
          -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
          -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
          -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
        0x01,   -1,   -1, 0x00,   -1,   -1,   -1,   -1,
          -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
          -1,   -1, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09,   -1,   -1,   -1,   -1,   -1,   -1,
          -1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23,   -1,   -1,   -1,   -1, 0x01,
          -1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23,   -1,   -1,   -1,   -1,   -1
    };
    return c >= 0 && c < 128 ? table[c] : -1;
}

static int
lc4_char(int v)
{
    static const char table[] = {
        0x23, 0x5f, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a
    };
    return table[v];
}

static int
lc4_valid(const char *key)
{
    int i;
    char seen[36] = {0};
    for (i = 0; i < 36; i++) {
        int v = lc4_value(key[i]);
        if (v == -1 || seen[v]++)
            return 0;
    }
    return !key[36];
}

static void
lc4_init(struct lc4 *lc4, const char *key)
{
    int i;
    lc4->i = 0;
    lc4->j = 0;
    for (i = 0; i < 36; i++) {
        int k = lc4_value(key[i]);
        lc4->s[i / 6][i % 6] = k;
        lc4->rev[k] = i;
    }
}

static void
lc4_rotate_row(struct lc4 *lc4, int r)
{
    int c;
    int last = lc4->s[r][5];
    for (c = 0; c < 6; c++) {
        int save = lc4->s[r][c];
        lc4->s[r][c] = last;
        lc4->rev[last] = r * 6 + c;
        last = save;
    }
}

static void
lc4_rotate_col(struct lc4 *lc4, int c)
{
    int r;
    int last = lc4->s[5][c];
    for (r = 0; r < 6; r++) {
        int save = lc4->s[r][c];
        lc4->s[r][c] = last;
        lc4->rev[last] = r * 6 + c;
        last = save;
    }
}

static int
lc4_encrypt(struct lc4 *lc4, int v)
{
    int pt = lc4_value(v);
    if (pt != -1) {
        int i = lc4->i;
        int j = lc4->j;
        int r = lc4->rev[pt] / 6;
        int c = lc4->rev[pt] % 6;
        int x = (r + lc4->s[i][j] / 6) % 6;
        int y = (c + lc4->s[i][j]) % 6;
        int ct = lc4->s[x][y];
        lc4_rotate_row(lc4, r);
        if (x == r) y = (y + 1) % 6;
        if (i == r) j = (j + 1) % 6;
        lc4_rotate_col(lc4, y);
        if (j == y) i = (i + 1);
        lc4->i = (i + ct / 6) % 6;
        lc4->j = (j + ct) % 6;
        return lc4_char(ct);
    }
    return 0;
}

static int
lc4_decrypt(struct lc4 *lc4, int v)
{
    int ct = lc4_value(v);
    if (ct != -1) {
        int i = lc4->i;
        int j = lc4->j;
        int x = lc4->rev[ct] / 6;
        int y = lc4->rev[ct] % 6;
        int r = (36 + x - lc4->s[i][j] / 6) % 6;
        int c = (36 + y - lc4->s[i][j]) % 6;
        int pt = lc4->s[r][c];
        lc4_rotate_row(lc4, r);
        if (x == r) y = (y + 1) % 6;
        if (i == r) j = (j + 1) % 6;
        lc4_rotate_col(lc4, y);
        if (j == y) i = (i + 1);
        lc4->i = (i + ct / 6) % 6;
        lc4->j = (j + ct) % 6;
        return lc4_char(pt);
    }
    return 0;
}

#endif
