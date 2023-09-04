// @Roll dice-rolling language parser and evaluator
// Based on: https://github.com/StellarWolfEntertainment/Atroll
//
// Usage (roll a new character):
//   $ cc -o atroll atroll.c
//   $ cat >demo.atroll <<EOF
//   Roll 4d6
//   Drop Lowest
//   Add 2
//   EOF
//   $ atroll <demo.atroll 6
//
// Basic structure:
//   Roll ROLL
//   Reroll COND ROLL
//   Add|Sub|Mul|Div INT
//   Drop Highest|Lowest
//   For INT STMT
//   If COND STMT
//   While COND STMT
//
// API:
//   // Parse a source buffer, allocating the tree out of the arena.
//   // Returns error information (line number, token) on failure.
//   atroll_tree atroll_parse(arena *, u8 *src, size len);
//
//   // Evaluate a tree from atroll_parse using the RNG. Uses arena as
//   // scratch space for evaluation. The evaluator is a tree-walker.
//   // The tree is unmodified and can be used concurrently.
//   atroll_sum atroll_eval(atroll_block *, uint64_t rng[1], arena);
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stddef.h>

typedef uint8_t       u8;
typedef int16_t       i16;
typedef int32_t       b32;
typedef int32_t       i32;
typedef int64_t       i64;
typedef uint64_t      u64;
typedef unsigned char byte;
typedef ptrdiff_t     size;

#define new(a, t, n) (t *)alloc(a, sizeof(t), _Alignof(t), n)

typedef struct {
    byte *mem;
    size  off;
    size  cap;
} arena;

static void *alloc(arena *a, size objsize, size align, size count)
{
    size avail = a->cap - a->off;
    size padding = -a->off & (align - 1);
    if (count > (avail - padding)/objsize) {
        return 0;
    }
    size total = objsize * count;
    byte *p = a->mem + a->off + padding;
    for (size i = 0; i < total; i++) {
        p[i] = 0;
    }
    a->off += padding + total;
    return p;
}

typedef struct {
    u8  *beg;
    u8  *end;
    size lineno;
} atroll_parser;

typedef enum {
    atroll_T_EOF,
    atroll_T_UNKNOWN,
    atroll_T_COND,
    atroll_T_DICE,
    atroll_T_INT,
    atroll_T_Add,
    atroll_T_Div,
    atroll_T_Drop,
    atroll_T_For,
    atroll_T_Highest,
    atroll_T_If,
    atroll_T_Lowest,
    atroll_T_Mul,
    atroll_T_Reroll,
    atroll_T_Roll,
    atroll_T_Sub,
    atroll_T_While,
} atroll_ttype;

typedef struct {
    u8          *beg;
    u8          *end;
    atroll_ttype type;
} atroll_token;

typedef enum {
    atroll_C_LT,
    atroll_C_LE,
    atroll_C_EQ,
    atroll_C_GE,
    atroll_C_GT,
} atroll_cmp;

static b32 atroll_isspace(u8 c)
{
    switch (c) {
    case '\t': case '\n': case '\r': case ' ':
        return 1;
    }
    return 0;
}

static b32 atroll_isdigit(u8 c)
{
    return c>='0' && c<='9';
}

static u8 *atroll_digits(u8 *beg, u8 *end)
{
    for (; beg<end && atroll_isdigit(*beg); beg++) {}
    return beg;
}

static b32 atroll_iscond(u8 *beg, u8 *end)
{
    size len = end - beg;
    if (len>1 && beg[0]=='<' && beg[1]=='=') {
        beg += 2;
    } else if (len>2 && beg[0]=='>' && beg[1]=='=') {
        beg += 2;
    } else if (len>1 && beg[0]=='<') {
        beg += 1;
    } else if (len>1 && beg[0]=='>') {
        beg += 1;
    } else if (len>1 && beg[0]=='=') {
        beg += 1;
    } else {
        return 0;
    }
    return atroll_digits(beg, end) == end;
}

static b32 atroll_isroll(u8 *beg, u8 *end)
{
    u8 *split = atroll_digits(beg, end);
    if (split==beg || split==end || *split!='d') {
        return 0;
    }
    return atroll_digits(split+1, end) == end;
}

static atroll_token atroll_lex(atroll_parser *p)
{
    atroll_token r = {0};

    // Skip whitespace
    for (;; p->beg++) {
        if (p->beg == p->end) {
            return r;
        }
        p->lineno += *p->beg == '\n';
        if (!atroll_isspace(*p->beg)) {
            break;
        }
    }

    r.beg = p->beg++;
    for (;; p->beg++) {
        if (p->beg==p->end || atroll_isspace(*p->beg)) {
            r.end = p->beg;
            break;
        }
    }

    if (atroll_digits(r.beg, r.end) == r.end) {
            r.type = atroll_T_INT;
            return r;
    }

    if (atroll_iscond(r.beg, r.end)) {
        r.type = atroll_T_COND;
        return r;
    }

    if (atroll_isroll(r.beg, r.end)) {
        r.type = atroll_T_DICE;
        return r;
    }

    static struct {
        u8  name[8];
        i16 len;
    } names[] = {
        #define atroll_E(p) p, sizeof(p)-1
        {atroll_E("Add")},
        {atroll_E("Div")},
        {atroll_E("Drop")},
        {atroll_E("For")},
        {atroll_E("Highest")},
        {atroll_E("If")},
        {atroll_E("Lowest")},
        {atroll_E("Mul")},
        {atroll_E("Reroll")},
        {atroll_E("Roll")},
        {atroll_E("Sub")},
        {atroll_E("While")},
    };
    i32 n = sizeof(names) / sizeof(*names);
    for (i32 i = 0; i < n; i++) {
        if (r.end-r.beg == names[i].len) {
            i32 match = 1;
            for (i16 j = 0; match && j<names[i].len; j++) {
                match = names[i].name[j] == r.beg[j];
            }
            if (match) {
                r.type = atroll_T_Add + i;
                return r;
            }
        }
    }
    r.type = atroll_T_UNKNOWN;
    return r;
}

static i32 atroll_atoi(u8 *beg, u8 *end, i32 min, i32 max)
{
    i32 r = 0;
    for (; beg < end; beg++) {
        i32 digit = *beg - '0';
        if (r > (max - digit)/10) {
            return -2;
        }
        r = r*10 + digit;
    }
    return r>=min ? r : -1;
}

typedef struct {
    atroll_cmp cmp;
    i32        op;
} atroll_cond;

typedef struct {
    i16 count;
    i16 sides;
} atroll_roll;

typedef enum {
    atroll_B_Roll,    // roll
    atroll_B_Reroll,  // cond, roll
    atroll_B_Add,     // operand
    atroll_B_Mul,     // operand
    atroll_B_Div,     // operand
    atroll_B_Drop,    // operand
    atroll_B_If,      // cond, child
    atroll_B_For,     // operand, child
    atroll_B_While,   // cond, child
} atroll_btype;

typedef struct atroll_block atroll_block;
struct atroll_block {
    atroll_block *next;
    atroll_block *child;
    size          lineno;
    atroll_cond   cond;
    atroll_roll   roll;
    i32           operand;
    atroll_btype  type;
};

static b32 atroll_parseroll(u8 *beg, u8 *end, atroll_roll *r)
{
    u8 *split = beg + 1;
    for (; *split != 'd'; split++) {}
    r->count = (i16)atroll_atoi(beg, split, 1, 99);
    r->sides = (i16)atroll_atoi(split+1, end, 1, 100);
    return r->count>=0 && r->sides>=0;
}

static b32 atroll_parsecond(u8 *beg, u8 *end, atroll_cond *c)
{
    if (end-beg == 1) {
        c->cmp = atroll_C_EQ;
    } else if (beg[0]=='<' && beg[1]=='=') {
        c->cmp = atroll_C_LE;
        beg += 2;
    } else if (beg[0]=='>' && beg[1]=='=') {
        c->cmp = atroll_C_GE;
        beg += 2;
    } else if (beg[0]=='<') {
        c->cmp = atroll_C_LT;
        beg += 1;
    } else if (beg[0]=='>') {
        c->cmp = atroll_C_GT;
        beg += 1;
    } else if (beg[0]=='=') {
        c->cmp = atroll_C_EQ;
        beg += 1;
    } else {
        c->cmp = atroll_C_EQ;
    }
    c->op = atroll_atoi(beg, end, 0, 1000000);
    return c->op >= 0;
}

typedef struct {
    atroll_block  *head;
    atroll_block **tail;
    char          *err;
    u8            *data;
    size           datalen;
    size           lineno;
} atroll_tree;

static atroll_tree atroll_parse(arena *a, u8 *src, size len)
{
    atroll_tree r = {0};
    r.tail = &r.head;

    atroll_parser p = {0};
    p.beg = src;
    p.end = src + len;
    p.lineno = 1;
    atroll_block *parent = 0;

    for (;;) {
        b32 valid;
        b32 leaf = 1;
        atroll_token op;
        atroll_block *b = new(a, atroll_block, 1);
        if (!b) {
            r.lineno = p.lineno;
            r.err = "out of memory";
            return r;
        }

        atroll_token t = atroll_lex(&p);
        b->lineno = p.lineno;
        switch (t.type) {
        case atroll_T_EOF:
            if (parent) {
                r.lineno = p.lineno;
                r.err = "unexpected end of input";
            }
            return r;

        case atroll_T_UNKNOWN:
            r.lineno = p.lineno;
            r.err = "unknown token";
            r.data = t.beg;
            r.datalen = t.end - t.beg;
            return r;

        case atroll_T_COND:
        case atroll_T_DICE:
        case atroll_T_INT:
        case atroll_T_Highest:
        case atroll_T_Lowest:
            r.lineno = p.lineno;
            r.err = "invalid token";
            r.data = t.beg;
            r.datalen = t.end - t.beg;
            return r;

        case atroll_T_Add:
        case atroll_T_Sub:
        case atroll_T_Mul:
        case atroll_T_Div:
            op = atroll_lex(&p);
            if (op.type != atroll_T_INT) {
                r.lineno = p.lineno;
                r.err = "invalid arithmetic operand";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }

            b->operand = atroll_atoi(op.beg, op.end, 0, 1000000);
            if (b->operand < 0) {
                r.lineno = p.lineno;
                r.err = "operand too large";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            switch (t.type) {
            case atroll_T_Add:
                b->type = atroll_B_Add;
                break;
            case atroll_T_Sub:
                b->operand = -b->operand;
                b->type = atroll_B_Add;
                break;
            case atroll_T_Mul:
                b->type = atroll_B_Mul;
                break;
            case atroll_T_Div:
                if (!b->operand) {
                    r.lineno = p.lineno;
                    r.err = "cannot divide by zero";
                    r.data = op.beg;
                    r.datalen = op.end - op.beg;
                    return r;
                }
                b->type = atroll_B_Div;
                break;
            default: *(volatile int *)0 = 0;
            }
            break;

        case atroll_T_Drop:
            b->type = atroll_B_Drop;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_Highest:
                b->operand = +1;
                break;
            case atroll_T_Lowest:
                b->operand = -1;
                break;
            default:
                r.lineno = p.lineno;
                r.err = "invalid Drop operand";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            break;

        case atroll_T_For:
            b->type = atroll_B_For;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_INT:
                b->operand = atroll_atoi(op.beg, op.end, 2, 100);
                valid = b->operand >= 0;
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid For operand";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            leaf = 0;
            break;

        case atroll_T_If:
            b->type = atroll_B_If;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_COND:
            case atroll_T_INT:
                valid = atroll_parsecond(op.beg, op.end, &b->cond);
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid If condition";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            leaf = 0;
            break;

        case atroll_T_Reroll:
            b->type = atroll_B_Reroll;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_INT:
            case atroll_T_COND:
                valid = atroll_parsecond(op.beg, op.end, &b->cond);
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid Reroll condition";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }

            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_DICE:
                valid = atroll_parseroll(op.beg, op.end, &b->roll);
                break;
            case atroll_T_INT:
                b->roll.count = 1;
                b->roll.sides = (i16)atroll_atoi(op.beg, op.end, 1, 100);
                valid = b->roll.sides >= 0;
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid Reroll roll";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            break;

        case atroll_T_Roll:
            b->type = atroll_B_Roll;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_DICE:
                valid = atroll_parseroll(op.beg, op.end, &b->roll);
                break;
            case atroll_T_INT:
                b->roll.count = 1;
                b->roll.sides = (i16)atroll_atoi(op.beg, op.end, 1, 100);
                valid = b->roll.sides >= 0;
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid Roll roll";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            break;

        case atroll_T_While:
            b->type = atroll_B_While;
            op = atroll_lex(&p);
            switch (op.type) {
            case atroll_T_COND:
                valid = atroll_parsecond(op.beg, op.end, &b->cond);
                break;
            default:
                valid = 0;
            }
            if (!valid) {
                r.lineno = p.lineno;
                r.err = "invalid While operand";
                r.data = op.beg;
                r.datalen = op.end - op.beg;
                return r;
            }
            leaf = 0;
            break;
        }
        if (parent) {
            parent->child = b;
        } else {
            *r.tail = b;
            r.tail = &b->next;
        }
        parent = leaf ? 0 : b;
    }
}

static i16 atroll_throw(i16 sides, u64 *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (i16)(1 + (i32)(*rng >> 33)%sides);
}

static b32 atroll_apply(atroll_cond cond, i32 x)
{
    switch (cond.cmp) {
    case atroll_C_LT: return x <  cond.op;
    case atroll_C_LE: return x <= cond.op;
    case atroll_C_EQ: return x == cond.op;
    case atroll_C_GE: return x >= cond.op;
    case atroll_C_GT: return x >  cond.op;
    }
    *(volatile int *)0 = 0;
    return 0;
}

typedef struct {
    char *err;
    size  lineno;
    i32   result;
} atroll_sum;

typedef struct atroll_frame atroll_frame;
struct atroll_frame {
    atroll_frame *prev;
    atroll_block *block;
    atroll_cond  *cond;
    i16           count;
};

static b32 atroll_accum(i16 *dice, i32 ndice, i32 *dst)
{
    i32 sum = 0;
    for (i32 i = 0; i < ndice; i++) {
        if (dice[i] > 0x7fffffff-sum) {
            return 0;
        }
        sum += dice[i];
    }
    if (*dst > 0x7fffffff-sum) {
        return 0;
    }
    *dst += sum;
    return 1;
}

static b32 atroll_add(i32 a, i32 b, i32 *r)
{
    if (a>0 && b>0x7fffffff-a) {
        return 0;
    } else if (a<0 && b<(i32)0x80000000-a) {
        return 0;
    }
    *r = a + b;
    return 1;
}

static b32 atroll_mul(i32 a, i32 b, i32 *r)
{
    i64 c = (i64)a*b;
    if (c<(i32)0x80000000 || c>0x7fffffff) {
        return 0;
    }
    *r = a * b;
    return 1;
}

static atroll_sum atroll_eval(atroll_block *program, u64 rng[1], arena a)
{
    atroll_sum r = {0};
    r.lineno = 1;

    i32 ndice = 0;
    i32 max = 1000;
    i16 *dice = new(&a, i16, max);
    if (!dice) goto oom;

    atroll_frame *free = 0;
    atroll_frame *stack = new(&a, atroll_frame, 1);
    if (!stack) goto oom;
    stack->count = 1;
    stack->block = program;

    while (stack) {
        atroll_block *b = 0;
        if (stack->cond) {
            b32 match = 0;
            for (i32 i = 0; !match && i<ndice; i++) {
                match = atroll_apply(*stack->cond, dice[i]);
            }
            if (match) {
                b = stack->block;
            } else {
                stack->cond = 0;
                continue;
            }
        } else if (stack->count && stack->block) {
            stack->count--;
            b = stack->block;
        } else if (stack->block) {
            stack->count = 1;
            stack->block = stack->block->next;
            continue;
        } else {
            atroll_frame *dead = stack;
            stack = stack->prev;
            dead->prev = free;
            free = dead;
            continue;
        }

        b32 match;
        b32 overflow;
        atroll_frame *frame;

        r.lineno = b->lineno;
        switch (b->type) {
        case atroll_B_Roll:
            if (b->roll.count > max-ndice) {
                r.err = "exceeded dice limit (out of memory)";
                return r;
            }
            for (i16 i = 0; i < b->roll.count; i++) {
                dice[ndice++] = atroll_throw(b->roll.sides, rng);
            }
            break;

        case atroll_B_Reroll:
            for (i32 i = 0; i < ndice; i++) {
                if (atroll_apply(b->cond, dice[i])) {
                    dice[i] = atroll_throw(b->roll.sides, rng);
                }
            }
            break;

        case atroll_B_Add:
            overflow = !atroll_accum(dice, ndice, &r.result) ||
                       !atroll_add(r.result, b->operand, &r.result);
            if (overflow) {
                r.err = "Add overflow";
                return r;
            }
            ndice = 0;
            break;

        case atroll_B_Mul:
            overflow = !atroll_accum(dice, ndice, &r.result) ||
                       !atroll_mul(r.result, b->operand, &r.result);
            if (overflow) {
                r.err = "Mul overflow";
                return r;
            }
            ndice = 0;
            break;

        case atroll_B_Div:
            if (!atroll_accum(dice, ndice, &r.result)) {
                r.err = "Div overflow (on sum)";
                return r;
            }
            ndice = 0;
            r.result /= b->operand;
            break;

        case atroll_B_Drop:
            if (!ndice) {
                r.err = "Drop used on an empty set of dice";
                return r;
            }
            i32 target = 0;
            if (b->operand < 0) {
                for (i32 i = 1; i < ndice; i++) {
                    target = dice[i]<dice[target] ? i : target;
                }
            } else {
                for (i32 i = 1; i < ndice; i++) {
                    target = dice[i]>dice[target] ? i : target;
                }
            }
            dice[target] = dice[--ndice];
            break;

        case atroll_B_If:
            match = 0;
            for (i32 i = 0; !match && i<ndice; i++) {
                match = atroll_apply(b->cond, dice[i]);
            }
            if (match) {
                frame = free;
                if (frame) {
                    free = free->prev;
                } else {
                    frame = new(&a, atroll_frame, 1);
                    if (!frame) goto oom;
                }
                frame->cond = &b->cond;
                frame->block = b->child;
                frame->prev = stack;
                stack = frame;
            }
            break;

        case atroll_B_For:
            frame = free;
            if (frame) {
                free = free->prev;
            } else {
                frame = new(&a, atroll_frame, 1);
                if (!frame) goto oom;
            }
            frame->count = (i16)b->operand;
            frame->block = b->child;
            frame->prev = stack;
            stack = frame;
            break;

        case atroll_B_While:
            frame = free;
            if (frame) {
                free = free->prev;
            } else {
                frame = new(&a, atroll_frame, 1);
                if (!frame) goto oom;
            }
            frame->cond = &b->cond;
            frame->block = b->child;
            frame->prev = stack;
            stack = frame;
            break;
        }
    }

    if (!atroll_accum(dice, ndice, &r.result)) {
        r.err = "final dice sum overflow";
    }
    return r;
    oom:
    r.err = "out of memory";
    return r;
}

#ifndef FUZZ
// Demo command line program
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static u64 hash64(u64 x)
{
    x += 1111111111111111111; x ^= x >> 32;
    x *= 1111111111111111111; x ^= x >> 32;
    x *= 1111111111111111111; x ^= x >> 32;
    return x;
}

int main(int argc, char **argv)
{
    arena arena = {0};
    arena.cap = 1<<21;
    arena.mem = malloc(arena.cap);

    size srccap = 1<<16;
    u8 *src = new(&arena, u8, srccap);
    size srclen = fread(src, 1, srccap, stdin);

    atroll_tree t = atroll_parse(&arena, src, srclen);
    if (t.err) {
        fprintf(stderr, "<stdin>:%td: %s: %.*s\n",
                t.lineno, t.err, (int)t.datalen, t.data);
        return 1;
    }

    // Portable seed generator
    u64 rng = hash64(time(0));
    for (clock_t beg = clock();; rng ^= hash64(rng + beg)) {
        clock_t end = clock();
        if (end != beg) {
            rng ^= hash64(end);
            break;
        }
    }

    int count = argc>1 ? atoi(argv[1]) : 1;
    for (int i = 0; i < count; i++) {
        atroll_sum r = atroll_eval(t.head, &rng, arena);
        if (r.err) {
            fprintf(stderr, "<stdin>:%td: %s\n", r.lineno, r.err);
            return 1;
        }
        printf("%ld\n", (long)r.result);
    }

    fflush(stdout);
    return ferror(stdout);
}


#else
// Fuzz tester (afl)
// $ afl-clang-fast -DFUZZ -g3 -fsanitize=address,undefined atroll.c
// $ mkdir i
// $ echo 'Roll 4d6 Drop Lowest While =4 Mul 10' >i/sample
// $ afl-fuzz -m32T -ii -oo ./a.out
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    u8 *src = 0;
    size heapcap = 1<<16;
    u8 *heap = malloc(heapcap);
    u8 *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size len = __AFL_FUZZ_TESTCASE_LEN;
        src = realloc(src, len);
        memcpy(src, buf, len);
        arena arena = {0};
        arena.cap = heapcap;
        arena.mem = heap;
        atroll_tree t = atroll_parse(&arena, src, len);
        if (!t.err) {
            uint64_t rng = 1;
            atroll_eval(t.head, &rng, arena);
        }
    }
}
#endif
