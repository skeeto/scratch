// Unix "find" bytecode compiler (demo)
// $ cc -std=gnu23 -o findc findc.c
// Note: Requires a fairly recent C compiler (GCC 15, Clang 22).
// Ref: https://nullprogram.com/blog/2025/12/23/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdio.h>

#define S(s)            (Str){s, sizeof(s)-1}
#define affirm(c)       while (!(c)) __builtin_trap()
#define lenof(a)        (ptrdiff_t)(sizeof(a) / sizeof(*(a)))
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

#define Slice(T)        \
    struct Slice##T {   \
        T        *data; \
        ptrdiff_t len;  \
        ptrdiff_t cap;  \
    }

#define push(a, s)                          \
  ((s)->len == (s)->cap                     \
    ? (s)->data = push_(                    \
        (a),                                \
        (s)->data,                          \
        &(s)->cap,                          \
        sizeof(*(s)->data),                 \
        _Alignof(typeof(*(s)->data))        \
      ),                                    \
      (s)->data + (s)->len++                \
    : (s)->data + (s)->len++)

static size_t to_usize(ptrdiff_t x)
{
    affirm(x >= 0);
    return (size_t)x;
}

typedef struct {
    char *beg;
    char *end;
} Arena;

static char *alloc(Arena *a, ptrdiff_t count, int size, int align)
{
    ptrdiff_t pad = (ptrdiff_t)-(size_t)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);  // TODO: oom policy
    char *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, to_usize(count*size));
}

static void *push_(Arena *a, void *data, ptrdiff_t *pcap, int size, int align)
{
    ptrdiff_t cap = *pcap;
    if (!data || a->beg != (char *)data + cap*size) {
        char *copy = alloc(a, cap, size, align);
        __builtin_memcpy(copy, data, to_usize(cap*size));
        data = copy;
    }
    ptrdiff_t extend = cap ? cap : 4;
    alloc(a, extend, size, align);
    *pcap = cap + extend;
    return data;
}

typedef struct {
    char     *data;
    ptrdiff_t len;
} Str;

static Str span(char *beg, char *end)
{
    affirm(end-beg >= 0);
    return (Str){beg, end-beg};
}

static Str import(char *s)
{
    Str r = {};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, r.len, char);
    __builtin_memcpy(r.data, s.data, to_usize(r.len));
    return r;
}

static Str concat(Arena *a, Str head, Str tail)
{
    if (head.data+head.len != a->beg) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static bool equals(Str a, Str b)
{
    return a.len==b.len && !__builtin_memcmp(a.data, b.data, to_usize(a.len));
}

typedef enum {
    TOK_not,     // "!"
    TOK_and,     // "-a"
    TOK_or,      // "-o"
    TOK_left,    // "("
    TOK_right,   // ")"
    TOK_dash,    // "-name", "-executable", etc.
    TOK_arg,     // regex, pattern, time, etc.
} Token;

static Token parse_token(Str s)
{
    if (equals(s, S("!"))) {
        return TOK_not;
    } else if (equals(s, S("-a"))) {
        return TOK_and;
    } else if (equals(s, S("-o"))) {
        return TOK_or;
    } else if (equals(s, S("("))) {
        return TOK_left;
    } else if (equals(s, S(")"))) {
        return TOK_right;
    } else if (s.len>1 && s.data[0]=='-') {
        return TOK_dash;
    }
    return TOK_arg;
}

typedef enum {
    OP_halt,
    OP_not,     // invert register
    OP_braf,    // branch if false
    OP_brat,    // branch if true
    OP_action,
} Opcode;

typedef struct {
    Opcode     opcode;
    union {
        Slice(Str) args; // action
        ptrdiff_t  rel;  // braf, brat
    };
} Asm;

typedef Slice(Asm) Program;

static Str print_int(Arena *a, Str dst, ptrdiff_t x)
{
    char  buf[32];
    char *end = buf + lenof(buf);
    char *beg = end;
    ptrdiff_t t = x<0 ? x : -x;
    do *--beg = '0' - (char)(t%10);
    while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    return concat(a, dst, span(beg, end));
}

static Str print_asm(Arena *a, Str d, Program p, ptrdiff_t i, ptrdiff_t *labels)
{
    if (labels[i]) {
        d = concat(a, d, S("L"));
        d = print_int(a, d, labels[i]);
        d = concat(a, d, S(":"));
    }
    d = concat(a, d, S("\t"));

    Asm ins = p.data[i];
    switch (ins.opcode) {
    case OP_halt:
        d = concat(a, d, S("halt"));
        break;
    case OP_not:
        d = concat(a, d, S("not"));
        break;
    case OP_braf:
    case OP_brat:
        Str name = ins.opcode==OP_braf ? S("braf\tL") : S("brat\tL");
        d = concat(a, d, name);
        d = print_int(a, d, labels[i+1+ins.rel]);
        #if 0  // extra debugging info
        d = concat(a, d, S("\t// rel "));  // raw value
        d = print_int(a, d, ins.rel);
        #endif
        break;
    case OP_action:
        d = concat(a, d, S("action\t"));
        for (ptrdiff_t i = 0; i < ins.args.len; i++) {
            if (i) d = concat(a, d, S(" "));
            d = concat(a, d, ins.args.data[i]);
        }
        break;
    }
    return concat(a, d, S("\n"));
}

static Str print_program(Arena *a, Str dst, Program program)
{
    ptrdiff_t  counter = 0;
    ptrdiff_t *labels  = new(a, program.len, ptrdiff_t);

    for (ptrdiff_t i = 0; i < program.len; i++) {
        Asm ins = program.data[i];
        switch (ins.opcode) {
        default:
            break;
        case OP_braf:
        case OP_brat:
            if (!labels[i+1+ins.rel]) {
                labels[i+1+ins.rel] = ++counter;
            }
        }
    }

    for (ptrdiff_t i = 0; i < program.len; i++) {
        dst = print_asm(a, dst, program, i, labels);
    }

    return dst;
}

static Program append(Program head, Program tail, Arena *a)
{
    for (ptrdiff_t i = 0; i < tail.len; i++) {
        *push(a, &head) = tail.data[i];
    }
    return head;
}

static Slice(Str) slice(Slice(Str) s, ptrdiff_t beg, ptrdiff_t end)
{
    affirm(beg>=0 && beg<=end && end<=s.len);
    s.data += beg;
    s.len   = end - beg;
    s.cap  -= beg;
    return s;
}

typedef struct {
    Slice(Token)   token_stack;
    Slice(Str)     args;
    ptrdiff_t      argi;
    Slice(Program) code_stack;
    bool           joinable;  // can we synthesize -a now?
    bool           active;    // has -exec, -ok, or -print?
} Parser;

static bool compile(Parser *p, Token t, Arena *a)
{
    switch (t) {

    case TOK_not:
        if (p->code_stack.len < 1) return false;
        Program *top = p->code_stack.data + p->code_stack.len - 1;
        *push(a, top) = (Asm){.opcode=OP_not};
        return true;

    case TOK_and:
    case TOK_or:
        if (p->code_stack.len < 2) return false;
        Program *head = p->code_stack.data + p->code_stack.len - 2;
        Program *tail = p->code_stack.data + p->code_stack.len - 1;
        p->code_stack.len--;
        Opcode jmp = t==TOK_and ? OP_braf : OP_brat;
        *push(a, head) = (Asm){
            .opcode = jmp,
            .rel    = tail->len,
        };
        *head = append(*head, *tail, a);
        return true;

    case TOK_dash:
        ptrdiff_t beg = p->argi - 1;
        for (; p->argi < p->args.len; p->argi++) {
            if (parse_token(p->args.data[p->argi]) != TOK_arg) {
                break;
            }
        }
        Program program = {};
        *push(a, &program) = (Asm){
            .opcode = OP_action,
            .args   = slice(p->args, beg, p->argi),
        };
        *push(a, &p->code_stack) = program;
        return true;

    case TOK_left:
    case TOK_right:
    case TOK_arg:
        break;
    }
    affirm(0);
}

static bool token_empty(Parser *p)
{
    return !p->token_stack.len;
}

static Token token_peek(Parser *p)
{
    affirm(p->token_stack.len);
    return p->token_stack.data[p->token_stack.len-1];
}

static Token token_pop(Parser *p)
{
    affirm(p->token_stack.len);
    return p->token_stack.data[--p->token_stack.len];
}

static void token_push(Parser *p, Token tok, Arena *a)
{
    *push(a, &p->token_stack) = tok;
}

static bool parser_push(Parser *p, Token tok, Arena *a)
{
    switch (tok) {

    case TOK_not:
    case TOK_and:
    case TOK_or:
        p->joinable = false;
        while (!token_empty(p) && token_peek(p)<tok) {
            Token pop = token_pop(p);
            if (!compile(p, pop, a)) {
                return false;  // misplaced operator
            }
        }
        token_push(p, tok, a);
        return 1;

    case TOK_left:
        p->joinable = false;
        token_push(p, tok, a);
        return 1;

    case TOK_right:
        p->joinable = true;
        for (;;) {
            if (token_empty(p)) {
                return false;  // mismatched ")"
            }
            Token pop = token_pop(p);
            if (pop == TOK_left) {
                return true;
            } else if (!compile(p, pop, a)) {
                return false;  // misplaced ")"
            }
        }

    case TOK_dash:
        p->joinable = true;
        return compile(p, tok, a);

    case TOK_arg:
        break;
    }
    affirm(0);
}

static Program parse_and_compile(Slice(Str) args, Arena *a)
{
    Parser p = {};
    p.args = args;

    while (p.argi < p.args.len) {
        Str   arg = p.args.data[p.argi++];
        Token tok = parse_token(arg);

        switch (tok) {
        case TOK_arg:
            return (Program){};  // missing action/operator
        case TOK_dash:
            p.active |=
                equals(arg, S("-exec")) ||
                equals(arg, S("-ok")) ||
                equals(arg, S("-print"));
            break;
        default:
            break;
        }

        if (p.joinable) {
            switch (tok) {
            case TOK_and:
            case TOK_or:
            case TOK_right:
                break;
            case TOK_left:
            case TOK_not:
            case TOK_dash:
                if (!parser_push(&p, TOK_and, a)) {
                    return (Program){};
                }
                break;
            case TOK_arg:
                affirm(0);
            }
        }

        if (!parser_push(&p, tok, a)) {
            return (Program){};
        }
    }

    while (!token_empty(&p)) {
        Token pop = token_pop(&p);
        if (pop == TOK_left) {
            return (Program){};  // misplaced "("
        } else if (!compile(&p, pop, a)) {
            return (Program){};
        }
    }

    if (!p.active) {
        // A little hacky. Clearing the token stack above essentially
        // wraps the explicit expression in parentheses. In a real find
        // we'd push TOK_print and wouldn't need this arg string.
        *push(a, &p.args) = S("-print");
        p.argi++;
        compile(&p, TOK_dash, a);  // cannot fail
        compile(&p, TOK_and, a);   // "
    }

    if (p.code_stack.len != 1) {
        return (Program){};
    }

    Program r = p.code_stack.data[0];
    *push(a, &r) = (Asm){.opcode=OP_halt};
    return r;
}

enum {
    FLAG_H = 1<<0,
    FLAG_L = 1<<1,
};

typedef struct {
    Slice(Str) paths;
    Slice(Str) expr;
    int        flags;
} Args;

static Args splitargs(int argc, char **argv, Arena *a)
{
    Args r = {};
    int  i = 1;

    for (; i < argc; i++) {
        Str arg = import(argv[i]);

        if (arg.len>1 && arg.data[0]=='-') {
            bool valid = true;
            int  flags = 0;
            for (ptrdiff_t i = 1; valid && i<arg.len; i++) {
                switch (arg.data[i]) {
                case 'L': flags |= FLAG_L; break;
                case 'H': flags |= FLAG_H; break;
                default:  valid = 0;
                }
            }
            if (!valid) {
                break;
            }
            r.flags |= flags;

        } else if (equals(arg, S("!")) || equals(arg, S("("))) {
            break;

        } else {
            *push(a, &r.paths) = arg;
        }
    }

    for (; i < argc; i++) {
        *push(a, &r.expr) = import(argv[i]);
    }

    if (!r.paths.len) {
        *push(a, &r.paths) = S(".");
    }

    return r;
}

int main(int argc, char **argv)
{
    static char mem[1<<21];
    Arena a = {mem, mem+lenof(mem)};

    Args args = splitargs(argc, argv, &a);
    Str  out  = {};

    if (args.flags) {
        out = concat(&a, out, S("//"));
        if (args.flags & FLAG_H) out = concat(&a, out, S(" -H"));
        if (args.flags & FLAG_L) out = concat(&a, out, S(" -L"));
        out = concat(&a, out, S("\n"));
    }

    for (ptrdiff_t i = 0; i < args.paths.len; i++) {
        out = concat(&a, out, S("// path: "));
        out = concat(&a, out, args.paths.data[i]);
        out = concat(&a, out, S("\n"));
    }

    Program program = parse_and_compile(args.expr, &a);
    if (program.len) {
        out = print_program(&a, out, program);
    } else {
        out = concat(&a, out, S("error: invalid expression\n"));
    }

    fwrite(out.data, 1, to_usize(out.len), stdout);
    fflush(stdout);
    return ferror(stdout);
}
