// Unix "find" optimizing bytecode compiler (demo)
// $ cc -std=gnu23 -o findc findc.c
// Note: Requires a fairly recent C compiler (GCC 15, Clang 22).
// Ref: https://nullprogram.com/blog/2025/12/23/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

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
    OP_nop,     // helps with optimization
    OP_halt,
    OP_not,     // invert register
    OP_braf,    // branch if false
    OP_brat,    // branch if true
    OP_action,
} Opcode;

typedef struct {
    Opcode opcode;
    union {
        Slice(Str) *args; // action
        ptrdiff_t   rel;  // braf, brat
    };
} Asm;

typedef struct IRasm IRasm;
struct IRasm {
    Opcode opcode;
    union {
        Slice(Str) args;    // action
        IRasm     *target;  // braf, brat
    };
    ptrdiff_t addr;  // final address for computing branches
    ptrdiff_t refs;  // number of incoming branches
    IRasm    *next;
};

typedef struct {
    IRasm  *head;
    IRasm **tail;
    IRasm  *links;  // branches to be linked to appended chain
} IRlist;

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
    case OP_nop:
        d = concat(a, d, S("nop"));
        break;
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
        Slice(Str) args = *ins.args;
        for (ptrdiff_t i = 0; i < args.len; i++) {
            if (i) d = concat(a, d, S(" "));
            d = concat(a, d, args.data[i]);
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

static Slice(Str) slice(Slice(Str) s, ptrdiff_t beg, ptrdiff_t end)
{
    affirm(beg>=0 && beg<=end && end<=s.len);
    s.data += beg;
    s.len   = end - beg;
    s.cap  -= beg;
    return s;
}

typedef struct {
    Slice(Token)  token_stack;
    Slice(Str)    args;
    ptrdiff_t     argi;
    Slice(IRlist) code_stack;
    bool          joinable;  // can we synthesize -a now?
    bool          active;    // has -exec, -ok, or -print?
} Parser;

static IRasm *new_ir(Arena *a, Opcode opcode)
{
    IRasm *r = new(a, 1, IRasm);
    r->opcode = opcode;
    return r;
}

// Append tail to head, linking all open branch links to the first
// instruction of tail.
static IRlist append(IRlist head, IRlist tail)
{
    while (head.links) {
        IRasm *next = head.links->target;
        tail.head->refs++;
        head.links->target = tail.head;
        head.links = next;
    }
    *head.tail = tail.head;
    head.tail = tail.tail;
    head.links = tail.links;
    return head;
}

static bool compile(Parser *p, Token t, Arena *a)
{
    switch (t) {

    case TOK_not:
        if (p->code_stack.len < 1) return false;
        IRlist *top = p->code_stack.data + p->code_stack.len - 1;
        *top->tail = new_ir(a, OP_not);
        top->tail = &(*top->tail)->next;
        affirm(!top->links);
        return true;

    case TOK_and:
    case TOK_or:
        if (p->code_stack.len < 2) return false;
        IRlist *head = p->code_stack.data + p->code_stack.len - 2;
        IRlist *tail = p->code_stack.data + p->code_stack.len - 1;
        p->code_stack.len--;

        Opcode opcode = t==TOK_and ? OP_braf : OP_brat;
        IRasm *jmp = new_ir(a, opcode);
        jmp->next   = tail->head;
        jmp->target = tail->links;
        tail->head  = jmp;
        tail->links  = jmp;

        *head = append(*head, *tail);
        return true;

    case TOK_dash:
        ptrdiff_t beg  = p->argi - 1;
        Str       cmd  = p->args.data[beg];
        bool      exec = equals(cmd, S("-exec")) || equals(cmd, S("-ok"));
        for (; p->argi < p->args.len; p->argi++) {
            Str arg = p->args.data[p->argi];
            if (exec && (equals(arg, S(";")) || equals(arg, S("+")))) {
                p->argi++;
                break;
            } else if (!exec && parse_token(arg) != TOK_arg) {
                break;
            }
        }
        IRasm *action = new_ir(a, OP_action);
        action->args = slice(p->args, beg, p->argi);
        *push(a, &p->code_stack) = (IRlist){
            .head = action,
            .tail = &action->next,
        };
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

static Program assemble(IRasm *ir, Arena *a)
{
    Program r = {};
    for (IRasm *n = ir; n; n = n->next) {
        n->addr = r.cap++;
    }

    r.data = new(a, r.cap, Asm);

    for (IRasm *n = ir; n; n = n->next) {
        ptrdiff_t i = r.len++;
        r.data[i].opcode = n->opcode;
        switch (n->opcode) {
        case OP_nop:
        case OP_halt:
        case OP_not:
            break;
        case OP_braf:
        case OP_brat:
            r.data[i].rel = n->target->addr - n->addr - 1;
            break;
        case OP_action:
            r.data[i].args = &n->args;
            break;
        }
        n->addr = r.cap++;
    }

    return r;
}

typedef struct {
    IRasm    *ir;    // new IR linked list head
    ptrdiff_t opts;  // number of optimizations applied
} OptResult;

static Opcode invert(Opcode opcode)
{
    switch (opcode) {
    case OP_braf: return OP_brat; break;
    case OP_brat: return OP_braf; break;
    default: affirm(0);
    }
}

static OptResult optimize_pass(IRasm *ir)
{
    OptResult r = {};
    r.ir = ir;

    IRasm **prev = &r.ir;
    for (IRasm *n = r.ir; n; n = n->next) {
        bool deleted = false;
        switch (n->opcode) {
        default:
            break;

        case OP_nop:
            if (!n->refs) {
                // delete nops which are not branch targets
                *prev = n->next;
                deleted = true;
                r.opts++;
            }
            break;

        case OP_not:
            if (!n->next->refs) {
                // These optimizations are only valid if the next
                // instruction is not a branch target.

                switch (n->next->opcode) {
                default:
                    break;

                case OP_not:
                    // not; not => nop; nop
                    n->opcode = n->next->opcode = OP_nop;
                    r.opts++;
                    break;

                case OP_braf:
                case OP_brat:
                    // not; brat => braf
                    // not; braf => brat
                    n->opcode = OP_nop;
                    n->next->opcode = invert(n->next->opcode);
                    r.opts++;
                    break;
                }
            }
            break;

        case OP_braf:
        case OP_brat:
            Opcode inv = invert(n->opcode);

            if (n->opcode == n->target->opcode) {
                // adopt target's target
                n->target->refs--;
                n->target = n->target->target;
                n->target->refs++;
                r.opts++;
            }

            if (n->target->opcode==OP_nop || n->target->opcode==inv) {
                // slide past target nop, allowing it to be deleted
                n->target->refs--;
                n->target = n->target->next;
                n->target->refs++;
                r.opts++;
            }
            break;
        }

        if (!deleted) {
            prev = &n->next;
        }
    }

    return r;
}

enum {
    OPT_debug = 1<<0,
};

static Program parse_and_compile(Slice(Str) args, int flags, Arena *a)
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

    IRlist node = *p.code_stack.data;
    IRasm *halt = new_ir(a, OP_halt);
    node = append(node, (IRlist){
        .head = halt,
        .tail = &halt->next
    });

    OptResult opt = {.ir = node.head};
    if (!(flags & OPT_debug)) {
        for (;;) {
            opt = optimize_pass(opt.ir);
            if (!opt.opts) break;
        }
    }

    Program r = assemble(opt.ir, a);
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

static Str demo(Args args, int flags, Arena *a)
{
    Str r = {};

    if (args.flags) {
        r = concat(a, r, S("//"));
        if (args.flags & FLAG_H) r = concat(a, r, S(" -H"));
        if (args.flags & FLAG_L) r = concat(a, r, S(" -L"));
        r = concat(a, r, S("\n"));
    }

    for (ptrdiff_t i = 0; i < args.paths.len; i++) {
        r = concat(a, r, S("// path: "));
        r = concat(a, r, args.paths.data[i]);
        r = concat(a, r, S("\n"));
    }

    Program program = parse_and_compile(args.expr, flags, a);
    if (program.len) {
        r = print_program(a, r, program);
    } else {
        r = concat(a, r, S("error: invalid expression\n"));
    }

    return r;
}


#if __wasm__
// $ clang --target=wasm32 -std=gnu23 -O -fno-builtin
//         -nostdlib -Wl,--no-entry -o findc.wasm findc.c

static int memcmp(char *a, char *b, size_t n)
{
    while (n--) {
        int r = (unsigned char)*a++ - (unsigned char)*b++;
        if (r) {
            return r;
        }
    }
    return 0;
}

static char mem[1<<21];
Arena arena = {mem, mem+lenof(mem)};

[[clang::export_name("alloc")]]
void *wasm_alloc(ptrdiff_t len)
{
    return new(&arena, len, char);
}

static Str cstr(Arena *a, char *beg, char *end)
{
    return concat(a, span(beg, end), S("\0"));
}

typedef struct {
    int    argc;
    char **argv;
} Argv;

static Argv shellsplit(Str s, Arena *a)
{
    Slice(Str) fields = {};

    char *beg = s.data;
    char *end = s.data + s.len;
    char *cut = beg;
    for (; cut < end; cut++) {
        if (*cut <= ' ') {
            if (cut > beg) {
                *push(a, &fields) = cstr(a, beg, cut);
            }
            beg = cut + 1;
        }
    }
    if (beg < end) {
        *push(a, &fields) = cstr(a, beg, end);
    }

    Argv r = {};
    r.argc = 1 + (int)fields.len;
    r.argv = new(a, 1+fields.len+1, char *);
    r.argv[0] = "findc";
    for (int i = 0; i < r.argc; i++) {
        r.argv[i+1] = fields.data[i].data;
    }
    return r;
}

[[clang::export_name("compile")]]
Str *wasm_compile(char *buf, ptrdiff_t len, bool debug)
{
    Str  cmd  = {buf, len};
    Argv argv = shellsplit(cmd, &arena);
    Args args = splitargs(argv.argc, argv.argv, &arena);
    Str *out  = new(&arena, 1, Str);

    int flags = debug ? OPT_debug : 0;
    *out = demo(args, flags, &arena);

    arena.beg = mem;
    arena.end = mem + lenof(mem);
    return out;
}


#else
#include <stdio.h>

int main(int argc, char **argv)
{
    static char mem[1<<21];
    Arena a = {mem, mem+lenof(mem)};

    Args args = splitargs(argc, argv, &a);
    Str  out  = demo(args, 0, &a);

    fwrite(out.data, 1, to_usize(out.len), stdout);
    fflush(stdout);
    return ferror(stdout);
}

#endif
