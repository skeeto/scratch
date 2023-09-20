// "assembler-interpreter" for a toy assembly language
//
// See enum mnemonic for syntax overview. The ISA has 26 32-bit
// registers (a-z), a 3-way comparison flag, and a call stack.
//
// Porting note: The host must implement os_oom() and os_loadstdin(),
// call run() with some working memory, write the returned buffers to
// stdout/stderr, and exit with the given status.
//
// Ref: https://github.com/youssefeldesouky/Assembler-Interpreter
// This is free and unencumbered software released into the public domain.

#include <stddef.h>
#include <stdint.h>

typedef uint8_t       u8;
typedef int32_t       b32;
typedef int32_t       i32;
typedef uint32_t      u32;
typedef uint64_t      u64;
typedef intptr_t      iptr;
typedef uintptr_t     uptr;
typedef unsigned char byte;
typedef ptrdiff_t     size;

#define sizeof(x)       (size)sizeof(x)
#define alignof(x)      (size)_Alignof(x)
#define countof(a)      (sizeof(a) / sizeof(*(a)))
#define lengthof(s)     (countof(s) - 1)
#define new(a, t, n)    (t *)alloc(a, sizeof(t), alignof(t), n)

static void os_oom(void);

typedef struct {
    byte *mem;
    size  off;
    size  cap;
} arena;

#if __GNUC__
__attribute((malloc, alloc_size(2, 4)))
#endif
static void *alloc(arena *a, size objsize, size align, size count)
{
    size avail = a->cap - a->off;
    size padding = -(uintptr_t)a->mem & (align - 1);
    if (count > (avail - padding)/objsize) {
        os_oom();
    }
    size total = objsize * count;
    byte *p = a->mem + padding;
    a->mem += padding + total;
    for (size i = 0; i < total; i++) {
        p[i] = 0;
    }
    return p;
}

static arena newscratch(arena *a)
{
    arena scratch = {0};
    scratch.cap = (a->cap - a->off) / 2;
    scratch.mem = new(a, byte, scratch.cap);
    return scratch;
}

#define S(s) (s8){(byte *)s, lengthof(s)}
typedef struct {
    u8  *buf;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {0};
    s.buf = beg;
    s.len = end - beg;
    return s;
}

static b32 s8equal(s8 a, s8 b)
{
    if (a.len != b.len) {
        return 0;
    }
    size mismatch = 0;
    for (size i = 0; i < a.len; i++) {
        mismatch += a.buf[i] != b.buf[i];
    }
    return !mismatch;
}

static u64 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
         h ^= s.buf[i];
         h *= 1111111111111111111;
    }
    return h ^ h>>32;
}

typedef struct {
    i32 value;
    b32 ok;
} i32result;

static i32result s8i32(s8 s)
{
    size i = 0;
    b32 neg = 0;
    u32 value = 0;
    i32result r = {0};
    u32 limit = 0x7fffffff;

    switch (*s.buf) {
    case '-':
        i = 1;
        neg = 1;
        limit = 0x80000000;
        break;
    case '+':
        i = 1;
        break;
    }

    for (; i < s.len; i++) {
        i32 d = s.buf[i] - '0';
        if (value > (limit - d)/10) {
            return r;
        }
        value = value*10 + d;
    }

    r.value = neg ? -value : value;
    r.ok = 1;
    return r;
}

static b32 whitespace(u8 c)
{
    return c=='\t' || c=='\r' || c== ' ';
}

static b32 digit(u8 c)
{
    return c>='0' && c<='9';
}

static b32 upper(u8 c)
{
    return c>='A' && c<='Z';
}

static b32 lower(u8 c)
{
    return c>='a' && c<='z';
}

static b32 letter(u8 c)
{
    return upper(c) || lower(c);
}

static b32 identifier(u8 c)
{
    return c=='_' || letter(c) || digit(c);
}

static s8 trim(s8 s)
{
    u8 *p = s.buf;
    u8 *e = p + s.len;
    for (; p<e && whitespace(*p); p++) {}
    s.buf = p;
    s.len = e - p;
    return s;
}

typedef enum {
    tok_error,
    tok_eof,
    tok_newline,
    tok_comma,
    tok_colon,
    tok_integer,
    tok_string,
    tok_register,
    tok_identifier,
} toktype;

typedef struct {
    s8      src;
    s8      token;
    toktype type;
} token;

static token lex(s8 s)
{
    token r = {0};

    for (;;) {
        s = trim(s);
        if (!s.len) {
            r.type = tok_eof;
            return r;
        } else if (*s.buf == ';') {
            u8 *buf = s.buf;
            u8 *end = s.buf + s.len;
            for (buf++; buf<end && *buf!='\n'; buf++) {}
            s = s8span(buf, end);
            continue;
        }
        break;
    }

    u8 *beg = s.buf;
    u8 *end = s.buf + s.len;
    u8 *buf = beg;

    if (*buf == '\n') {
        r.src = s8span(++buf, end);
        r.token = s8span(beg, buf);
        r.type = tok_newline;
        return r;
    }

    if (*buf == ',') {
        r.src = s8span(++buf, end);
        r.token = s8span(beg, buf);
        r.type = tok_comma;
        return r;
    }

    if (*buf == ':') {
        r.src = s8span(++buf, end);
        r.token = s8span(beg, buf);
        r.type = tok_colon;
        return r;
    }

    if (*buf == '\'') {
        for (buf++; buf<end && *buf!='\''; buf++) {}
        if (buf == end) {
            return r;
        }
        r.src = s8span(buf+1, end);
        r.token = s8span(beg+1, buf);
        r.type = tok_string;
        return r;
    }

    if (*buf=='-' || *buf=='+') {
        for (buf++; buf<end && digit(*buf); buf++) {}
        r.src = s8span(buf, end);
        r.token = s8span(beg, buf);
        if (r.token.len < 2) {
            return r;
        }
        r.type = tok_integer;
        return r;
    }

    if (digit(*buf)) {
        for (buf++; buf<end && digit(*buf); buf++) {}
        r.src = s8span(buf, end);
        r.token = s8span(beg, buf);
        r.type = tok_integer;
        return r;
    }

    if (letter(*buf) || *buf=='_') {
        for (buf++; buf<end && identifier(*buf); buf++) {}
        r.src = s8span(buf, end);
        r.token = s8span(beg, buf);
        b32 isregister = r.token.len==1 && lower(*r.token.buf);
        r.type = isregister ? tok_register : tok_identifier;
        return r;
    }

    return r;
}

typedef enum {
    m_null,
    m_inc,   // inc R
    m_dec,   // dec R
    m_ret,   // ret
    m_end,   // end    successful program halt
    m_mov,   // mov R, R|I
    m_add,   // add R, R|I
    m_sub,   // sub R, R|I
    m_mul,   // mul R, R|I
    m_div,   // div R, R|I
    m_cmp,   // cmp [R, I]|[I, R]|[R, R]
    m_jmp,   // jmp L
    m_jne,   // jne L
    m_je,    // je  L
    m_jge,   // jge L
    m_jg,    // jg  L
    m_jle,   // jle L
    m_jl,    // jl  L
    m_call,  // call L
    m_msg,   // msg [string|R, *]   print operands, then a newline
} mnemonic;

static mnemonic tomnemonic(s8 s)
{
    static const s8 names[] = {
        #define E(s) {(u8 *)s, lengthof(s)}
        E("inc"), E("dec"), E("ret"), E("end"),
        E("mov"), E("add"), E("sub"), E("mul"), E("div"),
        E("cmp"),
        E("jmp"), E("jne"), E("je" ), E("jge"), E("jg" ), E("jle"), E("jl" ),
        E("call"),
        E("msg"),
    };
    for (i32 i = 0; i < countof(names); i++) {
        if (s8equal(names[i], s)) {
            return i + 1;
        }
    }
    return 0;
}

typedef struct msg msg;
struct msg {
    msg *next;
    s8   string;
    i32  reg;
};

typedef enum {
    op_abort,
    op_inc, op_dec,
    op_movri, op_movrr,
    op_addri, op_addrr,
    op_subri, op_subrr,
    op_mulri, op_mulrr,
    op_divri, op_divrr,
    op_cmpii, op_cmpir, op_cmpri, op_cmprr,
    op_jmp,
    op_jne, op_je, op_jge, op_jg, op_jle, op_jl,
    op_call, op_ret,
    op_msg,
    op_end
} opcode;

typedef struct insn insn;
struct insn {
    insn   *next;
    msg    *head;
    s8      label;
    size    addr;
    size    lineno;
    opcode  op;
    i32     imm[2];
    u8      reg[2];
};

typedef struct {
    s8    src;
    insn *insn;
} insnresult;

static insnresult parseinsn(mnemonic m, s8 src, arena *a)
{
    insnresult r = {0};
    insn *n = new(a, insn, 1);
    msg **tail = &n->head;

    token t = {0};
    t.src = src;

    i32result ir;
    switch (m) {
    case m_null:
        return r;

    case m_mov:
    case m_add:
    case m_sub:
    case m_mul:
    case m_div:
        n->op = op_movri + 2*(m - m_mov);
        t = lex(t.src);
        switch (t.type) {
        default:
            return r;
        case tok_register:
            n->reg[0] = *t.token.buf;
            break;
        }

        t = lex(t.src);
        if (t.type != tok_comma) {
            return r;
        }

        t = lex(t.src);
        switch (t.type) {
        default:
            return r;
        case tok_integer:
            ir = s8i32(t.token);
            if (!ir.ok) {
                return r;
            }
            n->imm[1] = ir.value;
            break;
        case tok_register:
            n->op++;  // op_XXXrr
            n->reg[1] = *t.token.buf;
            break;
        }
        break;

    case m_cmp:
        t = lex(t.src);
        switch (t.type) {
        default:
            return r;
        case tok_integer:
            n->op = op_cmpii;
            ir = s8i32(t.token);
            if (!ir.ok) {
                return r;
            }
            n->imm[0] = ir.value;
            break;
        case tok_register:
            n->op = op_cmpri;
            n->reg[0] = *t.token.buf;
            break;
        }

        t = lex(t.src);
        if (t.type != tok_comma) {
            return r;
        }

        t = lex(t.src);
        switch (t.type) {
        default:
            return r;
        case tok_integer:
            ir = s8i32(t.token);
            if (!ir.ok) {
                return r;
            }
            n->imm[1] = ir.value;
            break;
        case tok_register:
            n->op++;  // op_XXXrr
            n->reg[1] = *t.token.buf;
            break;
        }
        if (n->op == op_cmpii) {
            return r;  // reject "cmp int, int"
        }
        break;

    case m_jmp:
    case m_jne:
    case m_je:
    case m_jge:
    case m_jg:
    case m_jle:
    case m_jl:
    case m_call:
        t = lex(t.src);
        if (t.type != tok_identifier) {
            return r;
        }
        n->label = t.token;
        n->op = op_jne + (m - m_jne);
        break;

    case m_msg:
        n->op = op_msg;
        for (toktype last = 0;;) {
            t = lex(t.src);
            switch (t.type) {
            case tok_newline:
            case tok_eof:
                if (last != tok_comma) {
                    r.insn = n;
                    r.src = t.src;
                }
                return r;
            case tok_string:
                if (last && last!=tok_comma) {
                    return r;
                }
                *tail = new(a, msg, 1);
                (*tail)->string = t.token;
                tail = &(*tail)->next;
                break;
            case tok_register:
                *tail = new(a, msg, 1);
                (*tail)->reg = *t.token.buf;
                tail = &(*tail)->next;
                break;
            case tok_comma:
                if (!last || last == tok_comma) {
                    return r;
                }
                break;
            default:
                return r;
            }
            last = t.type;
        }

    case m_inc:
    case m_dec:
        n->op = op_inc + (m - m_inc);
        t = lex(t.src);
        switch (t.type) {
        case tok_register:
            n->reg[0] = *t.token.buf;
            break;
        default:
            return r;
        }
        break;

    case m_ret: n->op = op_ret; break;
    case m_end: n->op = op_end; break;
    }

    t = lex(t.src);
    switch (t.type) {
    case tok_eof:
    case tok_newline:
        r.insn = n;
        r.src = t.src;
        // fallthrough
    default:
        return r;
    }
}

typedef struct labels labels;
struct labels {
    labels *child[4];
    s8      label;
    size    addr;
};

static size *upsert(labels **t, s8 label, arena *a)
{
    for (u64 h = s8hash(label); *t; h = h>>62 | h<<2) {
        if (s8equal((*t)->label, label)) {
            return &(*t)->addr;
        }
        t = &(*t)->child[h>>62];
    }
    if (!a) {
        return 0;
    }
    *t = new(a, labels, 1);
    (*t)->label = label;
    return &(*t)->addr;
}

typedef struct {
    insn *head;
    size  lineno;
    b32   ok;
} ast;

static ast parse(s8 src, arena *perm, arena scratch)
{
    ast r = {0};
    r.lineno = 1;

    token t = {0};
    t.src = src;

    size addr = 0;
    labels *table = 0;
    insn **tail = &r.head;

    for (;;) {
        mnemonic m;
        t = lex(t.src);
        switch (t.type) {
        case tok_error:
        case tok_comma:
        case tok_colon:
        case tok_integer:
        case tok_string:
        case tok_register:
            return r;

        case tok_newline:
            r.lineno++;
            break;

        case tok_eof:
            for (insn *n = r.head; n; n = n->next) {
                if (n->label.buf) {
                    size *value = upsert(&table, n->label, 0);
                    if (!value) {
                        r.lineno = n->lineno;
                        return r;
                    }
                    n->addr = *value;
                }
            }
            r.ok = 1;
            return r;

        case tok_identifier:
            m = tomnemonic(t.token);
            if (m) {
                insnresult ir = parseinsn(m, t.src, perm);
                if (!ir.insn) {
                    return r;
                }
                t.src = ir.src;
                ir.insn->lineno = r.lineno++;
                *tail = ir.insn;
                tail = &(*tail)->next;
                addr++;
            } else {
                s8 label = t.token;
                t = lex(t.src);
                if (t.type != tok_colon) {
                    return r;
                }
                t = lex(t.src);
                if (t.type != tok_newline) {
                    return r;
                }
                *upsert(&table, label, &scratch) = addr;
                r.lineno++;
            }
            break;
        }
    }
}

typedef struct {
    u8  op;
    u8  reg[2];
    union {
        i32  imm;
        size addr;
        msg *head;
    } operand;
} word;

// Note: retains references to the AST.
static word *assemble(insn *head, arena *perm)
{
    size len = 0;
    for (insn *n = head; n; n = n->next, len++) {}

    size i = 0;
    word *image = new(perm, word, len+1);
    for (insn *n = head; n; n = n->next, i++) {
        image[i].op = n->op;
        switch (n->op) {
        case op_abort:
        case op_cmpii:
            return 0;

        case op_ret:
        case op_end:
            break;

        case op_inc:
        case op_dec:
            image[i].reg[0] = n->reg[0];
            break;

        case op_movri:
        case op_addri:
        case op_subri:
        case op_mulri:
        case op_divri:
        case op_cmpri:
            image[i].reg[0] = n->reg[0];
            image[i].operand.imm = n->imm[1];
            break;

        case op_movrr:
        case op_addrr:
        case op_subrr:
        case op_mulrr:
        case op_divrr:
        case op_cmprr:
            image[i].reg[0] = n->reg[0];
            image[i].reg[1] = n->reg[1];
            break;

        case op_cmpir:
            image[i].operand.imm = n->imm[0];
            image[i].reg[1] = n->reg[1];
            break;

        case op_jmp:
        case op_jne:
        case op_je:
        case op_jge:
        case op_jg:
        case op_jle:
        case op_jl:
        case op_call:
            image[i].operand.addr = n->addr;
            break;

        case op_msg:
            image[i].operand.head = n->head;
            break;
        }
    }

    return image;
}

typedef struct {
    u8  *buf;
    size len;
    size cap;
    b32  err;
} output;

static s8 tos8(output *o)
{
    s8 s = {0};
    s.buf = o->buf;
    s.len = o->len;
    return s;
}

static void print(output *o, s8 s)
{
    size avail = o->cap - o->len;
    size count = s.len<avail ? s.len : avail;
    u8 *dst = o->buf + o->len;
    for (size i = 0; i < count; i++) {
        dst[i] = s.buf[i];
    }
    o->len += count;
    o->err |= count != s.len;
}

static void printi32(output *o, i32 v)
{
    u8  buf[16];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i32 t = v<0 ? v : -v;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (v < 0) {
        *--beg = '-';
    }
    print(o, s8span(beg, end));
}

typedef struct {
    output out;
    b32    ok;
} result;

// Note: returned buffer is allocated out of scratch.
static result execute(word *image, arena scratch)
{
    result r = {0};

    r.out.cap = 1 << 16;
    r.out.buf = new(&scratch, u8, r.out.cap);

    size len = 0;
    size cap = 1<<10;
    size *stack = new(&scratch, size, cap);

    i32 cmp = 0;
    i32 regs[26] = {0};

    for (size i = 0;; i++) {
        i32 a, b;
        word *w = image + i;
        switch (w->op) {
        case op_abort:
            return r;

        case op_inc:
            regs[w->reg[0]-'a'] += (u32)1;
            break;

        case op_dec:
            regs[w->reg[0]-'a'] -= (u32)1;
            break;

        case op_movri:
            regs[w->reg[0]-'a'] = w->operand.imm;
            break;

        case op_movrr:
            regs[w->reg[0]-'a'] = regs[w->reg[1]-'a'];
            break;

        case op_addri:
            regs[w->reg[0]-'a'] += (u32)w->operand.imm;
            break;

        case op_addrr:
            regs[w->reg[0]-'a'] += (u32)regs[w->reg[1]-'a'];
            break;

        case op_subri:
            regs[w->reg[0]-'a'] -= (u32)w->operand.imm;
            break;

        case op_subrr:
            regs[w->reg[0]-'a'] -= (u32)regs[w->reg[1]-'a'];
            break;

        case op_mulri:
            regs[w->reg[0]-'a'] *= (u32)w->operand.imm;
            break;

        case op_mulrr:
            regs[w->reg[0]-'a'] *= (u32)regs[w->reg[1]-'a'];
            break;

        case op_divri:
            switch (w->operand.imm) {
            case  0:
                return r;  // divide by zero
            case -1:
                regs[w->reg[0]-'a'] = -(u32)regs[w->reg[0]-'a'];
                break;
            default:
                regs[w->reg[0]-'a'] /= w->operand.imm;
            }
            break;

        case op_divrr:
            switch (regs[w->reg[1]-'a']) {
            case  0:
                return r;  // divide by zero
            case -1:
                regs[w->reg[0]-'a'] = -(u32)regs[w->reg[0]-'a'];
                break;
            default:
                regs[w->reg[0]-'a'] /= regs[w->reg[1]-'a'];
            }
            break;

        case op_cmpii:
            return r;

        case op_cmpir:
            a = w->operand.imm;
            b = regs[w->reg[1]-'a'];
            cmp = (a>b) - (a<b);
            break;

        case op_cmpri:
            a = regs[w->reg[0]-'a'];
            b = w->operand.imm;
            cmp = (a>b) - (a<b);
            break;

        case op_cmprr:
            a = regs[w->reg[0]-'a'];
            b = regs[w->reg[1]-'a'];
            cmp = (a>b) - (a<b);
            break;

        case op_jmp:
            i = w->operand.addr - 1;
            break;

        case op_jne:
            if (cmp) i = w->operand.addr - 1;
            break;

        case op_je:
            if (!cmp) i = w->operand.addr - 1;
            break;

        case op_jge:
            if (cmp >= 0) i = w->operand.addr - 1;
            break;

        case op_jg:
            if (cmp > 0) i = w->operand.addr - 1;
            break;

        case op_jle:
            if (cmp <= 0) i = w->operand.addr - 1;
            break;

        case op_jl:
            if (cmp < 0) i = w->operand.addr - 1;
            break;

        case op_call:
            if (len == cap) {
                return r;  // stack overflow
            }
            stack[len++] = i;
            i = w->operand.addr - 1;
            break;

        case op_ret:
            if (!len) {
                return r;  // stack empty
            }
            i = stack[--len];
            break;

        case op_msg:
            for (msg *m = w->operand.head; m; m = m->next) {
                if (m->string.buf) {
                    print(&r.out, m->string);
                } else {
                    printi32(&r.out, regs[m->reg-'a']);
                }
            }
            print(&r.out, S("\n"));
            break;

        case op_end:
            r.ok = 1;
            return r;
        }
    }
}

static s8 os_loadstdin(arena *);

typedef struct {
    s8  out;
    s8  err;
    i32 status;
} status;

static status run(arena heap)
{
    status r = {0};

    arena scratch = newscratch(&heap);

    output stderr = {0};
    stderr.cap = 1<<8;
    stderr.buf = new(&heap, u8, stderr.cap);

    s8 src = os_loadstdin(&heap);

    ast program = parse(src, &heap, scratch);
    if (!program.ok) {
        print(&stderr, S("<stdin>:"));
        printi32(&stderr, (i32)program.lineno);
        print(&stderr, S(": invalid program\n"));
        r.err = tos8(&stderr);
        r.status = 2;
        return r;
    }

    word *image = assemble(program.head, &heap);
    result er = execute(image, scratch);
    if (!er.ok) {
        r.err = S("fatal error: execution aborted\n");
        r.status = 1;
        return r;
    }
    r.out = tos8(&er.out);
    return r;
}


#if FUZZ
// $ afl-gcc-fast -DFUZZ -g3 -fsanitize=undefined asmint.c
// $ afl-fuzz -i Assembler-Interpreter/programs -o results ./a.out
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

static uptr oom[5];
void os_oom(void)
{
    __builtin_longjmp(oom, 1);
}

static s8 os_loadstdin(arena *a)
{
    __builtin_trap();
}

int main(void)
{
    __AFL_INIT();
    s8    src = {0};
    size  cap = 1<<21;
    byte *mem = malloc(cap);
    u8   *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        src.len = __AFL_FUZZ_TESTCASE_LEN;
        src.buf = realloc(src.buf, src.len);
        memcpy(src.buf, buf, src.len);
        if (__builtin_setjmp(oom)) {
            continue;
        }
        arena heap = {0};
        heap.cap = cap;
        heap.mem = mem;
        ast program = parse(src, &heap, newscratch(&heap));
        if (program.ok) {
            assemble(program.head, &heap);
        }
    }
}


#elif _WIN32
// w64devkit $ cc -nostartfiles -o asmint asmint
// MSVC      $ cl asmint.c /link /subsystem:console kernel32.lib
// Usage     $ ./asmint <program.asm

#define W32(r)  __declspec(dllimport) r __stdcall
W32(byte *) VirtualAlloc(byte *, size, u32, u32);
W32(iptr)   GetStdHandle(u32);
W32(b32)    WriteFile(iptr, byte *, u32, u32 *, void *);
W32(b32)    ReadFile(iptr, byte *, u32, u32 *, void *);
W32(b32)    GetFileSizeEx(iptr, u64 *);
W32(void)   ExitProcess(u32);

static void os_oom(void)
{
    uptr stderr = GetStdHandle(-12);
    static u8 msg[] = "out of memory\n";
    u32 dummy;
    WriteFile(stderr, msg, lengthof(msg), &dummy, 0);
    ExitProcess(101);
}

static s8 os_loadstdin(arena *a)
{
    s8 r = {0};

    iptr stdin = GetStdHandle(-10);
    u64 len64;
    GetFileSizeEx(stdin, &len64);
    if (len64 > 0x7fffffff) {
        return r;
    }
    u32 len = (u32)len64;

    r.buf = new(a, u8, len);
    if (ReadFile(stdin, r.buf, len, &len, 0)) {
        r.len = len;
    }
    return r;
}

#ifdef __i386__
__attribute((force_align_arg_pointer))
#endif
void mainCRTStartup(void)
{
    arena heap = {0};
    heap.cap = 1<<24;
    heap.mem = VirtualAlloc(0, heap.cap, 0x3000, 4);

    status r = run(heap);
    u32 dummy;
    uptr stdout = GetStdHandle(-11);
    uptr stderr = GetStdHandle(-12);
    if (r.err.len) {
        WriteFile(stderr, r.err.buf, (u32)r.err.len, &dummy, 0);
    }
    if (r.out.buf) {
        if (!WriteFile(stdout, r.out.buf, (u32)r.out.len, &dummy, 0)) {
            r.status = 100;
        }
    }
    ExitProcess(r.status);
}


#else
// $ cc -o asmint asmint
// $ ./asmint <program.asm
#include <stdio.h>
#include <stdlib.h>

static s8 os_loadstdin(arena *a)
{
    s8 s = {0};
    b32 err = 0;

    err |= fseek(stdin, 0, SEEK_END);
    long len = ftell(stdin);
    err |= len < 1;
    err |= fseek(stdin, 0, SEEK_SET);
    if (err) {
        return s;
    }

    s.buf = new(a, u8, len);
    s.len = fread(s.buf, 1, len, stdin);
    return s;
}

static void os_oom(void)
{
    exit(101);
}

int main(void)
{
    arena heap = {0};
    heap.cap = 1<<24;
    heap.mem = malloc(heap.cap);

    status r = run(heap);
    if (r.err.len) {
        fwrite(r.err.buf, r.err.len, 1, stderr);
    }
    if (r.out.len) {
        fwrite(r.out.buf, r.out.len, 1, stdout);
    }
    fflush(stdout);
    return ferror(stdout) ? 100 : 0;
}

#endif
