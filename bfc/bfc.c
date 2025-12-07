// Compile brainfuck programs to Windows x64 COFF objects
//
// w64devkit:
//   $ cc -nostartfiles -O -o bfc.exe bfc.c
//   $ cc -c -O runtime.c
//   $ ./bfc hello.bf
//   $ ld -o hello.exe hello.o runtime.o -lkernel32
//   $ ./hello.exe
//   Hello World!
//
// Or link with MSVC:
//   $ link /subsystem:console hello.o runtime.o kernel32.lib
//
// The program compiles to a function named bf_entry, and it calls two
// functions, bf_putchar and bf_getchar, to perform input/output.
//
//   void bf_entry(unsigned char *, void *ctx);
//   void bf_putchar(unsigned char *, void *ctx);
//   void bf_getchar(unsigned char *, void *ctx);
//
// The entry point expects a pointer to a zeroed, 30,000-element array.
// The context pointer is passed unmodified to the two I/O functions, so
// global variables are unnecessary. runtime.c has a console subsystem
// entry point and implements I/O with {Read,Write}File. Otherwise you
// could implement these in whatever way is useful and link brainfuck
// programs into your own programs.
//
// This is not an optimizing compiler. I wrote it mainly to explore
// creating and linking COFF files. It handles long symbols and large
// numbers of relocations.

typedef unsigned char           u8;
typedef unsigned short          u16;
typedef int                     b32;
typedef int                     i32;
typedef typeof((u8 *)0-(u8 *)0) iz;
typedef typeof(sizeof(0))       uz;

#define mcopy(d, s, n)  __builtin_memcpy(d, s, touz(n))
#define mzero(d, n)     __builtin_memset(d, 0, touz(n))
#define trap()          __builtin_trap()

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define newend(a, n, t) (t *)alloc_end(a, n, sizeof(t), _Alignof(t))
#define affirm(c)       while (!(c)) trap()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define S(s)            (Str){(u8 *)s, sizeof(s)-1}

static uz touz(iz x)
{
    affirm(x >= 0);
    return (uz)x;
}

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static u8 *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return mzero(r, count*size);
}

static u8 *alloc_end(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)a->end & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    return mzero(a->end -= pad + count*size, count*size);
}

typedef struct {
    u8 *data;
    iz  len;
} Str;

typedef struct {
    u8 *buf;
    iz  len;
    iz  cap;
} Buf;

static Str to_str(Buf b)
{
    return (Str){b.buf, b.len};
}

static Buf grow(Arena *a, Buf b)
{
    if (b.buf+b.cap != a->beg) {
        u8 *buf = new(a, b.cap, u8);
        mcopy(buf, b.buf, b.len);
        b.buf = buf;
    }
    iz extend = b.cap ? b.cap : 1<<12;
    new(a, extend, u8);
    b.cap += extend;
    return b;
}

static Buf append(Arena *a, Buf b, Str s)
{
    while (b.cap-b.len < s.len) {
        b = grow(a, b);
    }
    mcopy(b.buf+b.len, s.data, s.len);
    b.len += s.len;
    return b;
}

static void store_u16(u8 *d, u16 x)
{
    d[0] = (u8)(x >>  0);
    d[1] = (u8)(x >>  8);
}

static void store_i32(u8 *d, i32 x)
{
    d[0] = (u8)(x >>  0);
    d[1] = (u8)(x >>  8);
    d[2] = (u8)(x >> 16);
    d[3] = (u8)(x >> 24);
}

static Buf append_u8(Arena *a, Buf b, u8 x)
{
    return append(a, b, (Str){&x, 1});
}

static Buf append_u16(Arena *a, Buf b, u16 x)
{
    u8 buf[2];
    store_u16(buf, x);
    return append(a, b, (Str){buf, lenof(buf)});
}

static Buf append_i32(Arena *a, Buf b, i32 x)
{
    u8 buf[4];
    store_i32(buf, x);
    return append(a, b, (Str){buf, lenof(buf)});
}

typedef struct Node Node;
struct Node {
    Node *next;
    iz    value;
};

typedef struct {
    Node *head;
    Node *free;
} List;

static void push(List *l, iz x, Arena *a)
{
    Node *n = l->free;
    if (n) {
        l->free = n->next;
    } else {
        n = newend(a, 1, Node);
    }
    n->value = x;
    n->next = l->head;
    l->head = n;
}

static iz pop(List *l)
{
    Node *n = l->head;
    l->head = n->next;
    n->next = l->free;
    l->free = n;
    return n->value;
}

typedef struct Reloc Reloc;
struct Reloc {
    Reloc *next;
    i32    offset;
    i32    symbol;
};

static Buf append_symbol(Arena *a, Buf *strtab, Buf b, Str name, u16 section)
{
    // In this program all symbols are external functions.
    if (name.len > 8) {
        i32 off = (i32)strtab->len;
        *strtab = append(a, *strtab, name);
        *strtab = append_u8(a, *strtab, 0);
        b = append_i32(a, b, 0);   // Name (low)
        b = append_i32(a, b, off); // Name (high)
    } else {
        Str pad = (Str){(u8[8]){}, 8-name.len};
        b = append(a, b, name);  // Name
        b = append(a, b, pad);   // "
    }
    b = append_i32(a, b, 0);        // Value
    b = append_u16(a, b, section);  // SectionNumber
    b = append_u16(a, b, 0x20);     // Type (function)
    b = append_u8(a, b, 2);         // StorageClass
    b = append_u8(a, b, 0);         // NumberOfAuxSymbols
    return b;
}

// Compile the given program to a COFF object.
static Str compile(Arena *a, Str src)
{
    enum {
        IMAGE_SCN_CNT_CODE        = 0x00000020,
        IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    };
    i32 Characteristics = IMAGE_SCN_CNT_CODE;

    Buf r = {};

    // COFF header
    r = append_u16(a, r, 0x8664);  // Machine
    r = append_u16(a, r, 1);       // NumberOfSections
    r = append_i32(a, r, 0);       // TimeDateStamp
    r = append_i32(a, r, 60);      // PointerToSymbolTable
    r = append_i32(a, r, 3);       // NumberOfSymbols
    r = append_u16(a, r, 0);       // SizeOfOptionalHeader
    r = append_u16(a, r, 0);       // Characteristics

    // Section table
    r = append(a, r, S(".text\0\0\0"));  // Name
    iz pVirtualSize = r.len;
    r = append_i32(a, r, 0);             // VirtualSize
    r = append_i32(a, r, 0);             // VirtualAddress
    iz pSizeOfRawData = r.len;
    r = append_i32(a, r, 0);             // SizeOfRawData
    iz pPointerToRawData = r.len;
    r = append_i32(a, r, 0);             // PointerToRawData
    iz pPointerToRelocations = r.len;
    r = append_i32(a, r, 0);             // PointerToRelocations
    r = append_i32(a, r, 0);             // PointerToLinenumbers
    iz pNumberOfRelocations = r.len;
    r = append_u16(a, r, 0);             // NumberOfRelocations
    r = append_u16(a, r, 0);             // NumberOfLinenumbers
    iz pCharacteristics = r.len;
    r = append_i32(a, r, 0);             // Characteristics

    // Symbol table
    enum {
        SYM_bf_entry   = 0,
        SYM_bf_putchar = 1,
        SYM_bf_getchar = 2,
    };
    affirm(r.len == 60);
    Buf strtab = append_i32(a, (Buf){}, 0);
    r = append_symbol(a, &strtab, r, S("bf_entry"), 1);
    r = append_symbol(a, &strtab, r, S("bf_putchar"),  0);
    r = append_symbol(a, &strtab, r, S("bf_getchar"),  0);

    // String table
    store_i32(strtab.buf, (i32)strtab.len);
    r = append(a, r, to_str(strtab));

    List    stack   = {};
    Reloc  *head    = 0;
    Reloc **tail    = &head;
    iz      nrelocs = 0;

    // bf_entry prologue
    //   rsi = array pointer
    //   rdi = context pointer
    iz PointerToRawData = r.len;
    store_i32(r.buf+pPointerToRawData, (i32)PointerToRawData);
    r = append(a, r, S(
        "\x48\x83\xec\x38"      // sub $56, %rsp
        "\x48\x89\x74\x24\x20"  // mov %rsi, 32(%rsp)  # save
        "\x48\x89\x7c\x24\x28"  // mov %rdi, 40(%rsp)  # save
        "\x48\x89\xce"          // mov %rcx, %rsi
        "\x48\x89\xd7"          // mov %rdx, %rdi
    ));

    for (iz i = 0; i < src.len; i++) {
        Reloc *reloc = 0;
        switch (src.data[i]) {
        case '>':
            r = append(a, r, S(
                "\x48\xff\xc6"  // inc %rsi
            ));
            break;
        case '<':
            r = append(a, r, S(
                "\x48\xff\xce"  // dec %rsi
            ));
            break;
        case '+':
            r = append(a, r, S(
                "\xfe\x06"  // incb (%rsi)
            ));
            break;
        case '-':
            r = append(a, r, S(
                "\xfe\x0e"  // decb (%rsi)
            ));
            break;
        case '.':
            r = append(a, r, S(
                "\x48\x89\xf1"          // mov  %rsi, %rcx
                "\x48\x89\xfa"          // mov  %rdi, %rdx
                "\xe8\x00\x00\x00\x00"  // call bf_putchar
            ));
            reloc = newend(a, 1, Reloc);
            reloc->offset = (i32)(r.len - 4 - PointerToRawData);
            reloc->symbol = SYM_bf_putchar;
            *tail = reloc;
            tail = &reloc->next;
            nrelocs++;
            break;
        case ',':
            r = append(a, r, S(
                "\x48\x89\xf1"          // mov  %rsi, %rcx
                "\x48\x89\xfa"          // mov  %rdi, %rdx
                "\xe8\x00\x00\x00\x00"  // call bf_getchar
            ));
            reloc = newend(a, 1, Reloc);
            reloc->offset = (i32)(r.len - 4 - PointerToRawData);
            reloc->symbol = SYM_bf_getchar;
            *tail = reloc;
            tail = &reloc->next;
            nrelocs++;
            break;
        case '[':
            push(&stack, r.len, a);
            r = append(a, r, S(
                "\x80\x3e\x00"              // cmpb $0, (%rsi)
                "\x0f\x84\x00\x00\x00\x00"  // je   <fore>
            ));
            break;
        case ']':
            if (!stack.head) return (Str){};
            r = append(a, r, S(
                "\xe9\x00\x00\x00\x00"  // jmp <back>
            ));
            iz match = pop(&stack);
            iz jz    = match + 3;
            store_i32(r.buf+jz+2,    (i32)(r.len - (jz + 6)));
            store_i32(r.buf+r.len-4, (i32)(match - r.len));
            break;
        }
    }

    // bf_entry epilogue
    r = append(a, r, S(
        "\x48\x8b\x7c\x24\x28"  // mov 40(%rsp), %rdi  # restore
        "\x48\x8b\x74\x24\x20"  // mov 32(%rsp), %rsi  # restore
        "\x48\x83\xc4\x38"      // add $56, %rsp
        "\xc3"                  // ret
    ));

    iz SizeOfRawData = r.len - PointerToRawData;
    store_i32(r.buf+pVirtualSize, (i32)SizeOfRawData);
    store_i32(r.buf+pSizeOfRawData, (i32)SizeOfRawData);

    store_i32(r.buf+pPointerToRelocations, (i32)r.len);
    if (nrelocs < 0xffff) {
        store_u16(r.buf+pNumberOfRelocations, (u16)nrelocs);
    } else {
        Characteristics |= IMAGE_SCN_CNT_CODE;
        store_u16(r.buf+pNumberOfRelocations, 0xffff);
        Reloc *reloc = newend(a, 1, Reloc);
        reloc->next   = head;
        reloc->offset = (i32)++nrelocs;
        head = reloc;
    }
    store_i32(r.buf+pCharacteristics, Characteristics);

    for (Reloc *reloc = head; reloc; reloc = reloc->next) {
        enum { IMAGE_REL_AMD64_REL32 = 0x004 };
        r = append_i32(a, r, reloc->offset);          // VirtualAddress
        r = append_i32(a, r, reloc->symbol);          // SymbolTableIndex
        r = append_u16(a, r, IMAGE_REL_AMD64_REL32);  // Type
    }

    return stack.head ? (Str){} : to_str(r);
}


#if _WIN32

typedef u16 char16_t;
typedef char16_t c16;

#define U(s)    (Ustr){s, lenof(s)-1}

enum {
    FILE_ATTRIBUTE_NORMAL = 0x80,

    FILE_SHARE_ALL = 7,

    GENERIC_READ  = (i32)0x80000000,
    GENERIC_WRITE = (i32)0x40000000,

    INVALID_HANDLE_VALUE = -1,

    MEM_COMMIT  = 0x1000,
    MEM_RESERVE = 0x2000,

    CREATE_ALWAYS = 2,
    OPEN_EXISTING = 3,

    PAGE_READWRITE = 4,

    STD_OUTPUT_HANDLE = -11,
    STD_ERROR_HANDLE  = -12,
};

#define W32  [[gnu::stdcall, gnu::dllimport]]
W32 b32     CloseHandle(uz);
W32 c16   **CommandLineToArgvW(c16 *, i32 *);
W32 uz      CreateFileW(c16 *, i32, i32, uz, i32, i32, i32);
W32 void    ExitProcess(i32);
W32 c16    *GetCommandLineW();
W32 b32     ReadFile(uz, u8 *, i32, i32 *, uz);
W32 b32     WriteFile(uz, u8 *, i32, i32 *, uz);

typedef struct {
    c16 *data;
    i32  len;
} Ustr;

static Ustr import(c16 *s)
{
    Ustr r = {};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static Ustr clone(Arena *a, Ustr s)
{
    Ustr r = s;
    r.data = new(a, s.len, c16);
    mcopy(r.data, s.data, 2*r.len);
    return r;
}

static Ustr concat(Arena *a, Ustr head, Ustr tail)
{
    if ((u8 *)(head.data+head.len) != a->beg) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static Ustr drop_extension(Ustr s)
{
    iz i = s.len;
    for (; i>0 && s.data[i-1]!='.'; i--) {}
    if (i > 0) {
        s.len = i - 1;
    }
    return s;
}

static i32 trunc32(iz x)
{
    i32 max = 0x7fffffff;
    return x>max ? max : (i32)x;
}

static Str slurp(Arena *a, uz h)
{
    Str r   = {a->beg, 0};
    iz  cap = a->end - a->beg;
    while (r.len < cap) {
        i32 avail = trunc32(cap - r.len);
        i32 count;
        ReadFile(h, r.data+r.len, avail, &count, 0);
        if (count < 1) break;
        r.len += count;
    }
    a->beg += r.len;
    return r;
}

static i32 run(u8 *mem, iz len)
{
    c16  *cmd  = GetCommandLineW();
    i32   argc = 0;
    c16 **argv = CommandLineToArgvW(cmd, &argc);

    for (i32 i = 1; i < argc; i++) {
        Arena a = {mem, mem+len};

        uz hi = CreateFileW(
            argv[i],
            GENERIC_READ,
            FILE_SHARE_ALL,
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0
        );
        if (hi == (uz)-1) {
            return 1;  // TODO: error message
        }
        Str program = slurp(&a, hi);
        CloseHandle(hi);

        Ustr path = import(argv[i]);
        path = drop_extension(path);
        path = concat(&a, path, U(u".o\0"));

        uz ho = CreateFileW(
            path.data,
            GENERIC_WRITE,
            FILE_SHARE_ALL,
            0,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0
        );
        if (ho == (uz)-1) {
            return 2;  // TODO: error message
        }

        Str object = compile(&a, program);
        WriteFile(ho, object.data, (i32)object.len, 0, 0);
        CloseHandle(ho);
    }

    return 0;
}

void __stdcall mainCRTStartup()
{
    static u8 mem[1<<26];
    i32 r = run(mem, lenof(mem));
    ExitProcess(r);
}


#else  // POSIX
#include <fcntl.h>
#include <unistd.h>

static Str import(u8 *s)
{
    Str r = {(u8 *)s, 0};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, s.len, u8);
    mcopy(r.data, s.data, r.len);
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

static Str drop_extension(Str s)
{
    iz i = s.len;
    for (; i>0 && s.data[i-1]!='.'; i--) {}
    if (i > 0) {
        s.len = i - 1;
    }
    return s;
}

static Str terminate(Arena *a, Str s)
{
    s = concat(a, s, S("\0"));
    s.len--;
    return s;
}

static b32 print(int fd, Str s)
{
    return write(fd, s.data, touz(s.len)) == s.len;
}

static Str slurp(Arena *a, int fd)
{
    Str r   = {a->beg, 0};
    iz  cap = a->end - a->beg;
    while (r.len < cap) {
        i32 n = read(fd, r.data+r.len, touz(cap-r.len));
        if (n < 1) break;
        r.len += n;
    }
    a->beg += r.len;
    return r;
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        static u8 mem[1<<26];
        Arena a = {mem, mem+lenof(mem)};

        Str arg = import(argv[i]);

        int fdi = open(arg.data, O_RDONLY);
        if (fdi == -1) {
            print(2, S("bfc: could not open for reading: "));
            print(2, import(argv[i]));
            print(2, S("\n"));
            return 1;
        }
        Str program = slurp(&a, fdi);
        close(fdi);

        Str path = drop_extension(arg);
        path = concat(&a, path, S(".o"));
        path = terminate(&a, path);
            print(2, S("bfc: "));
            print(2, path);
            print(2, S("\n"));

        int fdo = open(path.data, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fdo == -1) {
            print(2, S("bfc: could not open for writing: "));
            print(2, path);
            print(2, S("\n"));
            return 2;
        }
        Str object = compile(&a, program);
        print(fdo, object);
        close(fdo);
    }
}
#endif
