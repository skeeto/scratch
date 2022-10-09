// simple brainfuck interpreter and compiler
//   $ cc -O -o bf bf.c
//   $ ./bf mandelbrot.bf
//   $ ./bf -i mandelbrot.bf
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

struct ins {
    enum {OP_MOVE, OP_ADD, OP_OUT, OP_IN, OP_JZ, OP_JN} op : 16;
    short arg;
};

// Interpret the given brainfuck program. Returns 0 for invalid programs.
static int interp(char *program, int len)
{
    unsigned char mem[30000] = {0};
    int c, dp = 0, ip = 0;
    while (ip < len) {
        switch (program[ip++]) {
        case '>':
            dp = (dp + 1) % 30000;
            break;
        case '<':
            dp = (dp + 29999) % 30000;
            break;
        case '+':
            mem[dp]++;
            break;
        case '-':
            mem[dp]--;
            break;
        case '.':
            putchar(mem[dp]);
            break;
        case ',':
            fflush(stdout);
            c = getchar();
            mem[dp] = c==EOF ? 0 : c;
            break;
        case '[':
            if (!mem[dp]) {
                int depth = 1;
                while (depth && ip<len) {
                    switch (program[ip++]) {
                    case '[': depth++; break;
                    case ']': depth--; break;
                    }
                }
                if (depth) {
                    return 0;  // invalid program
                }
                ip--;
            }
            break;
        case ']':
            if (mem[dp]) {
                int depth = 1;
                for (ip--; depth && ip>=0;) {
                    switch (program[--ip]) {
                    case ']': depth++; break;
                    case '[': depth--; break;
                    }
                }
                if (depth) {
                    return 0;  // invalid program
                }
                ip++;
            }
            break;
        }
    }
    return 1;
}

// Compile a program into bytecode. Returns the number of instructions,
// or -1 for invalid programs or out of memory.
static int compile(struct ins *bc, int nbc, char *program, int len)
{
    int depth, target, bp = 0, ip = 0;
    while (ip < len) {
        int c = program[ip++];
        switch (c) {
        case '>':
        case '<':
            if (bp && bc[bp-1].op==OP_MOVE) {
                // NOTE: may be truncated on assignment to arg
                bc[bp-1].arg += c=='>' ? +1L : -1L;  // coalesce
            } else {
                if (bp >= nbc) {
                    return -1;
                }
                bc[bp].op = OP_MOVE;
                bc[bp++].arg = c=='>' ? +1 : -1;
            }
            break;
        case '+':
        case '-':
            if (bp && bc[bp-1].op==OP_ADD) {
                // NOTE: may be truncated on assignment to arg
                bc[bp-1].arg += c=='+' ? +1L : -1L;  // coalesce
            } else {
                if (bp >= nbc) {
                    return -1;
                }
                bc[bp].op = OP_ADD;
                bc[bp++].arg = c=='+' ? +1 : -1;
            }
            break;
        case '.':
            if (bp >= nbc) {
                return -1;
            }
            bc[bp].op = OP_OUT;
            bc[bp++].arg = 0;
            break;
        case ',':
            if (bp >= nbc) {
                return -1;
            }
            bc[bp].op = OP_IN;
            bc[bp++].arg = 0;
            break;
        case '[':
            if (bp >= nbc) {
                return -1;
            }
            bc[bp++].op = OP_JZ;
            break;
        case ']':
            if (bp >= nbc) {
                return -1;
            }
            bc[bp++].op = OP_JN;
            break;
        }
    }

    // Resolve all jumps
    for (int i = 0; i < bp; i++) {
        switch ((int)bc[i].op) {
        case OP_JZ:
            depth = 1;
            target = i + 1;
            while (depth && target<bp) {
                switch ((int)bc[target++].op) {
                case OP_JZ: depth++; break;
                case OP_JN: depth--; break;
                }
            }
            if (depth) {
                return -1;  // invalid program
            }
            bc[i].arg = target;
            break;
        case OP_JN:
            depth = 1;
            target = i;
            while (depth && target>=0) {
                switch ((int)bc[--target].op) {
                case OP_JN: depth++; break;
                case OP_JZ: depth--; break;
                }
            }
            if (depth) {
                return -1;  // invalid program
            }
            bc[i].arg = target + 1;
            break;
        }
    }
    return bp;
}

// Run a compiled bytecode program.
static void run(struct ins *bc, int nbc)
{
    unsigned char mem[30000] = {0};
    int c, dp = 0, ip = 0;
    while (ip < nbc) {
        int arg = bc[ip].arg;
        switch (bc[ip++].op) {
        case OP_MOVE: dp = (dp + arg + 30000L) % 30000; break;
        case OP_ADD : mem[dp] += arg; break;
        case OP_JZ  : ip = mem[dp] ? ip : arg; break;
        case OP_JN  : ip = mem[dp] ? arg : ip; break;
        case OP_OUT : putchar(mem[dp]); break;
        case OP_IN  : fflush(stdout);
                      c = getchar();
                      mem[dp] = c==EOF ? 0 : c;
        }
    }
}

int main(int argc, char **argv)
{
    int slow = 0;
    static struct ins bc[1<<16];
    static char program[1<<20];

    if (argc < 2) {
        static const char usage[] =
        "usage: bf [-i] [PROGRAMS...]\n"
        "  -i    interpret (slowly) rather than byte compile\n";
        fwrite(usage, sizeof(usage)-1, 1, stderr);
        return 1;
    }

    if (argc>=2 && argv[1][0]=='-' && argv[1][1] == 'i') {
        slow = 1;
    }

    for (int i = 1+slow; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            return 1;
        }
        int len = fread(program, 1, sizeof(program), f);
        if (len == (int)sizeof(program) || ferror(f)) {
            return 1;  // too large or read error
        }
        fclose(f);

        if (slow) {
            if (!interp(program, len)) {
                return 1;  // invalid program
            }
        } else {
            int nbc = compile(bc, sizeof(bc)/sizeof(*bc), program, len);
            if (nbc < 0) {
                return 1;  // too large or invalid program
            }
            run(bc, nbc);
        }
    }
    return 0;
}
