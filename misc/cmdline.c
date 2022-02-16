// cmdline: low-level command line utilities for Windows x86 and x64
// This is free and unencumbered software released into the public domain.

#define CMDLINE_ARGV_MAX 16384  // worst case argv length
#define CMDLINE_BUF_MAX  98299  // worst case UTF-8 encoding

// Like GetCommandLineW(), but fetch the static string directly from the
// Process Environment Block (PEB) via the Thread Information Block (TIB).
static unsigned short *
cmdline_fetch(void)
{
    void *cmd = 0;
    #if __amd64
    __asm ("mov %%gs:(0x60), %0\n"
           "mov 0x20(%0), %0\n"
           "mov 0x78(%0), %0\n"
           : "=r"(cmd));
    #elif __i386
    __asm ("mov %%fs:(0x30), %0\n"
           "mov 0x10(%0), %0\n"
           "mov 0x44(%0), %0\n"
           : "=r"(cmd));
    #endif
    return cmd;
}

// Convert a command line to a WTF-8 argv following the same rules as
// CommandLineToArgvW(). Populates argv with pointers into buf (scratch
// space) and returns argc (always > 0).
//
// Expects cmd has no more than 32,767 elements including the null
// terminator, argv has at least CMDLINE_ARGV_MAX elements, and buf has
// least CMDLINE_BUF_MAX elements. These are each the worst possible
// case for a Windows command string, and so no further allocation is
// necessary.
//
// Unlike CommandLineToArgvW, when the command line string is empty
// this function does not invent an artificial argv[0] based on the
// calling module file name.
static int
cmdline_to_argv8(const unsigned short *cmd, char **argv, char *buf)
{
    int argc  = 1;  // worst case: argv[0] is an empty string
    int state = 1;  // begin as though inside a token
    int slash = 0;

    argv[0] = buf;
    while (*cmd) {
        int c = *cmd++;
        if (c>>10 == 0x36 && *cmd>>10 == 0x37) {  // surrogates?
            c = 0x10000 + ((c - 0xd800)<<10) + (*cmd++ - 0xdc00);
        }

        switch (state) {
        case 0: switch (c) {  // outside token
                case 0x09:
                case 0x20: continue;
                case 0x22: argv[argc++] = buf;
                           state = 2;
                           continue;
                case 0x5c: argv[argc++] = buf;
                           slash = 1;
                           state = 3;
                           break;
                default  : argv[argc++] = buf;
                           state = 1;
                } break;
        case 1: switch (c) {  // inside unquoted token
                case 0x09:
                case 0x20: *buf++ = 0;
                           state = 0;
                           continue;
                case 0x22: state = 2;
                           continue;
                case 0x5c: slash = 1;
                           state = 3;
                           break;
                } break;
        case 2: switch (c) {  // inside quoted token
                case 0x22: state = 1;
                           continue;
                case 0x5c: slash = 1;
                           state = 4;
                           break;
                } break;
        case 3:
        case 4: switch (c) {  // backslash sequence
                case 0x22: buf -= (1 + slash) >> 1;
                           if (slash & 1) {
                               state -= 2;
                               break;
                           } // fallthrough
                default  : cmd--;
                           state -= 2;
                           continue;
                case 0x5c: slash++;
                }
        }

        switch (c & 0x1f0880) {
        case 0x00000: *buf++ = 0x00 | ((c >>  0)     ); break;
        case 0x00080: *buf++ = 0xc0 | ((c >>  6)     );
                      *buf++ = 0x80 | ((c >>  0) & 63); break;
        case 0x00800:
        case 0x00880: *buf++ = 0xe0 | ((c >> 12)     );
                      *buf++ = 0x80 | ((c >>  6) & 63);
                      *buf++ = 0x80 | ((c >>  0) & 63); break;
        default     : *buf++ = 0xf0 | ((c >> 18)     );
                      *buf++ = 0x80 | ((c >> 12) & 63);
                      *buf++ = 0x80 | ((c >>  6) & 63);
                      *buf++ = 0x80 | ((c >>  0) & 63);
        }
    }

    *buf = 0;
    argv[argc] = 0;
    return argc;
}


#if TEST
#include <stdio.h>
#include <string.h>

int
main(void)
{
    wchar_t *cmd = cmdline_fetch();
    static char buf[CMDLINE_BUF_MAX];
    static char *argv[CMDLINE_ARGV_MAX];
    int argc = cmdline_to_argv8(cmd, argv, buf);

    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s (%d)", i, argv[i], (int)strlen(argv[i]));
        for (char *c = argv[i]; *c; c++) {
            printf(" %02x", *c&0xff);
        }
        putchar('\n');
    }
}
#endif
