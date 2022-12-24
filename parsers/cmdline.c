// cmdline: low-level command line utilities for Windows x86 and x64
// This is free and unencumbered software released into the public domain.

#define CMDLINE_CMD_MAX  32767  // max command line length on Windows
#define CMDLINE_ARGV_MAX (16384+(98298+(int)sizeof(char*))/(int)sizeof(char*))

// Like GetCommandLineW, but fetch the static string directly from the
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

// Convert an ill-formed-UTF-16 command line to a WTF-8 argv following
// field splitting semantics identical to CommandLineToArgvW, including
// undocumented behavior. Populates argv with pointers into itself and
// returns argc, which is always positive.
//
// Expects that cmd has no more than 32,767 (CMDLINE_CMD_MAX) elements
// including the null terminator, and argv has at least CMDLINE_ARGV_MAX
// elements. This covers the worst possible cases for a Windows command
// string, so no further allocation is ever necessary.
//
// Unlike CommandLineToArgvW, when the command line string is zero
// length this function does not invent an artificial argv[0] based on
// the calling module file name. To implement this behavior yourself,
// test if cmd[0] is zero and then act accordingly.
//
// This implementation follows CommandLineToArgvW's undocumented quoting
// behavior and its special first argument handling.
//
// If the input is UTF-16, then the output is UTF-8.
static int
cmdline_to_argv8(const unsigned short *cmd, char **argv)
{
    int argc  = 1;  // worst case: argv[0] is an empty string
    int state = 6;  // special argv[0] state
    int slash = 0;
    char *buf = (char *)(argv + 16384);  // second half: byte buffer

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
                case 0x22: state = 5;
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
                default  : cmd -= 1 + (c >= 0x10000);
                           state -= 2;
                           continue;
                case 0x5c: slash++;
                } break;
        case 5: switch (c) {  // quoted token exit
                default  : cmd -= 1 + (c >= 0x10000);
                           state = 1;
                           continue;
                case 0x22: state = 1;
                } break;
        case 6: switch (c) {  // begin argv[0]
                case 0x09:
                case 0x20: *buf++ = 0;
                           state = 0;
                           continue;
                case 0x22: state = 8;
                           continue;
                default  : state = 7;
                } break;
        case 7: switch (c) {  // unquoted argv[0]
                case 0x09:
                case 0x20: *buf++ = 0;
                           state = 0;
                           continue;
                } break;
        case 8: switch (c) {  // quoted argv[0]
                case 0x22: *buf++ = 0;
                           state = 0;
                           continue;
                } break;
        }

        // WTF-8/UTF-8 encoding
        switch ((c >= 0x80) + (c >= 0x800) + (c >= 0x10000)) {
        case 0: *buf++ = 0x00 | ((c >>  0)     ); break;
        case 1: *buf++ = 0xc0 | ((c >>  6)     );
                *buf++ = 0x80 | ((c >>  0) & 63); break;
        case 2: *buf++ = 0xe0 | ((c >> 12)     );
                *buf++ = 0x80 | ((c >>  6) & 63);
                *buf++ = 0x80 | ((c >>  0) & 63); break;
        case 3: *buf++ = 0xf0 | ((c >> 18)     );
                *buf++ = 0x80 | ((c >> 12) & 63);
                *buf++ = 0x80 | ((c >>  6) & 63);
                *buf++ = 0x80 | ((c >>  0) & 63); break;
        }
    }

    *buf = 0;
    argv[argc] = 0;
    return argc;
}

// Convert a WTF-8 argv into a Windows command line string. Returns the
// length not including the null terminator, or zero if the command line
// does not fit. The output buffer length must be 1 < len <= 32,767. It
// computes an optimally-short encoding, and the smallest output length
// is 1.
//
// This function is essentially the inverse of CommandLineToArgvW.
//
// If the input is UTF-8, then the output is UTF-16.
static int
cmdline_from_argv8(unsigned short *cmd, int len, char **argv)
{
    unsigned short *p = cmd;
    unsigned short *e = cmd + len;

    for (char **arg = argv; *arg; arg++) {
        if (*arg != *argv) {
            *p++ = 0x20;
            if (p == e) return 0;
        } else if (!**arg) {
            continue;  // empty argv[0] special case
        }

        int quoted = !*arg;
        for (char *s = *arg; *s && !quoted; s++) {
            quoted |= *s == 0x09;
            quoted |= *s == 0x20;
        }
        if (quoted) {
            *p++ = 0x22;
            if (p == e) return 0;
        }

        int state = 0;
        int slash = 0;
        for (char *s = *arg; *s; s++) {
            switch (state) {
            case 0: switch (s[0]) {  // passthrough
                    case 0x22: *p++ = 0x5c;
                               if (p == e) return 0;
                               break;
                    case 0x5c: slash = 1;
                               state = 1;
                    } break;
            case 1: switch (s[0]) {  // backslash sequence
                    case 0x22: for (int i = 0; i < slash+1; i++) {
                                   *p++ = 0x5c;
                                   if (p == e) return 0;
                               } // fallthrough
                    default  : state = 0;
                               break;
                    case 0x5c: slash++;
                    } break;
            }

            int c;
            switch (s[0]&0xf0) {  // ill-formed UTF-16 encoding
            default  : *p++ = s[0];
                       break;
            case 0xc0:
            case 0xd0: *p++ = (s[0]&0x1f) << 6 |
                              (s[1]&0x3f) << 0;
                       s += 1;
                       break;
            case 0xe0: *p++ = (s[0]&0x0f) << 12 |
                              (s[1]&0x3f) <<  6 |
                              (s[2]&0x3f) <<  0;
                       s += 2;
                       break;
            case 0xf0: c    = (s[0]&0x0f) << 18 |
                              (s[1]&0x3f) << 12 |
                              (s[2]&0x3f) <<  6 |
                              (s[3]&0x3f) <<  0;
                       c -= 0x10000;  // surrogates
                       *p++ = 0xd800 | (c >>  10);
                       if (p == e) return 0;
                       *p++ = 0xdc00 | (c & 1023);
                       s += 3;
            }
            if (p == e) return 0;
        }

        if (quoted) {
            *p++ = 0x22;
            if (p == e) return 0;
        }
    }

    if (p == cmd) {
        *p++ = 0x20;
    }
    *p = 0;
    return p - cmd;
}


#if defined(TEST)
// These tests can be run on non-Windows systems.
#include <stdio.h>
#include <string.h>

int
main(void)
{
    int fails = 0;
    char *argv[CMDLINE_ARGV_MAX];
    unsigned short cmd[CMDLINE_CMD_MAX];

    // Test basic argument splitting
    static const struct {
        char cmd[16];
        char argv[3][8];
    } tests[] = {
        {"\"abc\" d e",           {"abc",      "d",        "e"  }},
        {"a\\\\\\b d\"e f\"g h",  {"a\\\\\\b", "de fg",    "h"  }},
        {"a b\\\\\\\"c d",        {"a",        "b\\\"c",   "d"  }},
        {"a b\\\\\\\\\"c d\" e ", {"a",        "b\\\\c d", "e", }},
        {" a b",                  {"",         "a",        "b"  }},
        {"a \"b\"\"c\" d\" e",    {"a",        "b\"c d",   "e"  }},
        {"a \"\"\"b c\"\"\" ",    {"a",        "\"b",      "c\""}},
        {"a \"b\"\"\"c\" d",      {"a",        "b\"c",     "d"  }},
        {"a b\"\"\"\"\"c d",      {"a",        "b\"c",     "d"  }},
        {"a b\"\"\"\"\"\"c d",    {"a",        "b\"\"c",   "d"  }},
        {"\"\"a b\" c",           {"",         "a",        "b c"}},
        {"\\\\\\\" \\\\\\\" c",   {"\\\\\\\"", "\\\"",     "c"  }},
    };
    for (int i = 0; i < (int)(sizeof(tests)/sizeof(*tests)); i++) {
        unsigned short cmd[sizeof(tests[i].cmd)];
        for (int j = 0; j < (int)sizeof(tests[i].cmd); j++) {
            cmd[j] = tests[i].cmd[j];
        }

        int argc = cmdline_to_argv8(cmd, argv);
        if (argc != 3) {
            printf("FAIL: [%d] argc, want 3, got %d\n", i, argc);
            fails++;
        }
        for (int j = 0; j < 3; j++) {
            const char *want = tests[i].argv[j];
            if (!argv[j] || strcmp(want, argv[j])) {
                printf("FAIL: [%d] argv[%d], want %s, got %s\n",
                       i, j, want, argv[j] ? argv[j] : "(null)");
                fails++;
            }
        }
    }

    static const struct {
        short argvi;  // position to test (argv[0] is special)
        short skip;   // encoding directions to be skipped (bitflag)
        unsigned short cmd[6];
        char wtf8[8];
    } tests16[] = {
        {0, 1, {0xd800},         {0xed, 0xa0, 0x80}},
        {0, 0, {0xdcff},         {0xed, 0xb3, 0xbf}},
        {0, 0, {0xdbc4, 0xde34}, {0xf4, 0x81, 0x88, 0xb4}},
        {0, 0, {0xde34, 0xdbc4}, {0xed, 0xb8, 0xb4, 0xed, 0xaf, 0x84}},
        {0, 0, {0x03c0},         {0xcf, 0x80}},
        {0, 0, {0x005c, 0x0040}, {0x5c, 0x40}},
        // BMP following meta characters
        {0, 0, {0x005c, 0x03c0},                 {0x5c, 0xcf, 0x80}},
        {1, 0, {0x0020, 0x005c, 0x03c0},         {0x5c, 0xcf, 0x80}},
        {1, 2, {0x0020, 0x0022, 0x0022, 0x03c0}, {0xcf, 0x80}},
        // Surrogates (of U+2070E) following meta characters
        {0, 0, {0x005c, 0xd841, 0xdf0e},
               {0x5c, 0xf0, 0xa0, 0x9c, 0x8e}},
        {1, 0, {0x0020, 0x005c, 0xd841, 0xdf0e},
               {0x5c, 0xf0, 0xa0, 0x9c, 0x8e}},
        {1, 2, {0x0020, 0x0022, 0x0022, 0xd841, 0xdf0e},
               {0xf0, 0xa0, 0x9c, 0x8e}},
    };

    // Test ill-formed UTF-16 to WTF-8
    for (int i = 0; i < (int)(sizeof(tests16)/sizeof(*tests16)); i++) {
        if (tests16[i].skip&1) continue;
        cmdline_to_argv8(tests16[i].cmd, argv);
        if (strcmp(argv[tests16[i].argvi], tests16[i].wtf8)) {
            printf("FAIL: [%d] ill-formed UTF-16 to WTF-8\n", i);
            fails++;
        }
    }

    // Test WTF-8 to ill-formed UTF-16
    for (int i = 0; i < (int)(sizeof(tests16)/sizeof(*tests16)); i++) {
        if (tests16[i].skip&2) continue;
        char *argv[] = {"", 0, 0};
        argv[tests16[i].argvi] = (char *)tests16[i].wtf8;
        int cmdlen = cmdline_from_argv8(cmd, CMDLINE_CMD_MAX, argv);
        int match = !cmd[cmdlen] && !tests16[i].cmd[cmdlen];
        for (int j = 0; match && (cmd[j] || tests16[i].cmd[j]); j++) {
            match = cmd[j] == tests16[i].cmd[j];
        }
        if (!match) {
            printf("FAIL: [%d] WTF-8 to ill-formed UTF-16\n", i);
            fails++;
        }
    }

    if (fails) {
        return 1;
    }
    puts("All tests pass.");
    return 0;
}

#elif defined(FUZZ)
// Fuzzing can be done on non-Windows systems.
#include <assert.h>
#include <stdio.h>

int
main(void)
{
    unsigned short cmd[CMDLINE_CMD_MAX];
    char *argv[CMDLINE_ARGV_MAX];
    cmd[fread(cmd, 2, CMDLINE_CMD_MAX-1, stdin)] = 0;
    int argc = cmdline_to_argv8(cmd, argv);
    for (int i = 0; i < argc; i++) {
        assert(argv[i]);
        assert(argv[i] >= (char *)argv);
        assert(argv[i] < (char *)argv+sizeof(argv)-1);
    }
    assert(!argv[argc]);
}

#elif defined(DEMO)
#include <stdio.h>
#include <string.h>

#include <io.h>
#include <fcntl.h>
#include <windows.h>

int
main(void)
{
    _setmode(1, _O_U8TEXT);

    unsigned short *cmd = cmdline_fetch();
    wprintf(L"cmd = %ls\n", cmd);

    static char *argv[CMDLINE_ARGV_MAX];
    int argc = cmdline_to_argv8(cmd, argv);

    wprintf(L"argc = %d\n", argc);
    for (int i = 0; i < argc; i++) {
        unsigned short tmp[CMDLINE_CMD_MAX];
        MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, tmp, CMDLINE_CMD_MAX);
        wprintf(L"argv[%d] = %-20ls (%d)", i, tmp, (int)strlen(argv[i]));
        for (char *c = argv[i]; *c; c++) {
            wprintf(L" %02x", *c&0xff);
        }
        fputwc('\n', stdout);
    }

    unsigned short recmd[CMDLINE_CMD_MAX];
    cmdline_from_argv8(recmd, CMDLINE_CMD_MAX, argv);
    wprintf(L"recmd = %ls\n", recmd);
}
#endif
