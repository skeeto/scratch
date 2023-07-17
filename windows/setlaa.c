// Set the large-address-aware bit in a x86 PE executable
//
// An executable with this bit set can map the upper 2GiB of the 32-bit
// address space. On x64, such 32-bit processes can use the entire 4GiB
// for its own purposes. Ideally this bit is set at link time with ld
// --large-address-aware or link /LARGEADDRESSAWARE. This tool allows
// the bit to be flipped on later.
//
// Build: $ cc -nostartfiles -o setlaa.exe setlaa.c
//        $ cl /GS- setlaa.c /link /subsystem:console kernel32.lib
// Usage: $ setlaa <input.exe >output.exe
//
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <windows.h>

#define ERR_READ    "setlaa: could not map standard input\n"
#define ERR_WRITE   "setlaa: failed to write output\n"
#define ERR_INVALID "setlaa: invalid EXE image\n"
#define USAGE       "usage: setlaa <input.exe >output.exe\n"

// Flip the large-address-aware bit in the given image.
static int setlaa(uint8_t *exe, uint32_t len)
{
    if (len<64 || exe[0]!='M' || exe[1]!='Z') {
        return 0;
    }

    uint32_t pe_offset = (uint32_t)exe[60] <<  0 | (uint32_t)exe[61] <<  8 |
                         (uint32_t)exe[62] << 16 | (uint32_t)exe[63] << 24;
    if (pe_offset > len-24) {
        return 0;
    }

    uint8_t *pe = exe + pe_offset;
    uint8_t magic[] = {0x50, 0x45, 0x00, 0x00, 0x4c, 0x01};  // x86 PE
    for (int i = 0; i < (int)sizeof(magic); i++) {
        if (magic[i] != pe[i]) {
            return 0;
        }
    }

    pe[22] |= 0x20;  // IMAGE_FILE_LARGE_ADDRESS_AWARE
    return 1;
}

char *run(void)
{
    HANDLE stdin  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD hi, lo = GetFileSize(stdin, &hi);
    if (hi || !lo) {
        return ERR_INVALID;  // too large/small
    }
    HANDLE map = CreateFileMappingA(stdin, 0, PAGE_WRITECOPY, 0, lo, 0);
    if (!map) {
        return ERR_READ;
    }
    uint8_t *p = MapViewOfFile(map, FILE_MAP_COPY, 0, 0, lo);
    if (!p) {
        return ERR_READ;
    }

    if (!setlaa(p, lo)) {
        return ERR_INVALID;
    }

    DWORD written;
    if (!WriteFile(stdout, p, lo, &written, 0) || lo!=written) {
        return ERR_WRITE;
    }
    return 0;
}

#ifndef TEST
int mainCRTStartup(void)
{
    char *err = run();
    if (err) {
        HANDLE stderr = GetStdHandle(STD_ERROR_HANDLE);
        DWORD dummy;
        WriteFile(stderr, err, lstrlenA(err), &dummy, 0);
        WriteFile(stderr, USAGE, sizeof(USAGE)-1, &dummy, 0);
        return 1;
    }
    return 0;
}

#else
// A program that tests its own LAA capability at run time
// $ cc -DTEST -nostartfiles -o t.exe setlaa.c
// $ cl /DTEST /GS- /Fe:t.exe setlaa.c /link /subsystem:console kernel32.lib

int mainCRTStartup(void)
{
    #define SUCCESS "process can map large addresses\n"
    #define FAILURE "process can only map small addresses\n"
    DWORD dummy;
    HANDLE stderr = GetStdHandle(STD_ERROR_HANDLE);
    void *high = (void *)((SIZE_T)1 << (sizeof(void *)*8 - 1));
    if (!VirtualAlloc(high, 1, MEM_RESERVE, PAGE_READWRITE)) {
        WriteFile(stderr, FAILURE, sizeof(FAILURE)-1, &dummy, 0);
        return 1;
    }
    WriteFile(stderr, SUCCESS, sizeof(SUCCESS)-1, &dummy, 0);
    return 0;
}
#endif
