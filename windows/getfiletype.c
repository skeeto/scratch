// getfiletype: Report the standard output handle type on standard error
//   $ cc -nostartfiles -o getfiletype.exe getfiletype.c
//   $ cl /GS- getfiletype.c /link /subsystem:console kernel32.lib
//
// The purpose is to probe the behavior of various shells, particularly
// PowerShell, which, lacking of file redirection, strangely connects
// the ">" operator to a pipe.
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Minimal perfect hash that maps FILE_TYPE_* onto 0..4
#define HASH(x) (int)((x * 0x20010000u)>>29)

static struct {
    char  name[18];
    short length;
} types[] = {
    #define E(s) {s "\n", sizeof(s)}
    [HASH(FILE_TYPE_UNKNOWN)] = E("FILE_TYPE_UNKNOWN"),
    [HASH(FILE_TYPE_DISK)]    = E("FILE_TYPE_DISK"),
    [HASH(FILE_TYPE_CHAR)]    = E("FILE_TYPE_CHAR"),
    [HASH(FILE_TYPE_PIPE)]    = E("FILE_TYPE_PIPE"),
    [HASH(FILE_TYPE_REMOTE)]  = E("FILE_TYPE_REMOTE"),
};

int mainCRTStartup(void)
{
    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE stderr = GetStdHandle(STD_ERROR_HANDLE);
    DWORD type    = GetFileType(stdout);
    char *name    = types[HASH(type)].name;
    DWORD length  = types[HASH(type)].length;
    return !WriteFile(stderr, name, length, &length, 0);
}
