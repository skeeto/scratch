// Load and run the old "picture and fax viewer" a la rundll32
// $ cc -nostartfiles -mwindows -Os -s -o imageview.exe imageview.c -lshell32
// $ cl /O2 imageview.c /link /subsystem:windows kernel32.lib user32.lib shell32.lib
// This is free and unencumbered software released into the public domain.
typedef unsigned short wchar_t;
typedef void (__stdcall *rundll32)(void *, void *, wchar_t *, int);

#define W32(r) __declspec(dllimport) r __stdcall
W32(wchar_t **) CommandLineToArgvW(wchar_t * ,int *);
W32(void)       ExitProcess(int);
W32(int)        ExpandEnvironmentStringsW(wchar_t *, wchar_t *, int);
W32(wchar_t *)  GetCommandLineW(void);
W32(void *)     GetProcAddress(void *, char *);
W32(void *)     LoadLibraryW(wchar_t *);
W32(int)        MessageBoxA(void *, char *, char *, int);

void WinMainCRTStartup(void)
{
    wchar_t dll[512];
    wchar_t *var = L"%SystemRoot%\\system32\\shimgvw.dll";
    *dll = 0;
    ExpandEnvironmentStringsW(var, dll, sizeof(dll)-1);

    void *h = LoadLibraryW(dll);
    if (!h) {
        MessageBoxA(0, "Could not load shimgvw.dll", "ImageView", 0);
        ExitProcess(1);
    }
    rundll32 entry = GetProcAddress(h, "ImageView_FullscreenW");
    if (!entry) {
        MessageBoxA(0, "Could not find ImageView_Fullscreen", "ImageView", 0);
        ExitProcess(1);
    }

    int argc;
    wchar_t *cmd = GetCommandLineW();
    wchar_t **argv = CommandLineToArgvW(cmd, &argc);
    if (argc < 2) {
        entry(0, 0, L"", 0);
    } else {
        entry(0, 0, argv[1], 0);
    }
    ExitProcess(0);
}
