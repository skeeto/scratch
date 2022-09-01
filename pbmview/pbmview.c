// Netpbm Viewer for Windows
//
// Fast. Lightweight. Supports P2, P3, P5, and P6 at 255 maxdepth. Monitors for
// changes and automatically refreshes.
//
// Usage: $ pbmview.exe path\to\image.ppm
// Build: $ cc -s -O3 -mwindows -o pbmview.exe pbmview.c -ldwmapi -lshlwapi
//        $ cl /O2 pbmview.c
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlwapi.h>

#ifdef _MSC_VER
#  pragma comment(lib, "dwmapi.lib")
#  pragma comment(lib, "gdi32.lib")
#  pragma comment(lib, "shell32.lib")
#  pragma comment(lib, "shlwapi.lib")
#  pragma comment(lib, "user32.lib")
#  pragma comment(linker, "/subsystem:windows")
#endif

struct netpbm {
    long dims[3];
    int type;
};

// Input a byte into the Netpbm parser state machine, updating the width
// / height / depth array and returning the next state. The initial
// state is zero. A negative return is not a state, but an error:
// PGM_OVERFLOW, PGM_INVALID. The accept state is PGM_DONE, and no
// further input will be accepted. Dimensions are restricted to the
// given maximum: use something reasonable, not LONG_MAX. Fields may be
// left uninitialized on error.
//
// This parser supports arbitrary whitespace and comments.
static int
netpbm_parse(int state, int c, struct netpbm *pbm, long max)
{
    #define PGM_OVERFLOW  -2
    #define PGM_INVALID   -1
    #define PGM_DONE      +5
    switch (state) {
    default: return PGM_INVALID;
    case  0: switch (c) {
             default : return PGM_INVALID;
             case 'P': return 1;
             }
    case  1: switch (c) {
             default : return PGM_INVALID;
             case '2':
             case '3':
             case '5':
             case '6': pbm->type = c - '0';
                       return 2;
             }
    case  2:
    case  3:
    case  4: switch (c) {  // between fields
             default : return 0;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 pbm->dims[state-2] = c - '0';
                 return state + 4;
             case ' ': case '\n': case '\r': case '\t':
                 return state;
             case '#':
                 return state + 7;
             }
    case  6:
    case  7:
    case  8: switch (c) {  // dimensions
             default : return PGM_INVALID;
             case ' ': case '\n': case '\r': case '\t':
                 return state - 3;  // possibly PGM_DONE
             case '#':
                 return state + 4;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 pbm->dims[state-6] = pbm->dims[state-6]*10 + c - '0';
                 if (pbm->dims[state-6] > max) return PGM_OVERFLOW;
                 return state;
             }
    case  9:
    case 10:
    case 11: switch (c) {  // comments
             default  : return state;
             case '\n': return state - 7;
             }
    }
}

struct image {
    BITMAPINFO info;
    RGBQUAD palette[256];
    unsigned char *pbm, *pixels;
} image;

struct state {
    wchar_t *path;
    struct image *image;
    void *volatile next;
    HWND hwnd;
    WINDOWPLACEMENT wp;
};

static void
ideal_rect(RECT *r, struct image *im)
{
    int iw = +im->info.bmiHeader.biWidth;
    int ih = -im->info.bmiHeader.biHeight;
    if (iw < 128 || ih < 128) {
        // Too small, scale it up
        iw *= 128;
        ih *= 128;
    }

    int sw = GetSystemMetrics(SM_CXFULLSCREEN);
    int sh = GetSystemMetrics(SM_CYFULLSCREEN);
    if (iw > sw || ih > sh) {
        // Too large, scale to screen keeping aspect ratio
        double ia = (double)iw/ih;
        double sa = (double)sw/sh;
        if (ia < sa) {
            ih = sh;
            iw = ia * sh;
        } else {
            iw = sw;
            ih = sw / ia;
        }
    }

    RECT t = {0, 0, iw, ih};
    AdjustWindowRect(&t, WS_OVERLAPPEDWINDOW, 0);
    int ww = t.right - t.left;
    int wh = t.bottom - t.top;
    r->left = sw/2 - ww/2;
    r->top = sh/2 - wh/2;
    r->right = r->left + ww;
    r->bottom = r->top + wh;
}

static void
toggle_fullscreen(HWND hwnd, WINDOWPLACEMENT *wp)
{
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    if (style & WS_OVERLAPPEDWINDOW) {
        GetWindowPlacement(hwnd, wp);
        if (wp->showCmd == SW_NORMAL) {
            // Workaround: Due to an old Windows defect, GetWindowPlacement
            // returns the wrong normal position for snapped windows, so
            // override it with the correct position from GetWindowRect.
            GetWindowRect(hwnd, &wp->rcNormalPosition);
        }
        style &= ~WS_OVERLAPPEDWINDOW;
        SetWindowLongPtrA(hwnd, GWL_STYLE, style);
        MONITORINFO mi = {sizeof(mi)};
        GetMonitorInfo(MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY), &mi);
        SetWindowPos(
                hwnd, HWND_TOP,
                mi.rcMonitor.left, mi.rcMonitor.top,
                mi.rcMonitor.right-mi.rcMonitor.left,
                mi.rcMonitor.bottom-mi.rcMonitor.top,
                SWP_NOOWNERZORDER | SWP_FRAMECHANGED
                );

    } else {
        style |= WS_OVERLAPPEDWINDOW;
        SetWindowLongPtrA(hwnd, GWL_STYLE, style);
        SetWindowPos(
                hwnd, 0, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                SWP_NOOWNERZORDER | SWP_FRAMECHANGED
                );
        SetWindowPlacement(hwnd, wp);
    }
}

static LRESULT CALLBACK
proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    struct state *s = (struct state *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT *cs = (CREATESTRUCT *)lparam;
        s = (struct state *)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)s);

        DragAcceptFiles(hwnd, 1);

        #if _WIN32_WINNT >= NTDDI_WIN7
        // Disable rounded corners (hides pixels)
        DWORD v = 1;
        DwmSetWindowAttribute(hwnd, 33, &v, 4);
        #endif

        if (s->image) {
            GetWindowPlacement(hwnd, &s->wp);
            ideal_rect(&s->wp.rcNormalPosition, s->image);
            SetWindowPlacement(hwnd, &s->wp);
        }
    } break;

    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProc(hwnd, msg, wparam, lparam);
        return hit == HTCLIENT ? HTCAPTION : hit;
    } break;

    case WM_SIZE: {
        RECT r;
        GetClientRect(hwnd, &r);
        InvalidateRect(hwnd, &r, 1);
    } break;

    case WM_PAINT: {
        struct image *im = InterlockedExchangePointer(&s->next, (void *)0);
        if (im) {
            // Received new image
            if (s->image) {
                VirtualFree(s->image, 0, MEM_RELEASE);
            }
            s->image = im;
        } else {
            // No new image, get previous image
            im = s->image;
        }

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        HBRUSH brush;
        if (GetWindowLongPtr(hwnd, GWL_STYLE) & WS_OVERLAPPEDWINDOW) {
            brush = GetStockObject(DKGRAY_BRUSH);
        } else {
            brush = GetStockObject(BLACK_BRUSH);
        }

        RECT r;
        GetClientRect(hwnd, &r);
        double w = r.right - r.left;
        double h = r.bottom - r.top;

        if (!im) {
            FillRect(hdc, &r, brush);
            EndPaint(hwnd, &ps);
            break;
        }

        double a = w / h;
        double t = (double)im->info.bmiHeader.biWidth / -im->info.bmiHeader.biHeight;
        int xpad = 0, ypad = 0;
        if (a < t) {
            ypad = h - w/t;
            ypad = ypad < 0 ? -ypad : ypad;
            RECT beg = {0, 0, w, ypad/2}, end = {0, h-(ypad+1)/2, w, h};
            FillRect(hdc, &beg, brush);
            FillRect(hdc, &end, brush);
        } else {
            xpad = w - t*h;
            xpad = xpad < 0 ? -xpad : xpad;
            RECT box = {0, 0, xpad/2, h}, end = {w-(xpad+1)/2, 0, w, h};
            FillRect(hdc, &box, brush);
            FillRect(hdc, &end, brush);
        }
        StretchDIBits(
            hdc,
            r.left+xpad/2, r.top+ypad/2, w-xpad, h-ypad,
            0, 0, im->info.bmiHeader.biWidth, -im->info.bmiHeader.biHeight,
            im->pixels, &im->info, DIB_RGB_COLORS, SRCCOPY
        );

        EndPaint(hwnd, &ps);
    } break;

    case WM_DROPFILES: {
        wchar_t path[MAX_PATH];
        if (DragQueryFileW((HDROP)wparam, 0, path, sizeof(path))) {
            // TODO
        }
    } break;

    case WM_KEYDOWN: {
        switch (wparam) {
        case 0x1b:
        case 'Q':
            PostQuitMessage(0);
            break;
        case 'F':
            toggle_fullscreen(hwnd, &s->wp);
            break;
        case 'Z':
            if (s->image) {
                LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
                ideal_rect(&s->wp.rcNormalPosition, s->image);
                if (style & WS_OVERLAPPEDWINDOW) {
                    SetWindowPlacement(hwnd, &s->wp);
                } else {
                    toggle_fullscreen(hwnd, &s->wp);
                }
            }
            break;
        }
    } break;

    case WM_CLOSE:
    case WM_DESTROY: {
        PostQuitMessage(0);
    } break;

    default:
        return DefWindowProcA(hwnd, msg, wparam, lparam);
    }
    return 0;
}

// Decode an ASCII byte value from src to dst, returning updated src. Returns
// null on invalid input.
static unsigned char *
asciibyte(unsigned char *dst, unsigned char *src, unsigned char *end)
{
    for (int n = 0, b = 0; ;) {
        if (src == end) {
            if (!n) {
                return 0;
            }
            *dst = (unsigned char)b;
            return src;
        }

        unsigned char c = *src++;
        switch (c) {
        default:
            return 0;
        case '\t': case ' ' : case '\r': case '\n':
            if (n) {
                *dst = (unsigned char)b;
                return src;
            }
            continue;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            b = b*10 + c - '0';
            if (b > 255 || ++n > 3) {
                return 0;
            }
        }
    }
}

static struct image *
loadpbm(wchar_t *path)
{
    HANDLE h = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD hi, lo = GetFileSize(h, &hi);
    if (hi || (int)lo < 0) {
        // reject files >2GiB
        CloseHandle(h);
        return 0;
    }
    int len = lo;

    struct image *im = VirtualAlloc(0, sizeof(*im)+len, MEM_COMMIT, PAGE_READWRITE);
    if (!im) {
        CloseHandle(h);
        return 0;
    }
    im->pbm = (unsigned char *)im + sizeof(*im);
    im->info.bmiHeader.biSize = sizeof(im->info);
    im->info.bmiHeader.biPlanes = 1;
    im->info.bmiHeader.biBitCount = 24;
    im->info.bmiHeader.biCompression = BI_RGB;

    // Fill PGM palette
    for (int i = 0; i < 256; i++) {
        im->palette[i].rgbBlue = i;
        im->palette[i].rgbGreen = i;
        im->palette[i].rgbRed = i;
    }

    DWORD n;
    if (!ReadFile(h, im->pbm, len, &n, 0) || len != (int)n) {
        VirtualFree(im, 0, MEM_RELEASE);
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);

    struct netpbm pbm = {0};
    for (int ps = 0, off = 0, done = 0; !done;) {
        if (off >= len) {
            VirtualFree(im, 0, MEM_RELEASE);
            return 0;
        }
        ps = netpbm_parse(ps, im->pbm[off++], &pbm, 1000000);
        switch (ps) {
        case PGM_OVERFLOW:
        case PGM_INVALID:
            VirtualFree(im, 0, MEM_RELEASE);
            return 0;
        case PGM_DONE:
            if (pbm.dims[2] != 255) {
                // Unsupported depth
                VirtualFree(im, 0, MEM_RELEASE);
                return 0;
            }
            im->info.bmiHeader.biWidth = pbm.dims[0];
            im->info.bmiHeader.biHeight = -pbm.dims[1];
            im->pixels = im->pbm + off;
            done = 1;
        }
    }

    switch (pbm.type) {
    default: {
        // Unsupported format
        VirtualFree(im, 0, MEM_RELEASE);
        return 0;
    } break;

    case 2: {
        im->info.bmiHeader.biBitCount = 8;
        im->info.bmiHeader.biClrUsed = 256;
        long long npixels = 1LL * pbm.dims[0] * pbm.dims[1];
        unsigned char *src = im->pixels;
        unsigned char *end = src + len;
        for (long long i = 0; i < npixels; i++) {
            src = asciibyte(im->pixels+i, src, end);
            if (!src) {
                VirtualFree(im, 0, MEM_RELEASE);
                return 0;
            }
        }
    } break;

    case 3: {
        long long npixels = 3LL * pbm.dims[0] * pbm.dims[1];
        unsigned char *src = im->pixels;
        unsigned char *end = src + len;
        for (long long i = 0; i < npixels; i++) {
            src = asciibyte(im->pixels+i, src, end);
            if (!src) {
                VirtualFree(im, 0, MEM_RELEASE);
                return 0;
            }
        }
    } break;

    case 5: {
        im->info.bmiHeader.biBitCount = 8;
        im->info.bmiHeader.biClrUsed = 256;
        // Already in correct format
    } break;

    case 6: {
        // Already in correct format
    } break;
    }
    return im;
}

static DWORD WINAPI
monitor(void *arg)
{
    struct state *s = arg;
    size_t filelen, pathlen = wcslen(s->path) + 1;
    wchar_t dir[MAX_PATH], file[MAX_PATH];
    if (pathlen > MAX_PATH) {
        return 0;
    }

    memcpy(file, s->path, pathlen*2);
    PathStripPathW(file);
    filelen = wcslen(file);
    CharUpperBuffW(file, filelen);

    memcpy(dir, s->path, pathlen*2);
    PathRemoveFileSpecW(dir);
    if (!dir[0]) {
        dir[0] = '.';
        dir[1] = 0;
    }

    // Poll until directory exists
    HANDLE h;
    for (;; Sleep(1000)) {
        h = CreateFileW(
                dir,
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                0,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                0
                );
        if (h != INVALID_HANDLE_VALUE) {
            break;
        }
    }

    for (;;) {
        DWORD len, fni[1<<10];
        ReadDirectoryChangesW(h, fni, sizeof(fni), 0, FILE_NOTIFY_CHANGE_LAST_WRITE, &len, 0, 0);
        for (FILE_NOTIFY_INFORMATION *p = (void *)fni;;) {
            if (p->FileNameLength/2 == filelen) {
                // Normalize for case-insensitive path comparison
                CharUpperBuffW(p->FileName, filelen);
                if (!memcmp(file, p->FileName, p->FileNameLength)) {
                    struct image *im = loadpbm(s->path);
                    if (im) {
                        // Send new image to render thread
                        im = InterlockedExchangePointer(&s->next, im);
                        if (im) {
                            VirtualFree(im, 0, MEM_RELEASE);
                        }
                        RedrawWindow(s->hwnd, 0, 0, RDW_INVALIDATE|RDW_UPDATENOW);
                    }
                }
            }
            if (!p->NextEntryOffset) {
                break;
            }
            p = (FILE_NOTIFY_INFORMATION *)((char *)p + p->NextEntryOffset);
        }
    }
}

int WINAPI
WinMain(HINSTANCE hi, HINSTANCE pi, char *c, int n)
{
    (void)hi; (void)pi; (void)c; (void)n;

    int argc;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    wchar_t *path = argv[argc-1];

    struct state state = {0};
    state.path = path;
    state.image = loadpbm(path);

    WNDCLASSA wndclass = {
        .style = CS_OWNDC,
        .lpfnWndProc = proc,
        .lpszClassName = "pbmview",
        .hCursor = LoadCursor(0, IDC_ARROW),
        .hIcon = LoadIcon(GetModuleHandle(0), MAKEINTRESOURCE(1)),
    };
    RegisterClassA(&wndclass);

    HWND hwnd = CreateWindowA(
        "pbmview",
        "Netpbm Viewer",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0,
        &state
    );
    state.hwnd = hwnd;
    HDC hdc = GetDC(hwnd);
    SetStretchBltMode(hdc, HALFTONE);
    SetBrushOrgEx(hdc, 0, 0, 0);
    ReleaseDC(hwnd, hdc);

    CreateThread(0, 0, monitor, &state, 0, 0);

    MSG msg;
    while (GetMessageA(&msg, 0, 0, 0)) {
        if (msg.message == WM_QUIT) {
            TerminateProcess(GetCurrentProcess(), 0);
        }
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
