// Netpbm Viewer for Windows
//
// Fast. Lightweight. Supports P2, P3, P5, and P6 at 255 maxdepth.
// Monitors for changes and automatically refreshes.
//
// Usage: $ pbmview.exe path\to\image.ppm
// Build: $ cc -s -O3 -mwindows -o pbmview.exe pbmview.c -lshlwapi
//        $ cl /O2 pbmview.c
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>

#ifdef _MSC_VER
#  pragma comment(lib, "gdi32.lib")
#  pragma comment(lib, "shell32.lib")
#  pragma comment(lib, "shlwapi.lib")
#  pragma comment(lib, "user32.lib")
#  pragma comment(linker, "/subsystem:windows")
#endif

#define DIM_MAX 1000000

// Return non-zero if a and b match, otherwise zero.
static int
wequal(wchar_t *a, wchar_t *b, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++) {
        c += a[i] == b[i];
    }
    return c == n;
}

static unsigned long long
loadu64le(unsigned char *p)
{
    return (unsigned long long)p[0] <<  0 | (unsigned long long)p[1] <<  8 |
           (unsigned long long)p[2] << 16 | (unsigned long long)p[3] << 24 |
           (unsigned long long)p[4] << 32 | (unsigned long long)p[5] << 40 |
           (unsigned long long)p[6] << 48 | (unsigned long long)p[7] << 56;
}

static unsigned long
loadu32be(unsigned char *p)
{
    return (unsigned long)p[0] << 24 | (unsigned long)p[1] << 16 |
           (unsigned long)p[2] <<  8 | (unsigned long)p[3] <<  0;
}

struct netpbm {
    long dims[3];
    int type;
};

// Input a byte into the Netpbm parser state machine. Updates the header
// information and returns the next state. The initial state is zero.
// Negative states are errors: NETPBM_OVERFLOW, NETPBM_INVALID. The
// accept state is NETPBM_DONE, and no further input will be accepted.
// Dimensions are restricted to the given maximum. Use something
// reasonable, not LONG_MAX. Fields may be left uninitialized on error.
//
// This parser supports arbitrary whitespace and comments.
static int
netpbm_parse(int state, int c, struct netpbm *pbm, long max)
{
    #define NETPBM_OVERFLOW  -2
    #define NETPBM_INVALID   -1
    #define NETPBM_DONE      +5
    switch (state) {
    default: return NETPBM_INVALID;
    case  0: switch (c) {
             default : return NETPBM_INVALID;
             case 'P': return 1;
             }
    case  1: switch (c) {
             default : return NETPBM_INVALID;
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
             default : return NETPBM_INVALID;
             case ' ': case '\n': case '\r': case '\t':
                 return state - 3;  // possibly NETPBM_DONE
             case '#':
                 return state + 4;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 pbm->dims[state-6] = pbm->dims[state-6]*10 + c - '0';
                 if (pbm->dims[state-6] > max) {
                     return NETPBM_OVERFLOW;
                 }
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
            break;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            b = b*10 + c - '0';
            if (b > 255 || ++n > 3) {
                return 0;
            }
        }
    }
}

// A parsed Netpbm image ready to be blitted to a DC. Image data is
// allocated just beyond this structure.
struct image {
    BITMAPINFO info;
    RGBQUAD palette[256];
    unsigned char *header, *pixels;
} image;

static void
image_free(struct image *im)
{
    if (im) {
        VirtualFree(im, 0, MEM_RELEASE);
    }
}

static struct image *
newimage(wchar_t *path)
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

    struct image *im = VirtualAlloc(
        0, sizeof(*im)+len,
        MEM_COMMIT, PAGE_READWRITE
    );
    if (!im) {
        CloseHandle(h);
        return 0;
    }
    im->header = (unsigned char *)im + sizeof(*im);
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
    if (!ReadFile(h, im->header, len, &n, 0) || len != (int)n) {
        image_free(im);
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);

    // is it farbfeld?
    if (len >= 16 && loadu64le(im->header) == 0x646c656662726166) {
        unsigned long hdr_w = loadu32be(im->header +  8);
        unsigned long hdr_h = loadu32be(im->header + 12);
        if (hdr_w > DIM_MAX || hdr_h > DIM_MAX) {
            // too large
            image_free(im);
            return 0;
        }

        long w = hdr_w;
        long h = hdr_h;
        if (len < 16 + 8LL*w*h) {
            // file too short
            image_free(im);
            return 0;
        }

        im->info.bmiHeader.biWidth = w;
        im->info.bmiHeader.biHeight = -h;
        im->pixels = im->header;
        unsigned char *dst = im->header;
        unsigned char *src = im->header + 16;
        long npixels = w * h;  // cannot overflow
        for (long i = 0; i < npixels; i++) {
            dst[i*3+0] = src[i*8+4];
            dst[i*3+1] = src[i*8+2];
            dst[i*3+2] = src[i*8+0];
        }
        return im;
    }

    // is it Netpbm?
    struct netpbm pbm = {0};
    for (int ps = 0, off = 0, done = 0; !done;) {
        if (off >= len) {
            image_free(im);
            return 0;
        }
        ps = netpbm_parse(ps, im->header[off++], &pbm, DIM_MAX);
        switch (ps) {
        case NETPBM_OVERFLOW:
        case NETPBM_INVALID:
            image_free(im);
            return 0;
        case NETPBM_DONE:
            if (pbm.dims[2] != 255) {
                // Unsupported depth
                image_free(im);
                return 0;
            }
            im->info.bmiHeader.biWidth = pbm.dims[0];
            im->info.bmiHeader.biHeight = -pbm.dims[1];
            im->pixels = im->header + off;
            done = 1;
        }
    }

    switch (pbm.type) {
    default: {
        // Unsupported format
        image_free(im);
        return 0;
    } break;

    case 2: {
        // Convert in-place into 8-bit indexed grayscale that happens to
        // match the P5 format. Since each pixel is at least two ASCII
        // bytes, the indexed form is strictly smaller than the input.
        // (The last pixel may be one byte, which is still fine.)
        im->info.bmiHeader.biBitCount = 8;
        im->info.bmiHeader.biClrUsed = 256;
        long long npixels = 1LL * pbm.dims[0] * pbm.dims[1];
        unsigned char *src = im->pixels;
        unsigned char *end = im->header + len;
        for (long long i = 0; i < npixels; i++) {
            src = asciibyte(im->pixels+i, src, end);
            if (!src) {
                image_free(im);
                return 0;
            }
        }
    } break;

    case 3: {
        // Convert in-place into the P6 format. Since each pixel is at
        // least six ASCII bytes, the P6 form is strictly smaller than
        // the input. (The last pixel may be five bytes, which is still
        // fine.)
        long long nsubpixels = 3LL * pbm.dims[0] * pbm.dims[1];
        unsigned char *src = im->pixels;
        unsigned char *end = im->header + len;
        for (long long i = 0; i < nsubpixels; i += 3) {
            for (int j = 2; j >= 0; j--) {
                src = asciibyte(im->pixels+i+j, src, end);
                if (!src) {
                    image_free(im);
                    return 0;
                }
            }
        }
    } break;

    case 5: {
        // Treat as 8-bit indexed image.
        im->info.bmiHeader.biBitCount = 8;
        im->info.bmiHeader.biClrUsed = 256;
        // Already in correct format, check the length
        long long expect = 1LL * pbm.dims[0] * pbm.dims[1];
        ptrdiff_t actual = im->header + len - im->pixels;
        if (actual < expect) {
            image_free(im);
            return 0;
        }
    } break;

    case 6: {
        // Mostly in correct format, check the length
        long long expect = 3LL * pbm.dims[0] * pbm.dims[1];
        ptrdiff_t actual = im->header + len - im->pixels;
        if (actual < expect) {
            image_free(im);
            return 0;
        }
        // Swap R and B
        for (long i = 0; i < (long)expect; i += 3) {
            unsigned char t = im->pixels[i+0];
            im->pixels[i+0] = im->pixels[i+2];
            im->pixels[i+2] = t;
        }
    } break;
    }
    return im;
}

// Viewer state, shared between window procedure and a monitor thread.
// The monitor thread sends updated images to the window procedure using
// an atomic exchange on the "next" pointer. The path is allocated just
// beyond the end of this structure.
struct state {
    wchar_t *path;
    struct image *image;
    void *volatile next;
    HWND hwnd;
    WINDOWPLACEMENT wp;
    enum {MODE_AUTO, MODE_EXACT, MODE_FILTER} mode;

    #define STATE_LOADED (1 << 0)
    int flags;
};

static void
state_free(struct state *s)
{
    VirtualFree(s, 0, MEM_RELEASE);
}

// Create a new state, making a copy of the path.
static struct state *
newstate(wchar_t *path)
{
    struct state *s = VirtualAlloc(0, 1<<12, MEM_COMMIT, PAGE_READWRITE);
    if (s) {
        s->path = (wchar_t *)((char *)s + sizeof(*s));
        s->path[0] = 0;
        size_t len = lstrlenW(path) + 1;
        if (len <= MAX_PATH) {
            memcpy(s->path, path, len*2);
        }
    }
    return s;
}

// Force the image to be loaded immediately on this thread. Must be
// called before starting the monitor thread.
static void
state_syncload(struct state *s)
{
    s->flags |= STATE_LOADED;
    s->image = newimage(s->path);
}

// Send the possibly-null image to render thread. Returns 1 if a
// shutdown was requested.
static int
state_send(struct state *s, struct image *im)
{
    void *prev = InterlockedExchangePointer(&s->next, im);
    if (prev == s) {
        return 1;
    }
    image_free(prev);
    if (im) {
        RedrawWindow(s->hwnd, 0, 0, RDW_INVALIDATE|RDW_UPDATENOW);
    }
    return 0;
}

static DWORD WINAPI
state_monitor(void *arg)
{
    struct state *s = arg;

    if (!(s->flags & STATE_LOADED)) {
        if (state_send(s, newimage(s->path))) {
            state_free(s);
            return 0;
        }
    }

    size_t filelen, pathlen = lstrlenW(s->path) + 1;
    wchar_t dir[MAX_PATH], file[MAX_PATH];
    if (pathlen > MAX_PATH) {
        return 0;
    }

    memcpy(file, s->path, pathlen*2);
    PathStripPathW(file);
    filelen = lstrlenW(file);
    CharUpperBuffW(file, filelen);

    // PathRemoveFileSpecW and PathCchRemoveFileSpec are defective and
    // behave incorrectly with paths containing slashes. Convert to
    // backslashes as a workaround.
    for (int i = 0;; i++) {
        dir[i] = s->path[i]=='/' ? '\\' : s->path[i];
        if (!s->path[i]) {
            break;
        }
    }
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
        DWORD len = 0, fni[1<<10];
        DWORD filter = FILE_NOTIFY_CHANGE_LAST_WRITE |
                       FILE_NOTIFY_CHANGE_FILE_NAME |
                       FILE_NOTIFY_CHANGE_CREATION;
        ReadDirectoryChangesW(h, fni, sizeof(fni), 0, filter, &len, 0, 0);
        for (FILE_NOTIFY_INFORMATION *p = (void *)fni; len;) {
            if (p->FileNameLength/2 == filelen) {
                // Normalize for case-insensitive path comparison
                CharUpperBuffW(p->FileName, filelen);
                if (wequal(file, p->FileName, filelen)) {
                    if (state_send(s, newimage(s->path))) {
                        CloseHandle(h);
                        state_free(s);
                        return 0;
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

// Create a monitor thread to watch for image changes. Each time the
// image changes, and is valid, it will update the "next" pointer with
// the new image and then signal the window through a redraw.
static void
state_start(struct state *s, HWND hwnd)
{
    s->hwnd = hwnd;
    CloseHandle(CreateThread(0, 1<<16, state_monitor, s, 0, 0));
}

// Request monitor thread to shutdown the next time it wakes. The
// monitor will destroy the state when it shuts down.
static void
state_stop(struct state *s)
{
    // Signal a shutdown by placing the state in the "next" pointer.
    // This sentinel is a pointer guaranteed not to be mistaken for
    // either image or null.
    void *prev = InterlockedExchangePointer(&s->next, (void *)s);
    image_free(prev);
}

// Compute the ideal window size for the given image.
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
        MONITORINFO mi = {0};
        mi.cbSize = sizeof(mi);
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
        state_start(s, hwnd);

        GetWindowPlacement(hwnd, &s->wp);
        DragAcceptFiles(hwnd, 1);

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
            image_free(s->image);
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
        int w = r.right - r.left;
        int h = r.bottom - r.top;

        if (!im) {
            FillRect(hdc, &r, brush);
            EndPaint(hwnd, &ps);
            break;
        }

        int iw = im->info.bmiHeader.biWidth;
        int ih = -im->info.bmiHeader.biHeight;
        double a = (double)w / h;
        double t = (double)iw / ih;
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

        switch (s->mode) {
        case MODE_AUTO:
            if (w == iw && h == ih) {
                // fallthrough
                case MODE_EXACT:
                SetStretchBltMode(hdc, COLORONCOLOR);
            } else {
                // fallthrough
                case MODE_FILTER:
                SetStretchBltMode(hdc, HALFTONE);
                SetBrushOrgEx(hdc, 0, 0, 0);
            }
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
            struct state *ns = newstate(path);
            if (ns) {
                ns->wp = s->wp;
                state_stop(s);
                s = ns;
                SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)ns);
                state_start(ns, hwnd);
            }
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
        case 'S':
            switch (s->mode) {
            case MODE_AUTO  :
            case MODE_FILTER: s->mode = MODE_EXACT;
                              break;
            case MODE_EXACT : s->mode = MODE_FILTER;
            }
            RECT r;
            GetClientRect(hwnd, &r);
            InvalidateRect(hwnd, &r, 1);
            break;
        case 'Z':
            if (s->image) {
                LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
                ideal_rect(&s->wp.rcNormalPosition, s->image);
                s->wp.showCmd = SW_NORMAL;
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

#if __i386__
// Simplifies the command for CRT-less builds
__asm(".globl WinMain\nWinMain: jmp _WinMain@16");
#endif

int WINAPI
WinMain(HINSTANCE hi, HINSTANCE pi, char *c, int n)
{
    (void)hi; (void)pi; (void)c; (void)n;

    int argc;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    struct state *s = newstate(argv[argc-1]);
    state_syncload(s);

    WNDCLASSA wndclass = {
        .style = CS_OWNDC,
        .lpfnWndProc = proc,
        .lpszClassName = "pbmview",
        .hCursor = LoadCursor(0, IDC_ARROW),
        .hIcon = LoadIcon(GetModuleHandle(0), MAKEINTRESOURCE(1)),
    };
    RegisterClassA(&wndclass);

    CreateWindowA(
        "pbmview",
        "Netpbm Viewer",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, s
    );

    MSG msg;
    while (GetMessageA(&msg, 0, 0, 0)) {
        if (msg.message == WM_QUIT) {
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    // Cannot safely return from main() while threads are running, so
    // instead abruptly self-terminate. Besides, this program requires
    // no cleanup, so don't waste time on it.
    TerminateProcess(GetCurrentProcess(), 0);
    return 1;
}
