// Netpbm Viewer for Windows
//
// Fast. Lightweight. Supports P2/P3/P5/P6 at 255 maxdepth, farbfeld,
// and QOI. Monitors for changes and automatically refreshes.
//
// Usage: $ pbmview.exe path/to/image.ppm
// Build: $ cc -Os -s -nostartfiles -mwindows -o pbmview pbmview.c -lshlwapi
//        $ cl /O2 pbmview.c
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>

#ifdef _MSC_VER
  #pragma comment(lib, "kernel32.lib")
  #pragma comment(lib, "shell32.lib")
  #pragma comment(lib, "user32.lib")
  #pragma comment(lib, "gdi32.lib")
  #pragma comment(lib, "shlwapi.lib")
  #pragma comment(linker, "/subsystem:windows")
  #pragma function(memset)
  void *memset(void *d, int c, size_t n)
  {
      char *dst = (char *)d;
      for (; n; n--) *dst++ = (char)c;
      return d;
  }
#endif

#define DIM_MAX (1<<13)  // 8*DIM_MAX*DIM_MAX must not overflow int

static void
wcopy(wchar_t *dst, const wchar_t *src, size_t len)
{
    for (; len; len--) *dst++ = *src++;
}

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
    int dims[3];
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
netpbm_parse(int state, int c, struct netpbm *pbm, int max)
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

struct qoidecoder {
    int width, height, count, alpha, srgb, error;
    unsigned char *p, *end;  // internal
    int last, run;           // internal
    unsigned c, table[64];   // internal
};

// Validate the image header and populate a decoder with the image
// metadata (width, height, alpha, srgb). Image dimensions can always be
// multiplied without overflow. If the header is invalid, the error flag
// will be set immediately.
//
// Call the decoder exactly width*height times, or until the error flag
// is set. Alternatively, call until "count" reaches zero, then the
// error flag indicates if the entire decode was successful.
static struct qoidecoder qoidecoder(const void *buf, int len)
{
    struct qoidecoder q = {0};
    q.error = 1;
    if (len < 14) {
        return q;
    }

    unsigned char *p = (void *)buf;
    unsigned g = loadu32be(p+0);
    unsigned w = loadu32be(p+4);
    unsigned h = loadu32be(p+8);
    if (g!=0x716f6966U || (!w&&h) || (!h&&w) || p[12]-3u>1 || p[13]>1) {
        return q;  // invalid header
    }
    if (h && w>0x7fffffffU/h) {
        return q;  // multiplying dimensions will overflow
    }

    q.p      = p + 14;
    q.end    = p + len;
    q.width  = w;
    q.height = h;
    q.count  = w * h;
    q.last   = -1;
    q.error  = 0;
    q.alpha  = p[12]==4;
    q.srgb   = p[13]==1;
    q.c      = 0xff000000;
    return q;
}

// Decode the next ABGR pixel. The error flag is sticky, and it is
// permitted to continue "decoding" even when the error flag is set.
static unsigned qoidecode(struct qoidecoder *q)
{
    if (!q->count || q->error || q->p==q->end) {
        error: q->error=1, q->count=0;
        return 0;
    } else if (q->run) {
        q->run--;
    } else {
        int n, v=*q->p++;
        unsigned char *p=q->p, r, g, b, a;
        switch (v&0xc0) {
        case 0x00:  // INDEX
            if (q->last == v) goto error;
            q->c = q->table[v];
            goto skiptable;
        case 0x40:  // DIFF
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += (v>>4 & 3) - 2;
            g += (v>>2 & 3) - 2;
            b += (v>>0 & 3) - 2;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            break;
        case 0x80:  // LUMA
            n = v - (0x80 + 32);
            if (q->end-p < 1) goto error;
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += n + (*p>>4) - 8;
            g += n;
            b += n + (*p&15) - 8;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            q->p += 1;
            break;
        case 0xc0:
            switch ((n = v&63)) {
            case 63:  // RGBA
                if (q->end-p < 4) goto error;
                q->c = p[0] | p[1]<<8 | p[2]<<16 | (unsigned)p[3]<<24;
                q->p += 4;
                break;
            case 62:  // RGB
                if (q->end-p < 3) goto error;
                r=p[0], g=p[1], b=p[2], a=q->c>>24;
                q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
                q->p += 3;
                break;
            default:  // RUN
                if (q->count < n) goto error;
                q->run = n;
                break;
            }
        }
        r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
        q->table[(r*3 + g*5 + b*7 + a*11)&63] = q->c;
        skiptable: q->last = v;
    }

    if (!--q->count) {
        q->error |= q->end-q->p<8 || q->p[0] || q->p[1] || q->p[2] ||
            q->p[3] || q->p[4] || q->p[5] || q->p[6] || q->p[7]!=1;
    }
    return q->c;
}


// Decode an ASCII byte value from src to dst, returning updated src. Returns
// null on invalid input.
static unsigned char *
asciibyte(unsigned char *dst, unsigned char *src, unsigned char *end)
{
    for (int n=0, b=0; ;) {
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

struct argb {
    unsigned char a, r, g, b;
};

// A parsed Netpbm image ready to be blitted to a DC. Image data is
// allocated just beyond this structure.
struct image {
    BITMAPINFO info;
    RGBQUAD palette[256];
    unsigned char pixels[];
} image;

static void
image_free(struct image *im)
{
    if (im) {
        VirtualFree(im, 0, MEM_RELEASE);
    }
}

static struct image *
image_new(int width, int height, int nchannels)
{
    int pad = (-width*nchannels) & 3;
    int len = (nchannels*width + pad)*height;
    struct image *im = VirtualAlloc(
        0, sizeof(*im)+len,
        MEM_COMMIT, PAGE_READWRITE
    );
    if (!im) {
        return 0;
    }

    im->info.bmiHeader.biWidth = width;
    im->info.bmiHeader.biHeight = -height;
    im->info.bmiHeader.biSize = sizeof(im->info);
    im->info.bmiHeader.biPlanes = 1;
    im->info.bmiHeader.biBitCount = nchannels==1 ? 8 : 24;
    im->info.bmiHeader.biClrUsed = nchannels==1 ? 256 : 0;
    im->info.bmiHeader.biCompression = BI_RGB;

    // Create a PGM palette
    for (int i = 0; i < 256; i++) {
        im->palette[i].rgbBlue = i;
        im->palette[i].rgbGreen = i;
        im->palette[i].rgbRed = i;
    }

    return im;
}

static inline void
image_rgb(struct image *im, int x, int y, struct argb c)
{
    int w = im->info.bmiHeader.biWidth;
    int pad = (-w*3)&3;
    unsigned char *dst = im->pixels + y*(3*w + pad) + 3*x;
    dst[0] = c.b;
    dst[1] = c.g;
    dst[2] = c.r;
}

static inline void
image_idx(struct image *im, int x, int y, unsigned char v)
{
    int w = im->info.bmiHeader.biWidth;
    int pad = -w&3;
    unsigned char *dst = im->pixels + y*(w + pad) + x;
    dst[0] = v;
}

static inline void
image_argb(struct image *im, int x, int y, struct argb c)
{
    float a = c.a / 255.0f;
    unsigned char bg = ((x^y)>>4)&1 ? 0x66 : 0xaa;
    struct argb blend = {
        255,
        c.r*a + bg*(1 - a),
        c.g*a + bg*(1 - a),
        c.b*a + bg*(1 - a)
    };
    image_rgb(im, x, y, blend);
}

static struct image *
decode_farbfeld(unsigned char *imdata, int len)
{
    if (len<16 || loadu64le(imdata)!=0x646c656662726166) {
        return 0;
    }

    int w = loadu32be(imdata +  8);
    int h = loadu32be(imdata + 12);
    if (w<0 || w>DIM_MAX || h<0 || h>DIM_MAX || len-16<8*w*h) {
        return 0;
    }

    struct image *im = image_new(w, h, 3);
    if (!im) {
        return 0;
    }

    imdata += 16;
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            struct argb c = {imdata[6], imdata[0], imdata[2], imdata[4]};
            image_argb(im, x, y, c);
            imdata += 8;
        }
    }
    return im;
}

static struct image *
decode_netpbm(unsigned char *imdata, int len)
{
    struct image *im = 0;
    unsigned char *end = imdata + len;

    struct netpbm pbm = {0};
    for (int ps=0, off=0, done=0; !done;) {
        if (off >= len) {
            return 0;
        }
        ps = netpbm_parse(ps, imdata[off++], &pbm, DIM_MAX);
        switch (ps) {
        case NETPBM_OVERFLOW:
        case NETPBM_INVALID:
            return 0;
        case NETPBM_DONE:
            if (pbm.dims[2] != 255) {
                // Unsupported depth
                return 0;
            }
            int nchannels = pbm.type==2 || pbm.type==5 ? 1 : 3;
            im = image_new(pbm.dims[0], pbm.dims[1], nchannels);
            if (!im) {
                return 0;
            }
            imdata += off;
            done = 1;
        }
    }

    int w = pbm.dims[0];
    int h = pbm.dims[1];

    switch (pbm.type) {
    default: {
        // Unsupported format
        image_free(im);
        return 0;
    } break;

    case 2: {
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                unsigned char v;
                imdata = asciibyte(&v, imdata, end);
                if (!imdata) {
                    image_free(im);
                    return 0;
                }
                image_idx(im, x, y, v);
            }
        }
    } break;

    case 3: {
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                unsigned char rgb[3];
                for (int j = 0; j < 3; j++) {
                    imdata = asciibyte(rgb+j, imdata, end);
                    if (!imdata) {
                        image_free(im);
                        return 0;
                    }
                }
                struct argb c = {255, rgb[0], rgb[1], rgb[2]};
                image_rgb(im, x, y, c);
            }
        }
    } break;

    case 5: {
        if (w*h > end-imdata) {
            image_free(im);
            return 0;
        }
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                unsigned char v = *imdata++;
                image_idx(im, x, y, v);
            }
        }
    } break;

    case 6: {
        if (3*w*h > end-imdata) {
            image_free(im);
            return 0;
        }
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                struct argb c = {255, imdata[0], imdata[1], imdata[2]};
                image_rgb(im, x, y, c);
                imdata += 3;
            }
        }
    } break;
    }
    return im;
}

static struct image *
decode_qoi(unsigned char *imdata, int len)
{
    struct qoidecoder q = qoidecoder(imdata, len);
    if (q.error || q.width>DIM_MAX || q.height>DIM_MAX) {
        return 0;
    }
    int w = q.width;
    int h = q.height;

    struct image *im = image_new(w, h, 3);
    if (!im) {
        return 0;
    }

    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            unsigned abgr = qoidecode(&q);
            struct argb c = {abgr>>24, abgr, abgr>>8, abgr>>16};
            image_argb(im, x, y, c);
        }
    }

    if (q.error) {
        image_free(im);
        im = 0;
    }
    return im;
}

static struct image *
newimage(wchar_t *path)
{
    HANDLE fh = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (fh == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD hi, lo = GetFileSize(fh, &hi);
    if (hi || (int)lo < 0) {
        // reject files >2GiB
        CloseHandle(fh);
        return 0;
    }
    int len = lo;

    HANDLE *map = CreateFileMapping(fh, 0, PAGE_READONLY, 0, len, 0);
    CloseHandle(fh);
    if (!map) {
        return 0;
    }

    unsigned char *imdata = MapViewOfFile(map, FILE_MAP_READ, 0, 0, len);
    CloseHandle(map);
    if (!imdata) {
        return 0;
    }

    struct image *im = 0;
    im = im ? im : decode_farbfeld(imdata, len);
    im = im ? im : decode_netpbm(imdata, len);
    im = im ? im : decode_qoi(imdata, len);
    UnmapViewOfFile(imdata);
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
            wcopy(s->path, path, len);
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

    wcopy(file, s->path, pathlen);
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

    DWORD cap = 1 << 21;  // 2MiB: maybe get a large page?
    void *fni = VirtualAlloc(0, cap, MEM_COMMIT, PAGE_READWRITE);
    cap = fni ? cap : 0;

    for (;;) {
        DWORD len = 0;
        DWORD filter = FILE_NOTIFY_CHANGE_LAST_WRITE |
                       FILE_NOTIFY_CHANGE_FILE_NAME |
                       FILE_NOTIFY_CHANGE_CREATION;
        ReadDirectoryChangesW(h, fni, cap, 0, filter, &len, 0, 0);
        for (FILE_NOTIFY_INFORMATION *p = fni; len;) {
            if (p->FileNameLength/2 == filelen) {
                // Normalize for case-insensitive path comparison
                CharUpperBuffW(p->FileName, filelen);
                if (wequal(file, p->FileName, filelen)) {
                    if (state_send(s, newimage(s->path))) {
                        VirtualFree(fni, 0, MEM_RELEASE);
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

int WinMainCRTStartup(void)
{
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
