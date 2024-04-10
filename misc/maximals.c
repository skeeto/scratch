// Interactively show the maximal points among a set of points
// $ cc -nostartfiles -mwindows -o maximals.exe maximals.c -lopengl32
// $ cl maximals.c /link /subsystem:windows
//       kernel32.lib user32.lib gdi32.lib opengl32.lib
//
// Left click adds a point, right click removes the newest point.
//
// To port, write a platform layer that creates an OpenGL context, gives
// init() 2MiB memory, and then calls push(), pop(), and render() as
// needed. The OpenGL declarations will need to be generalized, too.
//
// This project was mainly an experiment building an interactive OpenGL
// application without including any Win32 SDK headers.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
typedef unsigned char      u8;
typedef   signed short     i16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef          float     f32;
typedef          ptrdiff_t isize;
typedef          size_t    uptr;
typedef          char      byte;


// OpenGL (Win32)

enum {
    GL_COLOR_BUFFER_BIT = 0x4000,
    GL_FLOAT            = 0x1406,
    GL_UNSIGNED_INT     = 0x1405,
    GL_POINTS           = 0x0000,
    GL_LINE_STRIP       = 0x0003,
    GL_VERTEX_ARRAY     = 0x8074,
};

#define GL(r) __declspec(dllimport) r __stdcall
GL(void) glClear(i32);
GL(void) glClearColor(f32, f32, f32, f32);
GL(void) glColor3f(f32, f32, f32);
GL(void) glDrawArrays(i32, i32, i32);
GL(void) glDrawElements(i32, i32, i32, void *);
GL(void) glEnableClientState(i32);
GL(void) glLineWidth(f32);
GL(void) glLoadIdentity(void);
GL(void) glPointSize(f32);
GL(void) glScalef(f32, f32, f32);
GL(void) glTranslatef(f32, f32, f32);
GL(void) glVertexPointer(i32, i32, i32, void *);
GL(void) glViewport(i32, i32, i32, i32);


// Application

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define countof(a)    (i32)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)  (t *)alloc(a, sizeof(t), n)

enum {
    WIDTH  = 500,
    HEIGHT = 500,
};

typedef struct {
    byte *beg, *end;
} arena;

static byte *alloc(arena *a, isize size, isize count)
{
    isize pad = (uptr)a->end & 7;
    assert(count < (a->end - a->beg - pad)/size);
    return a->end -= size*count + pad;  // NOTE: assumes zeroed arena
}

typedef struct {
    f32 x, y;
} v2;

typedef struct {
    i32 *maxs;
    i32 *sort;
    v2  *points;
    i32  len;
    i32  cap;
    i32  nmaxs;
} state;

static i32 compare(v2 a, v2 b)
{
    if (a.x == b.x) {
        return (a.y > b.y) - (a.y < b.y);
    }
    return (a.x < b.x) - (a.x > b.x);
}

static void splitmerge(i32 *dst, i32 beg, i32 end, i32 *src, v2 *points)
{
    if (end-beg < 2) return;

    i32 mid = beg + (end - beg)/2;
    splitmerge(src, beg, mid, dst, points);
    splitmerge(src, mid, end, dst, points);

    i32 i = beg;
    i32 j = mid;
    for (i32 k = beg; k < end; k++) {
        if (i<mid && (j==end || compare(points[src[i]], points[src[j]])<1)) {
            dst[k] = src[i++];
        } else {
            dst[k] = src[j++];
        }
    }
}

static void update(state *s)
{
    for (i32 i = 0; i < s->len; i++) {
        s->maxs[i] = s->sort[i] = i;
    }
    splitmerge(s->maxs, 0, s->len, s->sort, s->points);

    s->nmaxs = s->len ? 1 : 0;
    for (i32 i = 1; i < s->len; i++) {
        v2 pre = s->points[s->maxs[s->nmaxs-1]];
        v2 cur = s->points[s->maxs[i]];
        if (pre.y > cur.y) {
            s->maxs[s->nmaxs++] = s->maxs[i];
        }
    }
}

static state *init(void *mem, isize len)
{
    arena perm = {0};
    perm.beg = mem;
    perm.end = perm.beg + len;

    state *s  = new(&perm, state, 1);
    s->cap    = 100000;  // ought to be plenty
    s->points = new(&perm, v2,  s->cap);
    s->maxs   = new(&perm, i32, s->cap);
    s->sort   = new(&perm, i32, s->cap);

    static v2 points[] = {
        {200, 300}, {250, 300}, {330, 270}, {150, 380},
        {126, 172}, {397, 379}, {334, 441}, { 53, 288},
        { 89, 433}, {182, 215}, {251, 414},
    };
    for (i32 i = 0; i < countof(points); i++) {
        s->points[i] = points[i];
    }
    s->len = countof(points);
    update(s);
    return s;
}

static void push(state *s, f32 x, f32 y)
{
    if (s->len == s->cap) return;
    i32 i = s->len++;
    s->points[i].x = x * WIDTH;
    s->points[i].y = y * HEIGHT;
    update(s);
}

static void pop(state *s)
{
    s->len = s->len ? s->len-1 : 0;
    update(s);
}

static void render(state *s, i32 w, i32 h)
{
    glEnableClientState(GL_VERTEX_ARRAY);
    glColor3f(0, 0, 0);
    glPointSize(4);
    glLineWidth(2);

    glViewport(0, 0, w, h);
    glLoadIdentity();
    glTranslatef((f32)-1, (f32)1, 0);
    glScalef(2.0f/WIDTH, -2.0f/HEIGHT, 0);

    glClearColor(1, 1, 1, 0);
    glClear(GL_COLOR_BUFFER_BIT);

    glVertexPointer(2, GL_FLOAT, 0, s->points);
    glDrawArrays(GL_POINTS, 0, s->len);
    glDrawElements(GL_LINE_STRIP, s->nmaxs, GL_UNSIGNED_INT, s->maxs);
}


// Platform layer

#ifdef _WIN32
typedef struct {
  i32  style;
  uptr proc;
  i32  extra[2];
  uptr instance;
  uptr icon;
  uptr cursor;
  uptr background;
  u8  *menuname;
  u8  *classname;
} WndClass;

typedef struct {
  i16 size;
  i16 version;
  i32 flags;
  u8  color[20];
  i32 mask[3];
} Pfd;

typedef struct {
    uptr hwnd;
    i32  msg;
    uptr wp;
    uptr lp;
    i32  time;
    i32  x, y;
} Msg;

enum {
    WM_CLOSE           = 0x0010,
    WM_QUIT            = 0x0012,
    WM_LBUTTONDOWN     = 0x0201,
    WM_RBUTTONDOWN     = 0x0204,
    WS_MINIMIZEBOX     = 0x20000,
    WS_SYSMENU         = 0x80000,
    IDC_ARROW          = 0x7f00,
    PFD_DOUBLEBUFFER   = 0x01,
    PFD_DRAW_TO_WINDOW = 0x04,
    PFD_SUPPORT_OPENGL = 0x20,
    MEM_COMMIT         = 0x1000,
    MEM_RESERVE        = 0x2000,
    PAGE_READWRITE     = 4,
};

#define W32(r) __declspec(dllimport) r __stdcall
W32(i32)   ChoosePixelFormat(uptr, Pfd *);
W32(uptr)  CreateWindowExA(i32,u8*,u8*,i32,i32,i32,i32,i32,uptr,uptr,uptr,uptr);
W32(uptr)  DefWindowProcA(uptr, i32, uptr, uptr);
W32(uptr)  DispatchMessageA(Msg *);
W32(void)  ExitProcess(i32);
W32(b32)   GetClientRect(uptr, i32 *);
W32(b32)   GetCursorPos(i32 *);
W32(uptr)  GetDC(uptr);
W32(i32)   GetSystemMetrics(i32);
W32(uptr)  LoadCursorA(uptr, i32);
W32(b32)   GetMessageA(Msg *, uptr, i32, i32);
W32(void)  PostQuitMessage(i32);
W32(i16)   RegisterClassA(WndClass *);
W32(b32)   ScreenToClient(uptr, i32 *);
W32(b32)   SetPixelFormat(uptr, i32, Pfd *);
W32(b32)   ShowWindow(uptr, i32);
W32(b32)   SwapBuffers(uptr);
W32(b32)   TranslateMessage(Msg *);
W32(void*) VirtualAlloc(uptr, isize, i32, i32);
W32(uptr)  wglCreateContext(uptr);
W32(b32)   wglMakeCurrent(uptr, uptr);

static uptr __stdcall wndproc(uptr wnd, i32 msg, uptr wp, uptr lp)
{
    switch (msg) {
    case WM_CLOSE: {
        PostQuitMessage(0);
    } return 0;
    }
    return DefWindowProcA(wnd, msg, wp, lp);
}

void WinMainCRTStartup(void)
{
    WndClass wc  = {0};
    wc.proc      = (uptr)wndproc;
    wc.classname = (u8 *)"gl";
    wc.cursor    = LoadCursorA(0, IDC_ARROW);
    RegisterClassA(&wc);

    i32 width  = 800;
    i32 height = 800;
    i32 x      = GetSystemMetrics(0)/2 - width/2;
    i32 y      = GetSystemMetrics(1)/2 - height/2;
    i32 style  = WS_MINIMIZEBOX | WS_SYSMENU;
    uptr wnd = CreateWindowExA(
        0, (u8 *)"gl", (u8 *)"Points", style, x, y, width, height, 0, 0, 0, 0
    );

    uptr dc = GetDC(wnd);
    Pfd pfd = {0};
    pfd.size = sizeof(pfd);
    pfd.version = 1;
    pfd.flags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    i32 format = ChoosePixelFormat(dc, &pfd);
    SetPixelFormat(dc, format, &pfd);
    uptr ctx = wglCreateContext(dc);
    wglMakeCurrent(dc, ctx);
    ShowWindow(wnd, 1);

    isize cap = (isize)1<<21;  // 2MiB
    void *mem = VirtualAlloc(
        0, cap, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE
    );
    state *s = init(mem, cap);

    for (b32 dirty = 1;;) {
        i32 r[4] = {0};
        GetClientRect(wnd, r);
        i32 w = r[2] - r[0];
        i32 h = r[3] - r[1];

        Msg m;
        GetMessageA(&m, 0, 0, 0);
        switch (m.msg) {
        case WM_QUIT: {
            ExitProcess(0);
        } break;
        case WM_LBUTTONDOWN: {
            i32 pos[2];
            GetCursorPos(pos);
            ScreenToClient(wnd, pos);
            push(s, (f32)pos[0]/(f32)w, (f32)pos[1]/(f32)h);
            dirty = 1;
        } break;
        case WM_RBUTTONDOWN: {
            pop(s);
            dirty = 1;
        } break;
        }
        TranslateMessage(&m);
        DispatchMessageA(&m);

        if (dirty) {
            render(s, w, h);
            SwapBuffers(dc);
            dirty = 0;
        }
    }
}
#endif  // _WIN32
