// Icosphere mesh generator and "emerald" renderer (Windows)
//
// $ cc -O2 -ffast-math -fno-builtin -s -mwindows -nostartfiles
//      -o emerald.exe emerald.c -lglu32 -lopengl32
// $ cl /O2 /fp:fast /Zc:preprocessor /GS- emerald.c /link /subsystem:windows
//      kernel32.lib user32.lib gdi32.lib opengl32.lib glu32.lib
//
// "The Official Guide to Learning OpenGL, Version 1.1" (1997)
// http://blog.andreaskahler.com/2009/06/creating-icosphere-mesh-in-code.html
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <GL/glu.h>
#include <stdint.h>

#define sizeof(x)  (ptrdiff_t)sizeof(x)
#define countof(a) (sizeof(a) / sizeof(*(a)))

static float xsqrtf(float x)
{
    float e = 1;
    e = (e + x/e) / 2;  e = (e + x/e) / 2;
    e = (e + x/e) / 2;  e = (e + x/e) / 2;
    return e;
}

#define new(...)           new_(__VA_ARGS__, new3, new2)(__VA_ARGS__)
#define new_(a,b,c,d, ...) d
#define new3(h, t, n)      (t *)alloc(h, sizeof(t), _Alignof(t), n)
#define new2(h, t)         (t *)alloc(h, sizeof(t), _Alignof(t), 1)

typedef struct {
    char *p;
} arena;

#if __GNUC__
__attribute((malloc, alloc_size(2, 4), alloc_align(3)))
#endif
static void *alloc(arena *a, ptrdiff_t size, ptrdiff_t align, ptrdiff_t count)
{
    a->p += -(uintptr_t)a->p & (align - 1);
    char *r = a->p;
    char *e = a->p += size * count;
    for (char *p = r; p < e; p++) {
        *p = 0;
    }
    return r;
}

typedef struct map map;
typedef struct map {
    map *child[4];
    int  k1, k2;
    int  value;
} map;

static int *upsert(map **m, int p1, int p2, arena *heap)
{
    int k1 = p1<p2 ? p1 : p2;
    int k2 = p1>p2 ? p1 : p2;
    uint64_t hash = (uint64_t)k1<<32 | (uint32_t)k2;
    hash *= 1111111111111111111u;
    for (; *m; hash = hash>>62 | hash<<2) {
        if ((*m)->k1==k1 && (*m)->k2==k2) {
            return &(*m)->value;
        }
        *m = (*m)->child[hash>>62];
    }
    *m = new(heap, map);
    (*m)->k1 = k1;
    (*m)->k2 = k2;
    return &(*m)->value;
}

typedef struct {
    float x, y, z;
} point;

static point scale(point p, float s)
{
    p.x *= s;
    p.y *= s;
    p.z *= s;
    return p;
}

static point norm(point p)
{
    float length = xsqrtf(p.x*p.x + p.y*p.y + p.z*p.z);
    return scale(p, 1/length);
}

static point diff(point a, point b)
{
    point r;
    r.x = a.x - b.x;
    r.y = a.y - b.y;
    r.z = a.z - b.z;
    return r;
}

static point add(point a, point b)
{
    point p;
    p.x = a.x + b.x;
    p.y = a.y + b.y;
    p.z = a.z + b.z;
    return p;
}

static point cross(point a, point b)
{
    point r;
    r.x = a.y*b.z - b.y*a.z;
    r.y = b.x*a.z - a.x*b.z;
    r.z = a.x*b.y - b.x*a.y;
    return r;
}

typedef struct {
    int v1, v2, v3;
} triangle;

typedef struct {
    map      *map;
    point    *verts;
    triangle *faces;
    int       nverts;
    int       nfaces;
} mesh;

static int midpoint(mesh *mesh, int p1, int p2, arena *heap)
{
    int *i = upsert(&mesh->map, p1, p2, heap);
    if (!*i) {
        point point1 = mesh->verts[p1];
        point point2 = mesh->verts[p2];
        point middle = scale(add(point1, point2), 0.5f);
        *i = mesh->nverts;
        mesh->verts[mesh->nverts++] = norm(middle);
    }
    return *i;
}

static mesh *newicosphere(int granularity, arena *heap)
{
    #define R 1.618034f  // golden ratio
    #define N 1.902113f  // vector magnitude
    static const point verts[] = {
        {-1/N, R/N, 0/N}, {1/N, R/N, 0/N}, {-1/N,-R/N, 0/N}, { 1/N,-R/N, 0/N},
        { 0/N,-1/N, R/N}, {0/N, 1/N, R/N}, { 0/N,-1/N,-R/N}, { 0/N, 1/N,-R/N},
        { R/N, 0/N,-1/N}, {R/N, 0/N, 1/N}, {-R/N, 0/N,-1/N}, {-R/N, 0/N, 1/N},
    };
    static const triangle faces[] = {
        { 0, 11,  5}, { 0,  5,  1}, { 0,  1,  7}, { 0,  7, 10}, { 0, 10, 11},
        { 1,  5,  9}, { 5, 11,  4}, {11, 10,  2}, {10,  7,  6}, { 7,  1,  8},
        { 3,  9,  4}, { 3,  4,  2}, { 3,  2,  6}, { 3,  6,  8}, { 3,  8,  9},
        { 4,  9,  5}, { 2,  4, 11}, { 6,  2, 10}, { 8,  6,  7}, { 9,  8,  1},
    };

    mesh *m   = new(heap, mesh);
    m->nfaces = 20 * (1 << (2 * granularity));  // 20 * 4**granularity
    m->faces  = new(heap, triangle, m->nfaces);
    m->verts  = new(heap, point, m->nfaces-8);
    for (int i = 0; i < countof(verts); i++) {
        m->verts[i] = verts[i];
    }
    m->nverts = countof(verts);
    arena scratch = *heap;  // discard futher allocations on return

    typedef struct {
        int      i;
        triangle parent;
        triangle middle;
    } icostack;
    icostack *stack = new(&scratch, icostack, granularity+1);

    int len = 0;
    for (int i = 0; i < countof(faces); i++) {
        int top = 0;
        stack[0].i = 0;
        stack[0].parent = faces[i];
        while (top >= 0) {
            switch (stack[top].i++) {
            case 0:
                if (top == granularity) {
                    m->faces[len++] = stack[top--].parent;
                    break;
                }
                triangle p = stack[top].parent;
                stack[top].middle.v1 = midpoint(m, p.v1, p.v2, &scratch);
                stack[top].middle.v2 = midpoint(m, p.v2, p.v3, &scratch);
                stack[top].middle.v3 = midpoint(m, p.v3, p.v1, &scratch);
                stack[++top].i = 0;
                stack[top].parent = stack[top-1].middle;
                break;

            case 1:
                stack[++top].i = 0;
                stack[top].parent.v1 = stack[top-1].parent.v1;
                stack[top].parent.v2 = stack[top-1].middle.v1;
                stack[top].parent.v3 = stack[top-1].middle.v3;
                break;

            case 2:
                stack[++top].i = 0;
                stack[top].parent.v1 = stack[top-1].parent.v2;
                stack[top].parent.v2 = stack[top-1].middle.v2;
                stack[top].parent.v3 = stack[top-1].middle.v1;
                break;

            case 3:
                stack[++top].i = 0;
                stack[top].parent.v1 = stack[top-1].parent.v3;
                stack[top].parent.v2 = stack[top-1].middle.v3;
                stack[top].parent.v3 = stack[top-1].middle.v2;
                break;

            case 4:
                top--;
                break;
            }
        }
    }
    return m;
}

static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;
    case WM_KEYDOWN:
        switch (wparam) {
        case 0x1b:
        case 'Q':
            PostQuitMessage(0);
            return 0;
        }
        break;
    case WM_NCHITTEST:;
        LRESULT hit = DefWindowProcA(hwnd, msg, wparam, lparam);
        return hit==HTCLIENT ? HTCAPTION : hit;
    case WM_SETCURSOR:
        SetCursor(0);
        return 1;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

typedef struct {
    int64_t base;
    double  freq;
} timer;

static timer *newtimer(arena *a)
{
    LARGE_INTEGER freq, base;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&base);
    timer *t = new(a, timer);
    t->base = base.QuadPart;
    t->freq = (double)freq.QuadPart;
    return t;
}

static double getseconds(timer *t)
{
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (double)(count.QuadPart - t->base) / t->freq;
}

#if __i386__
__attribute((force_align_arg_pointer))
#endif
void WinMainCRTStartup(void)
{
    DWORD type = MEM_RESERVE | MEM_COMMIT;
    void *heap = VirtualAlloc(0, 1<<24, type, PAGE_READWRITE);
    arena init = {heap};

    WNDCLASSA *wc = new(&init, WNDCLASSA);
    wc->lpfnWndProc = proc;
    wc->lpszClassName = "gl";
    RegisterClassA(wc);

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    DWORD style = WS_POPUP;
    HWND hwnd = CreateWindowExA(
        0, "gl", "Emerald", style, 0, 0, w, h, 0, 0, 0, 0
    );
    HDC hdc = GetDC(hwnd);

    PIXELFORMATDESCRIPTOR *pfd = new(&init, PIXELFORMATDESCRIPTOR);
    pfd->nSize = sizeof(*pfd);
    pfd->nVersion = 1;
    pfd->dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, pfd), pfd);
    wglMakeCurrent(hdc, wglCreateContext(hdc));

    // Enable 8x antialiasing if possible
    typedef int (__stdcall *cpf)(HDC, const int *, float *, int, int *, int *);
    cpf wglChoosePixelFormat;
    wglChoosePixelFormat = (cpf)wglGetProcAddress("wglChoosePixelFormatARB");
    if (wglChoosePixelFormat) {
        enum {
            WGL_DRAW_TO_WINDOW_ARB    = 0x2001,
            WGL_ACCELERATION_ARB      = 0x2003,
            WGL_SUPPORT_OPENGL_ARB    = 0x2010,
            WGL_DOUBLE_BUFFER_ARB     = 0x2011,
            WGL_FULL_ACCELERATION_ARB = 0x2027,
            WGL_SAMPLE_BUFFERS_ARB    = 0x2041,
            WGL_SAMPLES_ARB           = 0x2042,
        };
        static const int attribs[] = {
            WGL_DRAW_TO_WINDOW_ARB, GL_TRUE,
            WGL_SUPPORT_OPENGL_ARB, GL_TRUE,
            WGL_DOUBLE_BUFFER_ARB,  GL_TRUE,
            WGL_ACCELERATION_ARB,   WGL_FULL_ACCELERATION_ARB,
            WGL_SAMPLE_BUFFERS_ARB, GL_TRUE,
            WGL_SAMPLES_ARB,        8,
            0
        };
        int idx, nidx;
        wglChoosePixelFormat(hdc, attribs, 0, 1, &idx, &nidx);
        if (nidx) {
            wglMakeCurrent(0, 0);
            DestroyWindow(hwnd);
            hwnd = CreateWindowExA(
                0, "gl", "Emerald", style, 0, 0, w, h, 0, 0, 0, 0
            );
            hdc = GetDC(hwnd);
            SetPixelFormat(hdc, idx, pfd);
            HGLRC ctx = wglCreateContext(hdc);
            wglMakeCurrent(hdc, ctx);
        }
    }
    ShowWindow(hwnd, SW_NORMAL);

    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);
    glEnable(GL_NORMALIZE);
    glEnable(GL_LIGHTING);
    glShadeModel(GL_FLAT);

    glMatrixMode(GL_PROJECTION);
    gluPerspective(60, (double)w/h, 1, 20);
    glViewport(0, 0, w, h);
    glMatrixMode(GL_MODELVIEW);

    static const float gray[] = {0.8f, 0.8f, 0.8f, 1.0f};
    glMaterialfv(GL_FRONT_AND_BACK, GL_SPECULAR, gray);
    glMaterialf(GL_FRONT_AND_BACK, GL_SHININESS, 20.0f);

    {
        glEnable(GL_LIGHT0);
        static const float green[]    = { 0.3f,  0.5f,  0.0f,  1.0f};
        static const float position[] = {+3.0f, +3.0f, +2.0f, +1.0f};
        glLightfv(GL_LIGHT0, GL_AMBIENT,  green);
        glLightfv(GL_LIGHT0, GL_DIFFUSE,  green);
        glLightfv(GL_LIGHT0, GL_POSITION, position);
    }

    {
        static const float green[]    = { 0.2f,  0.3f,  0.0f,  1.0f};
        static const float position[] = {+0.0f, -3.0f, +0.0f, +0.0f};
        glEnable(GL_LIGHT1);
        glLightfv(GL_LIGHT1, GL_DIFFUSE,  green);
        glLightfv(GL_LIGHT1, GL_POSITION, position);
    }

    arena perm = {heap};
    timer *timer = newtimer(&perm);

    for (;;) {
        for (MSG msg; PeekMessageA(&msg, 0, 0, 0, TRUE);) {
            if (msg.message == WM_QUIT) {
                ExitProcess(0);
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        arena frame = perm;
        double now = getseconds(timer);

        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        glLoadIdentity();
        glTranslatef(0.0f, 0.0f, -2.2f);

        float xrot = (float)(now *  7);
        float yrot = (float)(now * 23);
        float zrot = (float)(now *  5);
        glRotatef(xrot, 1.0f, 0.0f, 0.0f);
        glRotatef(yrot, 0.0f, 1.0f, 0.0f);
        glRotatef(zrot, 0.0f, 0.0f, 1.0f);

        int granularity = (int)(now / 20 * 6) % 6;
        mesh *sphere = newicosphere(granularity, &frame);

        point *attribs = new(&frame, point, sphere->nfaces*6);
        for (int i = 0; i < sphere->nfaces; i++) {
            point p1 = sphere->verts[sphere->faces[i].v1];
            point p2 = sphere->verts[sphere->faces[i].v2];
            point p3 = sphere->verts[sphere->faces[i].v3];
            attribs[i*6+1] = p1;
            attribs[i*6+3] = p2;
            attribs[i*6+4] = cross(diff(p1, p2), diff(p1, p3));
            attribs[i*6+5] = p3;
        }
        glInterleavedArrays(GL_N3F_V3F, 0, attribs);
        glDrawArrays(GL_TRIANGLES, 0, sphere->nfaces*3);

        #if 0  // wireframe outline
        glDisable(GL_LIGHTING);
        glLineWidth(2);
        glBegin(GL_LINES);
        glColor3f(1.0f, 1.0f, 1.0f);
        for (int i = 0; i < sphere->nfaces; i++) {
            point p1 = sphere->verts[sphere->faces[i].v1];
            point p2 = sphere->verts[sphere->faces[i].v2];
            point p3 = sphere->verts[sphere->faces[i].v3];
            glVertex3fv(&p1.x);  glVertex3fv(&p3.x);
            glVertex3fv(&p2.x);  glVertex3fv(&p3.x);
        }
        glEnd();
        glEnable(GL_LIGHTING);
        #endif

        SwapBuffers(hdc);
        Sleep(1);
    }
}
