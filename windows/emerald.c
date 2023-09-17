// Icosphere mesh generator and "emerald" renderer (Windows)
//
// $ cc -Os -ffast-math -fno-builtin -s -mwindows -nostartfiles
//      -o emerald.exe emerald.c -lopengl32
//
// Uses GCC extensions: typeof, expr _Alignof, statement expr, inline asm,
// func attributes, and some built-ins. Requires GCC or Clang.
//
// "The Official Guide to Learning OpenGL, Version 1.1" (1997)
// http://blog.andreaskahler.com/2009/06/creating-icosphere-mesh-in-code.html
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdint.h>

#define sizeof(x)  (ptrdiff_t)sizeof(x)
#define countof(a) (sizeof(a) / sizeof(*(a)))

static void copy(void *restrict dst, void *restrict src, ptrdiff_t len)
{
    if (len) __builtin_memcpy(dst, src, len);
}

static float sqrtf(float x)
{
    asm ("sqrtss %1, %0" : "=x"(x) : "x"(x));
    return x;
}

#define new(...)           new_(__VA_ARGS__, new3, new2)(__VA_ARGS__)
#define new_(a,b,c,d, ...) d
#define new3(h, t, n)      (t *)alloc(h, sizeof(t), _Alignof(t), n)
#define new2(h, t)         (t *)alloc(h, sizeof(t), _Alignof(t), 1)

typedef struct {
    char *p;
} arena;

__attribute((malloc, alloc_size(2, 4), alloc_align(3)))
static void *alloc(arena *a, ptrdiff_t size, ptrdiff_t align, ptrdiff_t count)
{
    a->p += -(uintptr_t)a->p & (align - 1);
    void *r = a->p;
    a->p += size * count;
    return __builtin_memset(r, 0, size*count);
}

#define push(d, heap) ({ \
    typeof(d)    d_ = (d); \
    typeof(heap) h_ = (heap); \
    if (d_->len == d_->cap) { \
        push_(d_, sizeof(*d_->data), _Alignof(*d_->data), h_); \
    } \
    d_->data + d_->len++; \
})

static void push_(void *header, int size, int align, arena *heap)
{
    struct {
        void *data;
        int   len;
        int   cap;
    } slice;
    copy(&slice, header, sizeof(slice));
    slice.cap += !slice.cap << 3;
    void *data = alloc(heap, 2*size, align, slice.cap);
    copy(data, slice.data, size*slice.len);
    slice.data = data;
    slice.cap *= 2;
    copy(header, &slice, sizeof(slice));
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
    float length = sqrtf(p.x*p.x + p.y*p.y + p.z*p.z);
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
    point *data;
    int    len;
    int    cap;
} vertices;

typedef struct {
    triangle *data;
    int       len;
    int       cap;
} triangles;

typedef struct {
    map      *map;
    vertices  verts;
    triangles faces;
} platonic;

static int midpoint(platonic *mesh, int p1, int p2, arena *heap)
{
    int *i = upsert(&mesh->map, p1, p2, heap);
    if (!*i) {
        point point1 = mesh->verts.data[p1];
        point point2 = mesh->verts.data[p2];
        point middle = scale(add(point1, point2), 0.5f);
        *i = mesh->verts.len;
        *push(&mesh->verts, heap) = norm(middle);
    }
    return *i;
}

static platonic *newicosphere(int granularity, arena *heap)
{
    platonic *mesh = new(heap, platonic);

    #define R 1.618034f  // golden ratio
    #define N 1.902113f  // vector magnitude
    static const point verts[] = {
        {-1/N, R/N, 0/N}, {1/N, R/N, 0/N}, {-1/N,-R/N, 0/N}, { 1/N,-R/N, 0/N},
        { 0/N,-1/N, R/N}, {0/N, 1/N, R/N}, { 0/N,-1/N,-R/N}, { 0/N, 1/N,-R/N},
        { R/N, 0/N,-1/N}, {R/N, 0/N, 1/N}, {-R/N, 0/N,-1/N}, {-R/N, 0/N, 1/N},
    };
    int nverts = countof(verts);
    mesh->verts = (vertices){(point *)verts, nverts, nverts};

    static const triangle faces[] = {
        { 0, 11,  5}, { 0,  5,  1}, { 0,  1,  7}, { 0,  7, 10}, { 0, 10, 11},
        { 1,  5,  9}, { 5, 11,  4}, {11, 10,  2}, {10,  7,  6}, { 7,  1,  8},
        { 3,  9,  4}, { 3,  4,  2}, { 3,  2,  6}, { 3,  6,  8}, { 3,  8,  9},
        { 4,  9,  5}, { 2,  4, 11}, { 6,  2, 10}, { 8,  6,  7}, { 9,  8,  1},
    };
    int nfaces = countof(faces);
    mesh->faces = (triangles){(triangle *)faces, nfaces, nfaces};

    for (int i = 0; i < granularity; i++) {
        triangles new = {0};
        for (int j = 0; j < mesh->faces.len; j++) {
            triangle tri = mesh->faces.data[j];
            int a = midpoint(mesh, tri.v1, tri.v2, heap);
            int b = midpoint(mesh, tri.v2, tri.v3, heap);
            int c = midpoint(mesh, tri.v3, tri.v1, heap);
            *push(&new, heap) = (triangle){tri.v1, a, c};
            *push(&new, heap) = (triangle){tri.v2, b, a};
            *push(&new, heap) = (triangle){tri.v3, c, b};
            *push(&new, heap) = (triangle){a, b, c};
        }
        mesh->faces = new;
    }
    return mesh;
}

__attribute((stdcall))
static LRESULT proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_NCHITTEST:;
        LRESULT hit = DefWindowProc(hwnd, msg, wparam, lparam);
        return hit==HTCLIENT ? HTCAPTION : hit;
    case WM_CLOSE:
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wparam, lparam);
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

__attribute((force_align_arg_pointer))
void WinMainCRTStartup(void)
{
    DWORD type = MEM_RESERVE | MEM_COMMIT;
    void *heap = VirtualAlloc(0, 1<<24, type, PAGE_READWRITE);
    arena init = {heap};

    WNDCLASS *wc = new(&init, WNDCLASS);
    wc->style = CS_OWNDC;
    wc->lpfnWndProc = proc;
    wc->lpszClassName = "icosphere";
    wc->hCursor = LoadCursor(0, IDC_ARROW);
    RegisterClass(wc);

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    int size = (w<h ? w : h) * 9 / 10;
    int x = (w - size) / 2;
    int y = (h - size) / 2;
    DWORD style = WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU;
    HWND hwnd = CreateWindow(
        "icosphere", "Emerald", style, x, y, size, size, 0, 0, 0, 0
    );
    HDC hdc = GetDC(hwnd);

    PIXELFORMATDESCRIPTOR *pfd = new(&init, PIXELFORMATDESCRIPTOR);
    pfd->nSize = sizeof(pfd);
    pfd->nVersion = 1;
    pfd->dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd->iPixelType = PFD_TYPE_RGBA;
    pfd->cColorBits = 32;
    pfd->cDepthBits = 24;
    pfd->cStencilBits = 8;
    pfd->iLayerType = PFD_MAIN_PLANE;
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, pfd), pfd);
    HGLRC old = wglCreateContext(hdc);
    wglMakeCurrent(hdc, old);
    ShowWindow(hwnd, SW_NORMAL);

    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);
    glEnable(GL_NORMALIZE);
    glEnable(GL_LIGHTING);
    glShadeModel(GL_FLAT);
    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_NORMAL_ARRAY);

    glEnable(GL_LIGHT0);
    static const float gray[]     = { 0.8f,  0.8f,  0.8f,  1.0f};
    static const float green[]    = { 0.3f,  0.5f,  0.0f,  1.0f};
    static const float position[] = {+0.2f, +0.3f, -8.0f, +0.2f};
    glLightfv(GL_LIGHT0, GL_AMBIENT,  green);
    glLightfv(GL_LIGHT0, GL_DIFFUSE,  green);
    glLightfv(GL_LIGHT0, GL_POSITION, position);
    glMaterialfv(GL_FRONT_AND_BACK, GL_SPECULAR, gray);
    glMaterialf(GL_FRONT_AND_BACK, GL_SHININESS, 1.5f);

    arena perm = {heap};
    timer *timer = newtimer(&perm);

    for (;;) {
        for (MSG msg; PeekMessage(&msg, 0, 0, 0, TRUE);) {
            if (msg.message == WM_QUIT) {
                ExitProcess(0);
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        arena frame = perm;
        double now = getseconds(timer);

        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();
        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();

        float xrot = (float)(now *  7);
        float yrot = (float)(now * 23);
        float zrot = (float)(now *  5);
        glRotatef(xrot, 1.0f, 0.0f, 0.0f);
        glRotatef(yrot, 0.0f, 1.0f, 0.0f);
        glRotatef(zrot, 0.0f, 0.0f, 1.0f);
        glScalef(0.8f, 0.8f, 0.8f);

        int granularity = (int)(now / 20 * 6) % 6;
        platonic *sphere = newicosphere(granularity, &frame);

        point *verts = new(&frame, point, sphere->faces.len*3);
        point *norms = new(&frame, point, sphere->faces.len*3);
        for (int i = 0; i < sphere->faces.len; i++) {
            point p1 = sphere->verts.data[sphere->faces.data[i].v1];
            point p2 = sphere->verts.data[sphere->faces.data[i].v2];
            point p3 = sphere->verts.data[sphere->faces.data[i].v3];
            verts[i*3+0] = p3;
            verts[i*3+1] = p2;
            verts[i*3+2] = p1;
            norms[i*3+2] = cross(diff(p1, p2), diff(p1, p3));
        }
        glVertexPointer(3, GL_FLOAT, 0, verts);
        glNormalPointer(GL_FLOAT, 0, norms);
        glDrawArrays(GL_TRIANGLES, 0, sphere->faces.len*3);

        #if 0  // wireframe outline
        glDisable(GL_LIGHTING);
        glLineWidth(2);
        glBegin(GL_LINES);
        glColor3f(1.0f, 1.0f, 1.0f);
        for (int i = 0; i < sphere->faces.len; i++) {
            point p1 = sphere->verts.data[sphere->faces.data[i].v1];
            point p2 = sphere->verts.data[sphere->faces.data[i].v2];
            point p3 = sphere->verts.data[sphere->faces.data[i].v3];
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
