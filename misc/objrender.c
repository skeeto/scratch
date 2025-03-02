// Minimal wavefront OBJ parser and renderer (OpenGL 1.1)
//
// linux: $ cc -o demo objrender.c $(sdl2-config --cflags --libs) -lGL
// w64dk: $ cc -o demo objrender.c $(sdl2-config --cflags --libs) -lopengl32
// usage: $ ./demo teapot.obj
//
// Models must have normals (vn) and triangle faces.
//
// Ref: https://github.com/kevinroast/phoria.js/blob/master/teapot.obj
// Ref: https://chuck.stanford.edu/chugl/examples/data/models/suzanne.obj
// Ref: https://casual-effects.com/data/
// Ref: https://en.wikipedia.org/wiki/Wavefront_.obj_file
// This is free and unencumbered software released into the public domain.
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define S(s)            (Str){s, sizeof(s)-1}

typedef struct {
    char    *beg;
    char    *end;
    jmp_buf *oom;
} Arena;

static void *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = (uintptr_t)a->end & (align - 1);
    if (count >= (a->end - a->beg - pad)/size) {
        longjmp(*a->oom, 1);
    }
    return memset(a->end -= pad + count*size, 0, count*size);
}

typedef struct {
    char     *data;
    ptrdiff_t len;
} Str;

static Str span(char *beg, char *end)
{
    Str r = {0};
    r.data = beg;
    r.len  = beg ? end-beg : 0;
    return r;
}

static _Bool equals(Str a, Str b)
{
    return a.len==b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

static Str trimleft(Str s)
{
    for (; s.len && *s.data<=' '; s.data++, s.len--) {}
    return s;
}

static Str trimright(Str s)
{
    for (; s.len && s.data[s.len-1]<=' '; s.len--) {}
    return s;
}

static Str substring(Str s, ptrdiff_t i)
{
    if (i) {
        s.data += i;
        s.len  -= i;
    }
    return s;
}

typedef struct {
    Str   head;
    Str   tail;
    _Bool ok;
} Cut;

static Cut cut(Str s, char c)
{
    Cut r = {0};
    if (!s.len) return r;  // null pointer special case
    char *beg = s.data;
    char *end = s.data + s.len;
    char *cut = beg;
    for (; cut<end && *cut!=c; cut++) {}
    r.ok   = cut < end;
    r.head = span(beg, cut);
    r.tail = span(cut+r.ok, end);
    return r;
}

static int32_t parseint(Str s)
{
    uint32_t r    = 0;
    int32_t  sign = 1;
    for (ptrdiff_t i = 0; i < s.len; i++) {
        switch (s.data[i]) {
        case '+':            break;
        case '-': sign = -1; break;
        default : r = 10*r + s.data[i] - '0';
        }
    }
    return r * sign;
}

static float expt10(int32_t e)
{
    float   y = 1.0f;
    float   x = e<0 ? 0.1f : e>0 ? 10.0f : 1.0f;
    int32_t n = e<0 ? e : -e;
    for (; n < -1; n /= 2) {
        y *= n%2 ? x : 1.0f;
        x *= x;
    }
    return x * y;
}

static float parsefloat(Str s)
{
    float r    = 0.0f;
    float sign = 1.0f;
    float exp  = 0.0f;
    for (ptrdiff_t i = 0; i < s.len; i++) {
        switch (s.data[i]) {
        case '+':            break;
        case '-': sign = -1; break;
        case '.': exp  =  1; break;
        case 'E':
        case 'e': exp  = exp ? exp : 1.0f;
                  exp *= expt10(parseint(substring(s, i+1)));
                  i    = s.len;
                  break;
        default : r = 10.0f*r + (s.data[i] - '0');
                  exp *= 0.1f;
        }
    }
    return sign * r * (exp ? exp : 1.0f);
}

typedef struct {
    float v[3];
} Vert;

static Vert parsevert(Str s)
{
    Vert r = {0};
    Cut c = cut(trimleft(s), ' ');
    r.v[0] = parsefloat(c.head);
    c = cut(trimleft(c.tail), ' ');
    r.v[1] = parsefloat(c.head);
    c = cut(trimleft(c.tail), ' ');
    r.v[2] = parsefloat(c.head);
    return r;
}

typedef struct {
    int32_t v[3];
    int32_t n[3];
} Face;

static Face parseface(Str s, ptrdiff_t nverts, ptrdiff_t nnorms)
{
    Face r      = {0};
    Cut  fields = {0};
    fields.tail = s;
    for (int i = 0; i < 3; i++) {
        fields = cut(trimleft(fields.tail), ' ');
        Cut elem = cut(fields.head, '/');
        r.v[i] = parseint(elem.head);
        elem = cut(elem.tail, '/');  // skip texture
        elem = cut(elem.tail, '/');
        r.n[i] = parseint(elem.head);

        // Process relative subscripts
        if (r.v[i] < 0) {
            r.v[i] = (int32_t)(r.v[i] + 1 + nverts);
        }
        if (r.n[i] < 0) {
            r.n[i] = (int32_t)(r.n[i] + 1 + nnorms);
        }
    }
    return r;
}

typedef struct {
    Vert     *verts;
    ptrdiff_t nverts;
    Vert     *norms;
    ptrdiff_t nnorms;
    Face     *faces;
    ptrdiff_t nfaces;
} Model;

static Model parseobj(Arena *a, Str obj)
{
    Model m     = {0};
    Cut   lines = {0};

    lines.tail = obj;
    while (lines.tail.len) {
        lines = cut(lines.tail, '\n');
        Cut fields = cut(trimright(lines.head), ' ');
        Str kind = fields.head;
        if (equals(S("v"), kind)) {
            m.nverts++;
        } else if (equals(S("vn"), kind)) {
            m.nnorms++;
        } else if (equals(S("f"), kind)) {
            m.nfaces++;
        }
    }

    m.verts  = new(a, m.nverts, Vert);
    m.norms  = new(a, m.nnorms, Vert);
    m.faces  = new(a, m.nfaces, Face);
    m.nverts = m.nnorms = m.nfaces = 0;

    lines.tail = obj;
    while (lines.tail.len) {
        lines = cut(lines.tail, '\n');
        Cut fields = cut(trimright(lines.head), ' ');
        Str kind = fields.head;
        if (equals(S("v"), kind)) {
            m.verts[m.nverts++] = parsevert(fields.tail);
        } else if (equals(S("vn"), kind)) {
            m.norms[m.nnorms++] = parsevert(fields.tail);
        } else if (equals(S("f"), kind)) {
            m.faces[m.nfaces++] = parseface(fields.tail, m.nverts, m.nnorms);
        }
    }
    return m;
}

typedef struct {  // GL_N3F_V3F
    Vert n, v;
} N3FV3F[3];

typedef struct {
    N3FV3F   *data;
    ptrdiff_t len;
} N3FV3Fs;

static N3FV3Fs n3fv3fize(Arena *a, Model m)
{
    N3FV3Fs r = {0};
    r.data = new(a, m.nfaces, N3FV3F);
    for (ptrdiff_t f = 0; f < m.nfaces; f++) {
        _Bool valid = 1;
        for (int i = 0; i < 3; i++) {
            valid &= m.faces[f].v[i]>0 && m.faces[f].v[i]<=m.nverts;
            valid &= m.faces[f].n[i]>0 && m.faces[f].n[i]<=m.nnorms;
        }

        if (valid) {
            ptrdiff_t t = r.len++;
            for (int i = 0; i < 3; i++) {
                r.data[t][i].n = m.norms[m.faces[f].n[i]-1];
                r.data[t][i].v = m.verts[m.faces[f].v[i]-1];
            }
        }
    }
    return r;
}


#if __AFL_COMPILER
// $ afl-gcc-fast -g3 -fsanitize=undefined objrender.c
// $ mkdir i
// $ printf 'v 1.2 -3.4 5.6e7\nf 1//2 3//4 5//6\n' >i/sample
// $ afl-fuzz -ii -oo ./a.out
#include <stdlib.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    int   cap = 1<<20;
    char *mem = malloc(cap);
    char *src = 0;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        src = realloc(src, len);
        memcpy(src, buf, len);
        Arena a = {mem, mem+cap, &(jmp_buf){}};
        if (!setjmp(*a.oom)) {
            Model m = parseobj(&a, (Str){src, len});
            n3fv3fize(&a, m);
        }
    }
}


#else  // SDL2
#include "SDL.h"
#include "SDL_opengl.h"
#include <float.h>

static Str loadfile(Arena *a, SDL_RWops *f)
{
    Str r   = {0};
    r.data  = a->beg;
    r.len   = a->end - a->beg;  // NOTE: SDL_RWread broken when len>=4G
    r.len   = SDL_RWread(f, r.data, 1, r.len);
    a->beg += r.len;
    return r;
}

static void perspective(double fovy, double aspect, double znear, double zfar)
{

    double h = znear * SDL_tan(fovy / 360 * 3.141592653589793);
    double w = h * aspect;
    glFrustum(-w, +w, -h, +h, znear, zfar);
}

static void xDwmFlush(void) {}

int main(int argc, char **argv)
{
    jmp_buf oom;
    if (setjmp(oom)) {
        SDL_ShowSimpleMessageBox(
            SDL_MESSAGEBOX_ERROR,
            "Out of Memory",
            "Not enough memory to display this model.",
            0
        );
        return 1;
    }

    ptrdiff_t cap  = (ptrdiff_t)1<<30;
    char     *mem  = SDL_malloc(cap);
    Arena     perm = {mem, mem+cap, &oom};

    char *objpath = argc > 1 ? argv[1] : "/dev/stdin";
    SDL_RWops *objfile = SDL_RWFromFile(objpath, "rb");
    if (!objfile) {
        SDL_Log("SDL_RWFromFile(): %s", SDL_GetError());
        return 1;
    }
    Str obj = loadfile(&perm, objfile);
    SDL_RWclose(objfile);

    Model m = parseobj(&perm, obj);
    SDL_Log("%d verts, %d norms, %d faces",
        (int)m.nverts, (int)m.nnorms, (int)m.nfaces
    );

    if (SDL_Init(SDL_INIT_VIDEO)) {
        SDL_Log("SDL_Init(): %s", SDL_GetError());
        return 1;
    }

    int width  = 1280;
    int height = 720;
    SDL_Window *w = SDL_CreateWindow(
        "OBJ Render", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        width, height, SDL_WINDOW_OPENGL
    );
    if (!w) {
        SDL_Log("SDL_CreateWindow(): %s", SDL_GetError());
        return 1;
    }

    SDL_GLContext *gl = SDL_GL_CreateContext(w);
    if (!gl) {
        SDL_Log("SDL_GL_CreateContext(): %s", SDL_GetError());
        return 1;
    }
    SDL_GL_SetSwapInterval(1);

    // Workaround for awful SDL stuttering on Windows 7 and later.
    // https://github.com/libsdl-org/SDL/issues/5797
    void (*DwmFlush)(void) = 0;
    void *dwmapi = SDL_LoadObject("dwmapi.dll");
    if (dwmapi) {
        DwmFlush = SDL_LoadFunction(dwmapi, "DwmFlush");
    }
    DwmFlush = DwmFlush ? DwmFlush : xDwmFlush;

    N3FV3Fs triangles = n3fv3fize(&perm, m);

    // Determine model center and scale
    float mid[3] = {0};
    float min[3] = {+FLT_MAX, +FLT_MAX, +FLT_MAX};
    float max[3] = {-FLT_MAX, -FLT_MAX, -FLT_MAX};
    float scale  = FLT_MAX;
    for (ptrdiff_t t = 0; t < triangles.len; t++) {
        for (int v = 0; v < 3; v++) {
            for (int i = 0; i < 3; i++) {
                float r = triangles.data[t][v].v.v[i];
                min[i] = min[i]<r ? min[i] : r;
                max[i] = max[i]>r ? max[i] : r;
            }
        }
    }
    for (int i = 0; i < 3; i++) {
        float size = max[i] - min[i];
        mid[i] = min[i] + size/2;
        scale = scale<size ? scale : size;
    }
    SDL_Log("%d triangles [%+.2g %+.2g %+.2g] x%.3g\n",
        (int)triangles.len,
        (double)mid[0], (double)mid[1], (double)mid[2],
        (double)scale
    );

    glEnable(GL_LIGHTING);
    glEnable(GL_NORMALIZE);
    glEnable(GL_LIGHT0);
    glLightfv(GL_LIGHT0, GL_AMBIENT,  (GLfloat[]){1, 1, 1, 1});
    glLightfv(GL_LIGHT0, GL_DIFFUSE,  (GLfloat[]){1, 1, 1, 1});
    glLightfv(GL_LIGHT0, GL_POSITION, (GLfloat[]){3, 3, 2, 1});

    glEnable(GL_DEPTH_TEST);
    glMatrixMode(GL_PROJECTION);
    perspective(35, (double)width/height, 1, 6);
    glViewport(0, 0, width, height);
    glMatrixMode(GL_MODELVIEW);

    for (;;) {
        for (SDL_Event e; SDL_PollEvent(&e);) {
            switch (e.type) {
            case SDL_QUIT:
                return 0;
            case SDL_KEYDOWN:
                switch (e.key.keysym.sym) {
                case 'q':
                    return 0;
                }
            // TODO: use quaternions to enable mouse look
            }
        }

        glClearColor(0, 0, 0, 0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        glLoadIdentity();
        glTranslatef(0.0f, 0.0f, -3.0f);
        glScalef(1/scale, 1/scale, 1/scale);
        glTranslatef(-mid[0], -mid[1], -mid[2]);
        float rotate = (float)(SDL_GetTicks64() % (30 * 360)) / 30;
        glRotatef(rotate, 0.0f, 1.0f, 0.0f);

        glInterleavedArrays(GL_N3F_V3F, 0, triangles.data);
        glDrawArrays(GL_TRIANGLES, 0, (GLsizei)(triangles.len*3));

        SDL_GL_SwapWindow(w);
        DwmFlush();
    }
}
#endif
