/* Tiny, freestanding Windows OpenGL 3.3 demo
 * This is free and unencumbered software released into the public domain.
 */
#include <windows.h>
#include <GL/gl.h>

typedef unsigned char           u8;
typedef signed char             s8;
typedef unsigned short int      u16;
typedef signed short int        s16;
typedef unsigned int            u32;
typedef signed int              s32;
typedef unsigned long long int  u64;
typedef signed long long int    s64;

#define FATAL(msg)                                      \
    do {                                                \
        MessageBoxA(0, msg, "Fatal Error", MB_OK);      \
        ExitProcess(-1);                                \
    } while (0)

static void
puts(char *s)
{
    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(stdout, s, lstrlen(s), (DWORD[]){0}, 0);
    WriteFile(stdout, "\n", 1, (DWORD[]){0}, 0);
}

#define GL_COMPILE_STATUS   0x8B81
#define GL_LINK_STATUS      0x8B82
#define GL_FRAGMENT_SHADER  0x8B30
#define GL_VERTEX_SHADER    0x8B31
#define GL_ARRAY_BUFFER     0x8892
#define GL_STATIC_DRAW      0x88E4

typedef ptrdiff_t GLsizeiptr;

static GLuint (*glCreateShader)(GLenum);
static void (*glShaderSource)(GLuint, GLsizei, char **, GLint *);
static void (*glCompileShader)(GLuint);
static GLuint (*glCreateProgram)(void);
static void (*glAttachShader)(GLuint, GLuint);
static void (*glLinkProgram)(GLuint);
static GLuint (*glGetUniformLocation)(GLuint, char *);
static void (*glUseProgram)(GLuint);
static void (*glGenVertexArrays)(GLsizei, GLuint *);
static void (*glBindVertexArray)(GLuint);
static void (*glGenBuffers)(GLsizei, GLuint *);
static void (*glBindBuffer)(GLenum, GLuint);
static void (*glBufferData)(GLenum, GLsizeiptr size, void *, GLenum);
static void (*glVertexAttribPointer)(GLuint, GLint, GLenum, GLboolean, GLsizei, void *);
static void (*glEnableVertexAttribArray)(GLuint);
static void (*glUniform1f)(GLint, float);

#ifndef NDEBUG
static void (*glGetProgramiv)(GLuint, GLenum, GLint *);
static void (*glGetProgramInfoLog)(GLuint, GLsizei, GLsizei *, char *);
static void (*glGetShaderiv)(GLuint, GLenum, GLint *);
static void (*glGetShaderInfoLog)(GLuint, GLsizei, GLsizei *, char *);
#endif

static GLuint
compile_shader(GLenum type, char *source)
{
    GLuint shader = glCreateShader(type);
    glShaderSource(shader, 1, &source, NULL);
    glCompileShader(shader);
#ifndef NDEBUG
    GLint param;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &param);
    if (!param) {
        char log[4096];
        glGetShaderInfoLog(shader, sizeof(log), NULL, log);
        FATAL(log);
    }
#endif
    return shader;
}

static GLuint
link_program(GLuint vert, GLuint frag)
{
    GLuint program = glCreateProgram();
    glAttachShader(program, vert);
    glAttachShader(program, frag);
    glLinkProgram(program);
#ifndef NDEBUG
    GLint param;
    glGetProgramiv(program, GL_LINK_STATUS, &param);
    if (!param) {
        char log[4096];
        glGetProgramInfoLog(program, sizeof(log), NULL, log);
        FATAL(log);
    }
#endif
    return program;
}

static struct {
    GLuint u_angle;
    float angle;
} context;

static void
game_init(void)
{
    /* Compile and link OpenGL program */
    char *vert_shader =
        "#version 330\n"
        "layout(location = 0) in vec2 point;\n"
        "uniform float angle;\n"
        "void main() {\n"
        "    mat2 rotate = mat2(cos(angle), -sin(angle),\n"
        "                       sin(angle), cos(angle));\n"
        "    gl_Position = vec4(0.75 * rotate * point, 0.0, 1.0);\n"
        "}\n";
    char *frag_shader =
        "#version 330\n"
        "out vec4 color;\n"
        "void main() {\n"
        "    color = vec4(0.75, 0.15, 0.15, 0);\n"
        "}\n";
    GLuint vert = compile_shader(GL_VERTEX_SHADER, vert_shader);
    GLuint frag = compile_shader(GL_FRAGMENT_SHADER, frag_shader);
    GLuint program = link_program(vert, frag);
    glUseProgram(program);
    context.u_angle = glGetUniformLocation(program, "angle");

    float SQUARE[] = {
        -1.0f,  1.0f,
        -1.0f, -1.0f,
        1.0f,  1.0f,
        1.0f, -1.0f
    };
    GLuint vao_point;
    glGenVertexArrays(1, &vao_point);
    glBindVertexArray(vao_point);
    GLuint vbo_point;
    glGenBuffers(1, &vbo_point);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_point);
    glBufferData(GL_ARRAY_BUFFER, sizeof(SQUARE), SQUARE, GL_STATIC_DRAW);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, 0);
    glEnableVertexAttribArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}

static void
game_render(void)
{
    glClearColor(0.1, 0.1, 0.1, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    glUniform1f(context.u_angle, context.angle += 0.01);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

#define WGL_CONTEXT_MAJOR_VERSION_ARB          0x2091
#define WGL_CONTEXT_MINOR_VERSION_ARB          0x2092
#define WGL_CONTEXT_FLAGS_ARB                  0x2094
#define WGL_CONTEXT_PROFILE_MASK_ARB           0x9126
#define WGL_CONTEXT_FLAGS_ARB                  0x2094

#define WGL_CONTEXT_CORE_PROFILE_BIT_ARB       0x0001
#define WGL_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB 0x0002

static BOOL win32_opengl_initialized;

static void
win32_opengl_init(HDC hdc)
{
    PIXELFORMATDESCRIPTOR pdf = {
        .nSize = sizeof(pdf),
        .nVersion = 1,
        .dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER,
        .iPixelType = PFD_TYPE_RGBA,
        .cColorBits = 32,
        .cDepthBits = 24,
        .cStencilBits = 8,
        .iLayerType = PFD_MAIN_PLANE,
    };
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, &pdf), &pdf);
    HGLRC old = wglCreateContext(hdc);
    wglMakeCurrent(hdc, old);
    int attribs[] = {
        WGL_CONTEXT_MAJOR_VERSION_ARB, 3,
        WGL_CONTEXT_MINOR_VERSION_ARB, 3,
        WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
        WGL_CONTEXT_FLAGS_ARB, WGL_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB,
        0
    };
    HGLRC hglrc =
        ((HGLRC(*)(HDC, HGLRC, int *))(wglGetProcAddress("wglCreateContextAttribsARB")))
        (hdc, old, attribs);
    wglMakeCurrent(hdc, hglrc);
    wglDeleteContext(old);
    ((BOOL(*)(int))wglGetProcAddress("wglSwapIntervalEXT"))(1);
    puts((char *)glGetString(GL_VERSION));

    /* Load OpenGL 3.3 */
    glCreateShader = (void *)wglGetProcAddress("glCreateShader");
    glShaderSource = (void *)wglGetProcAddress("glShaderSource");
    glCompileShader = (void *)wglGetProcAddress("glCompileShader");
    glCreateProgram = (void *)wglGetProcAddress("glCreateProgram");
    glAttachShader = (void *)wglGetProcAddress("glAttachShader");
    glLinkProgram = (void *)wglGetProcAddress("glLinkProgram");
    glGetUniformLocation = (void *)wglGetProcAddress("glGetUniformLocation");
    glUseProgram = (void *)wglGetProcAddress("glUseProgram");
    glGenVertexArrays = (void *)wglGetProcAddress("glGenVertexArrays");
    glBindVertexArray = (void *)wglGetProcAddress("glBindVertexArray");
    glGenBuffers = (void *)wglGetProcAddress("glGenBuffers");
    glBindBuffer = (void *)wglGetProcAddress("glBindBuffer");
    glBufferData = (void *)wglGetProcAddress("glBufferData");
    glVertexAttribPointer = (void *)wglGetProcAddress("glVertexAttribPointer");
    glEnableVertexAttribArray = (void *)wglGetProcAddress("glEnableVertexAttribArray");
    glUniform1f = (void *)wglGetProcAddress("glUniform1f");

#ifndef NDEBUG
    glGetShaderiv = (void *)wglGetProcAddress("glGetShaderiv");
    glGetShaderInfoLog = (void *)wglGetProcAddress("glGetShaderInfoLog");
    glGetProgramiv = (void *)wglGetProcAddress("glGetProgramiv");
    glGetProgramInfoLog = (void *)wglGetProcAddress("glGetProgramInfoLog");
#endif

    win32_opengl_initialized = TRUE;
}

static LRESULT CALLBACK
win32_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
        case WM_CREATE:
            win32_opengl_init(GetDC(hwnd));
            game_init();
            break;
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
            // FIXME: alt-f4
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wparam, lparam);
    }
    return 0;
}

static HWND
win32_window_init(void)
{
    char classname[2] = {'m'};
    WNDCLASS wndclass = {
        .style = CS_OWNDC,
        .lpfnWndProc = win32_wndproc,
        .lpszClassName = classname,
        .hCursor = LoadCursor(0, IDC_ARROW),
        .hIcon = LoadIcon(0, IDI_INFORMATION),
    };
    RegisterClass(&wndclass);
    int size = 800;
    int x = (GetSystemMetrics(SM_CXSCREEN) - size) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - size) / 2;
    DWORD style = WS_OVERLAPPED | WS_VISIBLE | WS_MINIMIZEBOX | WS_SYSMENU;
    HWND hwnd = CreateWindow(classname, "Main", style, x, y, size, size, 0, 0, 0, 0);
    return hwnd;
}

static void
win32_exit(int code)
{
    ExitProcess(code);
}

int WINAPI
WinMainCRTStartup(void)
{
    HDC hdc = GetDC(win32_window_init());
    for (;;) {
        MSG msg;
        while (PeekMessage(&msg, 0, 0, 0, TRUE)) {
            if (msg.message == WM_QUIT)
                win32_exit(0);
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (win32_opengl_initialized) {
            game_render();
            SwapBuffers(hdc);
        }
    }
    return 0;
}
