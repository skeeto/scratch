#pragma once

// Cross-platform OpenGL 3.3 / OpenGL ES 3.0 surface for just the functions
// this app uses.
//
//   - Emscripten -> <GLES3/gl3.h> (drivers provide the symbols).
//   - Anything else (macOS / Linux / Windows) -> a small SDL-backed loader.
//     Call gl_load() once after the GL context is current.

#ifdef __EMSCRIPTEN__
#  include <GLES3/gl3.h>
inline bool gl_load() { return true; }
#else
#  include <cstddef>

using GLenum     = unsigned int;
using GLbitfield = unsigned int;
using GLuint     = unsigned int;
using GLint      = int;
using GLsizei    = int;
using GLfloat    = float;
using GLboolean  = unsigned char;
using GLintptr   = std::ptrdiff_t;
using GLsizeiptr = std::ptrdiff_t;
using GLchar     = char;

#  define GL_FALSE                   0
#  define GL_TRUE                    1
#  define GL_TRIANGLES               0x0004
#  define GL_DEPTH_TEST              0x0B71
#  define GL_BLEND                   0x0BE2
#  define GL_SRC_ALPHA               0x0302
#  define GL_ONE_MINUS_SRC_ALPHA     0x0303
#  define GL_FLOAT                   0x1406
#  define GL_UNSIGNED_BYTE           0x1401
#  define GL_UNSIGNED_SHORT          0x1403
#  define GL_COLOR_BUFFER_BIT        0x4000
#  define GL_ARRAY_BUFFER            0x8892
#  define GL_ELEMENT_ARRAY_BUFFER    0x8893
#  define GL_STATIC_DRAW             0x88E4
#  define GL_DYNAMIC_DRAW            0x88E8
#  define GL_FRAGMENT_SHADER         0x8B30
#  define GL_VERTEX_SHADER           0x8B31
#  define GL_COMPILE_STATUS          0x8B81
#  define GL_LINK_STATUS             0x8B82
#  define GL_MULTISAMPLE             0x809D

// X-macro: one entry per GL function we use. (ret, suffix, paren-args)
#  define KNIGHTS_GL_FUNCS(X) \
    X(GLuint, CreateShader,            (GLenum)) \
    X(void,   ShaderSource,            (GLuint, GLsizei, const GLchar* const*, const GLint*)) \
    X(void,   CompileShader,           (GLuint)) \
    X(void,   GetShaderiv,             (GLuint, GLenum, GLint*)) \
    X(void,   GetShaderInfoLog,        (GLuint, GLsizei, GLsizei*, GLchar*)) \
    X(void,   DeleteShader,            (GLuint)) \
    X(GLuint, CreateProgram,           ()) \
    X(void,   AttachShader,            (GLuint, GLuint)) \
    X(void,   LinkProgram,             (GLuint)) \
    X(void,   GetProgramiv,            (GLuint, GLenum, GLint*)) \
    X(void,   GetProgramInfoLog,       (GLuint, GLsizei, GLsizei*, GLchar*)) \
    X(void,   DeleteProgram,           (GLuint)) \
    X(void,   BindAttribLocation,      (GLuint, GLuint, const GLchar*)) \
    X(GLint,  GetUniformLocation,      (GLuint, const GLchar*)) \
    X(void,   GenBuffers,              (GLsizei, GLuint*)) \
    X(void,   BindBuffer,              (GLenum, GLuint)) \
    X(void,   BufferData,              (GLenum, GLsizeiptr, const void*, GLenum)) \
    X(void,   BufferSubData,           (GLenum, GLintptr, GLsizeiptr, const void*)) \
    X(void,   GenVertexArrays,         (GLsizei, GLuint*)) \
    X(void,   BindVertexArray,         (GLuint)) \
    X(void,   EnableVertexAttribArray, (GLuint)) \
    X(void,   VertexAttribPointer,     (GLuint, GLint, GLenum, GLboolean, GLsizei, const void*)) \
    X(void,   VertexAttribDivisor,     (GLuint, GLuint)) \
    X(void,   DrawElementsInstanced,   (GLenum, GLsizei, GLenum, const void*, GLsizei)) \
    X(void,   UseProgram,              (GLuint)) \
    X(void,   Uniform1f,               (GLint, GLfloat)) \
    X(void,   Uniform2f,               (GLint, GLfloat, GLfloat)) \
    X(void,   DeleteVertexArrays,      (GLsizei, const GLuint*)) \
    X(void,   DeleteBuffers,           (GLsizei, const GLuint*)) \
    X(void,   Viewport,                (GLint, GLint, GLsizei, GLsizei)) \
    X(void,   ClearColor,              (GLfloat, GLfloat, GLfloat, GLfloat)) \
    X(void,   Clear,                   (GLbitfield)) \
    X(void,   Disable,                 (GLenum)) \
    X(void,   Enable,                  (GLenum)) \
    X(void,   BlendFunc,               (GLenum, GLenum))

struct GLProcs {
#  define KNIGHTS_GL_FIELD(ret, name, args) ret (*name) args = nullptr;
    KNIGHTS_GL_FUNCS(KNIGHTS_GL_FIELD)
#  undef KNIGHTS_GL_FIELD
};

extern GLProcs gl_procs;

// Make call sites look like normal GL.
#  define glCreateShader            gl_procs.CreateShader
#  define glShaderSource            gl_procs.ShaderSource
#  define glCompileShader           gl_procs.CompileShader
#  define glGetShaderiv             gl_procs.GetShaderiv
#  define glGetShaderInfoLog        gl_procs.GetShaderInfoLog
#  define glDeleteShader            gl_procs.DeleteShader
#  define glCreateProgram           gl_procs.CreateProgram
#  define glAttachShader            gl_procs.AttachShader
#  define glLinkProgram             gl_procs.LinkProgram
#  define glGetProgramiv            gl_procs.GetProgramiv
#  define glGetProgramInfoLog       gl_procs.GetProgramInfoLog
#  define glDeleteProgram           gl_procs.DeleteProgram
#  define glBindAttribLocation      gl_procs.BindAttribLocation
#  define glGetUniformLocation      gl_procs.GetUniformLocation
#  define glGenBuffers              gl_procs.GenBuffers
#  define glBindBuffer              gl_procs.BindBuffer
#  define glBufferData              gl_procs.BufferData
#  define glBufferSubData           gl_procs.BufferSubData
#  define glGenVertexArrays         gl_procs.GenVertexArrays
#  define glBindVertexArray         gl_procs.BindVertexArray
#  define glEnableVertexAttribArray gl_procs.EnableVertexAttribArray
#  define glVertexAttribPointer     gl_procs.VertexAttribPointer
#  define glVertexAttribDivisor     gl_procs.VertexAttribDivisor
#  define glDrawElementsInstanced   gl_procs.DrawElementsInstanced
#  define glUseProgram              gl_procs.UseProgram
#  define glUniform1f               gl_procs.Uniform1f
#  define glUniform2f               gl_procs.Uniform2f
#  define glDeleteVertexArrays      gl_procs.DeleteVertexArrays
#  define glDeleteBuffers           gl_procs.DeleteBuffers
#  define glViewport                gl_procs.Viewport
#  define glClearColor              gl_procs.ClearColor
#  define glClear                   gl_procs.Clear
#  define glDisable                 gl_procs.Disable
#  define glEnable                  gl_procs.Enable
#  define glBlendFunc               gl_procs.BlendFunc

bool gl_load();
#endif // platform branch
