#include "gl3.hpp"

#ifndef __EMSCRIPTEN__

#include <SDL3/SDL.h>

GLProcs gl_procs = {};

bool gl_load() {
    bool ok = true;
#  define KNIGHTS_GL_LOAD(ret, name, args)                                   \
    gl_procs.name = reinterpret_cast<ret(*) args>(                           \
        SDL_GL_GetProcAddress("gl" #name));                                  \
    if (!gl_procs.name) ok = false;
    KNIGHTS_GL_FUNCS(KNIGHTS_GL_LOAD)
#  undef KNIGHTS_GL_LOAD
    return ok;
}

#endif
