#include "renderer.hpp"

#include "simulation.hpp"
#include "view.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

#ifdef __EMSCRIPTEN__
constexpr const char* kVersion = "#version 300 es\nprecision mediump float;\n";
#else
constexpr const char* kVersion = "#version 330 core\n";
#endif

constexpr const char* kVS = R"GLSL(
in vec2 a_quad;
in vec2 a_world;
in vec4 a_color;

uniform vec2  u_view_offset;
uniform float u_view_scale;
uniform vec2  u_viewport;

out vec4 v_color;
out vec2 v_uv;

void main() {
    vec2 cell = a_world + a_quad;
    // Pixel offset from canvas center (y still in screen-down convention).
    vec2 px;
    px.x = (cell.x - u_view_offset.x) * u_view_scale;
    px.y = (u_view_offset.y - cell.y) * u_view_scale;
    vec2 clip = px / (u_viewport * 0.5);
    clip.y = -clip.y;
    gl_Position = vec4(clip, 0.0, 1.0);
    v_color = a_color;
    v_uv = a_quad;
}
)GLSL";

constexpr const char* kFS = R"GLSL(
in vec4 v_color;
in vec2 v_uv;
uniform float u_view_scale;  // pixels per cell
out vec4 frag_color;

void main() {
    // For sub-pixel-to-small cells: no border, just a solid color. This
    // eliminates the per-pixel discard pattern that produces moire when the
    // cell-to-pixel ratio isn't an integer.
    if (u_view_scale < 4.0) {
        frag_color = v_color;
        return;
    }
    // Otherwise, aim for a ~1-screen-pixel border between cells, with a
    // soft edge using screen-space derivatives.
    float border_uv = 1.0 / u_view_scale;
    border_uv = min(border_uv, 0.08);
    vec2 dd = min(v_uv, 1.0 - v_uv);
    float edge = min(dd.x, dd.y);
    float px = fwidth(edge);
    float alpha = smoothstep(border_uv - 0.5 * px, border_uv + 0.5 * px, edge);
    if (alpha < 0.005) discard;
    frag_color = vec4(v_color.rgb, v_color.a * alpha);
}
)GLSL";

struct InstanceData {
    float x;
    float y;
    std::uint32_t rgba;
};

std::uint32_t pack_rgba(const float c[4]) {
    auto to8 = [](float v) -> std::uint32_t {
        v = std::max(0.0f, std::min(1.0f, v));
        return std::uint32_t(v * 255.0f + 0.5f);
    };
    return to8(c[0]) | (to8(c[1]) << 8) | (to8(c[2]) << 16) | (to8(c[3]) << 24);
}

GLuint compile_shader(GLenum type, const char* src) {
    GLuint sh = glCreateShader(type);
    const char* parts[2] = { kVersion, src };
    glShaderSource(sh, 2, parts, nullptr);
    glCompileShader(sh);
    GLint ok = 0;
    glGetShaderiv(sh, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[2048];
        glGetShaderInfoLog(sh, sizeof(log), nullptr, log);
        std::fprintf(stderr, "shader compile failed (%s): %s\n",
                     type == GL_VERTEX_SHADER ? "vs" : "fs", log);
        glDeleteShader(sh);
        return 0;
    }
    return sh;
}

GLuint link_program(GLuint vs, GLuint fs) {
    GLuint p = glCreateProgram();
    glAttachShader(p, vs);
    glAttachShader(p, fs);
    glBindAttribLocation(p, 0, "a_quad");
    glBindAttribLocation(p, 1, "a_world");
    glBindAttribLocation(p, 2, "a_color");
    glLinkProgram(p);
    GLint ok = 0;
    glGetProgramiv(p, GL_LINK_STATUS, &ok);
    if (!ok) {
        char log[2048];
        glGetProgramInfoLog(p, sizeof(log), nullptr, log);
        std::fprintf(stderr, "program link failed: %s\n", log);
        glDeleteProgram(p);
        return 0;
    }
    return p;
}

} // namespace

bool Renderer::init() {
    GLuint vs = compile_shader(GL_VERTEX_SHADER, kVS);
    GLuint fs = compile_shader(GL_FRAGMENT_SHADER, kFS);
    if (!vs || !fs) return false;
    program_ = link_program(vs, fs);
    glDeleteShader(vs);
    glDeleteShader(fs);
    if (!program_) return false;

    u_view_offset_ = glGetUniformLocation(program_, "u_view_offset");
    u_view_scale_  = glGetUniformLocation(program_, "u_view_scale");
    u_viewport_    = glGetUniformLocation(program_, "u_viewport");

    glGenVertexArrays(1, &vao_);
    glBindVertexArray(vao_);

    static const float quad_verts[] = {
        0.0f, 0.0f,
        1.0f, 0.0f,
        1.0f, 1.0f,
        0.0f, 1.0f,
    };
    static const std::uint16_t quad_idx[] = { 0, 1, 2, 2, 3, 0 };

    glGenBuffers(1, &quad_vbo_);
    glBindBuffer(GL_ARRAY_BUFFER, quad_vbo_);
    glBufferData(GL_ARRAY_BUFFER, sizeof(quad_verts), quad_verts, GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, sizeof(float) * 2, (void*)0);
    glVertexAttribDivisor(0, 0);

    glGenBuffers(1, &quad_ibo_);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, quad_ibo_);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(quad_idx), quad_idx, GL_STATIC_DRAW);

    glGenBuffers(1, &instance_vbo_);
    glBindBuffer(GL_ARRAY_BUFFER, instance_vbo_);
    glBufferData(GL_ARRAY_BUFFER, sizeof(InstanceData) * 1024, nullptr, GL_DYNAMIC_DRAW);
    instance_capacity_ = 1024;
    glEnableVertexAttribArray(1);
    glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, sizeof(InstanceData), (void*)0);
    glVertexAttribDivisor(1, 1);
    glEnableVertexAttribArray(2);
    glVertexAttribPointer(2, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(InstanceData),
                          (void*)offsetof(InstanceData, rgba));
    glVertexAttribDivisor(2, 1);

    glBindVertexArray(0);
    return true;
}

void Renderer::shutdown() {
    if (instance_vbo_) glDeleteBuffers(1, &instance_vbo_);
    if (quad_ibo_)     glDeleteBuffers(1, &quad_ibo_);
    if (quad_vbo_)     glDeleteBuffers(1, &quad_vbo_);
    if (vao_)          glDeleteVertexArrays(1, &vao_);
    if (program_)      glDeleteProgram(program_);
    program_ = vao_ = quad_vbo_ = quad_ibo_ = instance_vbo_ = 0;
    instance_capacity_ = instance_count_ = 0;
}

void Renderer::ensure_capacity(std::size_t needed) {
    if (needed <= instance_capacity_) return;
    std::size_t new_cap = std::max<std::size_t>(instance_capacity_ * 2, needed);
    glBindBuffer(GL_ARRAY_BUFFER, instance_vbo_);
    glBufferData(GL_ARRAY_BUFFER, new_cap * sizeof(InstanceData), nullptr, GL_DYNAMIC_DRAW);
    instance_capacity_ = new_cap;
    // Caller is responsible for re-uploading existing data after resize.
}

void Renderer::upload_range(const Simulation& sim, std::size_t first, std::size_t last) {
    if (first >= last) return;
    auto log = sim.board.log();
    std::vector<InstanceData> tmp(last - first);
    for (std::size_t i = first; i < last; ++i) {
        const Piece& p = log[i];
        InstanceData& d = tmp[i - first];
        d.x = (float)p.x;
        d.y = (float)p.y;
        std::uint32_t rgba = 0xffff00ffu;
        if (p.color >= 0 && p.color < (int)sim.colors.size()) {
            rgba = pack_rgba(sim.colors[p.color].color);
        }
        d.rgba = rgba;
    }
    glBindBuffer(GL_ARRAY_BUFFER, instance_vbo_);
    glBufferSubData(GL_ARRAY_BUFFER,
                    GLintptr(first * sizeof(InstanceData)),
                    GLsizeiptr(tmp.size() * sizeof(InstanceData)),
                    tmp.data());
}

void Renderer::draw(const Simulation& sim, const View& view,
                    float viewport_w, float viewport_h) {
    const std::size_t log_size = sim.board.log().size();

    // Handle simulation reset or dirty flag: rebuild from scratch.
    if (dirty_ || log_size < instance_count_) {
        instance_count_ = 0;
        dirty_ = false;
    }

    if (log_size > instance_count_) {
        bool needs_full_reupload = log_size > instance_capacity_;
        if (needs_full_reupload) {
            ensure_capacity(log_size);
            // Re-upload everything (glBufferData orphaned the buffer).
            upload_range(sim, 0, log_size);
        } else {
            upload_range(sim, instance_count_, log_size);
        }
        instance_count_ = log_size;
    }

    if (instance_count_ == 0 || program_ == 0) return;

    glDisable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
#ifndef __EMSCRIPTEN__
    glEnable(GL_MULTISAMPLE);
#endif
    glUseProgram(program_);
    glUniform2f(u_view_offset_, view.view_x, view.view_y);
    glUniform1f(u_view_scale_, view.scale);
    glUniform2f(u_viewport_, viewport_w, viewport_h);

    glBindVertexArray(vao_);
    glDrawElementsInstanced(GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, nullptr,
                            (GLsizei)instance_count_);
    glBindVertexArray(0);
    glUseProgram(0);
}
