#pragma once

#include <cstddef>
#include <cstdint>

#include "gl3.hpp"

class Simulation;
struct View;

class Renderer {
public:
    Renderer() = default;
    ~Renderer() = default;
    Renderer(const Renderer&) = delete;
    Renderer& operator=(const Renderer&) = delete;

    bool init();
    void shutdown();

    // Mark the entire instance buffer for rebuild (e.g. after color changes
    // or simulation reset).
    void mark_dirty() { dirty_ = true; }

    // Draw the board's pieces to the current GL viewport.
    // viewport_w/h are the canvas size in pixels (matches glViewport).
    void draw(const Simulation& sim, const View& view,
              float viewport_w, float viewport_h);

private:
    void ensure_capacity(std::size_t needed);
    void upload_range(const Simulation& sim, std::size_t first, std::size_t last);

    GLuint program_ = 0;
    GLuint vao_ = 0;
    GLuint quad_vbo_ = 0;
    GLuint quad_ibo_ = 0;
    GLuint instance_vbo_ = 0;
    std::size_t instance_capacity_ = 0;
    std::size_t instance_count_ = 0;
    bool dirty_ = false;

    GLint u_view_offset_ = -1;
    GLint u_view_scale_ = -1;
    GLint u_viewport_ = -1;
};
