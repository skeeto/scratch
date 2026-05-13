#include "renderer.hpp"
#include "simulation.hpp"
#include "ui.hpp"
#include "view.hpp"

#include <SDL3/SDL.h>
#include <imgui.h>
#include <imgui_impl_opengl3.h>
#include <imgui_impl_sdl3.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/html5.h>
#endif

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace {

int run_selftest() {
    Simulation sim;
    sim.step(2000);
    const Leaper k = Leaper::knight();
    int errors = 0;
    for (auto const& p : sim.board.log()) {
        for (auto [dx, dy] : k.offsets) {
            if (sim.board.color_at(p.x + dx, p.y + dy) == p.color) ++errors;
        }
    }
    std::printf("selftest: placed=%zu, violations=%d (each counted twice)\n",
                sim.board.log().size(), errors);
    if (sim.board.log().size() < 5) {
        std::printf("selftest: first positions:");
        for (std::size_t i = 0; i < std::min<std::size_t>(5, sim.board.log().size()); ++i) {
            auto const& p = sim.board.log()[i];
            std::printf(" (%d,%d)", p.x, p.y);
        }
        std::printf("\n");
    }
    return errors == 0 ? 0 : 1;
}

} // namespace

struct App {
    SDL_Window* window = nullptr;
    SDL_GLContext gl_ctx = nullptr;
    Simulation sim;
    View view;
    Renderer renderer;
    bool running = true;
};

static App* g_app = nullptr;

// True if every color's cursor has advanced past the largest shell needed to
// fill the visible region. Lets us stop computing when the view is settled.
static bool view_is_filled(const Simulation& sim, const View& view,
                           float canvas_w, float canvas_h) {
    if (sim.colors.empty()) return true;
    const float half_w_world = canvas_w * 0.5f / view.scale;
    const float half_h_world = canvas_h * 0.5f / view.scale;
    const float xmax_w = std::max(std::abs(view.view_x - half_w_world),
                                  std::abs(view.view_x + half_w_world));
    const float ymax_w = std::max(std::abs(view.view_y - half_h_world),
                                  std::abs(view.view_y + half_h_world));
    const int needed_R = (int)std::ceil(std::max(xmax_w, ymax_w));
    for (auto const& c : sim.colors) {
        const int d = std::max(std::abs(c.cursor.x), std::abs(c.cursor.y));
        if (d <= needed_R) return false;
    }
    return true;
}

static void frame() {
    App* a = g_app;

#ifdef __EMSCRIPTEN__
    // Keep SDL's window size in sync with the page-driven canvas size.
    {
        int cw = 0, ch = 0;
        if (emscripten_get_canvas_element_size("#canvas", &cw, &ch) ==
            EMSCRIPTEN_RESULT_SUCCESS) {
            int sw = 0, sh = 0;
            SDL_GetWindowSize(a->window, &sw, &sh);
            if (cw > 0 && ch > 0 && (cw != sw || ch != sh)) {
                SDL_SetWindowSize(a->window, cw, ch);
            }
        }
    }
#endif

    int w = 0, h = 0;
    SDL_GetWindowSize(a->window, &w, &h);

    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        ImGui_ImplSDL3_ProcessEvent(&e);
        if (e.type == SDL_EVENT_QUIT) a->running = false;
        if (e.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED) a->running = false;
        if (e.type == SDL_EVENT_FINGER_DOWN   ||
            e.type == SDL_EVENT_FINGER_MOTION ||
            e.type == SDL_EVENT_FINGER_UP) {
            ui::ProcessFingerEvent(e.tfinger, a->view, (float)w, (float)h);
        }
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL3_NewFrame();
    ImGui::NewFrame();

    ui::DrawSidebar(a->sim, a->view, a->renderer);
    ui::HandleCanvasInput(a->view, (float)w, (float)h);

    if (a->view.auto_run && a->view.step_budget > 0 &&
        !view_is_filled(a->sim, a->view, (float)w, (float)h)) {
        a->sim.step(a->view.step_budget);
    }

    ImGui::Render();

    glViewport(0, 0, w, h);
    glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    a->renderer.draw(a->sim, a->view, (float)w, (float)h);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    SDL_GL_SwapWindow(a->window);
}

#ifdef __EMSCRIPTEN__
static void em_frame() { frame(); }
#endif

int main(int /*argc*/, char** /*argv*/) {
    if (std::getenv("KNIGHTS_SELFTEST")) return run_selftest();

    if (!SDL_Init(SDL_INIT_VIDEO)) {
        std::fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }

#ifdef __EMSCRIPTEN__
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    const char* glsl_version = "#version 300 es";
#else
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    const char* glsl_version = "#version 330 core";
#endif
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 0);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 0);
    SDL_GL_SetAttribute(SDL_GL_MULTISAMPLEBUFFERS, 1);
    SDL_GL_SetAttribute(SDL_GL_MULTISAMPLESAMPLES, 4);

    App app;
    app.window = SDL_CreateWindow("Knights", 1280, 800,
                                  SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
    if (!app.window) {
        std::fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }
    app.gl_ctx = SDL_GL_CreateContext(app.window);
    if (!app.gl_ctx) {
        std::fprintf(stderr, "SDL_GL_CreateContext failed: %s\n", SDL_GetError());
        SDL_DestroyWindow(app.window);
        SDL_Quit();
        return 1;
    }
    SDL_GL_MakeCurrent(app.window, app.gl_ctx);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    ImGui::StyleColorsDark();
    ImGui_ImplSDL3_InitForOpenGL(app.window, app.gl_ctx);
    ImGui_ImplOpenGL3_Init(glsl_version);

    if (!app.renderer.init()) {
        std::fprintf(stderr, "Renderer init failed\n");
        return 1;
    }

    g_app = &app;

#ifdef __EMSCRIPTEN__
    emscripten_set_main_loop(em_frame, 0, true);
#else
    while (app.running) frame();

    app.renderer.shutdown();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DestroyContext(app.gl_ctx);
    SDL_DestroyWindow(app.window);
    SDL_Quit();
#endif
    return 0;
}
