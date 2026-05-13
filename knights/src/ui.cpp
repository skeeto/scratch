#include "ui.hpp"

#include "renderer.hpp"
#include "simulation.hpp"
#include "view.hpp"

#include <SDL3/SDL_events.h>
#include <imgui.h>

#include <cmath>
#include <cstddef>
#include <initializer_list>
#include <set>
#include <utility>

namespace ui {
namespace {

int g_editing_color = -1;
bool g_symmetric = true;
bool g_drag_active = false;

// Multitouch pinch tracking. We hold up to two fingers; while two are down
// we interpret motion as pinch-zoom and suppress single-finger pan.
struct PinchState {
    struct Finger { SDL_FingerID id; float x, y; };
    Finger fingers[2];
    int count = 0;
    bool active = false;
    float ref_dist = 0.0f;  // updated incrementally between motion events
};
PinchState g_pinch;

void DrawMoveEditor(Simulation& sim, Renderer& renderer);

// ---- Full-configuration presets ----

struct PieceEntry {
    Leaper (*leaper)();
    float r, g, b;
};

void apply_team(Simulation& sim, bool cooperates,
                std::initializer_list<PieceEntry> pieces) {
    sim.colors.clear();
    for (auto const& p : pieces) {
        ColorState s;
        s.leaper = p.leaper();
        s.color[0] = p.r;
        s.color[1] = p.g;
        s.color[2] = p.b;
        s.color[3] = 1.0f;
        s.cooperates = cooperates;
        sim.colors.push_back(std::move(s));
    }
}

// Visible-on-dark-background renderings of the named colors. "Black" is
// rendered as a medium-light gray so it shows up against the dark canvas.
constexpr float c_red[3]      = {0.92f, 0.25f, 0.25f};
constexpr float c_black[3]    = {0.65f, 0.65f, 0.70f};
constexpr float c_cyan[3]     = {0.25f, 0.85f, 0.92f};
constexpr float c_blue[3]     = {0.30f, 0.45f, 0.95f};
constexpr float c_pink[3]     = {1.00f, 0.55f, 0.72f};
constexpr float c_babyblue[3] = {0.55f, 0.80f, 1.00f};
constexpr float c_darkblue[3] = {0.20f, 0.30f, 0.85f};
constexpr float c_purple[3]   = {0.65f, 0.35f, 0.92f};
constexpr float c_darkpink[3] = {0.92f, 0.32f, 0.55f};
constexpr float c_orange[3]   = {0.98f, 0.55f, 0.18f};
constexpr float c_yellow[3]   = {0.95f, 0.90f, 0.30f};
constexpr float c_white[3]    = {1.00f, 0.95f, 0.80f}; // default basic knight

#define PIECE(leaper_fn, col) PieceEntry{(leaper_fn), (col)[0], (col)[1], (col)[2]}

void preset_basic_knight(Simulation& sim) {
    apply_team(sim, false, { PIECE(&Leaper::knight, c_white) });
}

void preset_3_knights(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight, c_red),
        PIECE(&Leaper::knight, c_black),
        PIECE(&Leaper::knight, c_cyan),
    });
}

void preset_4_knights(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight, c_blue),
        PIECE(&Leaper::knight, c_red),
        PIECE(&Leaper::knight, c_pink),
        PIECE(&Leaper::knight, c_babyblue),
    });
}

void preset_5_knights(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight, c_darkblue),
        PIECE(&Leaper::knight, c_purple),
        PIECE(&Leaper::knight, c_darkpink),
        PIECE(&Leaper::knight, c_orange),
        PIECE(&Leaper::knight, c_yellow),
    });
}

void preset_elephant_dromedary(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::elephant,  c_black),
        PIECE(&Leaper::dromedary, c_orange),
    });
}

void preset_knight_antelope(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight,   c_black),
        PIECE(&Leaper::antelope, c_cyan),
    });
}

void preset_knight_dabbaba_wazirs(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight,  c_black),
        PIECE(&Leaper::dabbaba, c_red),
        PIECE(&Leaper::wazir,   c_cyan),
        PIECE(&Leaper::wazir,   c_purple),
    });
}

void preset_knight_zebra(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::knight, c_black),
        PIECE(&Leaper::zebra,  c_red),
    });
}

void preset_wazirs_ferzes(Simulation& sim) {
    apply_team(sim, true, {
        PIECE(&Leaper::wazir, c_black),
        PIECE(&Leaper::ferz,  c_red),
        PIECE(&Leaper::wazir, c_cyan),
        PIECE(&Leaper::ferz,  c_purple),
    });
}

#undef PIECE

struct ConfigPreset {
    const char* name;
    void (*apply)(Simulation&);
};

constexpr ConfigPreset kConfigPresets[] = {
    { "Knight (basic)",            &preset_basic_knight        },
    { "3 Knights",                 &preset_3_knights           },
    { "4 Knights",                 &preset_4_knights           },
    { "5 Knights",                 &preset_5_knights           },
    { "Elephant + Dromedary",      &preset_elephant_dromedary  },
    { "Knight + Antelope",         &preset_knight_antelope     },
    { "Knight + Dabbaba + Wazirs", &preset_knight_dabbaba_wazirs },
    { "Knight + Zebra",            &preset_knight_zebra        },
    { "Wazirs + Ferzes",           &preset_wazirs_ferzes       },
};

} // namespace

void DrawSidebar(Simulation& sim, View& view, Renderer& renderer) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(340.0f, vp->WorkSize.y));
    ImGui::Begin("Controls", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoResize  | ImGuiWindowFlags_NoCollapse);

    ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);
    ImGui::Text("Placed: %lld", (long long)sim.board.size());
    ImGui::Text("Turn:   %lld", (long long)sim.turn);
    if (!sim.colors.empty()) {
        ImGui::Text("Active color: %d", sim.active_color());
    }

    ImGui::Separator();
    if (ImGui::Button("Reset")) {
        sim.reset();
        renderer.mark_dirty();
    }
    ImGui::SameLine();
    if (ImGui::Button("Center view")) {
        view.view_x = 0.0f;
        view.view_y = 0.0f;
        view.scale  = 24.0f;
    }
    ImGui::Checkbox("Auto-run", &view.auto_run);
    ImGui::SliderInt("Budget / frame", &view.step_budget, 0, 50000);
    if (ImGui::Button("Step 1k")) sim.step(1000);
    ImGui::SameLine();
    if (ImGui::Button("Step 10k")) sim.step(10000);
    ImGui::SameLine();
    if (ImGui::Button("Step 100k")) sim.step(100000);

    ImGui::Separator();
    if (ImGui::CollapsingHeader("Presets", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (auto const& p : kConfigPresets) {
            if (ImGui::Button(p.name, ImVec2(-FLT_MIN, 0))) {
                p.apply(sim);
                sim.reset();
                renderer.mark_dirty();
            }
        }
    }

    ImGui::Separator();
    ImGui::Text("Colors");

    int remove_idx = -1;
    for (int i = 0; i < (int)sim.colors.size(); ++i) {
        ImGui::PushID(i);
        ColorState& cs = sim.colors[i];
        if (ImGui::ColorEdit3("##color", cs.color,
                              ImGuiColorEditFlags_NoInputs |
                              ImGuiColorEditFlags_NoLabel)) {
            renderer.mark_dirty();
        }
        ImGui::SameLine();
        if (ImGui::Button("Edit movement...")) {
            g_editing_color = i;
            ImGui::OpenPopup("Move Editor");
        }
        ImGui::SameLine();
        if (sim.colors.size() > 1) {
            if (ImGui::Button("X")) remove_idx = i;
        } else {
            ImGui::BeginDisabled();
            ImGui::Button("X");
            ImGui::EndDisabled();
        }
        ImGui::SameLine();
        ImGui::Text("(%lld)", (long long)cs.placed);
        if (ImGui::Checkbox("Cooperate with same color", &cs.cooperates)) {
            sim.reset();
            renderer.mark_dirty();
        }

        DrawMoveEditor(sim, renderer);
        ImGui::PopID();
    }

    if (remove_idx >= 0) {
        sim.colors.erase(sim.colors.begin() + remove_idx);
        sim.reset();
        renderer.mark_dirty();
    }

    if (ImGui::Button("Add color")) {
        ColorState s;
        s.leaper = Leaper::knight();
        s.cooperates = true; // team-mode default for added colors
        float h = float(sim.colors.size()) * 0.15f;
        h -= std::floor(h);
        ImGui::ColorConvertHSVtoRGB(h, 0.7f, 0.95f, s.color[0], s.color[1], s.color[2]);
        s.color[3] = 1.0f;
        // Also flip the first color to cooperate, so adding a second color
        // gives a proper team-mode pattern rather than a hybrid.
        if (!sim.colors.empty()) sim.colors[0].cooperates = true;
        sim.colors.push_back(std::move(s));
        sim.reset();
        renderer.mark_dirty();
    }

    ImGui::Separator();
    ImGui::TextWrapped(
        "Drag the canvas to pan. Mouse wheel to zoom.");

    ImGui::Separator();
    ImGui::TextDisabled("Numberphile:");
    ImGui::TextLinkOpenURL("Red & Black Knights",
        "https://www.youtube.com/watch?v=UiX4CFIiegM");
    ImGui::PushStyleColor(ImGuiCol_Text,
                          ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
    ImGui::TextWrapped("extraordinary result");
    ImGui::PopStyleColor();
    ImGui::TextLinkOpenURL("Amazing Chessboard Patterns",
        "https://www.youtube.com/watch?v=VgmDuBCayPw");
    ImGui::PushStyleColor(ImGuiCol_Text,
                          ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
    ImGui::TextWrapped("extra");
    ImGui::PopStyleColor();

    ImGui::End();
}

namespace {

void DrawMoveEditor(Simulation& sim, Renderer& renderer) {
    if (!ImGui::BeginPopupModal("Move Editor", nullptr,
                                ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    if (g_editing_color < 0 || g_editing_color >= (int)sim.colors.size()) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    ColorState& cs = sim.colors[g_editing_color];

    ImGui::Checkbox("Symmetric (mirror across origin)", &g_symmetric);
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        cs.leaper.offsets.clear();
    }
    ImGui::TextUnformatted("Presets:");
    auto presets = leaper_presets();
    for (std::size_t i = 0; i < presets.size(); ++i) {
        if (i > 0 && (i % 4) != 0) ImGui::SameLine();
        ImGui::PushID((int)i);
        if (ImGui::Button(presets[i].name.data())) {
            cs.leaper = presets[i].make();
        }
        ImGui::PopID();
    }

    std::set<std::pair<int,int>> active;
    for (auto& o : cs.leaper.offsets) active.insert(o);

    constexpr int kHalf = 4;
    const ImVec2 cell(28, 28);
    for (int dy = kHalf; dy >= -kHalf; --dy) {
        for (int dx = -kHalf; dx <= kHalf; ++dx) {
            ImGui::PushID(dy * 100 + dx);
            bool is_self = (dx == 0 && dy == 0);
            bool is_on = !is_self && active.count({dx, dy}) > 0;
            ImVec4 col;
            if (is_self) {
                col = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
            } else if (is_on) {
                col = ImVec4(cs.color[0], cs.color[1], cs.color[2], 1.0f);
            } else {
                col = ImVec4(0.18f, 0.18f, 0.20f, 1.0f);
            }
            ImGui::PushStyleColor(ImGuiCol_Button, col);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                                  ImVec4(col.x * 1.2f, col.y * 1.2f, col.z * 1.2f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                                  ImVec4(col.x * 0.8f, col.y * 0.8f, col.z * 0.8f, 1.0f));
            const char* label = is_self ? "*" : (is_on ? "X" : " ");
            if (ImGui::Button(label, cell) && !is_self) {
                if (is_on) {
                    active.erase({dx, dy});
                    if (g_symmetric) active.erase({-dx, -dy});
                } else {
                    active.insert({dx, dy});
                    if (g_symmetric) active.insert({-dx, -dy});
                }
                cs.leaper.offsets.assign(active.begin(), active.end());
            }
            ImGui::PopStyleColor(3);
            ImGui::PopID();
            if (dx < kHalf) ImGui::SameLine(0.0f, 2.0f);
        }
    }

    ImGui::Separator();
    if (ImGui::Button("OK", ImVec2(120, 0))) {
        sim.reset();
        renderer.mark_dirty();
        ImGui::CloseCurrentPopup();
        g_editing_color = -1;
    }
    ImGui::EndPopup();
}

} // namespace

void HandleCanvasInput(View& view, float canvas_w, float canvas_h) {
    ImGuiIO& io = ImGui::GetIO();

    // During a pinch the first finger still produces synthesized mouse events;
    // suppress the mouse-driven pan so the gesture is interpreted purely as
    // zoom.
    if (g_pinch.active) {
        g_drag_active = false;
        return;
    }

    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !io.WantCaptureMouse) {
        g_drag_active = true;
    }
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        g_drag_active = false;
    }

    if (g_drag_active) {
        ImVec2 delta = io.MouseDelta;
        if (delta.x != 0.0f || delta.y != 0.0f) {
            view.view_x -= delta.x / view.scale;
            view.view_y += delta.y / view.scale;
        }
    }

    if (!io.WantCaptureMouse && io.MouseWheel != 0.0f) {
        float factor = std::pow(1.15f, io.MouseWheel);
        const ImVec2 mp = io.MousePos;
        view.zoom_at(mp.x, mp.y, canvas_w, canvas_h, factor);
    }
}

void ProcessFingerEvent(const SDL_TouchFingerEvent& e, View& view,
                        float canvas_w, float canvas_h) {
    const float x = e.x * canvas_w;
    const float y = e.y * canvas_h;

    if (e.type == SDL_EVENT_FINGER_DOWN) {
        if (g_pinch.count < 2) {
            g_pinch.fingers[g_pinch.count++] = { e.fingerID, x, y };
        }
        if (g_pinch.count == 2) {
            const float dx = g_pinch.fingers[0].x - g_pinch.fingers[1].x;
            const float dy = g_pinch.fingers[0].y - g_pinch.fingers[1].y;
            g_pinch.ref_dist = std::sqrt(dx * dx + dy * dy);
            g_pinch.active = true;
            g_drag_active = false;
        }
    } else if (e.type == SDL_EVENT_FINGER_MOTION) {
        for (int i = 0; i < g_pinch.count; ++i) {
            if (g_pinch.fingers[i].id == e.fingerID) {
                g_pinch.fingers[i].x = x;
                g_pinch.fingers[i].y = y;
                break;
            }
        }
        if (g_pinch.active && g_pinch.count == 2) {
            const float dx = g_pinch.fingers[0].x - g_pinch.fingers[1].x;
            const float dy = g_pinch.fingers[0].y - g_pinch.fingers[1].y;
            const float cur = std::sqrt(dx * dx + dy * dy);
            if (g_pinch.ref_dist > 1.0f && cur > 1.0f) {
                const float factor = cur / g_pinch.ref_dist;
                const float cx = (g_pinch.fingers[0].x + g_pinch.fingers[1].x) * 0.5f;
                const float cy = (g_pinch.fingers[0].y + g_pinch.fingers[1].y) * 0.5f;
                view.zoom_at(cx, cy, canvas_w, canvas_h, factor);
                g_pinch.ref_dist = cur;
            }
        }
    } else if (e.type == SDL_EVENT_FINGER_UP) {
        for (int i = 0; i < g_pinch.count; ++i) {
            if (g_pinch.fingers[i].id == e.fingerID) {
                for (int j = i; j < g_pinch.count - 1; ++j) {
                    g_pinch.fingers[j] = g_pinch.fingers[j + 1];
                }
                --g_pinch.count;
                break;
            }
        }
        if (g_pinch.count < 2) g_pinch.active = false;
    }
}

} // namespace ui
