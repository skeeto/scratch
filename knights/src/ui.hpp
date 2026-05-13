#pragma once

class Simulation;
class Renderer;
struct View;
struct SDL_TouchFingerEvent;

namespace ui {

void DrawSidebar(Simulation& sim, View& view, Renderer& renderer);
void HandleCanvasInput(View& view, float canvas_w, float canvas_h);

// Mobile / multitouch: feed SDL3 SDL_EVENT_FINGER_DOWN/MOTION/UP events here.
// A two-finger gesture is interpreted as pinch-zoom around the midpoint, and
// single-finger pan (which already works via synthesized mouse events) is
// suppressed for the duration of the pinch.
void ProcessFingerEvent(const SDL_TouchFingerEvent& e, View& view,
                        float canvas_w, float canvas_h);

} // namespace ui
