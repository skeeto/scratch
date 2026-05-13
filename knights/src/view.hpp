#pragma once

// World coordinates: integer cells. y is up.
// view_x, view_y: world coords at the CENTER of the canvas.
// scale: framebuffer pixels per one world unit.
struct View {
    float view_x = 0.0f;
    float view_y = 0.0f;
    float scale  = 24.0f;
    bool  auto_run = true;
    int   step_budget = 5000;

    // (sx, sy): pixel from top-left of canvas. (cw, ch): canvas size in pixels.
    void screen_to_world(float sx, float sy, float cw, float ch,
                         float& wx, float& wy) const {
        wx = view_x + (sx - cw * 0.5f) / scale;
        wy = view_y - (sy - ch * 0.5f) / scale;
    }

    // Adjust scale and pan so that the world point currently at (sx, sy)
    // stays under (sx, sy) after multiplying scale by `factor`.
    void zoom_at(float sx, float sy, float cw, float ch, float factor) {
        float wx, wy;
        screen_to_world(sx, sy, cw, ch, wx, wy);
        scale *= factor;
        view_x = wx - (sx - cw * 0.5f) / scale;
        view_y = wy + (sy - ch * 0.5f) / scale;
    }
};
