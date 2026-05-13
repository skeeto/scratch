#pragma once

#include "board.hpp"
#include "leaper.hpp"
#include "spiral.hpp"

#include <cstdint>
#include <vector>

struct ColorState {
    Leaper leaper;
    float color[4] = { 1.0f, 1.0f, 1.0f, 1.0f }; // RGBA, each 0..1
    SpiralIter cursor;
    int64_t placed = 0;
    // If false, this color's own pieces block placement of this color (basic
    // mode / self-attack). If true, same-color pieces cooperate (team mode).
    bool cooperates = false;
};

class Simulation {
public:
    std::vector<ColorState> colors;
    Board board;
    int64_t turn = 0;

    Simulation();

    // Place one piece for the currently active color.
    void place_next();

    // Convenience: alternate turns, placing n pieces total.
    void step(int n);

    // Reset board + cursors; preserves color list and their leapers.
    void reset();

    int active_color() const {
        return colors.empty() ? 0 : int(turn % (int64_t)colors.size());
    }

    // True if some placed piece blocks `target_color` from placing at (x, y).
    bool is_blocked(int x, int y, int target_color) const;
};
