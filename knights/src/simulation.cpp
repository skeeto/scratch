#include "simulation.hpp"

Simulation::Simulation() {
    ColorState s;
    s.leaper = Leaper::knight();
    s.color[0] = 1.0f;
    s.color[1] = 0.95f;
    s.color[2] = 0.80f;
    s.color[3] = 1.0f;
    colors.push_back(std::move(s));
}

bool Simulation::is_blocked(int x, int y, int target_color) const {
    for (int c = 0; c < (int)colors.size(); ++c) {
        const bool same = (c == target_color);
        if (same && colors[c].cooperates) continue;
        for (auto [ox, oy] : colors[c].leaper.offsets) {
            if (board.color_at(x - ox, y - oy) == c) return true;
        }
    }
    return false;
}

void Simulation::place_next() {
    if (colors.empty()) return;
    const int n = (int)colors.size();
    const int c = int(turn % (int64_t)n);

    ColorState& state = colors[c];
    // Safety: bound the scan length so a degenerate configuration cannot
    // freeze the UI.
    constexpr int kMaxScan = 1 << 22;
    for (int i = 0; i < kMaxScan; ++i) {
        const int x = state.cursor.x;
        const int y = state.cursor.y;
        if (!board.contains(x, y) && !is_blocked(x, y, c)) {
            board.place(x, y, c);
            ++state.placed;
            state.cursor.advance();
            ++turn;
            return;
        }
        state.cursor.advance();
    }
}

void Simulation::step(int n) {
    for (int i = 0; i < n; ++i) place_next();
}

void Simulation::reset() {
    board.clear();
    turn = 0;
    for (auto& c : colors) {
        c.cursor = SpiralIter{};
        c.placed = 0;
    }
}
