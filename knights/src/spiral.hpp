#pragma once

#include <cstdint>

// Ulam-style spiral iterator.
// Starts at (0,0). advance() steps to the next position in the order
// R, U, L, L, D, D, R, R, R, U, U, U, L, L, L, L, ...
struct SpiralIter {
    int x = 0;
    int y = 0;
    int leg = 0;       // 0..3 cycle: R, U, L, D
    int leg_pos = 0;   // step within current leg
    int leg_len = 1;   // length of current leg
    int64_t index = 0; // 0-based spiral position

    static constexpr int kDx[4] = { 1, 0, -1, 0 };
    static constexpr int kDy[4] = { 0, 1,  0, -1 };

    void advance() {
        const int d = leg & 3;
        x += kDx[d];
        y += kDy[d];
        ++index;
        if (++leg_pos == leg_len) {
            leg_pos = 0;
            ++leg;
            if ((leg & 1) == 0) ++leg_len;
        }
    }
};
