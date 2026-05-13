#pragma once

#include <span>
#include <string_view>
#include <utility>
#include <vector>

struct Leaper {
    std::vector<std::pair<int, int>> offsets;

    // Chess-fairy leapers. Each is symmetric (closed under negation), so the
    // "attacked-by" relation is symmetric.
    static Leaper wazir();      // 1 step cardinal: (±1,0),(0,±1)
    static Leaper ferz();       // 1 step diagonal: (±1,±1)
    static Leaper dabbaba();    // 2 steps cardinal: (±2,0),(0,±2)
    static Leaper knight();     // 1x2 L-jump
    static Leaper elephant();   // 2 steps diagonal: (±2,±2)
    static Leaper dromedary();  // 3 steps cardinal: (±3,0),(0,±3)
    static Leaper zebra();      // 2x3 L-jump
    static Leaper antelope();   // 3x4 L-jump
};

struct LeaperPreset {
    std::string_view name;
    Leaper (*make)();
};

// Returns a contiguous list of all built-in presets, in display order.
std::span<const LeaperPreset> leaper_presets();
