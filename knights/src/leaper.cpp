#include "leaper.hpp"

namespace {

// Build the 4 symmetric (±a,±b) combinations. If a == b only 4 are distinct;
// otherwise this generator yields 4 entries (one quadrant of the orbit).
Leaper from_pair(int a, int b) {
    Leaper l;
    l.offsets = { { a,  b}, {-a,  b}, { a, -b}, {-a, -b} };
    return l;
}

// "L-jump" leaper with short=a, long=b. The 8-orbit (±a, ±b), (±b, ±a).
Leaper l_jump(int a, int b) {
    Leaper l;
    l.offsets = {
        { a,  b}, {-a,  b}, { a, -b}, {-a, -b},
        { b,  a}, {-b,  a}, { b, -a}, {-b, -a},
    };
    return l;
}

// Cardinal-only at distance d.
Leaper cardinal(int d) {
    Leaper l;
    l.offsets = { { d, 0}, {-d, 0}, { 0,  d}, { 0, -d} };
    return l;
}

} // namespace

Leaper Leaper::wazir()     { return cardinal(1); }
Leaper Leaper::ferz()      { return from_pair(1, 1); }
Leaper Leaper::dabbaba()   { return cardinal(2); }
Leaper Leaper::knight()    { return l_jump(1, 2); }
Leaper Leaper::elephant()  { return from_pair(2, 2); }
Leaper Leaper::dromedary() { return cardinal(3); }
Leaper Leaper::zebra()     { return l_jump(2, 3); }
Leaper Leaper::antelope()  { return l_jump(3, 4); }

namespace {
constexpr LeaperPreset kPresets[] = {
    { "Wazir",     &Leaper::wazir     },
    { "Ferz",      &Leaper::ferz      },
    { "Dabbaba",   &Leaper::dabbaba   },
    { "Knight",    &Leaper::knight    },
    { "Elephant",  &Leaper::elephant  },
    { "Dromedary", &Leaper::dromedary },
    { "Zebra",     &Leaper::zebra     },
    { "Antelope",  &Leaper::antelope  },
};
} // namespace

std::span<const LeaperPreset> leaper_presets() { return kPresets; }
