#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

struct Piece {
    int x;
    int y;
    int color;
};

class Board {
public:
    static int64_t key(int x, int y) {
        return (int64_t(uint32_t(x)) << 32) | uint32_t(y);
    }

    bool contains(int x, int y) const {
        return pieces_.find(key(x, y)) != pieces_.end();
    }

    // -1 if empty.
    int color_at(int x, int y) const {
        auto it = pieces_.find(key(x, y));
        return it == pieces_.end() ? -1 : it->second;
    }

    void place(int x, int y, int color);

    std::size_t size() const { return pieces_.size(); }
    std::span<const Piece> log() const { return log_; }
    void clear();

private:
    std::unordered_map<int64_t, int> pieces_;
    std::vector<Piece> log_;
};
