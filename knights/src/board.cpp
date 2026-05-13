#include "board.hpp"

void Board::place(int x, int y, int color) {
    pieces_[key(x, y)] = color;
    log_.push_back({x, y, color});
}

void Board::clear() {
    pieces_.clear();
    log_.clear();
}
