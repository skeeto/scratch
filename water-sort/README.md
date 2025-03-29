# Water Sort Puzzle Game (SDL2)

Move water between bottles until each bottle is a single color. Bottles
can only hold four units of water, and water can only be poured onto alike
or into empty bottles.

## Build

Get a C compiler and SDL2, then:

    $ eval cc -O water-sort-puzzle.c $(pkg-config --cflags --libs sdl2)

Or just run `make`. For WASM, get Clang, then:

	$ clang --target=wasm32 -nostdlib -DWASM -O2 -fno-builtin
            -s -Wl,--no-entry -o water-sort.wasm water-sort-puzzle.c

Or run `make`:

    $ make water-sort.wasm

Then visit `index.html` in a browser.

## User interface

* Left-click the "bottles" to make moves
* Middle-click to get a hint
* Right-click to undo
* <kbd>h</kbd>: hint move
* <kbd>q</kbd>: quit the game
* <kbd>r</kbd>: reset puzzle
* <kbd>u</kbd>: undo last move
* <kbd>1</kbd>-<kbd>5</kbd>: generate new puzzle (1=easy, 5=hard) [SDL only]

## See Also

* [r/watersortpuzzle](https://old.reddit.com/r/watersortpuzzle/)
