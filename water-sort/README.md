# Water Sort Puzzle Game (SDL2, WASM, Win32)

Move water between bottles until each bottle is a single color. Bottles
can only hold four units of water, and water can only be poured onto alike
or into empty bottles.

Play online (WASM): [Water Sort Puzzle](https://nullprogram.com/water-sort/)

## Build

For the native application, get any C compiler and SDL2, then:

    $ eval cc -O water-sort-puzzle.c $(pkg-config --cflags --libs sdl2)

Or just run `make`. For WASM, get Clang, then:

    $ make index.html

Then visit `index.html` in a browser. For a Win32 program:

    $ cc -nostartfiles -mwindows -O -o water-sort.exe

Or with MSVC:

    $ cl /GS- /O1 /Fe:water-sort.exe main_windows.c

Or run `make water-sort.exe` (w64devkit).

## User interface

* left-click the "bottles" to make moves
* middle-click to get a hint
* right-click to undo
* <kbd>h</kbd>: hint move
* <kbd>q</kbd>: quit the game
* <kbd>r</kbd>: reset puzzle
* <kbd>u</kbd>: undo last move
* <kbd>1</kbd>-<kbd>5</kbd>: generate new puzzle (1=easy, 5=hard) [SDL only]
* *left/right arrows*: navigate puzzle list [Win32 only]

## See Also

* [r/watersortpuzzle](https://old.reddit.com/r/watersortpuzzle/)
