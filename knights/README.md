# Knights — Spiral Leaper-Pattern Explorer

Visualize patterns that emerge from placing chess "leaper" pieces (knights and
custom variants) along an Ulam spiral on an infinite board. Inspired by a
recent Numberphile video.

The basic rule: walk the spiral outward from the origin. At each tile, place a
knight if no previously-placed knight attacks it. Team mode adds N colors with
custom leapers — same-color pieces cooperate, different colors block.

## Build (native)

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/knights
```

First configure fetches Dear ImGui and SDL3 via CMake `FetchContent` and takes
about a minute. Subsequent builds are fast.

## Build (web, Emscripten)

```
source $EMSDK/emsdk_env.sh
emcmake cmake -B build-web -DCMAKE_BUILD_TYPE=Release
cmake --build build-web -j
emrun build-web/index.html
```

Targets WebGL 2 / OpenGL ES 3.0. The build produces `index.html`,
`index.js`, and `index.wasm` ready to drop on a static host.

### Publish

```
cmake --install build-web                  # → build-web/dist/
# or, to a custom location:
cmake --install build-web --prefix ./out
```

Either form copies just the three files needed to serve the page.

## Controls

- Left-click + drag inside the canvas: pan
- Mouse wheel: zoom (toward cursor)
- Touch: one-finger drag to pan, two-finger pinch to zoom
- Sidebar:
  - `Reset`: clear board, keep colors & leapers
  - `Center view`: snap pan/zoom back to origin
  - `Auto-run` + `Budget / frame`: how many placements to compute per frame
  - `Step 1k` / `10k` / `100k`: manual stepping
  - Per-color row: color picker, `Edit movement...`, remove, count, and a
    `Cooperate with same color` toggle (off = basic-mode self-attack;
    on = team-mode cooperation)
  - `Add color`: appends a new color (knight by default, cooperative)

## Movement editor

A 9x9 grid. The center cell is the piece. Click a cell to toggle whether the
piece can leap to that offset. `Symmetric` (default on) mirrors clicks across
the origin, so a knight needs 4 clicks instead of 8.

## Self-test

A small headless correctness check is built into the binary:

```
KNIGHTS_SELFTEST=1 ./build/knights
```

Runs the basic-mode simulation for 2000 placements and verifies no two
placed pieces sit a knight's move apart.

## Numberphile videos

The class of patterns this explores was popularized in:

- [Red & Black Knights](https://www.youtube.com/watch?v=UiX4CFIiegM) —
  extraordinary result
- [Amazing Chessboard Patterns](https://www.youtube.com/watch?v=VgmDuBCayPw) —
  extra

## Layout

- `src/spiral.hpp` — Ulam spiral iterator
- `src/leaper.{hpp,cpp}` — `Leaper` struct + Knight preset
- `src/board.{hpp,cpp}` — placed-piece store and lookups
- `src/simulation.{hpp,cpp}` — turn-based per-color cursor; `is_blocked`
- `src/view.hpp` — pan/zoom state + screen↔world transforms
- `src/renderer.{hpp,cpp}` — instanced-quad OpenGL renderer (shared GLSL for
  GL 3.3 core and GL ES 3.0)
- `src/ui.{hpp,cpp}` — ImGui sidebar and movement-editor modal
- `src/main.cpp` — SDL3/GL/ImGui bootstrap and frame loop
