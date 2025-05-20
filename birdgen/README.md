# Bird Species Generator Turing Test

This program randomly selects a real North American bird species name,
then randomly generates three species that (hopefully) sound real, but
definitely are not real. It shuffles this list and then prints it. Your
job is to guess which is the real species. Hit RET to reveal which item
was the real species.

## Build

The game comes in three flavors: Go, Windows, and WASM.

    $ go build birdgen.go
    $ cc -std=gnu23 -nostartfiles -o birdgen.exe birdgen.c
    $ clang -std=gnu23 --target=wasm32 -Os -s
        -nostdlib -Wl,--no-entry -o birdgen.wasm birdgen.c

Use `index.html` to run the WASM version. In all cases name lists are
embedded in the binary and unneeded at run time. The C builds accomplish
this with C23's `#embed`.
