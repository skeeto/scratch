CC        = cc
CFLAGS    = -O2
LDFLAGS   = -s
D_CFLAGS  = -g3 -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -fsanitize=undefined -fsanitize-trap
LDLIBS   != pkg-config --cflags --libs sdl2

water-sort$(EXE): water-sort-puzzle.c
	$(CC) -DSDL $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

debug$(EXE): water-sort-puzzle.c
	$(CC) -DSDL $(D_CFLAGS) -o $@ $^ $(LDLIBS)

water-sort.wasm: water-sort-puzzle.c
	clang --target=wasm32 -nostdlib -DWASM -Wall -Wextra $(CFLAGS) \
	  $(LDFLAGS) -Wl,--no-entry -fno-builtin -o $@ $^

clean:
	rm -f water-sort-puzzle$(EXE) debug$(EXE) water-sort.wasm
