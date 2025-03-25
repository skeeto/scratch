CC        = cc
CFLAGS    = -O2
LDFLAGS   = -s
D_CFLAGS  = -g2 -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -fsanitize=undefined -fsanitize-trap
LDLIBS   != pkg-config --cflags --libs sdl2

water-sort-puzzle$(EXE): water-sort-puzzle.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

debug$(EXE): water-sort-puzzle.c
	$(CC) $(D_CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f water-sort-puzzle$(EXE)
