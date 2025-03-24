CC      = cc
CFLAGS  = -O2 -Wall -Wextra -Wconversion -Wno-sign-conversion
LDFLAGS = -s
LDLIBS != pkg-config --cflags --libs sdl2

water-sort-puzzle$(EXE): water-sort-puzzle.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f water-sort-puzzle$(EXE)
