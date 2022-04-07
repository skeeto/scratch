.POSIX:
CC      = cc
CFLAGS  = -Wall -Wextra -O3 -march=native -g
LDFLAGS =
LDLIBS  =

all: convert$(EXE) render$(EXE)

convert$(EXE): convert.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ convert.c $(LDLIBS)

render$(EXE): render.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ render.c $(LDLIBS)

clean:
	rm -f convert$(EXE) render$(EXE)
