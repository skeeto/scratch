.POSIX:
CC      = cc
CFLAGS  = -ansi -pedantic -Os -Wall -Wextra
LDFLAGS = -s
LDLIBS  =

prips$(EXE): prips.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ prips.c $(LDLIBS)

clean:
	rm -f prips$(EXE)
