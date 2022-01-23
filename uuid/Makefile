.POSIX:
CC      = cc
CFLAGS  = -std=c99 -O3 -Wall -Wextra
LDFLAGS = -s
LDLIBS  =

uuidgen$(EXE): etc/main.c uuidgen.c uuidgen.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ etc/main.c uuidgen.c $(LDLIBS)

clean:
	rm -f uuidgen$(EXE)
