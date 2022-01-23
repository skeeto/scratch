.POSIX:
CC      = cc
CFLAGS  = -ansi -pedantic -g -O3 -march=native
LDFLAGS =
LDLIBS  =

all: tests/dump tests/test

check: tests/test
	tests/test

clean:
	rm -rf tests/dump tests/test

tests/dump: tests/dump.c skipjack.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/dump.c $(LDLIBS)

tests/test: tests/test.c skipjack.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/test.c $(LDLIBS)
