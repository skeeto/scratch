.POSIX:
CC      = cc
CFLAGS  = -std=c99 -Wall -Wextra -O3 -maes -march=native
LDFLAGS =
LDLIBS  =

all: tests/tests tests/dump

tests/tests: tests/tests.c aes128ni.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/tests.c $(LDLIBS)

tests/dump: tests/dump.c aes128ni.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests/dump.c $(LDLIBS)

check: tests/tests
	tests/tests

clean:
	rm -f tests/dump tests/tests
