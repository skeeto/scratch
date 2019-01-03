.POSIX:
CC = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3

all: tests/md2sum tests/tests

tests/md2sum: tests/md2sum.c md2.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/md2sum.c $(LDLIBS)

tests/tests: tests/tests.c md2.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/tests.c $(LDLIBS)

clean:
	rm -f tests/md2sum tests/tests

check: tests/tests
	tests/tests
