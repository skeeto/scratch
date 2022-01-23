.POSIX:
CC      = cc -std=c99
CFLAGS  = -Wall -Wextra -O3
LDFLAGS =
LDLIBS  =

test: test.c set32.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test.c $(LDLIBS)

clean:
	rm -f test
