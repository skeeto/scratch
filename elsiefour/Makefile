.POSIX:
CC = cc
CFLAGS = -ansi -pedantic -Wall -Wextra -O3 -g3

lc4: lc4.c lc4.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ lc4.c $(LDLIBS)

check: lc4
	./lc4 -T

clean:
	rm -rf lc4
