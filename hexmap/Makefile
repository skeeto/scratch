.POSIX:
CC      = cc
CFLAGS  = -std=c99 -pedantic \
    -Ofast -march=native \
    -ggdb3 -fsanitize=address -fsanitize=undefined \
    -Wall -Wextra -Wdouble-promotion
LDFLAGS = -fsanitize=address -fsanitize=undefined
LDLIBS  = -lm

hexmap: hexmap.c bmp.h getopt.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ hexmap.c $(LDLIBS)

clean:
	rm -f hexmap hexmap.exe
