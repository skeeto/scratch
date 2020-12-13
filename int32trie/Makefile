.POSIX:
CC      = cc
CFLAGS  = -O3 -g -Wall -Wextra -Wno-int-in-bool-context
LDFLAGS = -fsanitize=address -fsanitize=undefined
LDLIBS  =
BENCH   =

check: test
	$(BENCH) ./test

test: test.c int32trie.c int32trie.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test.c int32trie.c $(LDLIBS)

clean:
	rm -f test test.exe
