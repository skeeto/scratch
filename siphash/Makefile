CC      = cc
CFLAGS  = -g -Og -fsanitize=address -fsanitize=undefined -Wall -Wextra
LDFLAGS = -fsanitize=address -fsanitize=undefined
LDLIBS  =

test: test.c siphash.c siphash.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test.c siphash.c $(LDLIBS)

check: test
	./test

clean:
	rm -f test test.exe
