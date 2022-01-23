.POSIX:
CC      = cc
CFLAGS  = -Wall -Wextra -Og -g
LDFLAGS =
LDLIBS  =

check: tests$(EXE)
	./tests

test: check

tests$(EXE): tests.c cp1252.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests.c $(LDLIBS)

clean:
	rm -f tests$(EXE)
