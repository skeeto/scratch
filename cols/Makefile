CC      = cc
CFLAGS  = -ansi -pedantic -O3 -Wall -Wextra
LDFLAGS = -s
LDLIBS  =

cols$(EXE): cols.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ cols.c $(LDLIBS)

clean:
	rm -f cols$(EXE)
