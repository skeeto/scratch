CC      = cc -std=c11
CFLAGS  = -march=x86-64-v3 -O3 -g3 -Wall -Wextra
LDFLAGS =
LDLIBS  =

csvquote$(EXE): csvquote.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ csvquote.c $(LDLIBS)

csvdump$(EXE): etc/csvdump.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ etc/csvdump.c $(LDLIBS)

bench: csvquote$(EXE) csvdump$(EXE)
	./csvdump | ./csvquote >/dev/null

clean:
	rm -f csvquote$(EXE) csvdump$(EXE)
