CC      = cc
CFLAGS  = -std=c11 -march=x86-64-v3 -O3 -g3 -Wall -Wextra
LDFLAGS =
LDLIBS  =

csvquote$(EXE): csvquote.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ csvquote.c $(LDLIBS)

bench$(EXE): etc/bench.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ etc/bench.c $(LDLIBS)

benchmark: csvquote$(EXE) bench$(EXE)
	./bench | ./csvquote >/dev/null

clean:
	rm -f csvquote$(EXE) bench$(EXE)
