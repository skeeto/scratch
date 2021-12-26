CC      = cc
CFLAGS  = -Wall -Wextra -Os
LDFLAGS = -s
LDLIBS  = -lz

pngattach$(EXE): pngattach.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pngattach.c $(LDLIBS)

clean:
	rm -f pngattach$(EXE)
