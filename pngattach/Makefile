.POSIX:
CC      = cc
CFLAGS  = -Wall -Wextra -Os
LDFLAGS = -s
LDLIBS  = -lz
PREFIX  = /usr/local

pngattach$(EXE): pngattach.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pngattach.c $(LDLIBS)

install: pngattach$(EXE)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 pngattach$(EXE) $(DESTDIR)$(PREFIX)/bin
	gzip <pngattach.1 >$(DESTDIR)$(PREFIX)/share/man/man1/pngattach.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pngattach$(EXE)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/pngattach.1.gz

clean:
	rm -f pngattach$(EXE)
