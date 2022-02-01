.POSIX:
CC      = cc
CFLAGS  = -ansi -pedantic -Os -Wall -Wextra
LDFLAGS = -s
LDLIBS  =

prips$(EXE): prips.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ prips.c $(LDLIBS)

install: prips$(EXE)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 prips$(EXE) $(DESTDIR)$(PREFIX)/bin
	gzip <prips.1 >$(DESTDIR)$(PREFIX)/share/man/man1/prips.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/prips$(EXE)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/prips.1.gz

clean:
	rm -f prips$(EXE)
