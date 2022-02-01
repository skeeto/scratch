.POSIX:
CC      = cc
CFLAGS  = -ansi -pedantic -O3 -Wall -Wextra
LDFLAGS = -s
LDLIBS  =

cols$(EXE): cols.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ cols.c $(LDLIBS)

install: cols$(EXE)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 cols$(EXE) $(DESTDIR)$(PREFIX)/bin
	gzip <cols.1 >$(DESTDIR)$(PREFIX)/share/man/man1/cols.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cols$(EXE)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/cols.1.gz

clean:
	rm -f cols$(EXE)
