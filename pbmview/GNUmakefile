.POSIX:
CROSS   =
CC      = $(CROSS)gcc
CFLAGS  = -std=c99 -Wall -Wextra -Wpedantic -Wno-missing-field-initializers -O3
LDFLAGS = -mwindows -s
LDLIBS  = -lshlwapi
WINDRES = $(CROSS)windres

pbmview.exe: pbmview.c icon.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pbmview.c icon.o $(LDLIBS)

icon.o: pbmview.ico
	echo '1 ICON "pbmview.ico"' | $(WINDRES) -o $@

clean:
	rm -f pbmview.exe icon.o
