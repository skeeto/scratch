.POSIX:
CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -std=c99 -Os -ffreestanding -Wall -Wextra -Werror \
    -fno-stack-check -fno-stack-protector -mno-stack-arg-probe \
    -DNDEBUG
LDFLAGS = -s -nostdlib -mwindows
LDLIBS  = -lkernel32 -luser32 -lgdi32 -lopengl32

main.exe: main.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c $(LDLIBS)

clean:
	rm -f main.exe
