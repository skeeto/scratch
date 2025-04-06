CC          = cc
CFLAGS      = -O2
LDFLAGS     = -s
DBG_CFLAGS  = -g3 -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -fsanitize=undefined -fsanitize-trap
SDL2_FLAGS != pkg-config --cflags --libs sdl2

water-sort-sdl2$(EXE): main_sdl2.c water-sort.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main_sdl2.c $(SDL2_FLAGS)

debug-sdl2$(EXE): main_sdl2.c water-sort.c
	$(CC) $(DBG_CFLAGS) -o $@ main_sdl2.c $(SDL2_FLAGS)

water-sort.wasm: main_wasm.c water-sort.c
	clang --target=wasm32 -nostdlib -Wall -Wextra $(CFLAGS) \
	  $(LDFLAGS) -Wl,--no-entry -fno-builtin -o $@ main_wasm.c

water-sort.wasm.b64: water-sort.wasm
	(printf '"'; base64 <$^ | tr -d '\n'; printf '"') >$@

index.html: index.html.in seeds.txt water-sort.wasm.b64
	clang -E -P -undef -nostdinc -x c -o $@ index.html.in

water-sort.exe: main_windows.c water-sort.c
	$(CC) -nostartfiles -mwindows -fno-builtin $(CFLAGS) $(LDFLAGS) \
	      -o $@ main_windows.c

debug.exe: main_windows.c water-sort.c
	$(CC) -nostartfiles -mwindows $(DBG_CFLAGS) -o $@ main_windows.c

clean:
	rm -f water-sort-sdl$(EXE) debug-sdl$(EXE) water-sort.exe debug.exe \
	   water-sort.wasm water-sort.wasm.b64 index.html
