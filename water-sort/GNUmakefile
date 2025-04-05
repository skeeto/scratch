CC        = cc
CFLAGS    = -O2
LDFLAGS   = -s
D_CFLAGS  = -g3 -Wall -Wextra -Wconversion -Wno-sign-conversion \
  -fsanitize=undefined -fsanitize-trap
LDLIBS   != pkg-config --cflags --libs sdl2

water-sort$(EXE): main_sdl2.c water-sort.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main_sdl2.c $(LDLIBS)

debug$(EXE): main_sdl2.c water-sort.c
	$(CC) $(D_CFLAGS) -o $@ main_sdl2.c $(LDLIBS)

water-sort.wasm: main_wasm.c water-sort.c
	clang --target=wasm32 -nostdlib -Wall -Wextra $(CFLAGS) \
	  $(LDFLAGS) -Wl,--no-entry -fno-builtin -o $@ main_wasm.c

water-sort.wasm.b64: water-sort.wasm
	(printf '"'; base64 <$^ | tr -d '\n'; printf '"') >$@

index.html: index.html.in seeds.txt water-sort.wasm.b64
	clang -E -P -undef -nostdinc -x c -o $@ index.html.in

clean:
	rm -f water-sort$(EXE) debug$(EXE) \
	   water-sort.wasm water-sort.wasm.b64 index.html
