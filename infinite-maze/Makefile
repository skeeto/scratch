WFLAGS = -Wall -Wconversion
SDLFLAGS != pkg-config --cflags --libs sdl2

maze.wasm: main_wasm.c maze.c
	clang --target=wasm32 -std=gnu23 $(WFLAGS) -Oz -nostdlib -s \
	  -mbulk-memory -fno-builtin -Wl,--no-entry -Wl,--stack-first \
	  -z stack-size=4096 -o maze.wasm main_wasm.c

maze.exe: main_win32.c maze.c
	cc -g3 $(WFLAGS) -fsanitize=undefined -fsanitize-trap -o $@ main_win32.c

maze-sdl2: main_sdl2.c maze.c
	cc -std=gnu23 -g3 $(WFLAGS) -o maze-sdl2 main_sdl2.c $(SDLFLAGS)

clean:
	rm -f maze.wasm maze.exe maze-sdl2
