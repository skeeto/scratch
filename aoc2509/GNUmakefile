all: aoc2509$(EXE) generate$(EXE)

aoc2509$(EXE): main_libc.c
	cc -Wall -Wconversion -g3 -fsanitize=undefined -fsanitize-trap -o $@ $^

generate$(EXE): generate.c
	cc -Wall -Wconversion -Wno-unused-functions \
	   -g3 -fsanitize=undefined -fsanitize-trap -o $@ $^

aoc2509.wasm: main_wasm.c
	clang -std=gnu23 \
		  --target=wasm32 \
		  -nostdlib \
		  -Wall -Wconversion \
		  -Oz -s \
		  -mbulk-memory \
		  -mmultivalue \
		  -Xclang -target-abi -Xclang experimental-mv \
		  -Wl,--no-entry \
		  -Wl,--stack-first \
		  -z stack-size=4096 \
		  -o $@ \
		  $^

clean:
	rm -f aoc2509$(EXE) generate$(EXE) aoc2509.wasm
