# Rough benchmarks for replacing hot spots with WebAssembly

If a Wasm runtime is available, what kind of speed-ups can we expect when
replacing hot spots written in the dynamic language with an implementation
in Wasm (e.g. compiled from C)? My results here suggest for cpython it's
in the realm of 10x to 100x faster, depending on how much the program must
context switch (copy in/out) with Wasm.
