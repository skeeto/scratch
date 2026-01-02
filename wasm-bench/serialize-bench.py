# $ uv run --with=wasmtime serialize-bench.py
import timeit
import wasmtime

def oneshot():
    # Compile once per instance.
    # Measures a naive re-recompilation on every instance.
    store    = wasmtime.Store()
    module   = wasmtime.Module.from_file(store.engine, "twosum.wasm")
    instance = wasmtime.Instance(store, module, ())

def serialize():
    # Compile, serialize, deserialize per instance.
    # Measures a scenario where only a single instance was needed.
    store    = wasmtime.Store()
    module   = wasmtime.Module.from_file(store.engine, "twosum.wasm")
    compiled = module.serialize()

    store    = wasmtime.Store()
    module   = wasmtime.Module.deserialize(store.engine, compiled)
    instance = wasmtime.Instance(store, module, ())

def create_multishot():
    # Compile once, deserialize per instance.
    # Measures amortized compile, instantiate many times.
    store    = wasmtime.Store()
    module   = wasmtime.Module.from_file(store.engine, "twosum.wasm")
    compiled = module.serialize()

    def multishot():
        store    = wasmtime.Store()
        module   = wasmtime.Module.deserialize(store.engine, compiled)
        instance = wasmtime.Instance(store, module, ())
    return multishot

for f in (oneshot, serialize, create_multishot()):
    print(f"{f.__name__:15}", min(*timeit.repeat(
        stmt="f()",
        repeat=100,
        number=100,
        globals={"f": f},
    )))
