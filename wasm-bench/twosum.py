# WebAssembly benchmarking
# $ clang --target=wasm32 -O -nostdlib -Wl,--no-entry -o twosum.wasm twosum.c
# $ uv run --with=pywasm3,wasmtime twosum.py
#
# WebAssembly runs much faster than Python, but the context switch is
# relatively expensive, copying data in and out of Wasm memory for each
# operation. The benchmark deliberately pays this cost, with results
# (shared instance only):
#
#             cpython   pypy
#   wasm3:         3x  1.25x
#   wasmtime:     10x  2.00x
#
# That would be typical when replacing hot spots in existing Python with
# equivalent Wasm, leaving the original interface untouched. A 10x boost
# just from that is a good start! Ideally we would change the interface
# to use batching and zero-copy buffer protocol, e.g. np.ndarray backed
# by Wasm memory. In that case typical speed boosts are more in the
# realm of 10x and 100x respectively (2x and 8x for pypy).
#
# That's straightforward single-threaded performance. Running solvers in
# parallel requires separate instances. In the results, "shared" reuses
# one instance between calls, and "fresh" creates a new instance on each
# call. In this benchmark, fresh instantation adds a ~40% overhead for
# wasmtime. So multi-threaded programs should instantate TwoSumWasmtime
# once per thread, then re-use that instance, perhaps caching it in a
# thread-local. This futher complicates Wasm as a transparent, drop-in
# replacement for an existing, thread-safe Python function.
#
# pywasm3 is delivered only as source, and so requires a C compiler on
# the target, which kind of defeats the purpose of doing this in Wasm.
# In contrast, the wasmtime package comes in all flavors of the three
# most popular operating systems and two most popular architectures. So
# you can bundle fast Wasm routines with your pure Python while only
# relying on plain old pip dependencies. It's overall better for this
# particular purpose.

import functools
import random
import struct
import timeit
import wasm3
import wasmtime

class TwoSumPython():
    @staticmethod
    def twosum(nums, target):
        seen = {}
        for i, num in enumerate(nums):
            try:
                return seen[target - num], i
            except:
                seen[num] = i
        return None

class TwoSumWasmtime():
    # NOTE: lazy cache, multi-threaded programs require synchronization
    _module = None

    @classmethod
    def _compile(cls, store):
        if cls._module is None:
            module = wasmtime.Module.from_file(store.engine, "twosum.wasm")
            cls._module = module.serialize()  # save for later
        else:
            module = wasmtime.Module.deserialize(store.engine, cls._module)
        return module

    def __init__(self):
        store    = wasmtime.Store()
        module   = self._compile(store)
        instance = wasmtime.Instance(store, module, ())
        exports  = instance.exports(store)

        newarena     = functools.partial(exports["newarena"], store)
        self._alloc  = functools.partial(exports["alloc"], store)
        self._reset  = functools.partial(exports["reset"], store)
        self._twosum = functools.partial(exports["twosum"], store)
        self._arena  = newarena(1<<30) & 0xffffffff
        self._memory = exports["memory"].get_buffer_ptr(store)

    def twosum(self, nums, target):
        self._reset(self._arena)
        numsptr = self._alloc(self._arena, len(nums), 4, 4) & 0xffffffff
        struct.pack_into(f"<{len(nums)}i", self._memory, numsptr, *nums)
        retptr = self._twosum(numsptr, len(nums), target, self._arena)
        if retptr == 0:
            return None
        return struct.unpack_from("<ii", self._memory, retptr)

class TwoSumWasm3():
    # NOTE: lazy cache, multi-threaded programs require synchronization
    _wasm = None

    @classmethod
    def _parse(cls, env):
        if cls._wasm is None:
            with open("twosum.wasm", "rb") as f:
                cls._wasm = f.read()
        return env.parse_module(cls._wasm)

    def __init__(self):
        env = wasm3.Environment()
        rt  = env.new_runtime(2**10)

        # Loading a module links it with this runtime. It cannot be
        # linked again. To have independant instances, each instance
        # must parse the Wasm image from scratch. That is why the
        # "fresh" bench performs worse than plain Python.
        rt.load(self._parse(env))

        newarena     = rt.find_function("newarena")
        self._alloc  = rt.find_function("alloc")
        self._reset  = rt.find_function("reset")
        self._twosum = rt.find_function("twosum")
        self._arena  = newarena(1<<30) & 0xffffffff
        self._memory = rt.get_memory(0)

    def twosum(self, nums, target):
        self._reset(self._arena)
        numsptr = self._alloc(self._arena, len(nums), 4, 4) & 0xffffffff
        struct.pack_into(f"<{len(nums)}i", self._memory, numsptr, *nums)
        retptr = self._twosum(numsptr, len(nums), target, self._arena)
        if retptr == 0:
            return None
        return struct.unpack_from("<ii", self._memory, retptr)

def bench(name, twosum):
    rng    = random.Random(150)  # chosen for unique solution
    nums   = [rng.randint(-10**9, 10**9) for _ in range(500000)]
    idx    = list(range(len(nums)))
    ai, aj = rng.sample(range(len(nums)), 2)
    target = nums[ai] + nums[aj]

    try:
        with open("nums.txt", "wx") as f:
            print(", ".join(str(n) for n in nums), file=f)
    except:
        pass

    ri, rj = twosum(nums, target)
    assert ri == ai and rj == aj

    time = min(*timeit.repeat(
        stmt="twosum(nums, target)",
        number=10,
        globals={
            "twosum": twosum,
            "nums":   nums,
            "target": target
        },
    ))
    print(f"{name:20}{time:.3g}")

bench("python", TwoSumPython().twosum)
bench("wasmtime-shared", TwoSumWasmtime().twosum)
bench("wasmtime-fresh", lambda n, t: TwoSumWasmtime().twosum(n, t))
bench("wasm3-shared", TwoSumWasm3().twosum)
bench("wasm3-fresh", lambda n, t: TwoSumWasm3().twosum(n, t))
