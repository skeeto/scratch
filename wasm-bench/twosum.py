# WebAssembly benchmarking
# $ clang --target=wasm32 -O -nostdlib -Wl,--no-entry -o twosum.wasm twosum.c
# $ uv run --with=pywasm3,wasmtime twosum.py
#
# WebAssembly runs much faster than Python, but the context switch is
# relatively expensive, copying data in and out of Wasm memory for each
# operation. The benchmark deliberately pays this cost, with results:
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

class TwoSumWasm3():
    def __init__(self):
        wasmenv  = wasm3.Environment()
        wasmrt   = wasmenv.new_runtime(2**10)
        with open("twosum.wasm", "rb") as f:
            wasmrt.load(wasmenv.parse_module(f.read()))
        newarena     = wasmrt.find_function("newarena")
        self._alloc  = wasmrt.find_function("alloc")
        self._reset  = wasmrt.find_function("reset")
        self._twosum = wasmrt.find_function("twosum")
        self._arena  = newarena(1<<30) & 0xffffffff
        self._memory = wasmrt.get_memory(0)

    def twosum(self, nums, target):
        self._reset(self._arena)
        numsptr = self._alloc(self._arena, len(nums), 4, 4) & 0xffffffff
        struct.pack_into(f"<{len(nums)}i", self._memory, numsptr, *nums)
        retptr = self._twosum(numsptr, len(nums), target, self._arena)
        if retptr == 0:
            return None
        return struct.unpack_from("<ii", self._memory, retptr)

class TwoSumWasmtime():
    def __init__(self):
        store    = wasmtime.Store()
        module   = wasmtime.Module.from_file(store.engine, "twosum.wasm")
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

def bench(name, solver):
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

    ri, rj = solver.twosum(nums, target)
    assert ri == ai and rj == aj

    print(f"{name:12}", min(*timeit.repeat(
        stmt="twosum(nums, target)",
        number=10,
        globals={
            "twosum": solver.twosum,
            "nums":   nums,
            "target": target
        },
    )))

bench("python",   TwoSumPython())    # 1x
bench("wasm3",    TwoSumWasm3())     # 3x to 10x
bench("wasmtime", TwoSumWasmtime())  # 10x to 100x
