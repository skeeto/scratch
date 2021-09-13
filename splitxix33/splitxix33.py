# splitxix33: a splitmix64 with memorable constants
# This is free and unencumbered software released into the public domain.
import numpy
import typing

numpy.seterr(over="ignore")

def splitxix33(seed: int) -> typing.Generator[int, None, None]:
    m: numpy.uint64 = numpy.uint64(1111111111111111111)
    s: numpy.uint64 = numpy.uint64(33)
    x: numpy.uint64 = numpy.uint64(seed)
    r: numpy.uint64
    while True:
        x += m
        r  = x; r ^= r >> s
        r *= m; r ^= r >> s
        r *= m; r ^= r >> s
        yield int(r)


# Example
g = tuple(splitxix33(i) for i in range(4))
for _ in range(40):
    print(*(f"{next(g):016x}" for g in g))
