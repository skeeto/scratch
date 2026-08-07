"""Formalized conjecture checks, in the shape verify.py expects.

These two were mined from OEIS by mine.py and formalized by hand as
worked examples. Add more by hand or via formalize.py (review its
output before pasting it here).
"""
from mine import bfile_terms


def sieve_primes(limit):
    composite = bytearray(limit + 1)
    primes = []
    for i in range(2, limit + 1):
        if not composite[i]:
            primes.append(i)
            for j in range(i * i, limit + 1, i):
                composite[j] = 1
    return primes


def check_gilbreath(rows=3000):
    """A036262: iterated absolute differences of the primes.

    Gilbreath's conjecture (1958): the first term of every difference
    row is 1. Recomputed from scratch; nothing taken from the entry.
    """
    row = sieve_primes(40000)[: rows + 1]
    for i in range(1, rows + 1):
        row = [abs(row[j + 1] - row[j]) for j in range(len(row) - 1)]
        if row[0] != 1:
            return ("row", i, "starts with", row[0])
    return None


def check_bras_amoros():
    """A007323: number of numerical semigroups of genus n.

    Bras-Amorós conjecture A (2007, still open): a(n) >= a(n-1) + a(n-2).
    Computing new terms is expensive (state of the art is genus ~75), so
    this tests the full b-file — every term anyone has computed.
    """
    a = bfile_terms("A007323")
    for n in sorted(a):
        if n - 2 in a and a[n] < a[n - 1] + a[n - 2]:
            return (n, a[n], "<", a[n - 1], "+", a[n - 2])
    return None


CHECKS = [
    {
        "id": "gilbreath",
        "oeis": "A036262",
        "claim": "first term of every iterated prime difference row is 1",
        "check": check_gilbreath,
    },
    {
        "id": "bras-amoros",
        "oeis": "A007323",
        "claim": "numerical semigroups: a(n) >= a(n-1) + a(n-2)",
        "check": check_bras_amoros,
    },
]
