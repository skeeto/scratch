#!/usr/bin/env python3
"""Run formalized conjecture checks and report any counterexamples.

Checks live in checks.py as a list of dicts:

    {
        "id": "short-name",
        "oeis": "A123456",          # or other source reference
        "claim": "the informal statement being tested",
        "check": callable,          # () -> witness (falsifies) or None (holds)
    }

Each check function does its own iteration and returns the first
counterexample witness it finds (any printable object), or None if the
claim survived the search range. Keep checks in exact integer
arithmetic — a counterexample is only as good as the checker.

Usage:
  python3 verify.py            # run everything
  python3 verify.py short-name # run one check
"""
import sys
import time

from checks import CHECKS


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    failures = 0
    for c in CHECKS:
        if only and c["id"] != only:
            continue
        t0 = time.time()
        witness = c["check"]()
        dt = time.time() - t0
        if witness is None:
            print(f"PASS  {c['id']:24s} ({c['oeis']}) {dt:6.1f}s")
        else:
            failures += 1
            print(f"FAIL  {c['id']:24s} ({c['oeis']}) {dt:6.1f}s")
            print(f"      claim:   {c['claim']}")
            print(f"      witness: {witness}")
    if failures:
        print(f"\n{failures} counterexample(s) found — verify by hand, "
              "then report (e.g. as an OEIS edit).")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
