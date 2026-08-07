# conjecture-hunt

Tooling for hunting counterexamples to neglected, machine-checkable
conjectures. A counterexample is the one mathematical artifact you can
fully trust without reading a proof: it's a witness you can verify with
a short program in exact arithmetic.

## Strategy

The expected value of a hunt is roughly:

    P(claim is false) x P(counterexample is within computational reach)
                      x (how un-picked-over the claim is)

Famous conjectures (Collatz, Goldbach, twin primes) fail on all three
factors: strong heuristic arguments say they're true, and the search
frontiers already sit at 2^68+. The fruit is in claims that are
*neglected*: stated once, checked to a few hundred terms, never
revisited.

The best hunting grounds, in rough order of hit-rate per CPU-hour:

1. **OEIS conjectures** (this repo's focus). Thousands of entries carry
   comments like "Conjecture: a(n) = ... for all n", typically verified
   only as far as the listed terms. People find false ones regularly;
   a counterexample becomes an accepted OEIS edit. This is also where
   an LLM helps most: parsing informal claim text into checker code is
   exactly the tedious-but-shallow work it's good at, while the actual
   verification stays in dumb, auditable, exact-arithmetic code.
2. **Machine-generated conjectures** (TxGraffiti and friends): graph
   inequality conjectures produced in bulk, many never examined. Test
   against exhaustive small-graph enumeration (nauty's `geng` covers
   all graphs on <= 10 vertices).
3. **Erdős problems database** (erdosproblems.com): filter for
   existence/construction questions where a verifiable object settles
   the problem.
4. **Combinatorial records**: not counterexamples, but the same shape —
   a small certificate anyone can check (Ramsey lower bounds, cap sets,
   a 6-chromatic unit-distance graph). Aubrey de Grey's 5-chromatic
   graph (2018) is the model story: an outsider with compute moved a
   60-year-old problem.

Historical calibration: Pólya's conjecture stood for ~40 years and held
for 900 million consecutive cases before failing (see below). Mertens,
Skewes-type crossovers, and Haselgrove-style results all rhyme:
"verified to N" is weak evidence over an infinite domain, especially
for claims with no heuristic drift argument backing them.

## Contents

| file | what it does |
|---|---|
| `polya.c` | Sanity anchor: refinds the minimal counterexample to Pólya's conjecture (1919) from scratch — L(906,150,257) = 1 — with a segmented Liouville sieve, ~1 min. Proves the whole loop end to end. |
| `mine.py` | Searches OEIS for conjecture-bearing entries, dumps them to JSONL. Also fetches/caches b-files. |
| `formalize.py` | Sends mined claims to Claude (Anthropic API) to classify testability and draft `check()` functions. Output is for **human review** — never exec unread generated code, and independently verify any counterexample a generated checker reports. |
| `checks.py` | Reviewed, formalized checks. Ships with two worked examples: Gilbreath (A036262, recomputed from primes) and Bras-Amorós (A007323, tested against the full b-file). |
| `verify.py` | Runs everything in `checks.py`, prints PASS/FAIL with the witness. |

## Quickstart

    cc -O2 -o polya polya.c && ./polya   # refind a famous counterexample
    python3 mine.py --pages 50           # harvest candidate conjectures
    python3 formalize.py mined.jsonl --limit 20   # needs ANTHROPIC_API_KEY
    # review formalized.jsonl, port keepers into checks.py, then:
    python3 verify.py

## Scaling up

- The OEIS search API returns 10 entries per page; for a full sweep,
  clone the `oeis/oeisdata` GitHub repo (every entry as a text file)
  and grep for `Conjecture` locally instead of paging the API.
- Push checker bounds by orders of magnitude past the listed terms —
  the marginal cost is CPU, and the frontier is usually where nobody
  has looked.
- A FAIL from verify.py is the start, not the end: reverify the witness
  with independent code (ideally a different algorithm), then check the
  claim's wording against the entry once more before reporting it.
