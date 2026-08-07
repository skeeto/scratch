#!/usr/bin/env python3
"""Mine OEIS for machine-checkable conjectures.

Searches oeis.org for entries whose comments or formulas state a
conjecture, and dumps them to JSONL for triage. Most OEIS conjectures
were checked only as far as the listed terms (often a few hundred), so
extending the computation by a few orders of magnitude is fresh ground.

Usage:
  python3 mine.py --pages 20 --out mined.jsonl
  python3 mine.py --bfile A000045          # fetch/cache b-file terms
"""
import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

SEARCH_URL = "https://oeis.org/search?q={query}&fmt=json&start={start}"
BFILE_URL = "https://oeis.org/A{num:06d}/b{num:06d}.txt"
CACHE = Path(__file__).parent / ".cache"

CONJ_RE = re.compile(r"conjectur", re.IGNORECASE)


def fetch(url, retries=3):
    req = urllib.request.Request(
        url, headers={"User-Agent": "conjecture-hunt/0.1 (OEIS miner)"}
    )
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            if i == retries - 1:
                raise
            time.sleep(2 ** (i + 1))


def mine(pages, query, out, delay=1.0):
    n = 0
    with open(out, "w") as f:
        for page in range(pages):
            body = fetch(SEARCH_URL.format(query=query, start=page * 10))
            try:
                results = json.loads(body)
            except json.JSONDecodeError:
                print(f"page {page}: bad JSON, skipping", file=sys.stderr)
                continue
            if not isinstance(results, list):
                results = results.get("results") or []
            for entry in results:
                claims = [
                    line
                    for field in ("comment", "formula", "conjecture")
                    for line in entry.get(field) or []
                    if CONJ_RE.search(line)
                ]
                if not claims and not CONJ_RE.search(entry.get("name", "")):
                    continue
                rec = {
                    "anum": "A%06d" % entry["number"],
                    "name": entry.get("name", ""),
                    "claims": claims,
                    "terms": entry.get("data", ""),
                }
                f.write(json.dumps(rec) + "\n")
                n += 1
            print(f"page {page}: {n} candidates so far", file=sys.stderr)
            time.sleep(delay)
    print(f"wrote {n} candidates to {out}", file=sys.stderr)


def bfile_terms(anum):
    """Return the entry's b-file as a dict {n: a(n)}, cached on disk."""
    num = int(anum.lstrip("A"))
    CACHE.mkdir(exist_ok=True)
    path = CACHE / f"b{num:06d}.txt"
    if not path.exists():
        path.write_text(fetch(BFILE_URL.format(num=num)))
    terms = {}
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        idx, val = line.split()[:2]
        terms[int(idx)] = int(val)
    return terms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=10)
    ap.add_argument("--query", default='"Conjecture:"')
    ap.add_argument("--out", default="mined.jsonl")
    ap.add_argument("--bfile", help="fetch b-file for this A-number and exit")
    args = ap.parse_args()
    if args.bfile:
        terms = bfile_terms(args.bfile)
        ns = sorted(terms)
        print(f"{args.bfile}: {len(terms)} terms, n = {ns[0]}..{ns[-1]}")
        return
    mine(args.pages, urllib.parse.quote(args.query), args.out)


if __name__ == "__main__":
    main()
