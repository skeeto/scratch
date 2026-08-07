#!/usr/bin/env python3
"""Turn mined OEIS conjecture text into candidate Python checkers via Claude.

Reads records from mine.py's JSONL output, asks Claude to classify each
claim and, when it's mechanically testable, emit a check() function in
the shape verify.py expects. Results go to a JSONL file for HUMAN REVIEW
— never exec generated code without reading it first. The generated
checker is a search program; any counterexample it reports must then be
verified independently by hand before you believe it.

Usage:
  python3 formalize.py mined.jsonl --out formalized.jsonl --limit 20

Requires ANTHROPIC_API_KEY (or an `ant auth login` profile).
"""
import argparse
import json
import sys

import anthropic

SCHEMA = {
    "type": "object",
    "properties": {
        "testable": {
            "type": "boolean",
            "description": "True only if the claim is a precise universal "
            "statement checkable by finite computation per n.",
        },
        "reason": {"type": "string"},
        "code": {
            "type": "string",
            "description": "Python source defining check() -> witness or "
            "None. Empty string when not testable.",
        },
    },
    "required": ["testable", "reason", "code"],
    "additionalProperties": False,
}

PROMPT = """\
You are formalizing a conjecture found in OEIS entry {anum} ("{name}").

Conjecture text (verbatim from the entry):
{claims}

First terms of the sequence, for grounding:
{terms}

Decide whether this is a mechanically testable universal claim (for all
n in some range, a decidable property holds). If it is, write a
self-contained Python function `check()` that recomputes the sequence
independently from its definition (do NOT trust the listed terms as
ground truth beyond sanity-checking), tests the claimed property for n
up to a bound reachable in about a minute of CPU, and returns the first
counterexample as a tuple (n, details) — or None if the claim holds
throughout. Use exact integer arithmetic only; no floats, no external
libraries beyond math/itertools/fractions. If the sequence definition
is ambiguous from the name alone, mark it not testable and say why.
"""


def formalize(client, rec):
    response = client.messages.create(
        model="claude-opus-5",
        max_tokens=16000,
        output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
        messages=[{
            "role": "user",
            "content": PROMPT.format(
                anum=rec["anum"],
                name=rec["name"],
                claims="\n".join(rec["claims"]) or rec["name"],
                terms=rec["terms"][:400],
            ),
        }],
    )
    if response.stop_reason == "refusal":
        return {"testable": False, "reason": "model refused", "code": ""}
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mined")
    ap.add_argument("--out", default="formalized.jsonl")
    ap.add_argument("--limit", type=int, default=10)
    args = ap.parse_args()

    client = anthropic.Anthropic()
    n = 0
    with open(args.mined) as f, open(args.out, "w") as out:
        for line in f:
            if n >= args.limit:
                break
            rec = json.loads(line)
            try:
                result = formalize(client, rec)
            except anthropic.APIStatusError as e:
                print(f"{rec['anum']}: API error {e.status_code}",
                      file=sys.stderr)
                continue
            result["anum"] = rec["anum"]
            result["claims"] = rec["claims"]
            out.write(json.dumps(result) + "\n")
            n += 1
            tag = "TESTABLE" if result["testable"] else "skip"
            print(f"{rec['anum']}: {tag} — {result['reason'][:80]}")
    print(f"\nwrote {n} records to {args.out}; review the code by hand, "
          "then port keepers into checks.py")


if __name__ == "__main__":
    main()
