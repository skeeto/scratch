# rec2json : record to JSON (a case study)

A record is a double precision floating point array. Each element is a
field with a unique name composed of non-empty alphanumeric segments
delimited by periods. The format contains a header listing field names,
delimited by commas, followed by concatenated records. For example, this
header names the fields a record of 7 elements:

    timestamp,point.x,point.y,foo.bar.baz,point.z,foo.bar.bax,foo.bar.quux

The goal is to convert these records to JSON, where dot-separated entries
are expanded into nested objects. Record order must be maintained, except
when it is required to move a field forward to join it with the rest of
its object, as JSON requires. So given this record:

    {1758158348, 1.23, 4.56, -100, 7.89, -200, -300}

The program would output:

```json
{
  "timestamp": 1758158348,
  "point": {
    "x": 1.23,
    "y": 4.56,
    "z": 7.89
  },
  "foo": {
    "bar": {
      "baz": -100,
      "bax": -200,
      "quux": -300
    }
  }
}
```

This is related to a recent, real-world problem I faced.

## Implementation outcomes

I wrote two nearly identical implementations, first in [my personal C
style][c], and then another in mostly conventional C++20 for comparison.
The implementations accept the header as a string, split and sort the
fields, and compile a bytecode program that converts records to JSON. The
expectation is that the header applies to many records, so resolve it once
ahead of time, then rapidly process many records by running the bytecode
on each. Both compile under the three major language implementations (GCC,
Clang, MSVC). Measurement results:

* Ignoring tests, the C implementation is ~60% longer due to defining the
  basics like the allocator and strings. Such definitions are amortized in
  real programs. The business logic is the about same size. It doesn't
  help that C++ does not automatically generate a basic hash function for
  user-defined types, and so it takes nearly as much code just to use an
  unordered map with custom keys as to write a map from scratch.

* The C version builds ~10x faster across all three compilers. This had
  substantial ergonomic effects while working on each.

* The C++ version compiles to much more code than the C version: ~10x in
  release builds and ~100x in debug builds. Plus it requires a monstrous
  runtime on top of this. The C version requires practically no runtime.

* Debug builds of the C version are ~2x faster than *release* builds of
  the C++ version across all three language implementations, despite using
  the relatively unusual `std::string_view` instead of `str::string` in
  the business logic in an effort to keep it fair. (Time spent in test
  generation is negligible.) In other words, it's faster to build *and
  then run* the C version than to simply run a run a release build of the
  C++ version. This is without taking shortcuts in the C version, e.g. by
  using fixed-length strings. Both the C and C++ versions are dynamic and
  have identical capabilities.

Ergonomically, the C version was substantially easier to debug and work
with. C++ standard library templates really throw a wrench in the works,
with enormous compiler error outputs, opaque and inaccessible variables in
debuggers (none of which are great with templates), messy backtraces, and
slow debug builds.

Only parsing and compiling are covered in the benchmark. Float to string
conversion is omitted, because it's messy and difficult to make "fair"
without more constraints (What precision is appropriate? Does it need to
be minimal? What output system?). C++ is generally the winner for this
detail as of `std::to_chars` (C++17), which provides superior float-string
conversion utilities compared to the meager C standard library. JSON from
the C++ version is minimal *and* round-trip, while the C version is merely
round-trip. Beyond floats, including C++ iostreams (greatly hindered by
locale nonsense) in the benchmark would put its performance even further
behind, so this cuts both ways.

Nothing here is surprising to me (except `std::to_chars` being better than
I realized). I was curious how well the results would match expectations,
which turned out to be well aligned: A simple, well-written C program is,
in general, significantly faster than equivalent, *conventional* C++.

## Implementation strategy

To sort the fields, each name component is interned into a string table
and assigned tokens monotonically starting from 1, leaving 0 as a special
"root" token. All strings are interned within a "namespace" of a previous
token, which can be the root token.

For instance, the `"f"` in `"a.f"` and `"b.f"` are distinct tokens. The
first is in the `[0, "a"]` namespace and the second is in the `[0, "b"]`
namespace. That is, a namespace describes a path into a JSON object. After
interning, each field is a sequence of one or more tokens. Finally sort
the fields lexicographically by their tokens. Earlier fields sort first,
being assigned tokens first, and alike fields group together.


[c]: https://nullprogram.com/blog/2025/01/19/
