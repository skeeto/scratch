# High performance csvquote with SIMD

Inspired by [the original][orig] ([via][]), this command line tool
converts LINE FEED (LF, U+000A) into RECORD SEPARATOR (RS, U+001E), and
COMMA (U+002C) into UNIT SEPARATOR (US, U+001F) when these characters
appear inside quoted CSV fields, allowing CSV files to be more easily
processed by standard unix command line tools.

    $ csvquote <data.csv |
          awk -F, '{print $1 "," $2+$3}' |
          csvquote -u >sum.csv

This version includes an AVX2 implementation that processes CSV at about 4
GiB/s on modern hardware. It operates on 32-byte chunks at a time and uses
a two's complement trick to discover quoted ranges of input. The slower
plain C fallback implementation uses a branchless lookup table, about 2x
faster than the original implementation.

It's fast enough that stdio becomes a serious bottleneck, so the program
bypasses it if possible.

## Benchmark

To run the live benchmark:

    make bench


[orig]: https://github.com/dbro/csvquote
[via]: https://github.com/adamgordonbell/csvquote
