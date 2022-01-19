# `cols`: wrap standard input into columns

Reads lines of input from standard input and wraps it into columns,
automatically adjusting the column width to accommodate the data. See
"Examples" below for illustrations. The input can be display row-order or
column-order.

Written in plain old ANSI C, so it works anywhere, from 16-bit DOS to
64-bit workstations. It's designed to use as little memory as possible
without sacrificing performance.

Similar to the `columns` command from GNU AutoGen, and the `column`
command from util-linux. However, this version is more portable, simpler,
faster, less memory-intensive, more precise, more correct, and
better-licensed.

Very roughly supports UTF-8 by assuming each code point has a display
width of one. This works out well in many common cases, but it will not
work with most CJK (i.e. double wide), glyphs composed of multiple code
points (combining characters, etc.), or bidirectional text. (Most terminal
emulators that would be displaying this program's output do not handle
these all correctly anyways.)

## Usage

Usage information is printed with `-h`:

    usage: cols [-Ch] [-W INT] [-w INT]
      -C      print lines in column-order
      -h      display usage information
      -W INT  desired line width [80]
      -w INT  desired column width [auto]

## Examples

Row-order:

    $ seq 100 | cols
    1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16  17  18
    19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36
    37  38  39  40  41  42  43  44  45  46  47  48  49  50  51  52  53  54
    55  56  57  58  59  60  61  62  63  64  65  66  67  68  69  70  71  72
    73  74  75  76  77  78  79  80  81  82  83  84  85  86  87  88  89  90
    91  92  93  94  95  96  97  98  99  100

Column-order:

    $ seq 100 | cols
    1   7   13  19  25  31  37  43  49  55  61  67  73  79  85  91  97
    2   8   14  20  26  32  38  44  50  56  62  68  74  80  86  92  98
    3   9   15  21  27  33  39  45  51  57  63  69  75  81  87  93  99
    4   10  16  22  28  34  40  46  52  58  64  70  76  82  88  94  100
    5   11  17  23  29  35  41  47  53  59  65  71  77  83  89  95
    6   12  18  24  30  36  42  48  54  60  66  72  78  84  90  96

Unicode-aware column layout:

    $ cols -W25 <alphabets
    A a B b C c D d E e F f G
    g H h I i J j K k L l M m
    N n O o P p Q q R r S s T
    t U u V v W w X x Y y Z z
    Α α Β β Γ γ Δ δ Ε ε Ζ ζ Η
    η Θ θ Ι ι Κ κ Λ λ Μ μ Ν ν
    Ξ ξ Ο ο Π π Ρ ρ Σ σ ς Τ τ
    Υ υ Φ φ Χ χ Ψ ψ Ω ω
