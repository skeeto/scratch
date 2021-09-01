# BrianVM: a programming challenge

BrianVM is a programming challenge I created in January 2020 for a friend
who just had a traumatic health experience and had endured a stay in the
hospital. He needed both a "brain exercise" and a good distraction, and I
thought this would fit the bill.

## BrianVM Specification

Memory is a 256-byte array containing both program and data. A program is
an array of 256 unsigned bytes loaded into this memory, and the program
may modify any byte of memory — i.e. it may be self-mutating. The machine
has one register, program counter (`PC`), which is initialized to zero.
The instruction set has 11 opcodes. An instruction is one opcode byte
followed by one or two operand bytes.  Out-of-bounds memory accesses are
impossible since only 256 bytes are addressable.

In the opcode specifications below, brackets indicate memory dereference
(as in x86).

    PUT: (opcode 0) [addr]

Output the byte at the address `ADDR`.

    MOV: (opcode 1) [dst] [src]

Copy byte from address `SRC` to address `DST`.

    ADD: (opcode 2) [dst] IMM
    SUB: (opcode 3) [dst] IMM
    MUL: (opcode 4) [dst] IMM
    DIV: (opcode 5) [dst] IMM
    MOD: (opcode 6) [dst] IMM

Add/sub/mul/div/mod 1-byte immediate with value at address `DST`, storing
result in address `DST`. Divide by zero is undefined. All operations are
unsigned and may overflow or underflow the result.

    RND: (opcode 7) [dst]

Store a random byte at address `DST`. How you generate it is up to you.

    SLP: (opcode 8) IMM

Sleep for `IMM` milliseconds. Must flush all output before sleeping
(important!).

    BRA: (opcode 9) abs

Unconditionally set `PC` to `ABS`.

    BRZ: (opcode 10) [test] abs

If the value at address `TEST` is zero, set `PC` to `ABS`.

## Sample program

Here's a program I made especially for Brian. Below are the 256 bytes in
hexadecimal. (No peeking at the ASCII values!) This program requires a
terminal supporting ANSI escapes at least as big as 80x24.

    01 04 07 0a 00 0d 00 f8 02 07 01 09 00 04 07 00
    02 07 f8 07 e0 06 e0 3a 07 df 06 df 18 01 ff df
    06 ff 0a 02 ff 30 01 d9 ff 05 df 0a 02 df 30 01
    d8 df 01 ff e0 06 ff 0a 02 ff 30 01 dc ff 05 e0
    0a 02 e0 30 01 db e0 01 4b 4e 0a 00 54 00 d6 02
    4e 01 09 47 04 4e 00 02 4e d6 07 ff 06 ff 08 02
    ff 30 01 d1 ff 01 69 6c 0a 00 72 00 ce 02 6c 01
    09 65 04 6c 00 02 6c ce 01 7c 7f 0a 00 87 00 e1
    02 7f 01 08 8c 09 78 04 7f 00 02 7f e1 08 fa 08
    fa 09 13 6a ba 1f 6d a3 e6 ad 3b ae 4d 6e c1 fa
    11 ed 22 2e 6d a3 ed 48 3d f9 4d ed 24 29 2a 16
    e3 09 25 c6 31 62 b5 21 2e a0 47 5b a2 02 3c 82
    83 4f 58 2a 65 87 25 43 6d de a9 31 81 09 1b 5b
    39 63 3b 31 6d 00 1b 5b 78 78 3b 79 79 48 00 18
    55 47 65 74 20 77 65 6c 6c 20 73 6f 6f 6e 2c 20
    42 72 69 61 6e 21 0a 00 1b 5b 32 4a 1b 5b 48 00
