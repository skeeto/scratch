# Incremental SipHash in C

Incremental, public domain, portable C implementation of [SipHash][sh], a
keyed hash function. It has [a minimalist interface][min] and makes no
allocations. It defines no extraneous macros or functions, making it perfect
for embedding and amalgamation.

```c
void     siphash_init(struct siphash *, uint64_t key0, uint64_t key1);
void     siphash_update(struct siphash *, const void *, size_t);
uint64_t siphash_final(const struct siphash *);
```

In Go style, finalization function does not modify the context, allowing more
input to be appended after the digest is computed. To clone the context, copy
it.

For a non-incremental, header library of SipHash: [**siphash.h**][hdr].


[hdr]: https://gist.github.com/skeeto/c8838cee7e97fbec483ae3cf58627154
[min]: https://nullprogram.com/blog/2018/06/10/
[sh]: https://cr.yp.to/siphash/siphash-20120620.pdf
