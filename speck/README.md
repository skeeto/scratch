# C99 implementation of Speck128/128

This is a public domain implementation of [NSA's Speck cipher][spec],
specificially the 128-bit block, 128-bit key variant. It's provided as a
header library with three functions:

~~~c
void speck_init(struct speck *, uint64_t, uint64_t);
void speck_encrypt(const struct speck *, uint64_t *, uint64_t *);
void speck_decrypt(const struct speck *, uint64_t *, uint64_t *);
~~~

[spec]: http://eprint.iacr.org/2013/404.pdf
