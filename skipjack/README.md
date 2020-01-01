# Skipjack C89 header file library

This is a strictly conforming C89 implementation of the [Skipjack
cipher][w] ([PDF][p], [HTML][h]) as an embeddable, single-file header
library. Keys are 80 bits long, blocks are 64 bits wide, 31 of 32 rounds
have long been broken, and there is no key setup. Only the encryption
function is implemented since that's sufficient for analysis, it's
enough to operate in CTR mode, and I really didn't feel like working out
decryption. The library is optimized for compactness and correctness,
not performance.

```c
void skipjack_encrypt(const void *key, void *block);
```

[h]: https://cryptome.org/jya/skipjack-spec.htm
[p]: https://web.archive.org/web/20010603000755/http://csrc.nist.gov/encryption/skipjack/skipjack.pdf
[w]: https://en.wikipedia.org/wiki/Skipjack_(cipher)
