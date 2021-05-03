# Marvin32 hash function

A lean C implementation of the [patented][] non-cryptographic, keyed hash
function Marvin32 as used in the .NET implementation of C#.

```c
uint32_t marvin32(const void *buf, size_t len, uint64_t key);
```

[patented]: https://patents.google.com/patent/US20130262421
