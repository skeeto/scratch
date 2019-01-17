# AES-128 implemented with AES-NI intrinsics in C

This is a C header library.

```c
void aes128_init(struct aes128 *ctx, const void *key);
void aes128_encrypt(struct aes128 *ctx, void *pt, const void *ct);
void aes128_decrypt(struct aes128 *ctx, void *ct, const void *pt);
```

Compile with `-maes` or equivalent.
