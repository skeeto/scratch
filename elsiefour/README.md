# ANSI C implementation of ElsieFour (LC4)

This is an ANSI C implementation of [ElsieFour][pdf] (LC4), a low-tech
authenticated encryption algorithm that can be computed by hand.

## API

Since LC4 is a plaintext-dependent stream cipher, the context is mutated
as the stream is encrypted and decrypted.

```c
/* Return non-zero if KEY is a valid key.
 * A valid key is null-terminated and contains each character from the
 * valid set exactly once.
 */
int lc4_valid(const char *key);

/* Initialize the LC4 context with the given valid key.
 */
void lc4_init(struct lc4 *, const char *key);

/* Encrypt a single character, modifying the context.
 * Returns 0 if the character isn't valid.
 */
int lc4_encrypt(struct lc4 *, int);

/* Decrypt a single character, modifying the context.
 * Returns 0 if the character isn't valid.
 */
int lc4_decrypt(struct lc4 *, int);
```

The nonce and signature are the responsibility of the caller. See the
paper for how to handle this. It's really simple.

## Command Line Program

The `lc4` program is both a test suite for the library as well as a
small encryption, decryption, and key/nonce generation utility. This
isn't seriously intended for securing messages but rather for testing.

    $ lc4 -G | tee key
    kidpgvnmybos4haf5628#xcj_uztrlq739ew

    $ echo hello world | ./lc4 -E $(cat key)
    9j#akdcp3fb

    $ echo 9j#akdcp3fb | ./lc4 -D $(cat key)
    hello_world

## Other implementations

* <https://github.com/dstein64/LC4> (Python)
* <https://github.com/Gavin-Song/elsie-four-cipher> (JavaScript)
* <https://github.com/tonetheman/golang_lc4> (Go)
* <https://gitea.blesmrt.net/exa/ls47> (LS47 in Python)

[pdf]: https://eprint.iacr.org/2017/339.pdf
