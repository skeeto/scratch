# Monocrypt

Monocrypt is a minimalistic password-based authenticated encryption tool
that encrypts files/pipes with XChacha20/Poly1305 as defined in [RFC
8439][rfc]. Keys are derived using Argon2i. Data are encrypted in chunks,
so arbitrarily large ciphertexts are supported with fixed memory.

Supported on unix-likes and Windows.

## Usage

    usage: monocrypt <-E|-D> [-h] [-o FILE] [-p PASSWORD] [FILE]

The two modes of operation are `-E` (encrypt) or `-D` (decrypt).

Without `-o` (output file), output is written to standard output. Without
the positional argument, input is read from standard input. Without `-p`
(password), `monocrypt` interactively prompts for a password.

Upon failure, `monocrypt` will try to delete the output file.

### Examples

    $ ./monocrypt -E -o message.txt.enc message.txt 

On the other end, this prints the decrypted message to the terminal:

    $ ./monocrypt -D message.txt.enc

## Details

The first 24 bytes of the format are the nonce, followed by 64MiB chunks
of ciphertext encrypted with XChacha20/Poly1305. The nonce is incremented
(little endian) after each chunk. A short chunk, possibly just the 16-byte
MAC, indicates end of file.


[rfc]: https://tools.ietf.org/html/rfc8439

