# Sponge4

Sponge4 is a small, simple sponge-like hash function based on RC4
intended for seeing PRNGs from arbitrary inputs. The absorb operation
corresponds to the key schedule, and the squeeze operation corresponds
to the RC4 generator.

Since it's mainly intended for seeding, performance isn't the highest
priority. My goals:

* A small number of lines of code so that it's very friendly to dropping
  it into wherever I need it.

* Few or no extraneous definitions (internal functions, constant tables,
  etc.) This "reference" Sponge4 implementation has no definitions
  outside its interface. It doesn't even define a new type. The only
  constant is the size of the state array.

* Good avalanche effects: every input bit should have a dramatic effect
  on the output. This is intended to be used for seeding after all.

The state is a 259-byte array. The first 256 bytes are the RC4 S array.
The last three are variables `i`, `j`, and `k`. Variables `i` and `j`
correspond to `i` and `j` in both the key schedule and generator. These
variables are shared since it's a sponge, and the key schedule can be
run further after the generating output (absorb, squeeze, absorb).

The `k` variable tracks the number of bytes absorbed without squeezing.
When switching from absorb to squeeze, the input is padded to the next
256-byte block of input.

The state array has an entropy capacity of 1,700 bits: `log2(256!) + 8 +
8`. The `k` variable isn't really state (by this count), since it rather
tracks work-to-be-done before squeezing.

In my reference implementation, the user initializes the input state to
all zeroes. When the very first byte is absorbed, the state is
initialized per RC4. It is therefore impossible to absorb zero bytes
before generating output or inserting a stop.

A special "stop" symbol can be absorbed into the state, which mutates
the state unlike any possible byte value. (It just increments `j`.) A
stop is automatically inserted between the input and the padding.

## API

The entire interface and implementation is just three functions.

```c
void sp4_absorb(unsigned char s[259], int byte);
void sp4_absorb_stop(unsigned char s[259]);
int  sp4_squeeze(unsigned char s[259]);
```

The `s` buffer is initialized by setting all elements to zero.

## Helper functions

```c
void
sp4_absorb_buf(unsigned char s[259], const void *buf, size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *end = p + len;
    while (p < end)
        sp4_absorb(s, *p++);
}

void
sp4_squeeze_buf(unsigned char s[259], void *buf, size_t len)
{
    unsigned char *p = buf;
    unsigned char *end = p + len;
    while (p < end)
        *p++ = sp4_squeeze(s);
}

/* Extract 32 bits without any host byte order dependency. */
unsigned long
sp4_squeeze32(unsigned char s[259])
{
    unsigned long a[4];
    a[0] = sp4_squeeze(s);
    a[1] = sp4_squeeze(s);
    a[2] = sp4_squeeze(s);
    a[3] = sp4_squeeze(s);
    return a[0] << 0 | a[1] << 8 | a[2] << 16 | a[3] << 24;
}

/* Extract 64 bits without any host byte order dependency. */
unsigned long long
sp4_squeeze64(unsigned char s[259])
{
    int i;
    unsigned char a[8];
    for (i = 0; i < 8; i++)
        a[i] = sp4_squeeze(s);
    return (unsigned long long)a[0] <<  0 |
           (unsigned long long)a[1] <<  8 |
           (unsigned long long)a[2] << 16 |
           (unsigned long long)a[3] << 24 |
           (unsigned long long)a[4] << 32 |
           (unsigned long long)a[5] << 40 |
           (unsigned long long)a[6] << 48 |
           (unsigned long long)a[7] << 56;
}
```

## Example usage

```c
int
main(void)
{
    unsigned char s[259] = {0}; /* sponge state */

    /* PIE */
    int (*f)(void) = main;
    sp4_absorb_buf(s, &f, sizeof(f));

    /* ASLR */
    void *(*m)(size_t) = malloc;
    sp4_absorb_buf(s, &m, sizeof(m));

    /* Allocator address */
    void *p = malloc(1024 * 1024);
    sp4_absorb_buf(s, &p, sizeof(p));
    free(p);

    /* Random stack */
    void *sp = s;
    sp4_absorb_buf(s, &sp, sizeof(sp));

    /* Timestamp (second resolution) */
    time_t t = time(0);
    sp4_absorb_buf(s, &t, sizeof(t));

    /* Sneakily grab entropy gathered by tmpnam().
     * Some implementations derive from getpid(2), gettimeofday(2),
     * or even arc4random(3).
     */
    char buf[L_tmpnam] = {0};
    tmpnam(buf);
    sp4_absorb_buf(s, buf, sizeof(buf));

    /* Squeeze a 64-bit sample from the sponge */
    printf("0x%016llx\n", sp4_squeeze64(s));
}
```
