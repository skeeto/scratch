# Mersenne Twister (MT19937) public domain C99 header library

```c
void     mt19937_init(struct mt19937 *, uint32_t seed);
uint32_t mt19937_next(struct mt19937 *);

void     mt19937_64_init(struct mt19937_64 *, uint64_t seed);
uint64_t mt19937_64_next(struct mt19937_64 *);
```

## Usage example

```c
#include <stdio.h>

#define MT19937_IMPLEMENTATION
#include "mt19937.h"

int main(void)
{
    struct mt19937 mt[1];
    mt19937_init(mt, 12345);
    printf("%f\n", mt19937_next(mt) / 4294967296.0);  // 0.929616
    printf("%f\n", mt19937_next(mt) / 4294967296.0);  // 0.890155
    printf("%f\n", mt19937_next(mt) / 4294967296.0);  // 0.316376
}
```

## Tests and benchmark

    $ cc -O3 -o test test.c
    $ ./test
    $ ./test 32 | RNG_test stdin32
    $ ./test 64 | RNG_test stdin64
