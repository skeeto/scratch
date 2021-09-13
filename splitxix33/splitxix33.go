// splitxix33: a splitmix64 with memorable constants
// This is free and unencumbered software released into the public domain.
package main

import (
	"fmt"
	"math/rand"
)

type Splitxix33 uint64

var _ rand.Source64 = (*Splitxix33)(nil)

func (s *Splitxix33) Seed(seed int64) {
	*s = Splitxix33(seed)
}

func (s *Splitxix33) Int63() int64 {
	return int64(s.Uint64() >> 1)
}

func (s *Splitxix33) Uint64() uint64 {
	*s += 1111111111111111111
	x := uint64(*s)
	x ^= x >> 33
	x *= 1111111111111111111
	x ^= x >> 33
	x *= 1111111111111111111
	x ^= x >> 33
	return x
}

func main() {
	g := [...]Splitxix33{0, 1, 2, 3}
	for i := 0; i < 40; i++ {
		fmt.Printf("%016x %016x %016x %016x\n",
			g[0].Uint64(), g[1].Uint64(), g[2].Uint64(), g[3].Uint64())
	}
}
