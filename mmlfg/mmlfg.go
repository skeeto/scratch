// Middle Multiplicative Lagged Fibonacci Generator
// This is free and unencumbered software released into the public domain.
package main

import (
	"fmt"
	"math/bits"
	"math/rand"
)

// A Mmlfg is a Middle Multiplicative Lagged Fibonacci generator. The
// output is the middle 64 bits of a 128-bit product. A larger state is
// required to pass statistical tests. Must be seeded carefully with
// good random values, and all state elements must be odd, so the Seed()
// method is highly recommended.
type Mmlfg struct {
	s    [15]uint64
	i, j int32
}

var _ rand.Source = (*Mmlfg)(nil)

func (m *Mmlfg) Seed(seed int64) {
	s := uint64(seed)
	for i := 0; i < 15; i++ {
		s = s*0x3243f6a8885a308d + 1111111111111111111
		m.s[i] = s ^ s>>31 | 1
	}
	m.i = 14
	m.j = 12
}

func (m *Mmlfg) Int63() int64 {
	return int64(m.Uint64() >> 1)
}

func (m *Mmlfg) Uint64() uint64 {
	hi, lo := bits.Mul64(m.s[m.i], m.s[m.j])
	m.s[m.i] = lo
	m.i--
	if m.i < 0 {
		m.i = 14
	}
	m.j--
	if m.j < 0 {
		m.j = 14
	}
	return hi<<32 | lo>>32
}

// Example
func main() {
	var m [4]Mmlfg
	for i := 0; i < 4; i++ {
		m[i].Seed(int64(i))
	}
	for i := 0; i < 40; i++ {
		fmt.Printf("%016x %016x %016x %016x\n",
			m[0].Uint64(), m[1].Uint64(), m[2].Uint64(), m[3].Uint64())
	}
}
