// Monte Carlo Method pi estimate via multi-precision integers
// This is free and unencumbered software released into the public domain.
package main

import (
	"fmt"
	"math/big"
	"math/bits"
	"math/rand"
	"runtime"
	"sync"
	"time"
)

// Unit square size is 2^precision.
const precision = 256

type Pcg64x struct{ Hi, Lo uint64 }

func (s *Pcg64x) Seed(seed int64) {
	s.Lo = 0xe1cf322879493bf1
	s.Hi = uint64(seed)
}

func (s *Pcg64x) Uint64() uint64 {
	const m = 0xb47d5ba190fb0fa5
	var c uint64
	c, s.Lo = bits.Mul64(s.Lo, m)
	s.Hi = s.Hi*m + c
	s.Lo, c = bits.Add64(s.Lo, 1, 0)
	s.Hi += c
	r := s.Hi
	r ^= r >> 32
	r *= m
	return r
}

func (s *Pcg64x) Int63() int64 {
	return int64(s.Uint64() >> 1)
}

type Report struct {
	total, inside int64
	sync.Mutex
}

func (r *Report) Accum(total, inside int64) {
	r.Lock()
	r.total += total
	r.inside += inside
	fmt.Printf("%-20v%16.9f%16.9f\n",
		float64(r.inside)*4/float64(r.total),
		float64(r.inside)/1e9,
		float64(r.total)/1e9)
	r.Unlock()
}

func worker(seed uint64, r, r2 *big.Int, report *Report) {
	var (
		total, inside int64
		src           Pcg64x
		x, y          big.Int
	)
	src.Seed(int64(seed))
	rng := rand.New(&src)
	for {
		x.Rand(rng, r)
		y.Rand(rng, r)
		x.Mul(&x, &x)
		y.Mul(&y, &y)
		x.Add(&x, &y)
		if x.Cmp(r2) <= 0 {
			inside++
		}
		total++
		if total&0x3ffff == 0 {
			report.Accum(total, inside)
			total = 0
			inside = 0
		}
	}
}

func hash64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func main() {
	var (
		report   Report
		r, r2, m big.Int
	)
	r.Exp(big.NewInt(2), big.NewInt(precision-1), nil)
	m.Sub(&r, big.NewInt(1))
	r2.Mul(&m, &m)

	seed := hash64(uint64(time.Now().UnixNano()))
	procs := runtime.GOMAXPROCS(0)
	for i := 0; i < procs; i++ {
		go worker(hash64(seed+uint64(i)), &r, &r2, &report)
	}
	worker(hash64(seed+uint64(procs)), &r, &r2, &report)
}
