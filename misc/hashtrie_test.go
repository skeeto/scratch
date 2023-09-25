// Generic hash-trie implementation
//
// Mainly to benchmark a standard "hash-trie" implementation against the
// gc built-in map type. On my machines with Go 1.21, this hash-trie is
// 1.5x to 2x faster, but 1.3x the memory footprint for small maps and
// up to 2x for huge maps (as reported by runtime.MemStats). This 30
// line implementation only has insert+lookup, but that's sufficient for
// most use cases.
//
// Unlike comparisons, Go does not expose its map hash generator to
// generics, and so a custom hash-based data structure cannot leverage
// it. That's probably for the better, as a significant part of the
// performance boost is that callers, including the benchmarks below,
// can provide a far better hash function than Go generates. The string
// key benchmark, which clocks in at 2x the speed of the built-in map,
// is still leaving performance on the table by using FNV-1a rather than
// a "chunkier" hash.
//
// Ref: https://nrk.neocities.org/articles/hash-trees-and-tries
// This is free and unencumbered software released into the public domain.
package hashtrie

import (
	"hash/fnv"
	"strconv"
	"testing"
)

// Implementation

type Map[K comparable, V any] struct {
	root *node[K, V]
	hash func(K) uint64
}

type node[K comparable, V any] struct {
	child [4]*node[K, V]
	key   K
	value V
}

func NewMap[K comparable, V any](hash func(K) uint64) *Map[K, V] {
	return &Map[K, V]{hash: hash}
}

func (m *Map[K, V]) Upsert(key K) *V {
	h := m.hash(key)
	n := &m.root
	for *n != nil {
		if (*n).key == key {
			return &(*n).value
		}
		n = &(*n).child[h>>62]
		h <<= 2
	}
	*n = &node[K, V]{key: key}
	return &(*n).value
}

// Tests and Benchmarks

func hash32x64(x int32) uint64 {
	return uint64(x) * 1111111111111111111
}

func TestMap(t *testing.T) {
	const n = 1000000
	m := NewMap[int32, int64](hash32x64)
	for i := int32(0); i < n; i++ {
		v := int64(i)
		*m.Upsert(i) = v * v
	}
	for i := int32(0); i < n; i++ {
		v := int64(i)
		got := *m.Upsert(i)
		if got != v*v {
			t.Fail()
		}
	}
}

func BenchmarkGoMapInt32(b *testing.B) {
	m := make(map[int32]bool)
	for i := 0; i < b.N; i++ {
		m[int32(i)] = true
	}
	for i := 0; i < b.N; i++ {
		if !m[int32(i)] {
			panic(i)
		}
	}
}

func BenchmarkMapInt32(b *testing.B) {
	m := NewMap[int32, bool](hash32x64)
	for i := 0; i < b.N; i++ {
		*m.Upsert(int32(i)) = true
	}
	for i := 0; i < b.N; i++ {
		if !*m.Upsert(int32(i)) {
			panic(i)
		}
	}
}

func genKeys(n int) []string {
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		keys[i] = strconv.Itoa(i)
	}
	return keys
}

func BenchmarkGoMapString(b *testing.B) {
	keys := genKeys(b.N)
	b.ResetTimer()

	m := make(map[string]bool)
	for i := 0; i < b.N; i++ {
		m[keys[i]] = true
	}

	for i := 0; i < b.N; i++ {
		if !m[keys[i]] {
			panic(i)
		}
	}
}

func BenchmarkMapString(b *testing.B) {
	keys := genKeys(b.N)
	b.ResetTimer()

	m := NewMap[string, bool](func(s string) uint64 {
		h := fnv.New64()
		h.Write([]byte(s))
		return h.Sum64()
	})

	for i := 0; i < b.N; i++ {
		*m.Upsert(keys[i]) = true
	}

	for i := 0; i < b.N; i++ {
		if !*m.Upsert(keys[i]) {
			panic(i)
		}
	}
}
