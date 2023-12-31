// Arena vs. new hashtrie benchmark
// $ go test -benchmem -bench .  # requires module, etc.
//
// How much faster is arena allocation than new for a hashtrie? In my
// runs an arena cuts insert time by 25%. The map benchmark provides a
// baseline comparison for conventional Go.
//
// This is free and unencumbered software released into the public domain.
package main

import (
	"math/bits"
	"testing"
	"unsafe"
)

type Arena struct {
	mem unsafe.Pointer
	len int
}

func NewArena(cap int) *Arena {
	if cap < 1 {
		panic("invalid arena capacity")
	}
	// Go does not allow one-past-the-end pointers. Report one less byte
	// so that zero-size allocations do not end up there.
	return &Arena{
		unsafe.Pointer(&make([]byte, cap)[0]),
		cap-1,
	}
}

func (a *Arena) Scratch() *Arena {
	tmp := *a
	clone := New[Arena](&tmp)
	*clone = tmp
	return clone
}

func New[T any](a *Arena) *T {
	var t T
	size := int(unsafe.Sizeof(t))
	align := a.len & (int(unsafe.Alignof(t)) - 1)
	if size > a.len-align {
		panic("Arena.New: out of memory")
	}
	a.len -= size + align
	r := (*T)(unsafe.Add(a.mem, a.len))
	*r = t
	return r
}

func Slice[T any](a *Arena, cap int) []T {
	var t T
	size := int(unsafe.Sizeof(t))
	align := a.len & (int(unsafe.Alignof(t)) - 1)
	if size > 0 && cap > (a.len-align)/size {
		panic("Arena.Slice: out of memory")
	}
	a.len -= size*cap + align
	r := unsafe.Slice((*T)(unsafe.Add(a.mem, a.len)), cap)
	for i := 0; i < cap; i++ {
		r[i] = t
	}
	return r
}

func Append[T any](a *Arena, slice []T, elems ...T) []T {
	if cap(slice)-len(slice) < len(elems) {
		newcap := 1 << bits.Len(uint(len(slice)+len(elems)))
		newslice := Slice[T](a, newcap)[:len(slice)]
		copy(newslice, slice)
		slice = newslice
	}
	return append(slice, elems...)
}

type Map struct {
	child [4]*Map
	key   string
	value int32
}

func hash(s string) uint64 {
	h := uint64(0x100)
	for _, b := range []byte(s) {
		h ^= uint64(b)
		h *= 0x100000001b3
	}
	return h
}

func UpsertArena(m **Map, key string, perm *Arena) *int32 {
	for h := hash(key); *m != nil; h <<= 2 {
		if (*m).key == key {
			return &(*m).value
		}
		m = &(*m).child[h>>62]
	}
	if perm == nil {
		return nil
	}
	*m = New[Map](perm)
	(*m).key = key
	return &(*m).value
}

func UpsertHeap(m **Map, key string, lookup bool) *int32 {
	for h := hash(key); *m != nil; h <<= 2 {
		if (*m).key == key {
			return &(*m).value
		}
		m = &(*m).child[h>>62]
	}
	if lookup {
		return nil
	}
	*m = new(Map)
	(*m).key = key
	return &(*m).value
}

func Itoa(perm *Arena, x int32) string {
	s := Slice[byte](perm, 10)
	for i := len(s) - 1; ; i-- {
		s[i] = (byte)(x%10) + '0'
		x /= 10
		if x == 0 {
			return unsafe.String(&s[i], len(s)-i)
		}
	}
}

func MakeKeys(perm *Arena, n int) []string {
	nkeys := n << 4
	s := Slice[string](perm, nkeys)
	for i := 0; i < nkeys; i++ {
		s[i] = Itoa(perm, int32(i))
	}
	return s
}

var arena *Arena

func GetArena() *Arena {
	if arena == nil {
		// NOTE: Too large for 32-bit hosts. The maps are so fast that
		// the benchmarks cannot scale to meaningful sizes in a 32-bit
		// address space anyway.
		arena = NewArena(1 << 32)
	}
	// Re-use the same arena across all benchmarks, which reflects the
	// real use case. Only returns a header copy, so allocations in the
	// returned arena are not retained when the copy is lost.
	return arena.Scratch()
}

func BenchmarkArena(b *testing.B) {
	scratch := GetArena()
	keys := MakeKeys(scratch, b.N)
	b.ResetTimer()
	var m *Map
	for i, key := range keys {
		*UpsertArena(&m, key, scratch) = int32(i)
	}
}

func BenchmarkNew(b *testing.B) {
	scratch := GetArena()
	keys := MakeKeys(scratch, b.N)
	b.ResetTimer()
	var m *Map
	for i, key := range keys {
		*UpsertHeap(&m, key, false) = int32(i)
	}
}

func BenchmarkMap(b *testing.B) {
	scratch := GetArena()
	keys := MakeKeys(scratch, b.N)
	b.ResetTimer()
	m := make(map[string]int32)
	for i, key := range keys {
		m[key] = int32(i)
	}
}
