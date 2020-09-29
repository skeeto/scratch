package main

import (
	"fmt"
	"math"
)

func hash22(x, y float32) (float32, float32) {
	hi, lo := math.Float32bits(x), math.Float32bits(y)
	v := ^(uint64(hi)<<32 | uint64(lo))
	v *= 0xaddc7c7ef4e6ce37
	v ^= v >> 32
	v *= 0x9e6f287da60cbcad
	v ^= v >> 32
	return float32(math.Ldexp(float64(v>>32), -32)),
		float32(math.Ldexp(float64(uint32(v)), -32))
}

func main() {
	var x float32 = math.Pi
	var y float32 = 1e6
	fmt.Println(x, y)
	fmt.Println(hash22(x, y))
}
