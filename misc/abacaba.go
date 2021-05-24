// ABACABA state machine
// Ref: https://redd.it/njxq95
// This is free and unencumbered software released into the public domain.
package main

import (
	"bufio"
	"os"
)

type State uint32

// Iterate the state matching, returning the next letter of the ABACABA
// sequence, the next state, and whether or not the machine has halted.
// The initial state is zero.
//
// The state is a 32-bit quantity where bits 0-25 are a bitstack, bits
// 26-30 are the stack size, and bit 31 is the recursion direction.
//
//     D IIIII SSSSSSSSSSSSSSSSSSSSSSSSSS
func (s State) Next() (rune, State, bool) {
	for {
		stack := s & 0x3ffffff
		i := s >> 26 & 0x1f
		descending := s>>31 == 1
		middle := s>>i&1 == 1

		if i == 25 {
			// Bottom out, descend back to the parent
			return 'a', State(1)<<31 | (i-1)<<26 | stack, false
		} else if descending && !middle {
			// Output "middle" character, ascend into right branch
			return 'z' - rune(i), (i+1)<<26 | stack | State(1)<<i, false
		} else if descending && middle {
			if i == 0 {
				// At root, halt
				return 0, 0, true
			}
			// Descend back to the parent
			s = State(1)<<31 | (i-1)<<26 | stack ^ State(1)<<i
		} else {
			// Ascend into the left branch
			s = (i+1)<<26 | stack
		}
	}
}

func main() {
	buf := bufio.NewWriter(os.Stdout)
	for c, s, done := State(0).Next(); !done; c, s, done = s.Next() {
		buf.WriteRune(c)
	}
	buf.WriteRune('\n')
	buf.Flush()
}
