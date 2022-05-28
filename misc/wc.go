// This is free and unencumbered software released into the public domain.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func process(f *os.File) (int64, int64, int64, error) {
	var ws = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}
	var lf = [256]uint8{'\n': 1}
	var c, w, n, s int64
	var r = bufio.NewReader(f)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return c, w + s, n, nil
			}
			return 0, 0, 0, err
		}
		c++
		n += int64(lf[b])
		w += int64(ws[b]) & s
		s = int64(ws[b]) ^ 1
	}
}

func run() error {
	c, w, n, err := process(os.Stdin)
	if err != nil {
		return err
	}
	_, err = fmt.Printf("%d\t%d\t%d\n", n, w, c)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "wc: %s\n", err)
		os.Exit(1)
	}
}
