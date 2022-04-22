// uwords: count unique words on standard input
// Same as uwords.c, but written in Go.
// This is free and unencumbered software released into the public domain.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"unicode"
)

func shouldSkip(r rune) bool {
	return unicode.IsControl(r) ||
		unicode.IsSpace(r) ||
		unicode.IsPunct(r)
}

func run() error {
	b := bufio.NewReader(os.Stdin)
	seen := make(map[string]struct{})
	var runes []rune
	var count int64

	for eof := false; !eof; {
		r, _, err := b.ReadRune()
		if err != nil {
			if err != io.EOF {
				return err
			}
			eof = true
			r = ' '
		}

		if !shouldSkip(r) {
			runes = append(runes, r)
		} else if len(runes) != 0 {
			word := string(runes)
			if _, ok := seen[word]; !ok {
				count++
				seen[word] = struct{}{}
			}
			runes = runes[:0]
		}
	}

	_, err := fmt.Println(count)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "count: %s", err)
		os.Exit(1)
	}
}
