// This is free and unencumbered software released into the public domain.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	//go:embed qualifiers.list
	qualifiersFull string
	qualifiers     = strings.Split(qualifiersFull, "\n")

	//go:embed species.list
	speciesFull string
	species     = strings.Split(speciesFull, "\n")

	//go:embed prefixes.list
	prefixesFull string
	prefixes     = strings.Split(prefixesFull, "\n")

	//go:embed suffixes.list
	suffixesFull string
	suffixes     = strings.Split(suffixesFull, "\n")

	//go:embed colors.list
	colorsFull string
	colors     = strings.Split(colorsFull, "\n")

	//go:embed actual.list
	actualFull string
	actual     = strings.Split(actualFull, "\n")
)

func generate(r *rand.Rand) string {
	for {
		var buf bytes.Buffer

		for buf.Len() == 0 {
			if r.Intn(10) == 0 {
				buf.WriteString(qualifiers[r.Intn(len(qualifiers))])
				buf.WriteByte(' ')
			}

			switch r.Intn(12) {
			case 0, 1, 2, 3, 4, 5:
				buf.WriteString(prefixes[r.Intn(len(prefixes))])
				buf.WriteByte('-')
				buf.WriteString(suffixes[r.Intn(len(suffixes))])
				buf.WriteByte(' ')
			case 6, 7, 8:
				buf.WriteString(colors[r.Intn(len(colors))])
				buf.WriteByte(' ')
			case 9:
				buf.WriteString(colors[r.Intn(len(colors))])
				if r.Intn(6) == 0 {
					buf.WriteByte('-')
				} else {
					buf.WriteString("-and-")
				}
				buf.WriteString(colors[r.Intn(len(colors))])
				buf.WriteByte(' ')
			}
		}

		buf.WriteString(species[r.Intn(len(species))])

		bird := buf.String()
		m := sort.SearchStrings(actual, bird)
		if m == len(actual) || actual[m] != bird {
			return bird
		}
	}
}

func main() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var birds [4]string
	for i := 0; i < len(birds)-1; i++ {
		birds[i] = generate(r)
	}

	n := r.Intn(len(birds))
	birds[len(birds)-1] = birds[n]
	correct := actual[r.Intn(len(actual))]
	birds[n] = correct

	for _, bird := range birds {
		fmt.Println(bird)
	}

	os.Stdin.Read(make([]byte, 1))
	fmt.Println(correct)
}
