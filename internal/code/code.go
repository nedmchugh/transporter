// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package code generates, parses and protects the one-time pairing code, and
// derives key material from it.
//
// A code is WordCount words drawn uniformly from an embedded list of
// WordListSize words (see docs/DECISIONS.md D-1.3 for why the list has 1999
// words and the code 9). The canonical form (CODE-5) is the lowercase words
// joined by single hyphens; all key derivation uses that string.
//
// The Code type is redacting (CODE-6): every formatting and marshaling path
// yields a placeholder, and only Reveal returns the secret.
package code

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed" // for the word list
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"unicode"
)

const (
	// WordCount is the number of words in a code.
	WordCount = 9

	// MinPrefix is the shortest prefix that Parse expands to a full word
	// (CODE-3).
	MinPrefix = 4

	// Redacted is printed in place of a code by every formatting method.
	Redacted = "[REDACTED]"

	// maxSuggestDistance bounds "did you mean" suggestions so that unrelated
	// input is not "corrected" to a random word.
	maxSuggestDistance = 2

	// maxInputLen bounds the input Parse will look at, so that a pasted file
	// cannot make parsing slow.
	maxInputLen = 1024
)

//go:embed wordlist.txt
var wordlistRaw string

// words is the sorted word list; wordIndex maps a word to its position.
var (
	words     []string
	wordIndex map[string]int
)

func init() {
	words = strings.Fields(wordlistRaw)
	wordIndex = make(map[string]int, len(words))
	for i, w := range words {
		wordIndex[w] = i
	}
	// The list is compile-time data and its properties are checked by tests;
	// a broken embed is a build defect, not a runtime condition.
	if len(words) != WordListSize || len(wordIndex) != WordListSize || !sort.StringsAreSorted(words) {
		panic("code: embedded word list is corrupt")
	}
}

// WordListSize is the number of words in the embedded list.
const WordListSize = 1999

// Words returns a copy of the embedded word list, in sorted order.
func Words() []string {
	return append([]string(nil), words...)
}

// Code is a pairing code. The zero value is an empty code (IsZero reports
// true). Code values are immutable and safe to copy.
//
// The canonical string is captured in a closure rather than stored in a
// field. fmt cannot call methods on unexported fields of an enclosing struct
// and falls back to reflection, which prints strings and dereferences
// pointers (even under %s, via its bad-verb path); a func value is only ever
// printed as an address (docs/DECISIONS.md D-2.3).
type Code struct {
	get func() string
}

func newCode(canonical string) Code {
	return Code{get: func() string { return canonical }}
}

// Generate returns a new random code using rnd, or crypto/rand if rnd is nil.
// Each word is chosen uniformly and independently (CODE-1).
func Generate(rnd io.Reader) (Code, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	n := big.NewInt(int64(len(words)))
	parts := make([]string, WordCount)
	for i := range parts {
		// rand.Int uses rejection sampling, so the choice is uniform even
		// though the list size is not a power of two.
		k, err := rand.Int(rnd, n)
		if err != nil {
			return Code{}, fmt.Errorf("generating code: %w", err)
		}
		parts[i] = words[k.Int64()]
	}
	return newCode(strings.Join(parts, "-")), nil
}

// CountError reports a code with the wrong number of words.
type CountError struct {
	Got, Want int
}

func (e *CountError) Error() string {
	return fmt.Sprintf("a code has %d words, but %d were given", e.Want, e.Got)
}

// WordError reports one word of a code that is not in the word list. It names
// only that word, never the whole code (CODE-4, CODE-7).
type WordError struct {
	Position   int    // 1-based position in the code
	Word       string // the unrecognized word, as typed (lowercased)
	Suggestion string // closest list word, or "" if none is close
}

func (e *WordError) Error() string {
	msg := fmt.Sprintf("word %d (%q) is not in the word list", e.Position, e.Word)
	if e.Suggestion != "" {
		msg += fmt.Sprintf("; did you mean %q?", e.Suggestion)
	}
	return msg
}

// ErrEmpty is returned by Parse for input that contains no words.
var ErrEmpty = errors.New("the code is empty")

// ErrTooLong is returned by Parse for input far longer than any code.
var ErrTooLong = errors.New("the code is too long")

// isSeparator reports whether r separates words (CODE-3): '-', '_', '.', ','
// and any whitespace.
func isSeparator(r rune) bool {
	return r == '-' || r == '_' || r == '.' || r == ',' || unicode.IsSpace(r)
}

// Parse parses a code leniently (CODE-3): case-insensitive, any run of
// separators between words, and unambiguous prefixes of at least MinPrefix
// letters expanded. The result is in canonical form (CODE-5).
func Parse(input string) (Code, error) {
	if len(input) > maxInputLen {
		return Code{}, ErrTooLong
	}
	fields := strings.FieldsFunc(input, isSeparator)
	if len(fields) == 0 {
		return Code{}, ErrEmpty
	}
	if len(fields) != WordCount {
		return Code{}, &CountError{Got: len(fields), Want: WordCount}
	}
	out := make([]string, len(fields))
	for i, f := range fields {
		w, ok := lookup(strings.ToLower(f))
		if !ok {
			lw := strings.ToLower(f)
			return Code{}, &WordError{Position: i + 1, Word: lw, Suggestion: suggest(lw)}
		}
		out[i] = w
	}
	return newCode(strings.Join(out, "-")), nil
}

// lookup resolves a lowercased word or prefix to a list word.
func lookup(w string) (string, bool) {
	if _, ok := wordIndex[w]; ok {
		return w, true
	}
	if len(w) < MinPrefix {
		return "", false
	}
	// The list is sorted, so all words with prefix w are contiguous starting
	// at the insertion point. Because the list has unique first four letters
	// (CODE-2), a prefix of four or more letters matches at most one word;
	// checking the next word as well keeps this correct even if that
	// property were ever weakened.
	i := sort.SearchStrings(words, w)
	if i < len(words) && strings.HasPrefix(words[i], w) {
		if i+1 < len(words) && strings.HasPrefix(words[i+1], w) {
			return "", false // ambiguous
		}
		return words[i], true
	}
	return "", false
}

// suggest returns the list word closest to w by edit distance, or "" if none
// is within maxSuggestDistance.
func suggest(w string) string {
	if len(w) > 32 {
		return ""
	}
	best, bestD := "", maxSuggestDistance+1
	for _, cand := range words {
		if d := levenshtein(w, cand, bestD); d < bestD {
			best, bestD = cand, d
		}
	}
	return best
}

// levenshtein returns the edit distance between a and b, or limit if it is at
// least limit (an early exit that keeps suggestion cheap).
func levenshtein(a, b string, limit int) int {
	if d := len(a) - len(b); d >= limit || -d >= limit {
		return limit
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			rowMin = min(rowMin, cur[j])
		}
		if rowMin >= limit {
			return limit
		}
		prev, cur = cur, prev
	}
	return min(prev[len(b)], limit)
}

// LooksLikeCode reports whether s resembles an attempt at a code: at least
// WordCount-2 separator-delimited words of letters, most of which are list
// words or prefixes. The CLI uses it to avoid echoing a mistyped code as a
// file name (docs/DECISIONS.md D-3.4).
func LooksLikeCode(s string) bool {
	if len(s) > maxInputLen {
		return false
	}
	fields := strings.FieldsFunc(s, isSeparator)
	if len(fields) < WordCount-2 {
		return false
	}
	known := 0
	for _, f := range fields {
		for _, r := range f {
			if !unicode.IsLetter(r) {
				return false
			}
		}
		if _, ok := lookup(strings.ToLower(f)); ok {
			known++
		}
	}
	return known*2 > len(fields)
}

// IsZero reports whether c is the zero Code.
func (c Code) IsZero() bool { return c.get == nil }

// Reveal returns the canonical code. It is the only way to obtain the secret
// and is called only where the receiver prints the code for the user
// (CODE-6). Everything else uses derived keys.
func (c Code) Reveal() string {
	if c.get == nil {
		return ""
	}
	return c.get()
}

// Equal reports whether two codes are identical, in constant time.
func (c Code) Equal(o Code) bool {
	return subtle.ConstantTimeCompare([]byte(c.Reveal()), []byte(o.Reveal())) == 1
}

// String implements fmt.Stringer with a placeholder.
func (c Code) String() string { return Redacted }

// GoString implements fmt.GoStringer with a placeholder.
func (c Code) GoString() string { return "code.Code{" + Redacted + "}" }

// Format implements fmt.Formatter so every verb (%v, %s, %q, %x, %d, ...)
// prints the placeholder.
func (c Code) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, c.GoString())
		return
	}
	_, _ = io.WriteString(f, Redacted)
}

// MarshalText implements encoding.TextMarshaler with a placeholder.
func (c Code) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON implements json.Marshaler with a placeholder.
func (c Code) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalBinary implements encoding.BinaryMarshaler with a placeholder, so
// gob and similar encoders cannot serialize the secret either.
func (c Code) MarshalBinary() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer with a placeholder.
func (c Code) LogValue() slog.Value { return slog.StringValue(Redacted) }
