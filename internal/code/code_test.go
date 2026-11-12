// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package code

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
	"testing/iotest"
)

const sampleCode = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"

// TestWordListProperties covers CODE-2: no duplicates, prefix-free, unique
// first four letters, lowercase ASCII letters only, and the size and entropy
// claimed in CODE-1.
func TestWordListProperties(t *testing.T) {
	ws := Words()
	if len(ws) != WordListSize {
		t.Fatalf("list has %d words, want %d", len(ws), WordListSize)
	}
	if bits := float64(WordCount) * math.Log2(float64(len(ws))); bits < 88 {
		t.Fatalf("CODE-1: entropy %.2f bits < 88", bits)
	}
	seen := map[string]bool{}
	first4 := map[string]string{}
	for _, w := range ws {
		if seen[w] {
			t.Errorf("duplicate word %q", w)
		}
		seen[w] = true
		for _, r := range w {
			if r < 'a' || r > 'z' {
				t.Errorf("word %q has non a-z rune", w)
			}
		}
		if len(w) < 3 {
			t.Errorf("word %q is shorter than 3 letters", w)
		}
		p := w[:min(4, len(w))]
		if o, ok := first4[p]; ok {
			t.Errorf("words %q and %q share first four letters", o, w)
		}
		first4[p] = w
	}
	// Sorted order means a word that is a prefix of another is immediately
	// followed by a word that starts with it, but check all pairs to be sure.
	for i, a := range ws {
		for j, b := range ws {
			if i != j && strings.HasPrefix(b, a) {
				t.Errorf("CODE-2: %q is a prefix of %q", a, b)
			}
		}
	}
}

// TestGenerate covers CODE-1: the right number of list words, canonical form,
// and use of the supplied random source.
func TestGenerate(t *testing.T) {
	c, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(c.Reveal(), "-")
	if len(parts) != WordCount {
		t.Fatalf("got %d words", len(parts))
	}
	for _, p := range parts {
		if _, ok := wordIndex[p]; !ok {
			t.Fatalf("word %q not in list", p)
		}
	}
	// Two codes in a row are different (probability of collision ~2^-98).
	c2, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Equal(c2) {
		t.Fatal("two generated codes are equal")
	}
	// A failing random source is reported, not ignored.
	if _, err := Generate(iotest.ErrReader(errors.New("boom"))); err == nil {
		t.Fatal("expected error from failing reader")
	}
	// A deterministic source yields a deterministic code.
	a, err := Generate(bytes.NewReader(make([]byte, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("abandon-", WordCount-1) + "abandon"; a.Reveal() != want {
		t.Fatalf("got %q, want %q", a.Reveal(), want)
	}
}

// TestGenerateUniform is a coarse check that word choice is not biased toward
// the start of the list (CODE-1 "uniformly at random").
func TestGenerateUniform(t *testing.T) {
	if testing.Short() {
		t.Skip("slow statistical test")
	}
	var low, total int
	for range 2000 {
		c, err := Generate(nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range strings.Split(c.Reveal(), "-") {
			if wordIndex[w] < WordListSize/2 {
				low++
			}
			total++
		}
	}
	// Expect ~50%; 18000 samples give a standard deviation of ~0.4%.
	if frac := float64(low) / float64(total); frac < 0.47 || frac > 0.53 {
		t.Fatalf("lower-half fraction %.3f is outside [0.47, 0.53]", frac)
	}
}

// TestParseLenient covers CODE-3 and CODE-5: case-insensitivity, separator
// runs, prefix expansion, and canonical output.
func TestParseLenient(t *testing.T) {
	tests := []struct {
		name, in string
	}{
		{"canonical", sampleCode},
		{"upper", strings.ToUpper(sampleCode)},
		{"mixed case", "Abandon-ABILITY-able-About-above-absent-absorb-abstract-absurd"},
		{"spaces", strings.ReplaceAll(sampleCode, "-", " ")},
		{"underscores", strings.ReplaceAll(sampleCode, "-", "_")},
		{"dots", strings.ReplaceAll(sampleCode, "-", ".")},
		{"commas", strings.ReplaceAll(sampleCode, "-", ",")},
		{"runs", strings.ReplaceAll(sampleCode, "-", " -_.,\t ")},
		{"leading and trailing", "  --" + sampleCode + "-- \n"},
		{"prefixes", "aban abil able abou abov abse abso abst absu"},
		{"longer prefixes", "aband abili able about above absen absor abstr absur"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if c.Reveal() != sampleCode {
				t.Fatalf("canonical = %q, want %q", c.Reveal(), sampleCode)
			}
		})
	}
}

// TestParseErrors covers CODE-4: errors name only the bad word, suggest the
// closest match, and state the expected count. They never contain the rest
// of the code (CODE-7).
func TestParseErrors(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantPos    int
		wantWord   string
		wantSugg   string
		wantCount  bool
		wantSubstr string
	}{
		{name: "too few", in: "abandon ability able", wantCount: true, wantSubstr: "9 words"},
		{name: "too many", in: sampleCode + "-zoo", wantCount: true, wantSubstr: "but 10"},
		{name: "typo", in: "abandon-abillity-able-about-above-absent-absorb-abstract-absurd", wantPos: 2, wantWord: "abillity", wantSugg: "ability"},
		{name: "garbage", in: "abandon-ability-able-about-above-absent-absorb-abstract-qqqqqqq", wantPos: 9, wantWord: "qqqqqqq"},
		{name: "short prefix", in: "aba ability able about above absent absorb abstract absurd", wantPos: 1, wantWord: "aba", wantSugg: "able"},
		{name: "prefix not matching", in: "abandonx ability able about above absent absorb abstract absurd", wantPos: 1, wantWord: "abandonx", wantSugg: "abandon"},
		{name: "removed prefix word", in: "act ability able about above absent absorb abstract absurd", wantPos: 1, wantWord: "act", wantSugg: "pact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := err.Error()
			// The error must not leak any correct word from the input
			// besides the single bad word it names.
			for _, w := range []string{"ability", "absorb", "abstract", "absurd"} {
				if strings.Contains(msg, w) && tc.wantSugg != w {
					t.Errorf("error %q leaks word %q", msg, w)
				}
			}
			if tc.wantCount {
				var ce *CountError
				if !errors.As(err, &ce) || ce.Want != WordCount {
					t.Fatalf("want CountError, got %v", err)
				}
				if !strings.Contains(msg, tc.wantSubstr) {
					t.Fatalf("message %q lacks %q", msg, tc.wantSubstr)
				}
				return
			}
			var we *WordError
			if !errors.As(err, &we) {
				t.Fatalf("want WordError, got %v", err)
			}
			if we.Position != tc.wantPos || we.Word != tc.wantWord || we.Suggestion != tc.wantSugg {
				t.Fatalf("got %+v", *we)
			}
			if !strings.Contains(msg, tc.wantWord) {
				t.Fatalf("message %q does not name the word", msg)
			}
		})
	}
	if _, err := Parse(" -- "); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: got %v", err)
	}
	if _, err := Parse(strings.Repeat("a", maxInputLen+1)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("long: got %v", err)
	}
}

// TestLookupAmbiguous exercises the defensive ambiguity branch by checking
// the real list cannot produce an ambiguous 4-letter prefix, and that a
// 3-letter prefix never expands.
func TestLookupAmbiguous(t *testing.T) {
	for _, w := range words {
		if len(w) >= MinPrefix {
			got, ok := lookup(w[:MinPrefix])
			if !ok || got != w {
				t.Fatalf("prefix %q -> %q, %v; want %q", w[:MinPrefix], got, ok, w)
			}
		}
	}
	if _, ok := lookup("ab"); ok {
		t.Fatal("2-letter prefix expanded")
	}
	// Simulate a list where a prefix is ambiguous.
	saved := words
	defer func() { words = saved }()
	words = []string{"abcde", "abcdf"}
	if _, ok := lookup("abcd"); ok {
		t.Fatal("ambiguous prefix expanded")
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b  string
		limit int
		want  int
	}{
		{"kitten", "sitting", 10, 3},
		{"", "abc", 10, 3},
		{"abc", "abc", 10, 0},
		{"abc", "abd", 10, 1},
		{"abcdef", "a", 3, 3},
		{"kitten", "sitting", 2, 2},
	}
	for _, tc := range tests {
		if got := levenshtein(tc.a, tc.b, tc.limit); got != tc.want {
			t.Errorf("levenshtein(%q,%q,%d) = %d, want %d", tc.a, tc.b, tc.limit, got, tc.want)
		}
	}
	if s := suggest(strings.Repeat("z", 40)); s != "" {
		t.Errorf("suggest(long) = %q", s)
	}
}

// TestRedaction covers CODE-6: no formatting or marshaling path reveals the
// code, including when the code is nested in other values.
func TestRedaction(t *testing.T) {
	c, err := Parse(sampleCode)
	if err != nil {
		t.Fatal(err)
	}
	type wrapper struct {
		Exported   Code
		unexported Code
		Ptr        *Code
	}
	w := wrapper{Exported: c, unexported: c, Ptr: &c}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10s", "%T"} {
		outputs = append(outputs, fmt.Sprintf(verb, c), fmt.Sprintf(verb, w), fmt.Sprintf(verb, &w), fmt.Sprintf(verb, []Code{c}))
	}
	outputs = append(outputs, c.String(), c.GoString(), fmt.Sprint(c), fmt.Sprintln(c, w))
	j, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(j))
	txt, _ := c.MarshalText()
	bin, _ := c.MarshalBinary()
	outputs = append(outputs, string(txt), string(bin))
	var gb bytes.Buffer
	if err := gob.NewEncoder(&gb).Encode(w); err == nil {
		outputs = append(outputs, gb.String())
	}
	var lb bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&lb, nil), slog.NewJSONHandler(&lb, nil)} {
		l := slog.New(h)
		l.Info("msg", "code", c, "wrapper", w, "ptr", &c)
		l.Info("msg", slog.Any("code", c), slog.Group("g", "c", c))
	}
	outputs = append(outputs, lb.String())
	err2 := fmt.Errorf("wrapped: %v / %w", c, errors.New("x"))
	outputs = append(outputs, err2.Error())
	for i, o := range outputs {
		for _, w := range strings.Split(sampleCode, "-") {
			// "able" is a substring of "ability"-free text only if leaked;
			// check the longer words, which cannot appear by accident.
			if len(w) >= 5 && strings.Contains(o, w) {
				t.Fatalf("output %d leaks code word %q: %s", i, w, o)
			}
		}
		if strings.Contains(o, sampleCode) {
			t.Fatalf("output %d leaks the code: %s", i, o)
		}
	}
	if !strings.Contains(fmt.Sprint(c), Redacted) {
		t.Fatal("placeholder missing")
	}
	if c.Reveal() != sampleCode {
		t.Fatal("Reveal does not return the code")
	}
}

func TestZeroCode(t *testing.T) {
	var z Code
	if !z.IsZero() || z.Reveal() != "" {
		t.Fatal("zero code not empty")
	}
	if _, err := z.PSK(); !errors.Is(err, ErrZeroCode) {
		t.Fatalf("PSK on zero: %v", err)
	}
	if _, err := z.DiscoveryTag(); !errors.Is(err, ErrZeroCode) {
		t.Fatalf("tag on zero: %v", err)
	}
	c, _ := Parse(sampleCode)
	c2, _ := Parse(strings.ReplaceAll(sampleCode, "-", " "))
	if z.Equal(c) || !c.Equal(c2) {
		t.Fatal("Equal wrong")
	}
}

// TestKDFGolden covers SEC-2 with vectors computed by an independent HKDF
// implementation (Python hmac/hashlib; see docs/DECISIONS.md D-3.3).
func TestKDFGolden(t *testing.T) {
	if PSKInfo != "transporter v1 psk" || DiscoveryInfo != "transporter v1 discovery" {
		t.Fatal("SEC-2: KDF labels changed")
	}
	tests := []struct {
		code, psk, tag string
	}{
		{sampleCode, "97ec51a315a13084adad2469a8609452633e36bfd06cc25ad62c7b7939326cc6", "cdee60db"},
		{"zoo-zone-zero-youth-young-yellow-year-wrong-write", "a130a52ed88b74264bcaea679ed742e109a5077baaaaa5171a09277db85e6b3e", "d426bb1c"},
	}
	for _, tc := range tests {
		// Input in non-canonical form must derive the same keys (CODE-5).
		c, err := Parse(strings.ToUpper(strings.ReplaceAll(tc.code, "-", "  ")))
		if err != nil {
			t.Fatal(err)
		}
		psk, err := c.PSK()
		if err != nil {
			t.Fatal(err)
		}
		tag, err := c.DiscoveryTag()
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(psk[:]); got != tc.psk {
			t.Errorf("psk = %s, want %s", got, tc.psk)
		}
		if got := hex.EncodeToString(tag[:]); got != tc.tag {
			t.Errorf("tag = %s, want %s", got, tc.tag)
		}
	}
}

func TestLooksLikeCode(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{sampleCode, true},
		{"abandon-abillity-able-about-above-absent-absorb-abstract-absurd", true},
		{"abandon ability able about above absent absorb", true},
		{"./project", false},
		{"my-file-name.txt", false},
		{"report-2024-final-v2-draft-copy-new-old-x", false},
		{"qqq-www-eee-rrr-ttt-yyy-uuu-iii-ooo", false},
		{strings.Repeat("a", maxInputLen+1), false},
	}
	for _, tc := range tests {
		if got := LooksLikeCode(tc.in); got != tc.want {
			t.Errorf("LooksLikeCode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sampleCode)
	f.Add("aban abil able abou abov abse abso abst absu")
	f.Add("")
	f.Add("----")
	f.Add("ÄBANDON ability")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse(s)
		if err != nil {
			if strings.Contains(err.Error(), "\x00") && !strings.Contains(s, "\x00") {
				t.Fatal("error invents NUL")
			}
			return
		}
		// Canonical form is a fixed point.
		c2, err := Parse(c.Reveal())
		if err != nil || !c2.Equal(c) {
			t.Fatalf("canonical form does not round-trip: %v", err)
		}
		_ = LooksLikeCode(s)
	})
}

func ExampleParse() {
	c, err := Parse("ABANDON abil able about above absent absorb abstract absurd")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(c)          // redacted
	fmt.Println(c.Reveal()) // canonical form
	// Output:
	// [REDACTED]
	// abandon-ability-able-about-above-absent-absorb-abstract-absurd
}
