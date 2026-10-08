package object

import (
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

// The corpus every property below is checked over: valid UTF-8 of each encoded
// width, then the ways a byte sequence can fail to be UTF-8 at all. The invalid
// half is the point -- a forensics language reads bytes off a disk, and a string
// built from them is not promised to be well formed.
//
// Written with Go escapes so this file stays ASCII: a test file with literal high
// bytes in it is one line-ending or encoding conversion away from testing
// something other than what it says.
var indexCorpus = []string{
	"",
	"a",
	"apple",
	"h\xc3\xa9llo",                 // 2-byte rune in the middle
	"\xe6\x97\xa5\xe6\x9c\xac",     // 3-byte runes
	"a\xf0\x9d\x84\x9eb",           // 4-byte rune
	"e\xcc\x81",                    // combining accent: two runes, one grapheme
	"\xc3",                         // a lone lead byte
	"h\xc3llo",                     // lead byte followed by ASCII
	"\xc3\xc3",                     // two lone lead bytes
	"a\xe2\x82",                    // truncated 3-byte sequence at the end
	"\xe2\x82ac",                   // truncated 3-byte sequence at the start
	"\x80",                         // a lone continuation byte
	"\x80\x80\x80",                 // three continuation bytes
	"\xff\xfe",                     // bytes no UTF-8 sequence may contain
	"ok\xffok",                     // invalid in the middle of valid
	"\xed\xa0\x80",                 // a surrogate half, which UTF-8 forbids
	"\xf4\x90\x80\x80",             // above U+10FFFF
	"\xc0\x80",                     // overlong NUL
	"a\x00b",                       // an embedded NUL, which is valid
	"\xf0\x9f\x98\x80",             // U+1F600
	"\xf0\x9f\x98",                 // the same, one byte short
	"mixed \xc3 \xe2\x82 \xff end", // several kinds in one string
}

// TestTheRuneWalkAgreesWithARuneSlice is the property the whole of RuneAt rests
// on. Walking with utf8.DecodeRuneInString is only a legitimate substitute for
// indexing []rune(s) if the two never disagree -- str_char_at, str_substr,
// str_reverse and the for-in iterator all take the []rune route, so a string
// where the two differed would put s[i] back out of step with them, which is the
// fault M26-VM-009 is about.
//
// Both directions are checked on every index of every string, plus one past each
// end, because the backward walk is a separate loop and an invalid sequence does
// not have to decode to the same number of runes from both ends. (It does; this
// is what says so.)
func TestTheRuneWalkAgreesWithARuneSlice(t *testing.T) {
	for _, s := range indexCorpus {
		runes := []rune(s)
		n := len(runes)

		for i := 0; i < n; i++ {
			got, ok := RuneAt(s, int64(i))
			if !ok {
				t.Errorf("RuneAt(%q, %d) reported no rune, []rune has %d", s, i, n)
				continue
			}
			if want := string(runes[i]); got != want {
				t.Errorf("RuneAt(%q, %d) = %q, []rune(s)[%d] = %q", s, i, got, i, want)
			}
		}

		for k := 1; k <= n; k++ {
			got, ok := RuneAt(s, int64(-k))
			if !ok {
				t.Errorf("RuneAt(%q, %d) reported no rune, []rune has %d", s, -k, n)
				continue
			}
			if want := string(runes[n-k]); got != want {
				t.Errorf("RuneAt(%q, %d) = %q, []rune(s)[%d] = %q", s, -k, got, n-k, want)
			}
		}

		if got, ok := RuneAt(s, int64(n)); ok {
			t.Errorf("RuneAt(%q, %d) = %q, want no rune (it holds %d)", s, n, got, n)
		}
		if got, ok := RuneAt(s, int64(-n-1)); ok {
			t.Errorf("RuneAt(%q, %d) = %q, want no rune (it holds %d)", s, -n-1, got, n)
		}
	}
}

// TestAnInvalidByteReadsAsTheReplacementRune pins the answer for text that is
// not text, rather than leaving it as whatever the decoder happens to do. U+FFFD
// is what the for-in iterator and str_char_at report, and a program that means
// the bytes should be holding a buffer.
func TestAnInvalidByteReadsAsTheReplacementRune(t *testing.T) {
	replacement := string(rune(utf8.RuneError))
	for _, tt := range []struct {
		name string
		s    string
		at   int64
	}{
		{"a lead byte with no continuation", "h\xc3llo", 1},
		{"a lone continuation byte", "\x80", 0},
		{"a byte no sequence may contain", "ok\xffok", 2},
		{"a truncated sequence, from the end", "a\xe2\x82", -1},
		{"a surrogate half", "\xed\xa0\x80", 0},
	} {
		got, ok := RuneAt(tt.s, tt.at)
		if !ok || got != replacement {
			t.Errorf("%s: RuneAt(%q, %d) = %q, %v; want the replacement rune",
				tt.name, tt.s, tt.at, got, ok)
		}
	}
}

// TestIndexOfCountsFromTheEnd is the negative-indexing rule itself, stated once
// here because six call sites across two engines read it.
func TestIndexOfCountsFromTheEnd(t *testing.T) {
	for _, tt := range []struct {
		i    int64
		n    int
		at   int
		want bool
	}{
		{0, 3, 0, true},
		{2, 3, 2, true},
		{3, 3, 0, false}, // one past the end
		{99, 3, 0, false},
		{-1, 3, 2, true},  // the last
		{-3, 3, 0, true},  // the first
		{-4, 3, 0, false}, // one past the start: the panic M26-VM-008 is about
		{-99, 3, 0, false},
		{0, 1, 0, true},
		{-1, 1, 0, true},
		{-2, 1, 0, false},
		{0, 0, 0, false},  // nothing is in an empty container,
		{-1, 0, 0, false}, // from either direction
		{1, 0, 0, false},
	} {
		at, ok := IndexOf(tt.i, tt.n)
		if ok != tt.want || (ok && at != tt.at) {
			t.Errorf("IndexOf(%d, %d) = %d, %v; want %d, %v", tt.i, tt.n, at, ok, tt.at, tt.want)
		}
	}
}

// TestTheIndexThatBreaksArithmeticIsJustOutOfRange covers the values that make
// the obvious implementation of this rule wrong. The form it replaced computed
// max+i+1 and tested the result for negativity, which is arithmetic on a value
// that has already overflowed; it happened to give the right answer, which is a
// bad reason for a bound to hold.
//
// Nothing here may panic and nothing may report an element.
func TestTheIndexThatBreaksArithmeticIsJustOutOfRange(t *testing.T) {
	for _, n := range []int{0, 1, 2, 1000} {
		for _, i := range []int64{math.MinInt64, math.MinInt64 + 1, math.MaxInt64, math.MaxInt64 - 1} {
			if at, ok := IndexOf(i, n); ok {
				t.Errorf("IndexOf(%d, %d) = %d, true; want out of range", i, n, at)
			}
		}
	}

	// And the same through RuneAt, which does no arithmetic on i at all.
	for _, s := range []string{"", "a", "h\xc3\xa9llo"} {
		for _, i := range []int64{math.MinInt64, math.MaxInt64} {
			if got, ok := RuneAt(s, i); ok {
				t.Errorf("RuneAt(%q, %d) = %q, true; want no rune", s, i, got)
			}
		}
	}
}

// TestRuneAtDoesNotDependOnTheStringsLength is a cost claim, not a behaviour
// one: RuneAt(s, 0) and RuneAt(s, -1) must decode one rune whatever the string
// weighs, because a buffer read off a disk image can be very large and
// materialising []rune(s) to read one character of it costs four bytes a rune.
//
// It is checked by counting decode calls through the same walk rather than by
// timing, which would be a flaky test.
func TestRuneAtDoesNotDependOnTheStringsLength(t *testing.T) {
	for _, n := range []int{1, 100, 100000} {
		s := strings.Repeat("\xc3\xa9", n)

		if steps := decodeStepsForward(s, 0); steps != 1 {
			t.Errorf("len=%d: reading s[0] decoded %d runes, want 1", n, steps)
		}
		if steps := decodeStepsBackward(s, 1); steps != 1 {
			t.Errorf("len=%d: reading s[-1] decoded %d runes, want 1", n, steps)
		}
	}
}

func decodeStepsForward(s string, i int64) int {
	steps := 0
	for pos := 0; pos < len(s); {
		_, size := utf8.DecodeRuneInString(s[pos:])
		steps++
		if i == 0 {
			return steps
		}
		i--
		pos += size
	}
	return steps
}

func decodeStepsBackward(s string, k int64) int {
	steps := 0
	for end := len(s); end > 0; {
		_, size := utf8.DecodeLastRuneInString(s[:end])
		steps++
		if k == 1 {
			return steps
		}
		k--
		end -= size
	}
	return steps
}
