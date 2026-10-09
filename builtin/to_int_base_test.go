package builtin

import (
	"testing"

	"mutant/object"
)

// TestToIntReadsBaseTenAndParseIntDetectsTheBase pins M26-BLT-008.
//
// to_int called strconv.ParseInt with base 0, so it auto-detected a prefix on
// strings nobody chose the spelling of: a zero-padded month read as octal, and
// the two months that are not octal digits failed outright. One timeline field
// could be wrong, refused or right depending only on which month it named.
//
// This is the same base-0 call as M26-LEX-008 at a different site, and it has
// the opposite answer on purpose: a literal is authored, so an ambiguous one is
// refused, while a string is data, so a zero-padded one is the decimal number
// it looks like. The builtin that auto-detects a base is parse_int, and the
// last assertions here are what make giving it up a move rather than a loss.
func TestToIntReadsBaseTenAndParseIntDetectsTheBase(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"010", 10},   // was 8
		{"0755", 755}, // was 493
		{"08", 8},     // was an error: not an octal digit
		{"09", 9},     // was an error
		{"0", 0},
		{"00", 0},
		{"31", 31},
		{"-07", -7},
		{"+07", 7},
	} {
		got, errObj := unwrapPair(t, ToInt(stringObj(tc.in)))
		if errObj != nil {
			t.Errorf("to_int(%q) errored: %v", tc.in, errObj)
			continue
		}
		if n := got.(*object.Integer).Value; n != tc.want {
			t.Errorf("to_int(%q) = %d, want %d", tc.in, n, tc.want)
		}
	}

	// A prefix is not a base to to_int any more, and the refusal says where to
	// go instead. It answered 31 for "0x1F" until now, and no summary said so.
	for _, in := range []string{"0x1F", "0b101", "0o17", "1_000", "nope", ""} {
		if _, errObj := unwrapPair(t, ToInt(stringObj(in))); errObj == nil {
			t.Errorf("to_int(%q) should be refused: base 10 is the contract", in)
		}
	}

	// parse_int still detects a base, which is what makes the above a move and
	// not a capability lost.
	for _, tc := range []struct {
		in   string
		base int64
		want int64
	}{
		{"0x1F", 0, 31},
		{"0b101", 0, 5},
		{"0755", 0, 493},
		{"0755", 8, 493},
		{"1F", 16, 31},
		{"010", 10, 10},
	} {
		got, errObj := unwrapPair(t, ParseInt(stringObj(tc.in), intObj(tc.base)))
		if errObj != nil {
			t.Errorf("parse_int(%q, %d) errored: %v", tc.in, tc.base, errObj)
			continue
		}
		if n := got.(*object.Integer).Value; n != tc.want {
			t.Errorf("parse_int(%q, %d) = %d, want %d", tc.in, tc.base, n, tc.want)
		}
	}
}
