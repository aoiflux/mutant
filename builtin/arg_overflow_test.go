package builtin

// M26-BLT-006: an argument a caller is entitled to pass panicked the builtin,
// and the panic was recorded as a security integrity failure.
//
// str_substr computed `start + length` before clamping it, so asking for the
// rest of a string by passing a number larger than it wrapped the sum negative
// and the slice panicked. rand_int computed `hi - lo` in int64, so a range
// wider than MaxInt64 wrapped non-positive and Int63n panicked on it. The VM
// catches such a panic as a runtime error, stops the program, and calls
// security.RecordIntegrityFailure("vm-panic"), which appends an event to the
// audit chain that case manifests seal -- so a bad argument forged a tamper
// record.
//
// Each case is run under recover, because a panic here is the defect and
// letting it through would end the test binary instead of reporting it.
//
// str_repeat and str_pad_left already carried an overflow-safe cap when this
// was written. They are held to it here so that a later change cannot quietly
// take one away: nothing in this file asks either of them to allocate, only to
// refuse.

import (
	"math"
	"testing"

	"mutant/object"
)

// answered runs one builtin and reports what it returned, or the panic it
// raised. A panic is never an acceptable answer: a builtin that cannot do what
// it was asked returns an *object.Error.
func answered(t *testing.T, what string, call func() object.Object) object.Object {
	t.Helper()
	var out object.Object
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked: %v -- the VM contains this as a runtime error, stops the "+
					"program and records a false integrity failure in the audit chain", what, r)
				out = nil
			}
		}()
		out = call()
	}()
	return out
}

func assertStringIs(t *testing.T, what string, got object.Object, want string) {
	t.Helper()
	if got == nil {
		return // the panic has already been reported
	}
	s, ok := got.(*object.String)
	if !ok {
		t.Errorf("%s returned %s %q, want STRING %q", what, got.Type(), got.Inspect(), want)
		return
	}
	if s.Value != want {
		t.Errorf("%s = %q, want %q", what, s.Value, want)
	}
}

func assertIsError(t *testing.T, what string, got object.Object) {
	t.Helper()
	if got == nil {
		return
	}
	if _, ok := got.(*object.Error); !ok {
		t.Errorf("%s returned %s %q, want an error", what, got.Type(), got.Inspect())
	}
}

func TestStrSubstrClampsALengthItCannotAdd(t *testing.T) {
	// Passing a length larger than the string is how a caller asks for the rest
	// of it. The sum overflowed first and the clamp against len(runes) never
	// fired, because a negative number is not greater than a positive one.
	//
	// start >= 1 is what it took: with start == 0 the sum did not overflow, so
	// the one case anybody would have tried by hand worked.
	for _, tt := range []struct {
		name          string
		s             string
		start, length int64
		want          string
	}{
		{"start 0, the case that always worked", "abc", 0, math.MaxInt64, "abc"},
		{"start 1", "abc", 1, math.MaxInt64, "bc"},
		{"start 2, length MaxInt64-1", "abc", 2, math.MaxInt64 - 1, "c"},
		{"start past the end", "abc", 99, math.MaxInt64, ""},
		{"start at the end", "abc", 3, math.MaxInt64, ""},
		{"a multi-byte string is still counted in runes", "héllo", 1, math.MaxInt64, "éllo"},
		{"an ordinary request is unchanged", "abcdef", 1, 3, "bcd"},
		{"length 0", "abc", 1, 0, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := answered(t, "str_substr", func() object.Object {
				return StrSubstr(&object.String{Value: tt.s}, &object.Integer{Value: tt.start},
					&object.Integer{Value: tt.length})
			})
			assertStringIs(t, "str_substr", got, tt.want)
		})
	}

	// A negative argument is still a caller's mistake and still named.
	assertIsError(t, "str_substr with a negative start",
		answered(t, "str_substr", func() object.Object {
			return StrSubstr(&object.String{Value: "abc"}, &object.Integer{Value: -1},
				&object.Integer{Value: 1})
		}))
}

func TestRandIntTakesARangeWiderThanInt64(t *testing.T) {
	for _, tt := range []struct {
		name   string
		lo, hi int64
	}{
		{"a span just inside int64", -1, math.MaxInt64 - 1},
		{"a span that wraps, from the row", -5_000_000_000_000_000_000, 5_000_000_000_000_000_000},
		{"the widest span there is", math.MinInt64, math.MaxInt64},
		{"the narrowest span there is", 0, 1},
		{"an ordinary span", 5, 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Several draws, because a wide span takes the rejection path and a
			// single draw would not exercise a retry.
			for i := 0; i < 64; i++ {
				got := answered(t, "rand_int", func() object.Object {
					return RandInt(&object.Integer{Value: tt.lo}, &object.Integer{Value: tt.hi})
				})
				if got == nil {
					return // already reported as a panic
				}
				n, ok := got.(*object.Integer)
				if !ok {
					t.Fatalf("rand_int returned %s %q, want INTEGER", got.Type(), got.Inspect())
				}
				if n.Value < tt.lo || n.Value >= tt.hi {
					t.Fatalf("rand_int(%d, %d) = %d, outside [lo, hi)", tt.lo, tt.hi, n.Value)
				}
			}
		})
	}

	// hi <= lo is still a caller's mistake and still named.
	assertIsError(t, "rand_int(5, 5)",
		answered(t, "rand_int", func() object.Object {
			return RandInt(&object.Integer{Value: 5}, &object.Integer{Value: 5})
		}))
	assertIsError(t, "rand_int(8, 5)",
		answered(t, "rand_int", func() object.Object {
			return RandInt(&object.Integer{Value: 8}, &object.Integer{Value: 5})
		}))
}

func TestStrRepeatAndStrPadStillRefuseWhatTheyCannotBuild(t *testing.T) {
	// Neither of these is asked to allocate. A count whose product overflows is
	// refused before any allocation, which is the property under test: the
	// comparison is a division in one and a subtraction in the other, so the
	// product that would overflow is never formed.
	assertIsError(t, "str_repeat with an overflowing product",
		answered(t, "str_repeat", func() object.Object {
			return StrRepeat(&object.String{Value: "ab"}, &object.Integer{Value: math.MaxInt64/2 + 1})
		}))
	assertIsError(t, "str_repeat with MaxInt64",
		answered(t, "str_repeat", func() object.Object {
			return StrRepeat(&object.String{Value: "ab"}, &object.Integer{Value: math.MaxInt64})
		}))
	assertIsError(t, "str_pad_left with MaxInt64 width",
		answered(t, "str_pad_left", func() object.Object {
			return StrPadLeft(&object.String{Value: "ab"}, &object.Integer{Value: math.MaxInt64},
				&object.String{Value: "x"})
		}))
	assertIsError(t, "str_pad_right with MaxInt64 width",
		answered(t, "str_pad_right", func() object.Object {
			return StrPadRight(&object.String{Value: "ab"}, &object.Integer{Value: math.MaxInt64},
				&object.String{Value: "x"})
		}))

	// And the ordinary job still works, at a size that costs nothing.
	assertStringIs(t, "str_repeat(ab, 3)",
		answered(t, "str_repeat", func() object.Object {
			return StrRepeat(&object.String{Value: "ab"}, &object.Integer{Value: 3})
		}), "ababab")
	assertStringIs(t, "str_pad_left(ab, 5, x)",
		answered(t, "str_pad_left", func() object.Object {
			return StrPadLeft(&object.String{Value: "ab"}, &object.Integer{Value: 5},
				&object.String{Value: "x"})
		}), "xxxab")
}
