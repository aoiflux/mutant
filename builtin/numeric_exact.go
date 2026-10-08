package builtin

// Exact comparison and arithmetic for Mutant's two numeric types.
//
// These exist because requireNumericArg hands every INTEGER back as a float64.
// That conversion is lossy above 2^53 and silent about it, and the lossy range
// is this tool's working range: an NTFS FILETIME is about 1.3e17, a Unix
// nanosecond timestamp about 1.7e18, and a 64-bit file reference number can be
// anything. So two timestamps a microsecond apart compared as float64 came out
// equal, and the smaller of them was whichever had been passed first
// (M26-BLT-004).
//
// Nothing here converts an integer to a float. Where the two types meet the
// comparison is decided without one, because the conversion is the defect.

import (
	"math"

	"mutant/object"
)

// twoPow63 is the smallest float64 above MaxInt64, and the boundary every
// range test here uses. MaxInt64 itself is not a float64 -- float64(MaxInt64)
// rounds up to this value -- so comparing against a conversion of it would
// admit one number it must not.
const twoPow63 = 9223372036854775808.0

// cmpIntFloat compares a against b exactly, returning -1, 0 or +1. ok is false
// for NaN alone, which stands in no order with anything including itself.
func cmpIntFloat(a int64, b float64) (int, bool) {
	if math.IsNaN(b) {
		return 0, false
	}
	// Outside int64's range the sign of b settles it, and no conversion in
	// either direction would be safe. -twoPow63 is exactly MinInt64, so a b
	// equal to it is in range and only a b below it is not.
	if b >= twoPow63 {
		return -1, true
	}
	if b < -twoPow63 {
		return 1, true
	}
	// b now lies in [-2^63, 2^63), so its floor converts to an int64 exactly
	// and comparing whole parts is comparing integers.
	whole := math.Floor(b)
	ib := int64(whole)
	if a < ib {
		return -1, true
	}
	if a > ib {
		return 1, true
	}
	// Equal whole parts. b carries a fraction exactly when it stands above its
	// own floor, and then a, which equals that floor, is the smaller.
	if b > whole {
		return -1, true
	}
	return 0, true
}

// cmpNumeric compares two numeric objects exactly, returning -1, 0 or +1. ok is
// false when either argument is not numeric, and when either is NaN.
func cmpNumeric(a, b object.Object) (int, bool) {
	ai, aIsInt := a.(*object.Integer)
	bi, bIsInt := b.(*object.Integer)
	switch {
	case aIsInt && bIsInt:
		if ai.Value < bi.Value {
			return -1, true
		}
		if ai.Value > bi.Value {
			return 1, true
		}
		return 0, true
	case aIsInt:
		bf, ok := b.(*object.Float)
		if !ok {
			return 0, false
		}
		return cmpIntFloat(ai.Value, bf.Value)
	case bIsInt:
		af, ok := a.(*object.Float)
		if !ok {
			return 0, false
		}
		// The arguments go in the other way round, so the answer comes back
		// the other way round.
		c, ok := cmpIntFloat(bi.Value, af.Value)
		return -c, ok
	}
	af, aOK := a.(*object.Float)
	bf, bOK := b.(*object.Float)
	if !aOK || !bOK {
		return 0, false
	}
	if math.IsNaN(af.Value) || math.IsNaN(bf.Value) {
		return 0, false
	}
	if af.Value < bf.Value {
		return -1, true
	}
	if af.Value > bf.Value {
		return 1, true
	}
	return 0, true
}

// numericLess is cmpNumeric in the shape a sort comparator wants. An unordered
// pair -- a NaN against anything -- answers false in both directions, which is
// what sort.SliceStable needs in order to leave such a pair where it found it.
func numericLess(a, b object.Object) bool {
	c, ok := cmpNumeric(a, b)
	return ok && c < 0
}

// addInt64 adds two int64 values and reports whether the result is one of them.
// The test is the operands' signs against the sum's, which is the standard
// check and needs no wider type: two positives cannot sum to a negative and two
// negatives cannot sum to a non-negative unless the result wrapped, and a mixed
// pair cannot overflow at all.
func addInt64(a, b int64) (int64, bool) {
	sum := a + b
	if a > 0 && b > 0 && sum < 0 {
		return 0, false
	}
	if a < 0 && b < 0 && sum >= 0 {
		return 0, false
	}
	return sum, true
}

// int64FromFloat converts a float to an int64 and reports whether the float had
// one to give.
//
// NaN, both infinities and every value outside [MinInt64, MaxInt64] do not. Go
// leaves that conversion's result undefined, and on this platform it is
// MinInt64 -- a specific wrong number rather than a refusal, which is the worst
// of the available outcomes: floor(1e19), round(NaN) and to_int(1e19) each
// reported -9223372036854775808 and no error.
func int64FromFloat(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	if f >= twoPow63 || f < -twoPow63 {
		return 0, false
	}
	return int64(f), true
}
