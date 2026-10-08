package builtin

// M26-BLT-004: integer math and sort went through float64.
//
// requireNumericArg hands every INTEGER back as a float64, so sum and clamp
// converted the float back with int64(), floor/ceil/round did the same to an
// argument that was already an integer, and min/max/sort compared the floats.
// Above 2^53 that conversion is lossy and says nothing about it.
//
// Every number here is chosen rather than picked. 2^53+1 is the first integer
// float64 cannot hold. ntfsFileTime is a real NTFS FILETIME -- 100-nanosecond
// ticks since 1601 -- which is the shape this actually broke: at that
// magnitude one float64 ulp spans 16 ticks, so two events 1.6 microseconds
// apart compare equal, and ordering events is what this tool is for. MaxInt64,
// NaN, the infinities and 1e19 are the inputs whose conversion Go leaves
// undefined, and which therefore came back as MinInt64 with no error.
//
// These tests compile against a tree without the fix, which is the point: the
// same bytes fail before it and pass after it.

import (
	"fmt"
	"math"
	"testing"

	"mutant/object"
)

const (
	ntfsFileTime    = int64(133700000000000000)
	firstInexactInt = int64(1)<<53 + 1 // 9007199254740993
)

func numInt(v int64) object.Object              { return &object.Integer{Value: v} }
func numFloat(v float64) object.Object          { return &object.Float{Value: v} }
func numArray(e ...object.Object) object.Object { return &object.Array{Elements: e} }

// assertExactInt requires an INTEGER result holding exactly want. It reports
// the difference as well as the two values, because every failure this guards
// against is off by a small amount and the amount is the evidence.
func assertExactInt(t *testing.T, what string, got object.Object, want int64) {
	t.Helper()
	i, ok := got.(*object.Integer)
	if !ok {
		t.Errorf("%s returned %s %q, want INTEGER %d", what, got.Type(), got.Inspect(), want)
		return
	}
	if i.Value != want {
		t.Errorf("%s = %d, want %d (off by %d)", what, i.Value, want, i.Value-want)
	}
}

// assertRefused requires an error rather than a number. A builtin that cannot
// answer must say so: returning MinInt64 is the one outcome worse than either
// a right answer or a refusal, because nothing downstream can tell it apart
// from a real result.
func assertRefused(t *testing.T, what string, got object.Object) {
	t.Helper()
	if _, ok := got.(*object.Error); !ok {
		t.Errorf("%s returned %s %q, want an error: it has no answer to give",
			what, got.Type(), got.Inspect())
	}
}

func TestSumOfIntegersIsExactOrRefused(t *testing.T) {
	assertExactInt(t, "sum([2^53+1])",
		Sum(numArray(numInt(firstInexactInt))), firstInexactInt)

	assertExactInt(t, "sum([FILETIME+1, 1])",
		Sum(numArray(numInt(ntfsFileTime+1), numInt(1))), ntfsFileTime+2)

	// A total that leaves int64 is refused rather than wrapped. Wrapping gave
	// MinInt64, which reads as a large negative measurement.
	assertRefused(t, "sum([MaxInt64, 1])",
		Sum(numArray(numInt(math.MaxInt64), numInt(1))))
	assertRefused(t, "sum([MinInt64, -1])",
		Sum(numArray(numInt(math.MinInt64), numInt(-1))))

	// An overflow only matters while every element is an integer. One float
	// puts the array on the float path, where the int64 total is not the answer
	// and its overflow is not a fault -- so this must NOT be refused.
	mixed := Sum(numArray(numInt(math.MaxInt64), numInt(1), numFloat(0.5)))
	if _, isErr := mixed.(*object.Error); isErr {
		t.Errorf("sum([MaxInt64, 1, 0.5]) was refused; the array is not all integers, so the " +
			"int64 total is not what it returns and its overflow is not a fault")
	}
	if _, isFloat := mixed.(*object.Float); !isFloat {
		t.Errorf("sum([MaxInt64, 1, 0.5]) returned %s, want FLOAT", mixed.Type())
	}
}

func TestClampKeepsAnIntegerExactly(t *testing.T) {
	assertExactInt(t, "clamp(2^53+1, 0, 2^53+1)",
		Clamp(numInt(firstInexactInt), numInt(0), numInt(firstInexactInt)), firstInexactInt)

	assertExactInt(t, "clamp(FILETIME+1, FILETIME, FILETIME+2)",
		Clamp(numInt(ntfsFileTime+1), numInt(ntfsFileTime), numInt(ntfsFileTime+2)), ntfsFileTime+1)

	assertExactInt(t, "clamp(FILETIME+5, FILETIME, FILETIME+1) clamps to hi",
		Clamp(numInt(ntfsFileTime+5), numInt(ntfsFileTime), numInt(ntfsFileTime+1)), ntfsFileTime+1)

	// lo one above hi is a caller's mistake and has to be named. As float64 the
	// two compare equal at this magnitude, so the refusal did not fire on
	// exactly the pair it exists for.
	assertRefused(t, "clamp(FILETIME, FILETIME+1, FILETIME)",
		Clamp(numInt(ntfsFileTime), numInt(ntfsFileTime+1), numInt(ntfsFileTime)))
}

func TestFloorCeilAndRoundLeaveAnIntegerAlone(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(...object.Object) object.Object
	}{
		{"floor", Floor},
		{"ceil", Ceil},
		{"round", Round},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// There is nothing to round. The round trip through float64 was
			// pure loss.
			assertExactInt(t, tt.name+"(2^53+1)", tt.call(numInt(firstInexactInt)), firstInexactInt)
			assertExactInt(t, tt.name+"(FILETIME+1)", tt.call(numInt(ntfsFileTime+1)), ntfsFileTime+1)
			assertExactInt(t, tt.name+"(MaxInt64)", tt.call(numInt(math.MaxInt64)), math.MaxInt64)
			assertExactInt(t, tt.name+"(MinInt64)", tt.call(numInt(math.MinInt64)), math.MinInt64)

			// A float with no integer value is refused. int64() on each of
			// these is undefined in Go and gave MinInt64 here.
			assertRefused(t, tt.name+"(NaN)", tt.call(numFloat(math.NaN())))
			assertRefused(t, tt.name+"(+Inf)", tt.call(numFloat(math.Inf(1))))
			assertRefused(t, tt.name+"(-Inf)", tt.call(numFloat(math.Inf(-1))))
			assertRefused(t, tt.name+"(1e19)", tt.call(numFloat(1e19)))
			assertRefused(t, tt.name+"(-1e19)", tt.call(numFloat(-1e19)))
		})
	}

	// The ordinary job still works, so the guards above are not refusing
	// everything.
	assertExactInt(t, "floor(2.7)", Floor(numFloat(2.7)), 2)
	assertExactInt(t, "ceil(2.1)", Ceil(numFloat(2.1)), 3)
	assertExactInt(t, "round(2.5)", Round(numFloat(2.5)), 3)
	assertExactInt(t, "floor(-2.1)", Floor(numFloat(-2.1)), -3)
}

func TestMinAndMaxChooseByTheIntegerNotItsFloat(t *testing.T) {
	// min/max return the argument object, so no value was ever corrupted here:
	// only the choice was wrong, which is harder to notice.
	assertExactInt(t, "min(FILETIME+1, FILETIME)",
		Min(numInt(ntfsFileTime+1), numInt(ntfsFileTime)), ntfsFileTime)
	assertExactInt(t, "max(FILETIME, FILETIME+1)",
		Max(numInt(ntfsFileTime), numInt(ntfsFileTime+1)), ntfsFileTime+1)
	assertExactInt(t, "min(2^53+1, 2^53)",
		Min(numInt(firstInexactInt), numInt(firstInexactInt-1)), firstInexactInt-1)
	assertExactInt(t, "max(MaxInt64, MaxInt64-1)",
		Max(numInt(math.MaxInt64), numInt(math.MaxInt64-1)), math.MaxInt64)

	// An integer against a float is the case a conversion cannot decide: the
	// float is exactly 2^53 and the integer is one above it, so converting
	// either way makes them equal.
	lowest := Min(numInt(firstInexactInt), numFloat(float64(int64(1)<<53)))
	if f, ok := lowest.(*object.Float); !ok || f.Value != float64(int64(1)<<53) {
		t.Errorf("min(2^53+1, 2^53 as a float) = %s %q, want the float: it is the smaller",
			lowest.Type(), lowest.Inspect())
	}
	highest := Max(numInt(firstInexactInt), numFloat(float64(int64(1)<<53)))
	if i, ok := highest.(*object.Integer); !ok || i.Value != firstInexactInt {
		t.Errorf("max(2^53+1, 2^53 as a float) = %s %q, want the integer: it is the larger",
			highest.Type(), highest.Inspect())
	}
}

func TestSortOrdersIntegersFloat64CannotTellApart(t *testing.T) {
	// Four FILETIMEs within one float64 ulp of each other. Compared as floats
	// they are all equal, and a stable sort then leaves them exactly as they
	// arrived -- a timeline that reports itself as sorted and is not.
	in := numArray(
		numInt(ntfsFileTime+3),
		numInt(ntfsFileTime+1),
		numInt(ntfsFileTime+4),
		numInt(ntfsFileTime+2),
	)
	out, ok := Sort(in).(*object.Array)
	if !ok {
		t.Fatalf("sort returned %T, want *object.Array", Sort(in))
	}
	want := []int64{ntfsFileTime + 1, ntfsFileTime + 2, ntfsFileTime + 3, ntfsFileTime + 4}
	if len(out.Elements) != len(want) {
		t.Fatalf("sort returned %d elements, want %d", len(out.Elements), len(want))
	}
	for i, w := range want {
		assertExactInt(t, fmt.Sprintf("sort result element %d", i), out.Elements[i], w)
	}

	// Mixed numbers still sort, and the float lands between the two integers it
	// belongs between rather than beside whichever it converts to.
	mixed, ok := Sort(numArray(numInt(3), numFloat(1.5), numInt(1), numFloat(2.5))).(*object.Array)
	if !ok {
		t.Fatal("sort of a mixed numeric array did not return an array")
	}
	var order []string
	for _, el := range mixed.Elements {
		order = append(order, el.Inspect())
	}
	if len(order) != 4 || order[0] != "1" || order[3] != "3" {
		t.Errorf("sort([3, 1.5, 1, 2.5]) = %v, want 1, 1.5, 2.5, 3", order)
	}
}

func TestToIntRefusesAFloatWithNoIntegerValue(t *testing.T) {
	// to_int already returns through a (value, error) pair, so the channel for
	// this was there and unused.
	errorSlotOf := func(res object.Object) object.Object {
		mv, ok := res.(*object.MultiValue)
		if !ok || len(mv.Values) != 2 {
			t.Fatalf("to_int returned %T, want a two-value pair", res)
		}
		return mv.Values[1]
	}
	for _, tt := range []struct {
		name string
		arg  object.Object
	}{
		{"NaN", numFloat(math.NaN())},
		{"+Inf", numFloat(math.Inf(1))},
		{"-Inf", numFloat(math.Inf(-1))},
		{"1e19", numFloat(1e19)},
		{"-1e19", numFloat(-1e19)},
	} {
		assertRefused(t, "to_int("+tt.name+")", errorSlotOf(ToInt(tt.arg)))
	}

	// A float that does have an integer value still converts.
	converted, ok := ToInt(numFloat(2.9)).(*object.MultiValue)
	if !ok || len(converted.Values) != 2 {
		t.Fatalf("to_int(2.9) returned %T, want a two-value pair", ToInt(numFloat(2.9)))
	}
	assertExactInt(t, "to_int(2.9)", converted.Values[0], 2)
}

func TestAbsRefusesTheOneIntegerWithNoAbsoluteValue(t *testing.T) {
	// -MinInt64 is not an int64, so negating it returns MinInt64 unchanged:
	// abs reported a negative magnitude and called it success.
	assertRefused(t, "abs(MinInt64)", Abs(numInt(math.MinInt64)))

	assertExactInt(t, "abs(MinInt64+1)", Abs(numInt(math.MinInt64+1)), math.MaxInt64)
	assertExactInt(t, "abs(-FILETIME)", Abs(numInt(-ntfsFileTime)), ntfsFileTime)
	assertExactInt(t, "abs(FILETIME)", Abs(numInt(ntfsFileTime)), ntfsFileTime)
}
