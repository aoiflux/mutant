package builtin

import (
	crand "crypto/rand"
	"math"
	mrand "math/rand"

	"mutant/object"
)

func allIntegers(objs ...object.Object) bool {
	for _, o := range objs {
		if _, ok := o.(*object.Integer); !ok {
			return false
		}
	}
	return true
}

func Abs(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	switch v := args[0].(type) {
	case *object.Integer:
		if v.Value == math.MinInt64 {
			// Negating MinInt64 gives MinInt64 back, so the one thing this
			// must not do is answer. There is no absolute value of it in a
			// signed 64-bit integer (M26-BLT-004).
			return newError("abs: %d has no absolute value as a 64-bit integer", v.Value)
		}
		if v.Value < 0 {
			return intObj(-v.Value)
		}
		return intObj(v.Value)
	case *object.Float:
		return floatObj(math.Abs(v.Value))
	default:
		return newError("argument 1 to `abs` must be INTEGER or FLOAT, got %s", args[0].Type())
	}
}

func Min(args ...object.Object) object.Object { return minMax(BuiltinNameMin, args, true) }
func Max(args ...object.Object) object.Object { return minMax(BuiltinNameMax, args, false) }

func minMax(op string, args []object.Object, wantMin bool) object.Object {
	if len(args) == 0 {
		return newError("wrong number of arguments to `%s`. got=0, want=1 or more", op)
	}
	// requireNumericArg is still called on every argument, for the type error
	// it gives and for nothing else: the float64 it returns is what made
	// min(FILETIME+1, FILETIME) answer FILETIME+1, because the two convert to
	// one float. The comparison below is exact (M26-BLT-004).
	//
	// Only the choice was ever wrong here, never a value: these return the
	// argument object, so an integer comes back as the integer it was.
	best := args[0]
	if _, errObj := requireNumericArg(op, args[0], 1); errObj != nil {
		return errObj
	}
	for i := 1; i < len(args); i++ {
		if _, errObj := requireNumericArg(op, args[i], i+1); errObj != nil {
			return errObj
		}
		order, ok := cmpNumeric(args[i], best)
		if !ok {
			// NaN stands in no order, so it neither displaces the best nor is
			// displaced by what follows -- which is what comparing it as a
			// float did too, and is worth keeping.
			continue
		}
		if (wantMin && order < 0) || (!wantMin && order > 0) {
			best = args[i]
		}
	}
	return best
}

func Clamp(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	x, errObj := requireNumericArg(BuiltinNameClamp, args[0], 1)
	if errObj != nil {
		return errObj
	}
	lo, errObj := requireNumericArg(BuiltinNameClamp, args[1], 2)
	if errObj != nil {
		return errObj
	}
	hi, errObj := requireNumericArg(BuiltinNameClamp, args[2], 3)
	if errObj != nil {
		return errObj
	}
	// Three integers are clamped as integers. Going out through float64 and
	// back with int64() is what turned clamp(2^53+1, 0, 2^53+1) into 2^53, and
	// the bounds check has to move inside this arm as well: as float64 a lo one
	// above hi compares equal to it, so the refusal below would not fire on a
	// pair it is there to catch (M26-BLT-004).
	if allIntegers(args[0], args[1], args[2]) {
		xi := args[0].(*object.Integer).Value
		loI := args[1].(*object.Integer).Value
		hiI := args[2].(*object.Integer).Value
		if loI > hiI {
			return newError("clamp: lo (%d) must be <= hi (%d)", loI, hiI)
		}
		switch {
		case xi < loI:
			return intObj(loI)
		case xi > hiI:
			return intObj(hiI)
		}
		return intObj(xi)
	}
	if lo > hi {
		return newError("clamp: lo (%v) must be <= hi (%v)", lo, hi)
	}
	return floatObj(math.Min(math.Max(x, lo), hi))
}

func Pow(args ...object.Object) object.Object {
	x, y, errObj := twoNumericArgs(BuiltinNamePow, args)
	if errObj != nil {
		return errObj
	}
	return floatObj(math.Pow(x, y))
}

func Sqrt(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	x, errObj := requireNumericArg(BuiltinNameSqrt, args[0], 1)
	if errObj != nil {
		return errObj
	}
	if x < 0 {
		return newError("sqrt: argument must be non-negative, got %v", x)
	}
	return floatObj(math.Sqrt(x))
}

func Mod(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	if allIntegers(args[0], args[1]) {
		a := args[0].(*object.Integer).Value
		b := args[1].(*object.Integer).Value
		if b == 0 {
			return newError("mod: division by zero")
		}
		return intObj(a % b)
	}
	a, errObj := requireNumericArg(BuiltinNameMod, args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireNumericArg(BuiltinNameMod, args[1], 2)
	if errObj != nil {
		return errObj
	}
	if b == 0 {
		return newError("mod: division by zero")
	}
	return floatObj(math.Mod(a, b))
}

func Floor(args ...object.Object) object.Object { return roundish(BuiltinNameFloor, args, math.Floor) }
func Ceil(args ...object.Object) object.Object  { return roundish(BuiltinNameCeil, args, math.Ceil) }
func Round(args ...object.Object) object.Object { return roundish(BuiltinNameRound, args, math.Round) }

func roundish(op string, args []object.Object, fn func(float64) float64) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	// An integer is already the integer each of these names, so there is
	// nothing to round and the round trip through float64 is pure loss:
	// floor(9007199254740993) came back 9007199254740992 (M26-BLT-004).
	if i, ok := args[0].(*object.Integer); ok {
		return intObj(i.Value)
	}
	x, errObj := requireNumericArg(op, args[0], 1)
	if errObj != nil {
		return errObj
	}
	// A float with no integer value is refused rather than converted. int64()
	// on NaN, an infinity or 1e19 is undefined in Go and gives MinInt64 here,
	// so the old code answered -9223372036854775808 and reported success.
	n, ok := int64FromFloat(fn(x))
	if !ok {
		return newError("%s: %v has no value as a 64-bit integer", op, x)
	}
	return intObj(n)
}

func Sum(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument 1 to `sum` must be ARRAY, got %s", args[0].Type())
	}
	// Two totals are carried, and the elements decide which is returned. An
	// all-integer array has an exact integer total or it has none: float64
	// accumulation gave a near one and int64(total) presented it as exact, so
	// sum([133700000000000001, 1]) answered 133700000000000000 and
	// sum([MaxInt64, 1]) answered MinInt64 (M26-BLT-004).
	//
	// An overflow is remembered rather than returned on the spot, because it
	// only matters if every element turns out to be an integer: a later float
	// element puts the array on the float path, where the int64 total is not
	// the answer and its overflow is not a fault.
	allInt := true
	overflowAt := -1
	var exact int64
	var total float64
	for i, el := range arr.Elements {
		f, errObj := requireNumericArg(BuiltinNameSum, el, i+1)
		if errObj != nil {
			return newError("sum: element %d must be numeric, got %s", i, el.Type())
		}
		if iv, isInt := el.(*object.Integer); isInt {
			if overflowAt < 0 {
				if next, ok := addInt64(exact, iv.Value); ok {
					exact = next
				} else {
					overflowAt = i
				}
			}
		} else {
			allInt = false
		}
		total += f
	}
	if allInt {
		if overflowAt >= 0 {
			return newError("sum: the total leaves the range of a 64-bit integer at element %d", overflowAt)
		}
		return intObj(exact)
	}
	return floatObj(total)
}

func Avg(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument 1 to `avg` must be ARRAY, got %s", args[0].Type())
	}
	if len(arr.Elements) == 0 {
		return newError("avg: cannot average an empty array")
	}
	var total float64
	for i, el := range arr.Elements {
		f, errObj := requireNumericArg(BuiltinNameAvg, el, i+1)
		if errObj != nil {
			return newError("avg: element %d must be numeric, got %s", i, el.Type())
		}
		total += f
	}
	return floatObj(total / float64(len(arr.Elements)))
}

func Rand(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	return floatObj(mrand.Float64())
}

func RandInt(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	lo, errObj := requireIntArg(BuiltinNameRandInt, args[0], 1)
	if errObj != nil {
		return errObj
	}
	hi, errObj := requireIntArg(BuiltinNameRandInt, args[1], 2)
	if errObj != nil {
		return errObj
	}
	if hi <= lo {
		return newError("rand_int: hi (%d) must be greater than lo (%d)", hi, lo)
	}
	// hi-lo is the one subtraction here that can overflow, and rand_int(-5e18,
	// 5e18) is enough to do it: the span wraps to a non-positive number and
	// Int63n panics on that, which the VM contains as a runtime error that
	// stops the program and records a false integrity failure (M26-BLT-006).
	//
	// In uint64 the subtraction is exact for every hi > lo, including a span
	// that crosses zero. The narrow case keeps the original call rather than
	// routing everything through the wide one, so a seeded run draws exactly
	// the numbers it always did and no golden moves.
	span := uint64(hi) - uint64(lo)
	if span <= uint64(math.MaxInt64) {
		return intObj(lo + mrand.Int63n(int64(span)))
	}
	// lo + a value in [0, span) is inside [lo, hi) and therefore inside int64,
	// so the conversion of a draw above MaxInt64 wrapping negative is not a
	// problem: two's-complement addition lands on the right number.
	return intObj(lo + int64(uniformUint64Below(span)))
}

// uniformUint64Below returns a uniform value in [0, n) for n > 0. It is for the
// one case Int63n cannot take, a span wider than MaxInt64.
//
// The top partial block is rejected rather than folded in. Reducing a full
// uint64 draw with `v % n` favours the values in n's last incomplete block, and
// that bias is invisible in a range test and real in a sample. Rejection costs
// a second draw with probability below one half for every n, because the
// rejected region is smaller than n and n is more than half of 2^64 here.
func uniformUint64Below(n uint64) uint64 {
	if n&(n-1) == 0 {
		return mrand.Uint64() & (n - 1)
	}
	limit := (uint64(math.MaxUint64) / n) * n
	for {
		if v := mrand.Uint64(); v < limit {
			return v % n
		}
	}
}

func RandBytes(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	n, errObj := requireIntArg(BuiltinNameRandBytes, args[0], 1)
	if errObj != nil {
		return errObj
	}
	if n < 0 {
		return newError("argument 1 to `rand_bytes` must be non-negative, got %d", n)
	}
	if n > maxBuiltinResultBytes {
		return newError("argument 1 to `rand_bytes` asks for %d bytes, over the %d-byte limit on one builtin result; write data this large to a file instead",
			n, int64(maxBuiltinResultBytes))
	}
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		return newError("rand_bytes: %s", err.Error())
	}
	return stringObj(string(buf))
}

func MathPi(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	return floatObj(math.Pi)
}

func MathE(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	return floatObj(math.E)
}

func twoNumericArgs(op string, args []object.Object) (float64, float64, *object.Error) {
	if len(args) != 2 {
		return 0, 0, newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	a, errObj := requireNumericArg(op, args[0], 1)
	if errObj != nil {
		return 0, 0, errObj
	}
	b, errObj := requireNumericArg(op, args[1], 2)
	if errObj != nil {
		return 0, 0, errObj
	}
	return a, b, nil
}
