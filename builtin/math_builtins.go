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

func Min(args ...object.Object) object.Object { return minMax("min", args, true) }
func Max(args ...object.Object) object.Object { return minMax("max", args, false) }

func minMax(op string, args []object.Object, wantMin bool) object.Object {
	if len(args) == 0 {
		return newError("wrong number of arguments to `%s`. got=0, want=1 or more", op)
	}
	best := args[0]
	bestF, errObj := requireNumericArg(op, args[0], 1)
	if errObj != nil {
		return errObj
	}
	for i := 1; i < len(args); i++ {
		f, errObj := requireNumericArg(op, args[i], i+1)
		if errObj != nil {
			return errObj
		}
		if (wantMin && f < bestF) || (!wantMin && f > bestF) {
			best, bestF = args[i], f
		}
	}
	return best
}

func Clamp(args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	x, errObj := requireNumericArg("clamp", args[0], 1)
	if errObj != nil {
		return errObj
	}
	lo, errObj := requireNumericArg("clamp", args[1], 2)
	if errObj != nil {
		return errObj
	}
	hi, errObj := requireNumericArg("clamp", args[2], 3)
	if errObj != nil {
		return errObj
	}
	if lo > hi {
		return newError("clamp: lo (%v) must be <= hi (%v)", lo, hi)
	}
	r := math.Min(math.Max(x, lo), hi)
	if allIntegers(args[0], args[1], args[2]) {
		return intObj(int64(r))
	}
	return floatObj(r)
}

func Pow(args ...object.Object) object.Object {
	x, y, errObj := twoNumericArgs("pow", args)
	if errObj != nil {
		return errObj
	}
	return floatObj(math.Pow(x, y))
}

func Sqrt(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	x, errObj := requireNumericArg("sqrt", args[0], 1)
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
	a, errObj := requireNumericArg("mod", args[0], 1)
	if errObj != nil {
		return errObj
	}
	b, errObj := requireNumericArg("mod", args[1], 2)
	if errObj != nil {
		return errObj
	}
	if b == 0 {
		return newError("mod: division by zero")
	}
	return floatObj(math.Mod(a, b))
}

func Floor(args ...object.Object) object.Object { return roundish("floor", args, math.Floor) }
func Ceil(args ...object.Object) object.Object  { return roundish("ceil", args, math.Ceil) }
func Round(args ...object.Object) object.Object { return roundish("round", args, math.Round) }

func roundish(op string, args []object.Object, fn func(float64) float64) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	x, errObj := requireNumericArg(op, args[0], 1)
	if errObj != nil {
		return errObj
	}
	return intObj(int64(fn(x)))
}

func Sum(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument 1 to `sum` must be ARRAY, got %s", args[0].Type())
	}
	allInt := true
	var total float64
	for i, el := range arr.Elements {
		f, errObj := requireNumericArg("sum", el, i+1)
		if errObj != nil {
			return newError("sum: element %d must be numeric, got %s", i, el.Type())
		}
		if _, isInt := el.(*object.Integer); !isInt {
			allInt = false
		}
		total += f
	}
	if allInt {
		return intObj(int64(total))
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
		f, errObj := requireNumericArg("avg", el, i+1)
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
	lo, errObj := requireIntArg("rand_int", args[0], 1)
	if errObj != nil {
		return errObj
	}
	hi, errObj := requireIntArg("rand_int", args[1], 2)
	if errObj != nil {
		return errObj
	}
	if hi <= lo {
		return newError("rand_int: hi (%d) must be greater than lo (%d)", hi, lo)
	}
	return intObj(lo + mrand.Int63n(hi-lo))
}

func RandBytes(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	n, errObj := requireIntArg("rand_bytes", args[0], 1)
	if errObj != nil {
		return errObj
	}
	if n < 0 {
		return newError("argument 1 to `rand_bytes` must be non-negative, got %d", n)
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
