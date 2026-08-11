package builtin

import (
	"strconv"

	"mutant/object"
)

func ToInt(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	switch v := args[0].(type) {
	case *object.Integer:
		return resultAndError(intObj(v.Value), nil)
	case *object.Float:
		return resultAndError(intObj(int64(v.Value)), nil)
	case *object.Boolean:
		if v.Value {
			return resultAndError(intObj(1), nil)
		}
		return resultAndError(intObj(0), nil)
	case *object.String:
		n, err := strconv.ParseInt(v.Value, 0, 64)
		if err != nil {
			return resultAndError(nil, newError("to_int: cannot parse %q as integer", v.Value))
		}
		return resultAndError(intObj(n), nil)
	default:
		return resultAndError(nil, newError("to_int: cannot convert %s to INTEGER", args[0].Type()))
	}
}

func ToFloat(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	switch v := args[0].(type) {
	case *object.Integer:
		return resultAndError(floatObj(float64(v.Value)), nil)
	case *object.Float:
		return resultAndError(floatObj(v.Value), nil)
	case *object.Boolean:
		if v.Value {
			return resultAndError(floatObj(1), nil)
		}
		return resultAndError(floatObj(0), nil)
	case *object.String:
		f, err := strconv.ParseFloat(v.Value, 64)
		if err != nil {
			return resultAndError(nil, newError("to_float: cannot parse %q as float", v.Value))
		}
		return resultAndError(floatObj(f), nil)
	default:
		return resultAndError(nil, newError("to_float: cannot convert %s to FLOAT", args[0].Type()))
	}
}

func ToString(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	switch v := args[0].(type) {
	case *object.String:
		return stringObj(v.Value)
	case *object.Integer:
		return stringObj(strconv.FormatInt(v.Value, 10))
	case *object.Float:
		return stringObj(strconv.FormatFloat(v.Value, 'g', -1, 64))
	case *object.Boolean:
		return stringObj(strconv.FormatBool(v.Value))
	default:
		return stringObj(args[0].Inspect())
	}
}

func ToBool(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	switch v := args[0].(type) {
	case *object.Boolean:
		return resultAndError(boolObj(v.Value), nil)
	case *object.Integer:
		return resultAndError(boolObj(v.Value != 0), nil)
	case *object.Float:
		return resultAndError(boolObj(v.Value != 0), nil)
	case *object.String:
		b, err := strconv.ParseBool(v.Value)
		if err != nil {
			return resultAndError(nil, newError("to_bool: cannot parse %q as bool", v.Value))
		}
		return resultAndError(boolObj(b), nil)
	default:
		return resultAndError(nil, newError("to_bool: cannot convert %s to BOOLEAN", args[0].Type()))
	}
}

func ParseInt(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	s, errObj := requireStringArg("parse_int", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	base, errObj := requireIntArg("parse_int", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if base != 0 && (base < 2 || base > 36) {
		return resultAndError(nil, newError("parse_int: base must be 0 or between 2 and 36, got %d", base))
	}
	n, err := strconv.ParseInt(s, int(base), 64)
	if err != nil {
		return resultAndError(nil, newError("parse_int: %s", err.Error()))
	}
	return resultAndError(intObj(n), nil)
}

func ParseFloat(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	s, errObj := requireStringArg("parse_float", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return resultAndError(nil, newError("parse_float: %s", err.Error()))
	}
	return resultAndError(floatObj(f), nil)
}

func TypeOf(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	return stringObj(string(args[0].Type()))
}

func IsNull(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	_, ok := args[0].(*object.Null)
	return boolObj(ok)
}
