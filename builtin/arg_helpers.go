package builtin

import "mutant/object"

// floatObj constructs a Float object (companion to stringObj/intObj/boolObj).
func floatObj(v float64) *object.Float { return &object.Float{Value: v} }

// requireStringArg validates that a positional argument is a STRING.
func requireStringArg(op string, arg object.Object, pos int) (string, *object.Error) {
	s, ok := arg.(*object.String)
	if !ok {
		return "", newError("argument %d to `%s` must be STRING, got %s", pos, op, arg.Type())
	}
	return s.Value, nil
}

// requireIntArg validates that a positional argument is an INTEGER.
func requireIntArg(op string, arg object.Object, pos int) (int64, *object.Error) {
	i, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to `%s` must be INTEGER, got %s", pos, op, arg.Type())
	}
	return i.Value, nil
}

// requireNumericArg accepts INTEGER or FLOAT and returns it as float64.
func requireNumericArg(op string, arg object.Object, pos int) (float64, *object.Error) {
	switch v := arg.(type) {
	case *object.Integer:
		return float64(v.Value), nil
	case *object.Float:
		return v.Value, nil
	default:
		return 0, newError("argument %d to `%s` must be INTEGER or FLOAT, got %s", pos, op, arg.Type())
	}
}
