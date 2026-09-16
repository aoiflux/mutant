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

// requireBinaryArg validates that a positional argument is a buffer, in either
// representation, and returns its bytes.
//
// This is the widening helper for consumers. A builtin that only ever cared
// about the bytes it was handed -- a hash, a writer, a compressor -- has no
// reason to refuse a BYTES now that the type exists, and accepting both is
// backward compatible in a way that changing a return type is not.
//
// The returned slice aliases a BYTES argument's payload. Callers that modify it
// must copy first.
func requireBinaryArg(op string, arg object.Object, pos int) ([]byte, *object.Error) {
	switch v := arg.(type) {
	case *object.Bytes:
		return v.Value, nil
	case *object.String:
		return []byte(v.Value), nil
	default:
		return nil, newError("argument %d to `%s` must be BYTES or STRING, got %s", pos, op, arg.Type())
	}
}

// binaryResult renders a payload as a BYTES or as a STRING.
//
// It is the seam every producer with a *_bytes twin runs through, so the two
// share one implementation and cannot drift: the pair differs in the type of
// the value it hands back and in nothing else.
func binaryResult(binary bool, data []byte) object.Object {
	if binary {
		return &object.Bytes{Value: data}
	}
	return &object.String{Value: string(data)}
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
