package object

import "testing"

// The rule itself, value by value, including the two arms a caller cannot reach
// through a type assertion: nil, and a type the switch does not name.
func TestIsTruthyAnswersEveryKind(t *testing.T) {
	for _, tt := range []struct {
		what string
		obj  Object
		want bool
	}{
		// The falsy set, in full.
		{"false", &Boolean{Value: false}, false},
		{"null", &Null{}, false},
		{"the empty string", &String{Value: ""}, false},
		{"an empty buffer", &Bytes{Value: []byte{}}, false},
		{"a nil-slice buffer", &Bytes{}, false},
		{"integer zero", &Integer{Value: 0}, false},
		{"float zero", &Float{Value: 0}, false},
		{"negative float zero", &Float{Value: negativeZero()}, false},
		{"nil", nil, false},

		// Truthy, including the values a reader is most likely to guess wrong.
		{"true", &Boolean{Value: true}, true},
		{"a one-space string", &String{Value: " "}, true},
		{"a tab", &String{Value: "\t"}, true},
		{"the string zero", &String{Value: "0"}, true},
		{"the string false", &String{Value: "false"}, true},
		{"the string null", &String{Value: "null"}, true},
		{"integer one", &Integer{Value: 1}, true},
		{"integer minus one", &Integer{Value: -1}, true},
		{"a small float", &Float{Value: 0.0000001}, true},
		{"a one-byte buffer", &Bytes{Value: []byte{0}}, true},
		{"an empty array", &Array{}, true},
		{"an empty hash", &Hash{}, true},
		{"an error value", &Error{Message: "boom"}, true},
	} {
		if got := IsTruthy(tt.obj); got != tt.want {
			t.Errorf("IsTruthy(%s) = %v, want %v", tt.what, got, tt.want)
		}
	}
}

// negativeZero produces -0.0 without writing a literal the compiler folds to +0.
func negativeZero() float64 {
	zero := 0.0
	return -zero
}

// A buffer holding one zero byte is truthy and the empty buffer is falsy, because
// the rule is the length and not the contents. This is easy to get backwards when
// reading `len(o.Value) != 0` quickly, and bytes_* callers depend on it.
func TestABufferIsJudgedByLengthNotContents(t *testing.T) {
	if IsTruthy(&Bytes{Value: []byte{}}) {
		t.Error("an empty buffer must be falsy")
	}
	for _, b := range [][]byte{{0}, {0, 0}, {0xff}} {
		if !IsTruthy(&Bytes{Value: b}) {
			t.Errorf("a buffer of %d byte(s) must be truthy whatever they are", len(b))
		}
	}
}

// IsTruthy is total: it answers for a type it has never seen rather than panicking.
// A new object type must not silently become falsy, since falsy is the answer that
// skips a branch.
func TestAnUnknownTypeIsTruthy(t *testing.T) {
	if !IsTruthy(&Macro{}) {
		t.Error("a type the switch does not name must be truthy, not falsy")
	}
}
