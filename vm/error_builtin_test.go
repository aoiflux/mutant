package vm

import (
	"testing"

	"mutant/object"
)

// A constructed error is a value on the stack, not a failure. The VM needs no
// special rule for this -- its fatal errors are Go errors, so an *object.Error
// reaching the stack is a value by construction -- and that is exactly what
// makes it worth pinning: the property holds by accident of the design, and a
// future change that routed builtin errors through the Go channel would break
// error() without touching it.
func TestConstructedErrorIsAValueOnTheStack(t *testing.T) {
	result := evalTail(t, `let e = error("boom", "parser"); e.message`)

	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("e.message gave %T (%+v), want a string", result, result)
	}
	if str.Value != "boom" {
		t.Errorf("message = %q, want %q", str.Value, "boom")
	}
}

// Position comes free from decorateError, which runs on every builtin result
// and stamps any error it finds. An error a program constructs therefore points
// at the error() call that made it, exactly as a builtin's error points at the
// builtin call -- with no code in the builtin itself.
func TestConstructedErrorIsStampedWithItsCallSite(t *testing.T) {
	line := evalTail(t, `let e = error("boom"); e.line`)
	integer, ok := line.(*object.Integer)
	if !ok {
		t.Fatalf("e.line gave %T, want an integer", line)
	}
	if integer.Value != 1 {
		t.Errorf("line = %d, want 1 -- the constructor was not stamped", integer.Value)
	}

	file := evalTail(t, `let e = error("boom"); e.file`)
	name, ok := file.(*object.String)
	if !ok {
		t.Fatalf("e.file gave %T, want a string", file)
	}
	if name.Value == "" {
		t.Error("file is empty; the constructed error carries no origin")
	}
}

func TestRelatedRoundTripsThroughTheConstructor(t *testing.T) {
	src := `let e = error("bad record", "parser", {"offset": 4096, "path": "/d.img"}); type_of(e.related["offset"])`

	result := evalTail(t, src)
	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("gave %T, want a string", result)
	}
	if str.Value != "INTEGER" {
		t.Errorf("offset came back as %s; related flattened a value to text", str.Value)
	}
}

// Equality compares what went wrong, not where. Two errors built at different
// call sites carry different positions, so an Inspect-based comparison -- which
// is what errors used to fall through to -- would call them unequal.
func TestErrorEqualityIgnoresPosition(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{`error("a") == error("a")`, true},
		{`error("a") == error("b")`, false},
		{`error("a") != error("b")`, true},
		{`error("a") == "ERROR:a"`, false},
		{`let e = error("a"); e == e`, true},
	}
	for _, tt := range tests {
		result := evalTail(t, tt.src)
		boolean, ok := result.(*object.Boolean)
		if !ok {
			t.Fatalf("%s gave %T, want a boolean", tt.src, result)
		}
		if boolean.Value != tt.want {
			t.Errorf("%s = %t, want %t", tt.src, boolean.Value, tt.want)
		}
	}
}

// A constructed error stays read-only, like every other error: OpSetField
// accepts only a struct, so a program cannot rewrite where a failure happened.
func TestConstructedErrorsAreReadOnly(t *testing.T) {
	bytecode := compilePositioned(t, `let e = error("boom"); e.message = "quiet";`)
	if _, err := runSealed(t, bytecode); err == nil {
		t.Fatal("assigning to an error field was accepted; errors must stay read-only")
	}
}
