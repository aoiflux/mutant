package builtin

import (
	"testing"

	"mutant/ast"
	"mutant/object"
)

// makeParams builds a parameter list of the given length. Only the count is
// read here -- PrepareResource asks how many parameters a function declares,
// never what they are called.
func makeParams(n int) []*ast.Identifier {
	params := make([]*ast.Identifier, n)
	for i := range params {
		params[i] = &ast.Identifier{}
	}
	return params
}

// SplitResult is the seam both engines read results through, so what it counts
// as a (value, err) pair decides what with_resource hands back. The cases that
// matter are the ones where a MULTI_VALUE is not a pair: guessing there would
// silently drop parts of a value.
func TestSplitResultReadsOnlyTheConventionAsAPair(t *testing.T) {
	failure := &object.Error{Message: "boom"}
	handle := &object.Integer{Value: 7}
	null := &object.Null{}

	cases := []struct {
		name      string
		result    object.Object
		wantValue object.Object
		wantErr   *object.Error
	}{
		{"a bare error is a failure", failure, nil, failure},
		{"a plain value is a value", handle, handle, nil},
		{"a pair with an error", &object.MultiValue{Values: []object.Object{handle, failure}}, handle, failure},
		{"a pair with null", &object.MultiValue{Values: []object.Object{handle, null}}, handle, nil},
		{
			// Three values is not the convention. Handing back the first would
			// throw the other two away without saying so.
			"three values pass through whole",
			&object.MultiValue{Values: []object.Object{handle, null, handle}},
			&object.MultiValue{Values: []object.Object{handle, null, handle}},
			nil,
		},
		{
			// A second value that is neither an error nor null is data, not an
			// error slot.
			"a two-value tuple passes through whole",
			&object.MultiValue{Values: []object.Object{handle, handle}},
			&object.MultiValue{Values: []object.Object{handle, handle}},
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := SplitResult(tc.result)
			if err != tc.wantErr {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
			switch {
			case tc.wantValue == nil && value != nil:
				t.Errorf("value = %v, want none", value)
			case tc.wantValue != nil && value == nil:
				t.Errorf("value = none, want %v", tc.wantValue)
			case tc.wantValue != nil && value.Inspect() != tc.wantValue.Inspect():
				t.Errorf("value = %s, want %s", value.Inspect(), tc.wantValue.Inspect())
			}
		})
	}
}

// A close that fails while the body has already failed must lose neither. The
// body's error is the one the program asked about, so it stays the error; the
// close failure is a fact about it.
func TestWithCloseErrorKeepsBothWithoutMutating(t *testing.T) {
	bodyErr := &object.Error{
		Message: "listing failed",
		Context: "test",
		Related: map[string]object.Object{"path": &object.String{Value: "/d.img"}},
	}
	closeErr := &object.Error{Message: "unknown handle", Context: "builtin.ntfs_close"}

	merged := WithCloseError(bodyErr, closeErr)

	if merged.Message != bodyErr.Message {
		t.Errorf("message = %q, want the body's", merged.Message)
	}
	if merged.Related["close_error"] != object.Object(closeErr) {
		t.Errorf("related[close_error] = %v, want the close's error", merged.Related["close_error"])
	}
	if merged.Related["path"] == nil {
		t.Error("the body's own related facts were dropped")
	}
	// The original may already be held elsewhere; an error that changed shape
	// after being returned would break the equality the two engines agreed on.
	if _, mutated := bodyErr.Related["close_error"]; mutated {
		t.Error("the body's error was mutated in place")
	}
}

func TestWithCloseErrorPassesThroughWhenOnlyOneFailed(t *testing.T) {
	bodyErr := &object.Error{Message: "body"}
	closeErr := &object.Error{Message: "close"}

	if got := WithCloseError(bodyErr, nil); got != bodyErr {
		t.Errorf("with no close failure got %v, want the body's error unchanged", got)
	}
	if got := WithCloseError(nil, closeErr); got != closeErr {
		t.Errorf("with no body failure got %v, want the close's error", got)
	}
	if got := WithCloseError(nil, nil); got != nil {
		t.Errorf("with neither got %v, want none", got)
	}
}

// PrepareResource is checked in the order it is because the arguments were
// evaluated before it ran: a call diagnosed as malformed may already hold an
// open resource, and the caller has to be able to close it.
func TestPrepareResourceLeavesAMalformedCallCloseable(t *testing.T) {
	handle := &object.MultiValue{Values: []object.Object{&object.Integer{Value: 3}, &object.Null{}}}
	closer := &object.String{Value: BuiltinNameChanClose}
	twoParams := &object.Function{Parameters: makeParams(2)}

	call, opened, bad := PrepareResource([]object.Object{handle, closer, twoParams})
	if opened != nil {
		t.Fatalf("the open reported %v", opened)
	}
	if bad == nil {
		t.Fatal("a two-parameter body was accepted")
	}
	if !call.Closeable() {
		t.Error("the malformed call left nothing to close; the handle leaks")
	}
	if call.Body != nil {
		t.Error("the body was accepted despite the complaint")
	}
}

// When the closer itself is what could not be resolved there is nothing to be
// done, and Closeable has to say so rather than inviting a call on a nil.
func TestPrepareResourceIsNotCloseableWithoutACloser(t *testing.T) {
	handle := &object.MultiValue{Values: []object.Object{&object.Integer{Value: 3}, &object.Null{}}}
	call, _, bad := PrepareResource([]object.Object{
		handle,
		&object.String{Value: "chan_clos"},
		&object.Function{Parameters: makeParams(1)},
	})

	if bad == nil {
		t.Fatal("a closer naming no builtin was accepted")
	}
	if call.Closeable() {
		t.Error("a call with no resolved closer reported itself closeable")
	}
}

func TestPrepareResourceRefusesAnExecutorNativeCloser(t *testing.T) {
	_, _, bad := PrepareResource([]object.Object{
		&object.Integer{Value: 1},
		&object.String{Value: BuiltinNameEach},
		&object.Function{Parameters: makeParams(1)},
	})

	if bad == nil {
		t.Fatal("each was accepted as a closer")
	}
	if bad.Context != "builtin."+BuiltinNameWithResource {
		t.Errorf("context = %q, want the builtin's own name", bad.Context)
	}
}
