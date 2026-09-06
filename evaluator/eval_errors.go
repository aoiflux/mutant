package evaluator

import (
	"fmt"
	"mutant/object"
)

// fault is the tree-walker's fatal signal: "this expression cannot produce a
// value, stop and propagate".
//
// The evaluator used one *object.Error for two jobs -- the language's error
// value and this signal -- and isError, which tested only the object type,
// could not tell them apart. Nothing forced the two apart while every error a
// program could hold arrived inside a MULTI_VALUE, because isError never saw
// one. The error() builtin ends that: it returns a bare error as its result, so
// a bare error is no longer unambiguously a fault.
//
// The signal is the thing that gets a type, not the value, because the value is
// what the rest of the language already knows how to handle. A fault never
// leaves the package -- Eval unwraps it -- so outside here an error is a value
// and nothing has to know this type exists.
type fault struct{ err *object.Error }

func (f *fault) Type() object.ObjectType { return object.ERROR_OBJ }
func (f *fault) Inspect() string         { return f.err.Inspect() }

// newError raises. It is spelled as it always was because every one of its
// callers means "give up here", and the type change is what makes that meaning
// explicit rather than inferred from where the result happens to be returned.
func newError(format string, a ...interface{}) *fault {
	return &fault{err: &object.Error{Message: fmt.Sprintf(format, a...), Context: "evaluator"}}
}

// errorValue builds an error the program is meant to hold rather than one that
// stops it: the error half of a (value, err) pair. The two spellings exist so
// the difference is made at the point the error is built, by the code that
// knows which one it means, instead of being guessed at later.
func errorValue(format string, a ...interface{}) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, a...), Context: "evaluator"}
}

// isError reports whether evaluation gave up. It tests for the signal, not for
// the error type: an *object.Error that is not a fault is a value a program is
// holding -- destructured out of a pair, or built by error() -- and reading a
// field off it or storing it in a list is ordinary work, not a failure.
func isError(obj object.Object) bool {
	_, raised := obj.(*fault)
	return raised
}
