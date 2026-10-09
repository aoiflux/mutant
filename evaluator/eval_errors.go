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

// isAbrupt reports whether a block ended rather than produced a value: a
// `return`, a `break` or a `continue` was reached inside it.
//
// The three are one predicate because they are one thing to an expression. A
// block is a value here -- `let v = if (c) { break; } else { 1 };` -- so eval of
// a block hands back whatever its last statement gave, and evalBlockBody
// propagates all three out by the same line. Reaching one means the value the
// enclosing expression was assembling will never be wanted.
//
// None of the three types can be a value a program holds. *object.Break and
// *object.Continue are built in exactly one place each, the two statement arms
// of eval, and *object.ReturnValue only in the return arm; nothing stores one in
// a variable, a list or a hash, and no builtin returns one. So this predicate
// cannot report a true value as a signal, which is what lets it be asked
// unconditionally at an operand position.
func isAbrupt(obj object.Object) bool {
	if obj == nil {
		return false
	}
	switch obj.Type() {
	case object.RETURN_VALUE_OBJ, object.BREAK_OBJ, object.CONTINUE_OBJ:
		return true
	}
	return false
}

// isSignal is what an operand position asks: is this a value I can use, or a
// signal I have to hand upward untouched?
//
// Every site that evaluates a sub-expression and then USES the result asks this
// rather than isError. Asking only isError is M26-EVL-025: the signal was not an
// error, so it was appended to an argument list, stored as a hash value or added
// to an integer, and the loop or function it was meant for never saw it. Three
// shapes answered a wrong number with no diagnostic at all, and `while (if (i ==
// 2) { break; } else { true })` did not terminate, because a Break object is
// truthy.
//
// isError survives everywhere the question really is "did this fail": after a
// call, where applyFunction has already refused an escaping break and unwrapped
// a return, and in evalBlockBody, which tests the three types itself because it
// propagates them deliberately.
func isSignal(obj object.Object) bool {
	return isError(obj) || isAbrupt(obj)
}
