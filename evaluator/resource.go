package evaluator

import (
	"mutant/builtin"
	"mutant/object"
)

// evalWithResource is the tree-walker's half of with_resource, mirroring the
// VM's hoWithResource. Both engines validate through builtin.PrepareResource
// and read results through builtin.SplitResult, so the only thing that differs
// here is how a function gets called and how a failure travels.
//
// The difference that matters: the VM's fatal errors are Go errors, so a body
// that dies reaches hoWithResource as a value it can act on before returning.
// Here a fault is an object flowing back out of eval, and the closer has to run
// before that object is propagated -- which is the same guarantee, made in the
// one place the tree-walker can make it.
func evalWithResource(args []object.Object) object.Object {
	call, opened, bad := builtin.PrepareResource(args)
	if bad != nil {
		// Malformed, but the arguments were already evaluated, so the resource
		// may already be open. Close it before reporting -- a diagnostic is no
		// reason for the one builtin that guarantees a close to skip one.
		if call.Closeable() {
			return evalPair(nil, builtin.WithCloseError(bad, evalCloseResource(call)))
		}
		return evalPair(nil, bad)
	}
	if opened != nil {
		// The open's own error, passed straight back: nothing was opened, so
		// nothing runs and nothing is closed.
		return evalPair(nil, opened)
	}

	result := applyFunction(call.Body, []object.Object{call.Handle})

	// Unconditional, and before any return.
	closeErr := evalCloseResource(call)

	if isError(result) {
		// The body gave up. The fault propagates as it would have without
		// with_resource; the close already happened, which is the point.
		return result
	}

	value, bodyErr := builtin.SplitResult(result)
	if bodyErr != nil {
		return evalPair(nil, builtin.WithCloseError(bodyErr, closeErr))
	}
	return evalPair(value, closeErr)
}

// evalCloseResource runs the closer and reports what it said. A closer that
// itself gives up is reported as a value rather than propagated: the body has
// already finished and its result is what the program asked for.
func evalCloseResource(call builtin.ResourceCall) *object.Error {
	result := applyFunction(call.Closer, []object.Object{call.Handle})
	if isError(result) {
		return errorValue("%s: the closer failed: %s", builtin.BuiltinNameWithResource, result.Inspect())
	}
	return builtin.ErrorIn(result)
}
