package vm

import (
	"fmt"

	"mutant/builtin"
	"mutant/object"
)

// hoWithResource is the VM half of with_resource: it runs the body and then
// runs the closer, on every path out.
//
// It is VM-native for the same reason map and each are -- it has to call a user
// function -- but the machinery it leans on is more specific than that.
// CallClosureSync already restores the frame index and the stack pointer when
// the closure it ran died, and hands the Go error back to its caller rather
// than unwinding past it. That is precisely what makes the guarantee possible:
// the VM is in a consistent state when control returns here, so there is still
// a VM to run the closer on.
func (vm *VM) hoWithResource(args []object.Object) (object.Object, error) {
	call, opened, bad := builtin.PrepareResource(args)
	if bad != nil {
		// The call is malformed, but its arguments were evaluated before the
		// VM got here, so the resource may already be open. Closing it is the
		// whole point of the builtin, and a diagnostic is no reason to skip it.
		if call.Closeable() {
			return vmPair(nil, builtin.WithCloseError(bad, vm.closeResource(call))), nil
		}
		return vmPair(nil, bad), nil
	}
	if opened != nil {
		// The open failed, so there is nothing to close and nothing to run.
		// The error is returned exactly as the open produced it, which is what
		// makes wrapping an existing call in with_resource invisible.
		return vmPair(nil, opened), nil
	}

	body, ok := call.Body.(*object.Closure)
	if !ok {
		return vmPair(nil, vmErrorf("%s: third argument must be a function, got %s",
			builtin.BuiltinNameWithResource, call.Body.Type())), nil
	}

	result, runErr := vm.CallClosureSync(body, []object.Object{call.Handle})

	// Unconditional, and before any return: this line is the whole builtin.
	closeErr := vm.closeResource(call)

	if runErr != nil {
		// The body did not merely fail, it died -- a frame-integrity
		// violation, a tamper response, a stack overflow. The run is over, so
		// the error propagates rather than becoming a value. The close still
		// happened; a close that also failed is folded into the message
		// because a Go error has no Related to hang it on, and %w keeps
		// errors.Is answering about the original.
		if closeErr != nil {
			return nil, fmt.Errorf("%w (the close also failed: %s)", runErr, closeErr.Message)
		}
		return nil, runErr
	}

	value, bodyErr := builtin.SplitResult(result)
	if bodyErr != nil {
		return vmPair(nil, builtin.WithCloseError(bodyErr, closeErr)), nil
	}
	return vmPair(value, closeErr), nil
}

// closeResource runs the closer against the handle and reports what it said.
//
// A closer named as a string is a plain builtin -- resolveCloser refuses the
// executor-native ones -- so it can be invoked directly. decorateError runs on
// its result so a close failure carries the position of the with_resource call,
// the same position every other builtin error gets.
func (vm *VM) closeResource(call builtin.ResourceCall) *object.Error {
	switch closer := call.Closer.(type) {
	case *builtin.BuiltIn:
		return builtin.ErrorIn(vm.decorateError(closer.Fn(call.Handle)))
	case *object.Closure:
		result, err := vm.CallClosureSync(closer, []object.Object{call.Handle})
		if err != nil {
			// A closer that dies cannot be allowed to end the run: the body
			// already finished, and its result is what the program asked for.
			// The failure becomes a value so it can be reported alongside.
			return vmErrorf("%s: the closer failed: %s", builtin.BuiltinNameWithResource, err)
		}
		return builtin.ErrorIn(vm.decorateError(result))
	}
	return nil
}
