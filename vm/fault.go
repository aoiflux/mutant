package vm

// A fault is a malformed-bytecode failure detected in the middle of an
// instruction: an operand indexing past the end of the constants pool, a pop
// with nothing on the stack, a call whose argument count reaches below the stack
// floor. None of them can happen to a program this toolchain compiled and
// signed; all of them can happen to one that was corrupted, truncated, or
// rewritten by hand.
//
// Faults are raised by panicking rather than by returning an error, for one
// practical reason. The accessors that detect them -- pop, currentFrame,
// popFrame -- have no error in their signature and are called from more than
// twenty places inside a single dispatch switch. Threading a second return value
// through all of them would bury the instruction dispatch that is the point of
// that function, to guard a case that is unreachable for a well-formed program.
//
// The panic carries a type so the boundary can tell a fault the VM raised itself
// from a Go runtime panic that came from somewhere else. Both are contained --
// otherwise whether a bad program produces an error or a stack trace depends on
// which execution path it happened to take -- but they are reported, and
// recorded, as the different things they are.

import (
	"fmt"

	"mutant/security"
)

type vmFault struct{ err error }

func (f vmFault) Error() string { return f.err.Error() }

// faultf raises a fault from a site that cannot return one.
func faultf(format string, args ...interface{}) {
	panic(vmFault{err: fmt.Errorf(format, args...)})
}

// containFault converts a panic raised anywhere under the execution loop into
// the error the loop returns. Call it from a defer with a named error return.
//
// It deliberately does not route through security.ApplyTamperResponse. That
// returns nil under the warn and delay policies, which means "carry on", and
// there is no carrying on from here: the loop unwound out of the middle of an
// instruction, so the stack and frame pointers describe a state no instruction
// left behind. The event is still recorded, so warn mode keeps its audit trail;
// what it does not get is permission to continue.
func containFault(r any, err *error) {
	if r == nil {
		return
	}

	if fault, ok := r.(vmFault); ok {
		security.RecordIntegrityFailure("vm-decode")
		*err = fault.err
		return
	}

	security.RecordIntegrityFailure("vm-panic")
	*err = fmt.Errorf("vm_runtime_error: recovered panic: %v", r)
}
