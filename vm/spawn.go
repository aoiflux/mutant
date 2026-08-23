package vm

// spawn runs one closure alongside the rest of the program.
//
// It is the general form of what pmap does for an array: the same worker VM, the
// same globals snapshot, the same share-nothing guarantee. The difference is
// lifetime. pmap waits for its workers before it returns, so the shared program
// is guaranteed to outlive them; a spawned task keeps running after spawn
// returns, and may outlive the program that started it.
//
// That is why the task registry lives in the builtin package and the runtime
// waits on it (builtin.WaitForTasks) before tearing the program down. A task
// still running is still decrypting the constants pool that teardown zeroes --
// the trap serve.go documents -- so exiting without waiting would corrupt work
// that was about to succeed. task_wait and task_done need nothing from the VM
// and stay ordinary builtins; only spawn is executor-native, because only the VM
// can run a closure.

import (
	"fmt"

	"mutant/builtin"
	"mutant/global"
	"mutant/object"
)

// vmPair builds the (value, err) result shape the builtin package's
// resultAndError produces, for the executor-native builtins that follow the same
// convention. spawn does: it can fail for a reason the caller can act on (the
// task ceiling), so its error belongs in the second binding rather than as a
// bare error value.
func vmPair(result object.Object, errObj *object.Error) object.Object {
	if result == nil {
		result = global.Null
	}
	var errValue object.Object = global.Null
	if errObj != nil {
		errValue = errObj
	}
	return &object.MultiValue{Values: []object.Object{result, errValue}}
}

// hoSpawn starts cl on its own VM and returns a handle to collect it with.
//
// spawn(fn) calls a zero-parameter function; spawn(fn, arg) calls a
// one-parameter function with arg. Requiring the two to agree turns what would
// be a silent "argument ignored" into an error at the call.
func (vm *VM) hoSpawn(args []object.Object) (object.Object, error) {
	if len(args) != 1 && len(args) != 2 {
		return vmPair(nil, vmErrorf("spawn: want 1 or 2 arguments (function[, arg]), got %d", len(args))), nil
	}

	cl, ok := args[0].(*object.Closure)
	if !ok {
		return vmPair(nil, vmErrorf("spawn: first argument must be a function, got %s", args[0].Type())), nil
	}

	var callArgs []object.Object
	if len(args) == 2 {
		callArgs = []object.Object{args[1]}
	}
	if cl.Fn.NumParams != len(callArgs) {
		return vmPair(nil, vmErrorf("%s, but this one takes %d", spawnShapeWanted(len(callArgs)), cl.Fn.NumParams)), nil
	}

	handle, regErr := builtin.RegisterTask()
	if regErr != nil {
		return vmPair(nil, regErr), nil
	}

	// Snapshot the globals here, on the caller's goroutine. The caller carries
	// straight on to its next instruction once spawn returns, so taking the
	// snapshot on the new goroutine would race that write and hand the task a
	// globals slice from an unpredictable point in the caller's execution.
	//
	// Building the VM from that snapshot is deliberately NOT done here. It walks
	// every compiled function to map instruction boundaries, which on a real
	// program costs enough to be visible -- and paying it here would make spawn
	// block its caller for as long as the setup takes, which is exactly what an
	// accept loop cannot afford.
	globals := vm.snapshotGlobals()

	go func() {
		var (
			result  object.Object
			failure error
		)

		// Register the outcome from a defer so a panic inside the task is
		// reported through task_wait instead of taking the process down, and so
		// the task is never left counted as live -- which would hang the
		// runtime's wait at exit.
		defer func() {
			if r := recover(); r != nil {
				result = nil
				failure = fmt.Errorf("task panicked: %v", r)
			}
			builtin.CompleteTask(handle, result, failure)
		}()

		// Deliberately no CleanupRuntimeSensitiveData on the worker, for the
		// same reason pmap's workers skip it: its stack sweep would zero the
		// constants the parent and any sibling task are still reading.
		worker := vm.newWorkerVMWithGlobals(globals)
		result, failure = worker.CallClosureSync(cl, callArgs)
	}()

	return vmPair(&object.Integer{Value: handle}, nil), nil
}

// spawnShapeWanted phrases the parameter requirement in terms of the call the
// program actually wrote, which is the thing the author can see.
func spawnShapeWanted(passed int) string {
	if passed == 0 {
		return "spawn: spawn(fn) needs a function that takes no parameters"
	}
	return "spawn: spawn(fn, arg) needs a function that takes one parameter"
}
