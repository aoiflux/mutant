package vm

import (
	"fmt"
	"runtime"
	"sync"

	"mutant/global"
	"mutant/object"
)

// pmap/peach apply a callback to array elements concurrently.
//
// The unit of concurrency is a whole VM, not a goroutine sharing one. That is
// forced by the design and is also what makes it safe: CallClosureSync re-enters
// the calling VM's own execution loop, so two goroutines cannot drive one VM.
// Each worker therefore gets its own stack, frames and globals, exactly as
// net_serve gives each connection its own VM.
//
// What the workers share is the compiled program -- the instruction stream and
// the constants pool -- and that sharing is safe for the reason serve.go
// documents: reading the shared bytecode (SecureXOROneAt over instructions,
// DecryptObject over constants) is pure. The one rule is that a worker must
// never run CleanupRuntimeSensitiveData, whose stack sweep would zero constants
// its siblings are still decrypting.
//
// Values crossing between VMs are already copies. Every push encrypts and every
// pop decrypts, deep-copying containers on the way, so a worker cannot hand a
// sibling a reference to mutate. Globals are snapshotted per worker for the same
// reason: a callback sees the values that existed when pmap was called, and its
// writes stay local. Callbacks should be self-contained and report results
// through their return value.

// maxParallelWorkers bounds the worker VMs one pmap call may create, so a large
// array cannot spawn an unbounded number of stacks. It mirrors the bound
// net_serve puts on handler goroutines.
const maxParallelWorkers = 1024

// snapshotGlobals copies the globals a worker will start from, so it reads what
// existed at the call and its own writes stay local. The elements are encrypted
// objects treated as immutable, so copying the slice is enough.
//
// It is separate from newWorkerVMWithGlobals because the two have to happen in
// different places for spawn: the snapshot must be taken before the caller runs
// another instruction, while building the VM is slow enough that it belongs on
// the worker's own goroutine.
func (vm *VM) snapshotGlobals() []object.Object {
	globals := make([]object.Object, len(vm.globals))
	copy(globals, vm.globals)
	return globals
}

// newWorkerVM builds a sibling VM over the same compiled program. It mirrors
// serve.go's per-connection VM: same bytecode, same password, its own globals.
func (vm *VM) newWorkerVM() *VM {
	return vm.newWorkerVMWithGlobals(vm.snapshotGlobals())
}

// newWorkerVMWithGlobals is the expensive half. prepareForExecution walks every
// compiled function in the constants pool to map its instruction boundaries,
// decrypting a byte at a time, so this is far from free on a large program --
// which is why callers that must stay responsive run it on the worker's
// goroutine rather than their own.
func (vm *VM) newWorkerVMWithGlobals(globals []object.Object) *VM {
	worker := NewWithGlobalStoreAndPassword(vm.bytecode, globals, vm.password)
	worker.secureMode = vm.secureMode
	worker.enforceSecurityCheckOpcodes = vm.enforceSecurityCheckOpcodes

	// A worker inherits the serve context, so a net_serve handler that hands
	// work to pmap or spawn does not lose the connection it is running for.
	worker.serveContextSet = vm.serveContextSet
	worker.serveConn = vm.serveConn
	worker.serveArg = vm.serveArg

	// A worker enters through CallClosureSync and never calls Run, so it has to
	// do Run's one-time setup itself. The security-opcode validation Run also
	// performs is deliberately not repeated: the parent already validated this
	// very instruction stream before execution, and re-scanning it once per
	// worker would only repeat that work.
	worker.prepareForExecution()
	return worker
}

// resolveWorkerCount picks how many worker VMs to run: never more than there are
// elements, never more than the cap, and at least one.
func resolveWorkerCount(requested, elements int) int {
	count := requested
	if count <= 0 {
		count = runtime.NumCPU()
	}
	if count > elements {
		count = elements
	}
	if count > maxParallelWorkers {
		count = maxParallelWorkers
	}
	if count < 1 {
		count = 1
	}
	return count
}

// parallelArgs validates the (array, fn[, workers]) shape shared by pmap/peach.
func parallelArgs(op string, args []object.Object) (*object.Array, *object.Closure, int, *object.Error) {
	if len(args) != 2 && len(args) != 3 {
		return nil, nil, 0, vmErrorf("%s: want 2 or 3 arguments (array, function[, workers]), got %d", op, len(args))
	}

	arr, cl, argErr := arrayAndCallback(op, args[:2])
	if argErr != nil {
		return nil, nil, 0, argErr
	}

	requested := 0
	if len(args) == 3 {
		workers, ok := args[2].(*object.Integer)
		if !ok {
			return nil, nil, 0, vmErrorf("%s: third argument (workers) must be INTEGER, got %s", op, args[2].Type())
		}
		if workers.Value < 1 {
			return nil, nil, 0, vmErrorf("%s: workers must be at least 1, got %d", op, workers.Value)
		}
		requested = int(workers.Value)
	}

	return arr, cl, requested, nil
}

// runParallel applies cl to every element across worker VMs and returns the
// results in the input's order. Work is handed out from a shared index so a slow
// element does not stall a worker that could be starting the next one.
func (vm *VM) runParallel(op string, arr *object.Array, cl *object.Closure, requested int) ([]object.Object, error) {
	elements := arr.Elements
	if len(elements) == 0 {
		return nil, nil
	}

	results := make([]object.Object, len(elements))
	workerCount := resolveWorkerCount(requested, len(elements))

	var (
		next     int
		nextMu   sync.Mutex
		firstErr error
		errMu    sync.Mutex
		wg       sync.WaitGroup
	)

	takeNext := func() (int, bool) {
		nextMu.Lock()
		defer nextMu.Unlock()
		if next >= len(elements) {
			return 0, false
		}
		index := next
		next++
		return index, true
	}

	recordErr := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	failed := func() bool {
		errMu.Lock()
		defer errMu.Unlock()
		return firstErr != nil
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// A panic inside one element's callback must not take the process
			// down with it, the way net_serve contains a handler panic.
			defer func() {
				if r := recover(); r != nil {
					recordErr(fmt.Errorf("%s: worker panicked: %v", op, r))
				}
			}()

			worker := vm.newWorkerVM()
			// Deliberately no CleanupRuntimeSensitiveData on the worker: its
			// stack sweep would zero the shared constants siblings are still
			// reading. The worker's own stack and globals are garbage-collected
			// when this goroutine returns.

			for {
				if failed() {
					return
				}
				index, ok := takeNext()
				if !ok {
					return
				}

				result, err := worker.callElement(cl, elements[index], index)
				if err != nil {
					recordErr(err)
					return
				}
				results[index] = result
			}
		}()
	}

	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func (vm *VM) hoPMap(args []object.Object) (object.Object, error) {
	arr, cl, requested, argErr := parallelArgs("pmap", args)
	if argErr != nil {
		return argErr, nil
	}

	results, err := vm.runParallel("pmap", arr, cl, requested)
	if err != nil {
		return nil, err
	}
	if results == nil {
		return &object.Array{Elements: []object.Object{}}, nil
	}
	return &object.Array{Elements: results}, nil
}

func (vm *VM) hoPEach(args []object.Object) (object.Object, error) {
	arr, cl, requested, argErr := parallelArgs("peach", args)
	if argErr != nil {
		return argErr, nil
	}

	if _, err := vm.runParallel("peach", arr, cl, requested); err != nil {
		return nil, err
	}
	return global.Null, nil
}
