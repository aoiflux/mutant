package evaluator

import (
	"errors"
	"sort"

	"mutant/builtin"
	"mutant/global"
	"mutant/object"
)

// The builtins an executor must run itself are handled natively by the evaluator
// (mirroring the VM): the collection operations, because they call user
// functions the builtin placeholder cannot, and the serve-context pair, because
// their answer lives in the running program. Errors surface as *object.Error
// values, per the evaluator's convention.

func applyExecutorNative(kind string, args []object.Object) object.Object {
	switch kind {
	case "map":
		return evalMap(args)
	case "filter":
		return evalFilter(args)
	case "reduce":
		return evalReduce(args)
	case "each":
		return evalEach(args)
	case "sort_by":
		return evalSortBy(args)
	case "pmap":
		return evalParallel("pmap", args)
	case "peach":
		return evalParallel("peach", args)
	case "spawn":
		return evalSpawn(args)
	case "serve_conn", "serve_arg":
		// Macro expansion has no connection and no net_serve arg, which is the
		// same answer a program gets when it runs outside a handler.
		if len(args) != 0 {
			return evalPair(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
		}
		return evalPair(nil, nil)
	default:
		return newError("unknown executor-native builtin %q", kind)
	}
}

func isCallable(obj object.Object) bool {
	switch obj.(type) {
	case *object.Function, *builtin.BuiltIn:
		return true
	}
	return false
}

// arrayAndCallback validates the (array, function) shape shared by
// map/filter/each/sort_by.
func arrayAndCallback(op string, args []object.Object) (*object.Array, object.Object, object.Object) {
	if len(args) != 2 {
		return nil, nil, newError("%s: want 2 arguments (array, function), got %d", op, len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return nil, nil, newError("%s: first argument must be ARRAY, got %s", op, args[0].Type())
	}
	if !isCallable(args[1]) {
		return nil, nil, newError("%s: second argument must be a function, got %s", op, args[1].Type())
	}
	return arr, args[1], nil
}

// callElement invokes the callback with (element) or (element, index) depending
// on how many parameters a user function declares.
func callElement(fn object.Object, el object.Object, index int) object.Object {
	if f, ok := fn.(*object.Function); ok && len(f.Parameters) == 2 {
		return applyFunction(fn, []object.Object{el, &object.Integer{Value: int64(index)}})
	}
	return applyFunction(fn, []object.Object{el})
}

func evalMap(args []object.Object) object.Object {
	arr, fn, errObj := arrayAndCallback("map", args)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, len(arr.Elements))
	for i, el := range arr.Elements {
		r := callElement(fn, el, i)
		if isError(r) {
			return r
		}
		out[i] = r
	}
	return &object.Array{Elements: out}
}

func evalFilter(args []object.Object) object.Object {
	arr, fn, errObj := arrayAndCallback("filter", args)
	if errObj != nil {
		return errObj
	}
	out := make([]object.Object, 0, len(arr.Elements))
	for i, el := range arr.Elements {
		r := callElement(fn, el, i)
		if isError(r) {
			return r
		}
		if isTruthy(r) {
			out = append(out, el)
		}
	}
	return &object.Array{Elements: out}
}

func evalEach(args []object.Object) object.Object {
	arr, fn, errObj := arrayAndCallback("each", args)
	if errObj != nil {
		return errObj
	}
	for i, el := range arr.Elements {
		if r := callElement(fn, el, i); isError(r) {
			return r
		}
	}
	return NULL
}

func evalReduce(args []object.Object) object.Object {
	if len(args) != 3 {
		return newError("reduce: want 3 arguments (array, function, initial), got %d", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("reduce: first argument must be ARRAY, got %s", args[0].Type())
	}
	if !isCallable(args[1]) {
		return newError("reduce: second argument must be a function, got %s", args[1].Type())
	}
	acc := args[2]
	for _, el := range arr.Elements {
		r := applyFunction(args[1], []object.Object{acc, el})
		if isError(r) {
			return r
		}
		acc = r
	}
	return acc
}

func evalSortBy(args []object.Object) object.Object {
	arr, fn, errObj := arrayAndCallback("sort_by", args)
	if errObj != nil {
		return errObj
	}
	type keyed struct {
		el, key object.Object
	}
	items := make([]keyed, len(arr.Elements))
	for i, el := range arr.Elements {
		k := callElement(fn, el, i)
		if isError(k) {
			return k
		}
		items[i] = keyed{el, k}
	}

	var cmpErr object.Object
	sort.SliceStable(items, func(i, j int) bool {
		if cmpErr != nil {
			return false
		}
		less, err := sortKeyLess(items[i].key, items[j].key)
		if err != nil {
			cmpErr = err
			return false
		}
		return less
	})
	if cmpErr != nil {
		return cmpErr
	}

	out := make([]object.Object, len(items))
	for i, it := range items {
		out[i] = it.el
	}
	return &object.Array{Elements: out}
}

func sortKeyLess(a, b object.Object) (bool, object.Object) {
	switch av := a.(type) {
	case *object.Integer:
		switch bv := b.(type) {
		case *object.Integer:
			return av.Value < bv.Value, nil
		case *object.Float:
			return float64(av.Value) < bv.Value, nil
		}
	case *object.Float:
		switch bv := b.(type) {
		case *object.Float:
			return av.Value < bv.Value, nil
		case *object.Integer:
			return av.Value < float64(bv.Value), nil
		}
	case *object.String:
		if bv, ok := b.(*object.String); ok {
			return av.Value < bv.Value, nil
		}
	}
	return false, newError("sort_by: cannot compare keys of type %s and %s", a.Type(), b.Type())
}

// evalParallel runs pmap/peach sequentially.
//
// Parallelism there means one VM per worker (see vm/parallel.go), which the
// evaluator has no way to create -- and it does not need to: the evaluator's
// only remaining job is expanding macros, where a callback runs at compile time
// over a handful of elements. Running in order produces the same results, so a
// macro body that uses pmap still expands correctly; it simply does not run
// concurrently. The optional third argument (worker count) is accepted and
// ignored, because it only ever tunes throughput.
func evalParallel(op string, args []object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return newError("%s: want 2 or 3 arguments (array, function[, workers]), got %d", op, len(args))
	}
	if len(args) == 3 {
		if _, ok := args[2].(*object.Integer); !ok {
			return newError("%s: third argument (workers) must be INTEGER, got %s", op, args[2].Type())
		}
	}

	arr, fn, errObj := arrayAndCallback(op, args[:2])
	if errObj != nil {
		return errObj
	}

	out := make([]object.Object, len(arr.Elements))
	for i, el := range arr.Elements {
		r := callElement(fn, el, i)
		if isError(r) {
			return r
		}
		out[i] = r
	}

	if op == "peach" {
		return NULL
	}
	return &object.Array{Elements: out}
}

// evalSpawn runs the closure immediately, on this goroutine, and hands back a
// handle for an already-finished task.
//
// Concurrency there means one VM per task (see vm/spawn.go), which the evaluator
// has no way to create -- and does not need to. Its only remaining job is
// expanding macros, which happens before bytecode exists; a macro body that
// spawns still produces the same expansion, it simply produces it in order. The
// task registry is the same one task_wait reads, so waiting on the handle works
// and returns at once.
func evalSpawn(args []object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return evalPair(nil, newError("spawn: want 1 or 2 arguments (function[, arg]), got %d", len(args)))
	}
	if !isCallable(args[0]) {
		return evalPair(nil, newError("spawn: first argument must be a function, got %s", args[0].Type()))
	}

	var callArgs []object.Object
	if len(args) == 2 {
		callArgs = []object.Object{args[1]}
	}
	if fn, ok := args[0].(*object.Function); ok && len(fn.Parameters) != len(callArgs) {
		wanted := "spawn: spawn(fn) needs a function that takes no parameters"
		if len(callArgs) == 1 {
			wanted = "spawn: spawn(fn, arg) needs a function that takes one parameter"
		}
		return evalPair(nil, newError("%s, but this one takes %d", wanted, len(fn.Parameters)))
	}

	handle, regErr := builtin.RegisterTask()
	if regErr != nil {
		return evalPair(nil, regErr)
	}

	result := applyFunction(args[0], callArgs)
	if errObj, failed := result.(*object.Error); failed {
		builtin.CompleteTask(handle, nil, errors.New(errObj.Message))
	} else {
		builtin.CompleteTask(handle, result, nil)
	}

	return evalPair(&object.Integer{Value: handle}, nil)
}

// evalPair builds the (value, err) shape for the executor-native builtins that
// follow that convention, matching resultAndError in the builtin package.
func evalPair(result object.Object, errObj *object.Error) object.Object {
	if result == nil {
		result = global.Null
	}
	var errValue object.Object = global.Null
	if errObj != nil {
		errValue = errObj
	}
	return &object.MultiValue{Values: []object.Object{result, errValue}}
}
