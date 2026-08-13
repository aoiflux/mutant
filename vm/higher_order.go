package vm

import (
	"fmt"
	"sort"

	"mutant/global"
	"mutant/object"
)

// This file implements the higher-order collection builtins natively in the VM.
// They are registered as builtins (so they compile as ordinary calls) but the VM
// intercepts them in callBuiltin because they must call user closures, which only
// the VM can do — via CallClosureSync. Handling them per-VM (rather than through
// a shared package hook) keeps them safe under concurrent VMs.

func (vm *VM) applyHigherOrder(kind string, args []object.Object) (object.Object, error) {
	switch kind {
	case "map":
		return vm.hoMap(args)
	case "filter":
		return vm.hoFilter(args)
	case "reduce":
		return vm.hoReduce(args)
	case "each":
		return vm.hoEach(args)
	case "sort_by":
		return vm.hoSortBy(args)
	default:
		return vmErrorf("unknown higher-order builtin %q", kind), nil
	}
}

func vmErrorf(format string, a ...any) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, a...)}
}

// arrayAndCallback validates the shared (array, function) argument shape for
// map/filter/each/sort_by, where the callback takes the element and optionally
// its index. It returns an *object.Error (not a Go error) for argument problems
// so they surface as catchable values rather than aborting the run.
func arrayAndCallback(op string, args []object.Object) (*object.Array, *object.Closure, *object.Error) {
	if len(args) != 2 {
		return nil, nil, vmErrorf("%s: want 2 arguments (array, function), got %d", op, len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return nil, nil, vmErrorf("%s: first argument must be ARRAY, got %s", op, args[0].Type())
	}
	cl, ok := args[1].(*object.Closure)
	if !ok {
		return nil, nil, vmErrorf("%s: second argument must be a function, got %s", op, args[1].Type())
	}
	if cl.Fn.NumParams < 1 || cl.Fn.NumParams > 2 {
		return nil, nil, vmErrorf("%s: function must take 1 or 2 parameters (element[, index]), got %d", op, cl.Fn.NumParams)
	}
	return arr, cl, nil
}

// callElement invokes a 1- or 2-parameter callback with (element[, index]).
func (vm *VM) callElement(cl *object.Closure, el object.Object, index int) (object.Object, error) {
	if cl.Fn.NumParams == 2 {
		return vm.CallClosureSync(cl, []object.Object{el, &object.Integer{Value: int64(index)}})
	}
	return vm.CallClosureSync(cl, []object.Object{el})
}

func (vm *VM) hoMap(args []object.Object) (object.Object, error) {
	arr, cl, argErr := arrayAndCallback("map", args)
	if argErr != nil {
		return argErr, nil
	}
	out := make([]object.Object, len(arr.Elements))
	for i, el := range arr.Elements {
		r, err := vm.callElement(cl, el, i)
		if err != nil {
			return nil, err
		}
		out[i] = r
	}
	return &object.Array{Elements: out}, nil
}

func (vm *VM) hoFilter(args []object.Object) (object.Object, error) {
	arr, cl, argErr := arrayAndCallback("filter", args)
	if argErr != nil {
		return argErr, nil
	}
	out := make([]object.Object, 0, len(arr.Elements))
	for i, el := range arr.Elements {
		r, err := vm.callElement(cl, el, i)
		if err != nil {
			return nil, err
		}
		if isTruthy(r) {
			out = append(out, el)
		}
	}
	return &object.Array{Elements: out}, nil
}

func (vm *VM) hoEach(args []object.Object) (object.Object, error) {
	arr, cl, argErr := arrayAndCallback("each", args)
	if argErr != nil {
		return argErr, nil
	}
	for i, el := range arr.Elements {
		if _, err := vm.callElement(cl, el, i); err != nil {
			return nil, err
		}
	}
	return global.Null, nil
}

func (vm *VM) hoReduce(args []object.Object) (object.Object, error) {
	if len(args) != 3 {
		return vmErrorf("reduce: want 3 arguments (array, function, initial), got %d", len(args)), nil
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return vmErrorf("reduce: first argument must be ARRAY, got %s", args[0].Type()), nil
	}
	cl, ok := args[1].(*object.Closure)
	if !ok {
		return vmErrorf("reduce: second argument must be a function, got %s", args[1].Type()), nil
	}
	if cl.Fn.NumParams != 2 {
		return vmErrorf("reduce: function must take 2 parameters (accumulator, element), got %d", cl.Fn.NumParams), nil
	}
	acc := args[2]
	for _, el := range arr.Elements {
		r, err := vm.CallClosureSync(cl, []object.Object{acc, el})
		if err != nil {
			return nil, err
		}
		acc = r
	}
	return acc, nil
}

func (vm *VM) hoSortBy(args []object.Object) (object.Object, error) {
	arr, cl, argErr := arrayAndCallback("sort_by", args)
	if argErr != nil {
		return argErr, nil
	}
	type keyed struct {
		el, key object.Object
	}
	items := make([]keyed, len(arr.Elements))
	for i, el := range arr.Elements {
		k, err := vm.callElement(cl, el, i)
		if err != nil {
			return nil, err
		}
		items[i] = keyed{el, k}
	}

	var cmpErr *object.Error
	sort.SliceStable(items, func(i, j int) bool {
		if cmpErr != nil {
			return false
		}
		less, err := objectKeyLess(items[i].key, items[j].key)
		if err != nil {
			cmpErr = err
			return false
		}
		return less
	})
	if cmpErr != nil {
		return cmpErr, nil
	}

	out := make([]object.Object, len(items))
	for i, it := range items {
		out[i] = it.el
	}
	return &object.Array{Elements: out}, nil
}

// objectKeyLess orders sort_by keys of comparable scalar types.
func objectKeyLess(a, b object.Object) (bool, *object.Error) {
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
	return false, vmErrorf("sort_by: cannot compare keys of type %s and %s", a.Type(), b.Type())
}
