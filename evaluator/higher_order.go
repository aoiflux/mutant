package evaluator

import (
	"sort"

	"mutant/builtin"
	"mutant/object"
)

// The higher-order collection builtins are handled natively by the evaluator
// (mirroring the VM), because they must call user functions — which the builtin
// placeholder cannot. Errors surface as *object.Error values, per the evaluator's
// convention.

func applyHigherOrder(kind string, args []object.Object) object.Object {
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
	default:
		return newError("unknown higher-order builtin %q", kind)
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
