package builtin

import "mutant/object"

// The higher-order collection builtins (map/filter/reduce/each/sort_by) call user
// functions, which only the executor (VM or evaluator) can do. They are
// registered so they resolve and compile like any builtin, but each executor
// intercepts them via HigherOrderKind and runs them natively. The placeholder Fn
// only fires if one is somehow invoked outside an executor, and errors honestly.

var (
	mapBuiltin    = &BuiltIn{Fn: higherOrderStub("map")}
	filterBuiltin = &BuiltIn{Fn: higherOrderStub("filter")}
	reduceBuiltin = &BuiltIn{Fn: higherOrderStub("reduce")}
	eachBuiltin   = &BuiltIn{Fn: higherOrderStub("each")}
	sortByBuiltin = &BuiltIn{Fn: higherOrderStub("sort_by")}
)

var higherOrderKinds = map[*BuiltIn]string{
	mapBuiltin:    "map",
	filterBuiltin: "filter",
	reduceBuiltin: "reduce",
	eachBuiltin:   "each",
	sortByBuiltin: "sort_by",
}

// HigherOrderKind returns the higher-order operation name for a builtin, or "" if
// it is an ordinary builtin. Executors call this to intercept these builtins and
// run them natively (they must invoke user closures).
func HigherOrderKind(b *BuiltIn) string { return higherOrderKinds[b] }

func higherOrderStub(name string) BuiltinFunction {
	return func(args ...object.Object) object.Object {
		return resultAndError(nil, newError("%s must be applied to a function inside a running program", name))
	}
}
