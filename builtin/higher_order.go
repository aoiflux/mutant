package builtin

import "mutant/object"

// Some builtins need something only the executor has, so the executor runs them
// itself rather than calling the registered Fn.
//
// Most of them need the ability to CALL a closure: the collection operations
// map/filter/reduce/each/sort_by, their parallel forms pmap/peach, and spawn,
// which runs one on its own VM. serve_conn and serve_arg need the other thing an
// executor has -- the running program's own context, which for a net_serve
// handler is the connection it was dispatched for.
//
// All of them are registered so they resolve and compile like any builtin, and
// each executor intercepts them via ExecutorNativeKind. What the registered Fn
// does when it is somehow reached outside an executor differs by builtin: the
// closure-calling ones cannot do their job at all and say so, while serve_conn
// and serve_arg have an honest answer, which is that there is no context.

var (
	mapBuiltin    = &BuiltIn{Fn: higherOrderStub("map")}
	filterBuiltin = &BuiltIn{Fn: higherOrderStub("filter")}
	reduceBuiltin = &BuiltIn{Fn: higherOrderStub("reduce")}
	eachBuiltin   = &BuiltIn{Fn: higherOrderStub("each")}
	sortByBuiltin = &BuiltIn{Fn: higherOrderStub("sort_by")}
	pmapBuiltin   = &BuiltIn{Fn: higherOrderStub("pmap")}
	peachBuiltin  = &BuiltIn{Fn: higherOrderStub("peach")}
	spawnBuiltin  = &BuiltIn{Fn: higherOrderStub("spawn")}

	// These two answer for themselves outside an executor -- "no serve context"
	// is a real answer, not a failure -- so they are registered with their real
	// implementations rather than a stub.
	serveConnBuiltin = &BuiltIn{Fn: ServeConn}
	serveArgBuiltin  = &BuiltIn{Fn: ServeArg}
)

var executorNativeKinds = map[*BuiltIn]string{
	mapBuiltin:    "map",
	filterBuiltin: "filter",
	reduceBuiltin: "reduce",
	eachBuiltin:   "each",
	sortByBuiltin: "sort_by",
	pmapBuiltin:   "pmap",
	peachBuiltin:  "peach",
	spawnBuiltin:  "spawn",

	serveConnBuiltin: "serve_conn",
	serveArgBuiltin:  "serve_arg",
}

// ExecutorNativeKind returns the operation name an executor must run natively
// for a builtin, or "" for an ordinary builtin the executor can simply call.
func ExecutorNativeKind(b *BuiltIn) string { return executorNativeKinds[b] }

func higherOrderStub(name string) BuiltinFunction {
	return func(args ...object.Object) object.Object {
		return resultAndError(nil, newError("%s must be applied to a function inside a running program", name))
	}
}
