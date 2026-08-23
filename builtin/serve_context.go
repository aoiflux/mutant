package builtin

// Per-connection serve context.
//
// net_serve dispatches each connection to a fresh VM running a handler. The
// handler needs its connection handle and the shared arg. Rather than inject
// them as predefined globals (which would force handler files to be
// net_serve-only and uncompilable standalone), they are exposed as the builtins
// serve_conn()/serve_arg(). A handler file therefore compiles and runs both
// standalone (serve_conn() -> null) and under net_serve, so a program can serve
// *itself* per connection with no separate worker file.
//
// The context itself is carried by the running VM (vm.SetServeContext), which
// intercepts these two through ExecutorNativeKind and answers from its own
// field. It used to live in a goroutine-keyed map, with the goroutine id read by
// parsing runtime.Stack() output on every call. That worked only because a
// handler VM ran synchronously on the goroutine that set the context -- so work
// the handler spawned onto another goroutine silently lost its connection, which
// is precisely what spawn does. A field on the VM has no such condition, and
// costs nothing to read.
//
// The implementations below are what answers when there is no executor at all.

import "mutant/object"

// ServeConn reports no connection. Inside a running program the executor
// intercepts this and answers from the VM's serve context.
// serve_conn() -> (INTEGER | NULL, err)
func ServeConn(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	return resultAndError(&object.Null{}, nil)
}

// ServeArg reports no shared arg. Inside a running program the executor
// intercepts this and answers from the VM's serve context.
// serve_arg() -> (any | NULL, err)
func ServeArg(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	return resultAndError(&object.Null{}, nil)
}
