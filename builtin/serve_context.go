package builtin

// Per-connection serve context (dev-sec-platform-upgrades).
//
// net_serve dispatches each connection to a fresh VM running a handler. The
// handler needs its connection handle and the shared arg. Rather than inject them
// as predefined globals (which would force handler files to be net_serve-only and
// uncompilable standalone), we expose them as builtins serve_conn()/serve_arg()
// backed by a goroutine-keyed registry. A handler file therefore compiles and
// runs both standalone (serve_conn() -> null) and under net_serve, so a program
// can serve *itself* per connection with no separate worker file.
//
// The serve package (which owns net_serve) sets/clears the context around each
// handler's machine.Run() via SetServeContext/ClearServeContext. The handler VM
// runs synchronously on the same goroutine, so goID() matches.

import (
	"runtime"
	"strconv"
	"sync"

	"mutant/object"
)

type serveCtx struct {
	conn int64
	arg  object.Object
}

var serveContexts sync.Map // goID -> serveCtx

// goID returns the current goroutine's id by parsing the runtime stack header
// ("goroutine <id> [status]:"). Cheap and dependency-free.
func goID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	s := buf[:n]
	// s starts with "goroutine "
	const prefix = "goroutine "
	s = s[len(prefix):]
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	id, _ := strconv.ParseUint(string(s[:i]), 10, 64)
	return id
}

// SetServeContext records the connection handle and arg for the current goroutine
// (called by the serve package before running a handler).
func SetServeContext(conn int64, arg object.Object) {
	serveContexts.Store(goID(), serveCtx{conn: conn, arg: arg})
}

// ClearServeContext removes the current goroutine's serve context.
func ClearServeContext() {
	serveContexts.Delete(goID())
}

// ServeConn returns the current handler's connection handle (INTEGER), or null
// when not running inside a net_serve handler.
// serve_conn() -> (INTEGER | NULL, err)
func ServeConn(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	if v, ok := serveContexts.Load(goID()); ok {
		return resultAndError(intObj(v.(serveCtx).conn), nil)
	}
	return resultAndError(&object.Null{}, nil)
}

// ServeArg returns the shared arg passed to net_serve for the current handler, or
// null when not inside a handler.
// serve_arg() -> (any | NULL, err)
func ServeArg(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	if v, ok := serveContexts.Load(goID()); ok {
		arg := v.(serveCtx).arg
		if arg == nil {
			return resultAndError(&object.Null{}, nil)
		}
		return resultAndError(arg, nil)
	}
	return resultAndError(&object.Null{}, nil)
}
