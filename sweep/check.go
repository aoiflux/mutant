package sweep

import (
	"fmt"

	"mutant/builtin"
)

// Check reports whether a file's sweep marker agrees with what the file does.
//
// Two rules, in opposite directions, and the asymmetry is the point:
//
//   - A file whose code implies it may not return -- it opens a listener, or it
//     reads its connection from serve_conn() -- has to say something. A sweep
//     cannot guess, and guessing wrong is what makes a timeout unreadable.
//   - A marker naming server or serve-handler has to be backed by code that
//     actually does that. This is the rule that keeps markers from rotting: one
//     left behind after a rewrite makes a sweep skip an example forever, and
//     nothing else would ever notice.
//
// What Check deliberately does not do is dictate which mode a file gets. An
// example can call serve_conn() and still be worth running -- portscan_service's
// handler checks for null and prints a notice -- so `run`, with a reason, stays
// available to any file. A marker says what a sweep should do with the file, not
// what category the file belongs to.
func Check(src string) error {
	marker, err := ParseMarker(src)
	if err != nil {
		return err
	}

	handler, listener := serveShape(src)

	if !marker.Explicit && (handler || listener) {
		return fmt.Errorf("this file %s, so a sweep cannot tell whether it returns; mark it"+
			"\n\t// %s %s %s <why>\nor `%s`, with a reason, if it really does exit",
			describeShape(handler, listener),
			Directive, Classify(src), reasonSeparator, ModeRun)
	}

	switch marker.Mode {
	case ModeServeHandler:
		if !handler {
			return fmt.Errorf("marked %s on line %d, but this file never calls serve_conn() or "+
				"serve_arg(); a handler reads its connection from there, so the marker is stale "+
				"and a sweep is skipping an example it could run",
				ModeServeHandler, marker.Line)
		}
	case ModeServer:
		if !listener {
			return fmt.Errorf("marked %s on line %d, but this file never opens a listener; the "+
				"marker is stale and a sweep is skipping an example it could run",
				ModeServer, marker.Line)
		}
	}

	return nil
}

// serveShape reports the two properties every rule here turns on: whether the
// file reads a dispatched connection, and whether it opens a listener.
func serveShape(src string) (handler, listener bool) {
	called := calledNames(src)

	handler = called[builtin.BuiltinNameServeConn] || called[builtin.BuiltinNameServeArg]
	listener = called[builtin.BuiltinNameNetListen] ||
		called[builtin.BuiltinNameNetTlsListen] ||
		called[builtin.BuiltinNameNetServe]
	return handler, listener
}

func describeShape(handler, listener bool) string {
	switch {
	case handler && listener:
		return "opens a listener and calls serve_conn()"
	case handler:
		return "calls serve_conn()"
	default:
		return "opens a listener"
	}
}
