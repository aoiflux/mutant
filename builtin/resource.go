package builtin

import "mutant/object"

// with_resource is Tier 2 of the resource-leak answer (L-6 §7): a guarantee
// that the closer runs, for one registry entry and no keyword.
//
// The leak it closes is real and measured. Twenty families open a handle that
// lives in a package-level map with no cap, no eviction and no cleanup at exit,
// so an unclosed handle holds its OS resource for the life of the process. The
// workaround visible in the corpus is `else` nesting instead of early return,
// so the close stays on the path -- one level deeper per resource.
//
//	let files, err = with_resource(ntfs_open("disk.img"), "ntfs_close", fn(h) {
//	    let names, list_err = ntfs_list_files(h, "/");
//	    if (list_err) { return list_err; }
//	    return names;
//	});
//
// The closer runs whatever the body does -- returns, returns an error, or dies.
// That is what neither the lint nor the nesting can promise.
//
// This file holds only the parts both executors share: argument validation and
// the reading of the three shapes that carry an error. The calling itself is
// engine-specific -- the VM drives an *object.Closure through CallClosureSync,
// the evaluator an *object.Function through applyFunction -- so each has its
// own small driver over these pieces, and the messages cannot drift because
// they are built here.

// ResourceCall is a validated with_resource call: the handle to hand the body,
// the thing to close it with, and the body itself.
type ResourceCall struct {
	Handle object.Object
	Closer object.Object
	Body   object.Object
}

// PrepareResource validates a with_resource call and reads the handle out of
// the open call's result.
//
// It returns at most one of two failures. `bad` is a mistake in the call
// itself -- wrong arity, a closer that names nothing, a body that takes the
// wrong number of parameters. `opened` is the open call's own error, passed
// straight back so that
//
//	let x, err = with_resource(ntfs_open(p), "ntfs_close", body)
//
// reports exactly what `let x, err = ntfs_open(p)` would have. Transparency on
// that path is the property that lets with_resource be wrapped around an
// existing call without changing what the program sees.
//
// The checks run in the order they do because the arguments are evaluated
// before this is reached: by the time a malformed call is diagnosed, the
// resource is already open. So the closer is resolved and the handle read
// before the body is looked at, and `call` comes back carrying both even when
// `bad` is set. A caller that gets a `bad` with a usable Closer and Handle
// should close anyway -- a builtin whose purpose is that the closer runs should
// not leak the one resource it was handed because the call spelled the body
// wrong. When the closer itself is what could not be resolved there is nothing
// to be done, and Closer is nil to say so.
func PrepareResource(args []object.Object) (call ResourceCall, opened *object.Error, bad *object.Error) {
	if len(args) != 3 {
		return call, nil, resourceError("%s: want 3 arguments (resource, closer, function), got %d",
			BuiltinNameWithResource, len(args))
	}

	closer, bad := resolveCloser(args[1])
	if bad != nil {
		return call, nil, bad
	}

	handle, opened := resourceHandle(args[0])
	if opened != nil {
		return call, opened, nil
	}
	call = ResourceCall{Handle: handle, Closer: closer}

	params, ok := CallableParamCount(args[2])
	if !ok {
		return call, nil, resourceError("%s: third argument must be a function, got %s",
			BuiltinNameWithResource, args[2].Type())
	}
	if params != 1 {
		return call, nil, resourceError("%s: function must take 1 parameter (the resource), got %d",
			BuiltinNameWithResource, params)
	}

	call.Body = args[2]
	return call, nil, nil
}

// Closeable reports whether enough of the call was understood to run the
// closer. It is false only when the closer itself could not be resolved, or
// when nothing was opened.
func (c ResourceCall) Closeable() bool { return c.Closer != nil && c.Handle != nil }

// resourceError builds a with_resource error carrying the builtin's own name as
// its context. newError derives the context from the calling Go function, which
// here is PrepareResource -- and "builtin.prepare_resource" names something no
// program can call.
func resourceError(format string, a ...any) *object.Error {
	failure := newError(format, a...)
	failure.Context = "builtin." + BuiltinNameWithResource
	return failure
}

// resolveCloser accepts either the name of a registered builtin or a function
// of one parameter.
//
// The string spelling is the one the twenty close families use, and naming it
// rather than passing the builtin lets the editor check it: the
// unclosedResource diagnostic can tell "ntfs_close" from "ntfs_clos" without
// running anything. The function spelling is for cleanup that is not a single
// call -- a handle plus a flush, or a resource that is not a builtin's.
func resolveCloser(arg object.Object) (object.Object, *object.Error) {
	if name, ok := arg.(*object.String); ok {
		bi := GetBuiltinByName(name.Value)
		if bi == nil {
			return nil, resourceError("%s: second argument names no builtin: %q",
				BuiltinNameWithResource, name.Value)
		}
		// An executor-native builtin is one that drives a user function --
		// map, each, spawn, with_resource itself. None of them closes
		// anything, and naming one here would ask the executor to re-enter
		// itself from inside a cleanup path. Refused by name, so the mistake
		// reads as a mistake instead of as a strange failure later.
		if ExecutorNativeKind(bi) != "" {
			return nil, resourceError("%s: %q takes a function and cannot close a resource",
				BuiltinNameWithResource, name.Value)
		}
		return bi, nil
	}

	params, ok := CallableParamCount(arg)
	if !ok {
		return nil, resourceError("%s: second argument must be a builtin name or a function, got %s",
			BuiltinNameWithResource, arg.Type())
	}
	if params != 1 {
		return nil, resourceError("%s: closer function must take 1 parameter (the resource), got %d",
			BuiltinNameWithResource, params)
	}
	return arg, nil
}

// resourceHandle reads the handle out of whatever the open call returned.
//
// Nearly every opener follows the (value, err) convention, so the common case
// is a two-element MULTI_VALUE. A bare error is an open that failed without a
// pair. Anything else is taken as the handle itself, which is what lets a
// resource opened earlier, or one that is not a builtin's at all, be passed
// through.
func resourceHandle(arg object.Object) (object.Object, *object.Error) {
	handle, failure := SplitResult(arg)
	if failure != nil {
		return nil, failure
	}
	if handle == nil {
		return nil, resourceError("%s: first argument produced no value", BuiltinNameWithResource)
	}
	return handle, nil
}

// SplitResult reads a call's result as a value and a failure.
//
// It recognises the (value, err) pair the standard library returns and hands
// back its halves, so with_resource is transparent to the convention: a body
// that ends in `return ntfs_list_files(h, "/")` gives the caller the file list
// and the list's error, not a MULTI_VALUE it has to take apart itself.
//
// A MULTI_VALUE that is not a pair -- three values, or a second value that is
// neither an error nor null -- is passed through whole rather than being
// guessed at. Only the two-element shape with an error-or-null tail is the
// convention; anything else is a value that happens to have several parts.
func SplitResult(result object.Object) (object.Object, *object.Error) {
	switch value := result.(type) {
	case *object.Error:
		return nil, value
	case *object.MultiValue:
		if value == nil || len(value.Values) == 0 {
			return nil, nil
		}
		if len(value.Values) == 2 {
			switch tail := value.Values[1].(type) {
			case *object.Error:
				return value.Values[0], tail
			case *object.Null:
				return value.Values[0], nil
			}
		}
	}
	return result, nil
}

// ErrorIn reports the failure a call's result carries, or nil when it carries
// none.
func ErrorIn(result object.Object) *object.Error {
	_, failure := SplitResult(result)
	return failure
}

// CallableParamCount reports how many parameters a function value declares. It
// answers for both engines' function representations -- the VM's compiled
// closure and the evaluator's tree-walking function -- because with_resource is
// validated in one place for both.
//
// A builtin is deliberately not callable here: with_resource's body is user
// code, and a builtin passed as the body would be a mistake worth naming rather
// than a call whose arity nothing can check.
func CallableParamCount(fn object.Object) (int, bool) {
	switch value := fn.(type) {
	case *object.Closure:
		if value.Fn == nil {
			return 0, false
		}
		return value.Fn.NumParams, true
	case *object.Function:
		return len(value.Parameters), true
	}
	return 0, false
}

// WithCloseError returns the body's error with the closer's failure attached
// under "close_error", so neither is lost.
//
// The body's error is the one the program asked about, so it stays the error;
// the close failure is a fact about it, which is what Related is for. A copy is
// made rather than the original being mutated: the body's error may already be
// held elsewhere, and an error that changed shape after it was returned would
// break the equality the two engines just agreed on.
func WithCloseError(bodyErr, closeErr *object.Error) *object.Error {
	if bodyErr == nil {
		return closeErr
	}
	if closeErr == nil {
		return bodyErr
	}

	merged := *bodyErr
	merged.Related = make(map[string]object.Object, len(bodyErr.Related)+1)
	for key, value := range bodyErr.Related {
		merged.Related[key] = value
	}
	merged.Related["close_error"] = closeErr
	return &merged
}
