package builtin

import "mutant/object"

// Error constructs an error value.
//
//	error(message)                    -> ERROR
//	error(message, context)           -> ERROR
//	error(message, context, related)  -> ERROR
//
// This is the constructor half of L-6: a program could read an error's fields
// but could only ever raise one by calling something that failed. A function
// that validates its own arguments, or that wraps a failure with what it was
// doing at the time, had to borrow an unrelated builtin's error or return a
// bare string and lose the position, the context and the related facts.
//
// It is single-return rather than following the (value, err) convention,
// because constructing an error cannot fail on well-typed arguments -- and that
// is not merely a comment, it is checked: builtinSingleReturn flags
// `let e, err = error("x")` in the editor.
//
// Position is stamped for free. vm.decorateError runs on the result of every
// builtin call and fills File, Line, Column, SourceLine and Stack on any
// *object.Error it sees, leaving fields already set alone. So an error a user
// function constructs points at the error() call that made it, exactly as a
// builtin's error points at the builtin call, with no code here.
//
// One consequence is worth naming rather than discovering: on bad arguments
// this returns an error about the bad arguments, which is the same type as the
// error it would have built. A program cannot tell the two apart by type. That
// is not a new hazard -- it is the arity and argument-type mistake that
// builtinArity and builtinArgType already report in the editor before the
// program runs -- but it is the reason the messages below name `error` and the
// position, so a reader of the value can tell.
func Error(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 3 {
		return newError("wrong number of arguments. got=%d, want=1..3", len(args))
	}

	message, errObj := requireStringArg(BuiltinNameError, args[0], 1)
	if errObj != nil {
		return errObj
	}

	// Context defaults to "user" rather than to the empty string. Every error
	// the runtime raises carries a context naming its origin ("builtin.fs_read",
	// "evaluator"), and an error with an empty one would be the only kind whose
	// origin could not be read off it.
	context := "user"
	if len(args) >= 2 {
		context, errObj = requireStringArg(BuiltinNameError, args[1], 2)
		if errObj != nil {
			return errObj
		}
	}

	var related map[string]object.Object
	if len(args) == 3 {
		hash, errObj := requireHashArg(BuiltinNameError, args[2], 3)
		if errObj != nil {
			return errObj
		}
		related, errObj = relatedFromHash(hash)
		if errObj != nil {
			return errObj
		}
	}

	return &object.Error{Message: message, Context: context, Related: related}
}

// relatedFromHash converts a mutant hash into an error's Related map.
//
// Mutant hash keys may be STRING, INTEGER or BOOLEAN; Related is keyed by Go
// string. A non-string key is rejected by name rather than rendered through
// Inspect, because rendering would silently turn {1: "a"} into {"1": "a"} and
// the program would have no way to learn that it happened. Refusing an
// ambiguity is the choice the rest of the error design makes.
//
// Values are carried across as they are. That is the whole point of Related
// being Object-valued: an offset stays an INTEGER and a record stays a BYTES
// buffer instead of being flattened to text by whoever raised the error.
func relatedFromHash(hash *object.Hash) (map[string]object.Object, *object.Error) {
	if hash == nil || len(hash.Pairs) == 0 {
		return nil, nil
	}
	related := make(map[string]object.Object, len(hash.Pairs))
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return nil, newError("argument 3 to `%s` must have STRING keys, got %s (%s)",
				BuiltinNameError, pair.Key.Type(), pair.Key.Inspect())
		}
		related[key.Value] = pair.Value
	}
	return related, nil
}

// errorValuedBuiltins is the set of builtins whose *success* value is an error,
// keyed by the registry entry so a caller holding a *BuiltIn can ask without
// carrying the name around. It is derived from the declared return contracts
// rather than listing error() by hand, so a second such builtin is covered the
// moment it declares itself.
var errorValuedBuiltins = func() map[*BuiltIn]struct{} {
	set := make(map[*BuiltIn]struct{}, 1)
	for _, def := range Builtins {
		spec, ok := ReturnSpec(def.Name)
		if !ok || spec.Pair {
			continue
		}
		for _, kind := range spec.Kinds {
			if kind == ParamError {
				set[def.Builtin] = struct{}{}
				break
			}
		}
	}
	return set
}()

// ReturnsErrorValue reports whether an error coming back from this builtin is
// its result rather than its failure.
//
// The tree-walking evaluator needs this and the VM does not, which is the whole
// asymmetry between them: the VM's fatal errors are Go errors, so an
// *object.Error reaching its stack is unambiguously a value, while the
// evaluator has to decide. Deciding from the declared contract keeps that
// decision in one place and keeps it honest -- the same ReturnSpec the editor's
// return-shape lint rules read.
func ReturnsErrorValue(b *BuiltIn) bool {
	_, ok := errorValuedBuiltins[b]
	return ok
}
