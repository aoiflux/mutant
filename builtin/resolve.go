package builtin

import "fmt"

// Aliases maps a builtin name that no longer exists in the registry to the name
// that replaced it. It exists for one purpose: bytecode already in the wild
// names the builtins it calls, so a rename would otherwise make every artifact
// compiled against the old name unloadable.
//
// It is deliberately *not* consulted when the compiler builds its symbol table.
// An alias keeps old bytecode running; it does not keep an old spelling valid in
// new source, which would leave the retired name callable forever and defeat the
// rename. New source uses the new name.
//
// An entry is added when a builtin is renamed or removed, never as a synonym for
// a name that is still live. TestAliasesDoNotShadowLiveBuiltins enforces that.
var Aliases = map[string]string{}

// ResolveName returns the builtin registered under name, following one alias hop
// if the name has been retired. The bool reports whether anything was found.
func ResolveName(name string) (*BuiltIn, bool) {
	if fn := GetBuiltinByName(name); fn != nil {
		return fn, true
	}
	if replacement, aliased := Aliases[name]; aliased {
		if fn := GetBuiltinByName(replacement); fn != nil {
			return fn, true
		}
	}
	return nil, false
}

// LegacyOrdinalCount is the number of builtins the frozen pre-name ordinal table
// covers. An OpGetBuiltin operand at or above it, in bytecode old enough to be
// resolved by ordinal, was never valid.
func LegacyOrdinalCount() int { return len(legacyBuiltinOrdinals) }

// LegacyOrdinalName returns the builtin name that ordinal referred to in
// bytecode compiled before OpGetBuiltin carried names.
func LegacyOrdinalName(ordinal int) (string, bool) {
	if ordinal < 0 || ordinal >= len(legacyBuiltinOrdinals) {
		return "", false
	}
	return legacyBuiltinOrdinals[ordinal], true
}

// ResolveNames turns a program's builtin-name table into the functions it names.
//
// It is the load-time half of name-indexed resolution: the compiler records
// which builtins a program referenced, and this reports -- by name, before the
// program runs -- any the running binary does not have. The alternative, failing
// at the call site, hides a missing dependency behind whichever branch happens
// not to be taken.
func ResolveNames(names []string) ([]*BuiltIn, error) {
	resolved := make([]*BuiltIn, len(names))
	for i, name := range names {
		fn, ok := ResolveName(name)
		if !ok {
			return nil, fmt.Errorf(
				"this program calls the builtin %q, which this mutant runtime does not have; "+
					"it was compiled against a build that did", name)
		}
		resolved[i] = fn
	}
	return resolved, nil
}

// ResolveLegacyOrdinals turns the ordinals of pre-name bytecode into functions,
// by way of the frozen snapshot of the registry those ordinals indexed.
//
// count is how many entries the caller needs; bytecode carries no table of its
// own, so the whole frozen snapshot is resolved and the operand indexes it
// directly. A name in the snapshot that no longer resolves is reported by name
// rather than by number, which is the only useful form of that message.
func ResolveLegacyOrdinals() ([]*BuiltIn, error) {
	resolved := make([]*BuiltIn, len(legacyBuiltinOrdinals))
	for i, name := range legacyBuiltinOrdinals {
		fn, ok := ResolveName(name)
		if !ok {
			return nil, fmt.Errorf(
				"this program was compiled before builtins were resolved by name, and the builtin "+
					"at index %d (%q) has since been removed with no alias; recompile it from source", i, name)
		}
		resolved[i] = fn
	}
	return resolved, nil
}
