package analyzer

import "mutant/builtin"

// Builtin result types, derived from the contracts in builtin/metadata.go.
//
// This used to be a hand-curated table of 110 entries maintained here, in the
// language server, with no link to the implementations it described. Deriving
// instead of curating takes coverage to all 399 and removes the drift: the same
// declarations the hover card shows are the ones inference reasons about, and
// return_conformance_test.go checks them against the implementations.
//
// The switch also found three bugs the curated table had been carrying:
// fs_write was typed INTEGER when it returns a BOOLEAN, fs_exists was typed as a
// bare BOOLEAN when it returns a (value, err) pair, and two entries named
// builtins — str_split, str_replace — that do not exist.

type builtinSig struct {
	ret Type
	// pair marks the (value, err) convention, so a multi-name `let` can type
	// the first name as the value and the last as the error.
	pair bool
}

var (
	tInt    = Type{Kind: TypeInt}
	tFloat  = Type{Kind: TypeFloat}
	tBool   = Type{Kind: TypeBool}
	tString = Type{Kind: TypeString}
	tHash   = Type{Kind: TypeHash}
	tArray  = Type{Kind: TypeArray}
)

var builtinReturnTypes = deriveBuiltinReturnTypes()

// deriveBuiltinReturnTypes reads every builtin's declared return once at init.
//
// Only a single, concrete kind becomes a type. A union or an explicit ANY is
// left out entirely, so it infers to Any exactly as an unknown builtin does:
// widening *coverage* must not widen what the editor claims, because a type
// shown here is a type the reader will believe.
func deriveBuiltinReturnTypes() map[string]builtinSig {
	types := make(map[string]builtinSig, len(builtin.Builtins))
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		spec, ok := builtin.ReturnSpec(def.Name)
		if !ok || len(spec.Kinds) != 1 {
			continue
		}
		ret, ok := typeForParamKind(spec.Kinds[0])
		if !ok {
			continue
		}
		if ret.Kind == TypeArray && len(spec.Elem) == 1 {
			if elem, ok := typeForParamKind(spec.Elem[0]); ok {
				ret = arrayOf(elem)
			}
		}
		types[def.Name] = builtinSig{ret: ret, pair: spec.Pair}
	}
	return types
}

// typeForParamKind translates a declared kind into the inference lattice,
// reporting false for the ones it deliberately cannot express: ANY carries no
// information, and NULL as a *declared* result would make `let x = putln(...)`
// claim a type where "no useful value" is the honest answer.
func typeForParamKind(kind builtin.ParamKind) (Type, bool) {
	switch kind {
	case builtin.ParamInt:
		return tInt, true
	case builtin.ParamFloat:
		return tFloat, true
	case builtin.ParamBool:
		return tBool, true
	case builtin.ParamString:
		return tString, true
	case builtin.ParamArray:
		return tArray, true
	case builtin.ParamHash:
		return tHash, true
	}
	return AnyType, false
}

func builtinReturnType(name string) (builtinSig, bool) {
	sig, ok := builtinReturnTypes[name]
	return sig, ok
}
