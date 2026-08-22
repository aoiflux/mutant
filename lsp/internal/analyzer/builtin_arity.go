package analyzer

import (
	"fmt"

	"mutant/builtin"
)

// Argument-count contracts for the builtins, derived from the teaching
// signatures in builtin/metadata.go.
//
// This used to be a hand-curated table of a couple of dozen entries, on the
// grounds that arity was not machine-readable — each builtin validates
// len(args) imperatively in Go, so the only trustworthy source was a human
// reading the implementation. The signature strings turn out to carry the same
// information: `?` marks an optional parameter and `...` a variadic tail, which
// is exactly min and max. builtin.SignatureArity reads them.
//
// What makes deriving safe rather than merely convenient is that the
// signatures are now checked against the implementations. TestSignatureArity-
// MatchesImplementation in the builtin package calls every builtin with an
// argument count its signature forbids and requires the builtin to refuse it,
// and TestHigherOrderArityMatchesExecutor in the vm package covers the five
// that the executors intercept. A signature narrower than its implementation —
// the only kind of disagreement that could turn into a warning on correct code
// — fails the suite. Those probes found four real bugs the curated table had no
// way to catch: bytes_cstr_at documented two of its three required parameters,
// fs_hash and fs_walk each omitted an optional one, and putf answered a missing
// format argument with silence.

type builtinArity struct {
	min int
	max int // -1 == unbounded (variadic)
}

// accepts reports whether n arguments satisfy the contract.
func (a builtinArity) accepts(n int) bool {
	if n < a.min {
		return false
	}
	return a.max < 0 || n <= a.max
}

// message renders the human diagnostic for a call that passed `got` arguments.
func (a builtinArity) message(name string, got int) string {
	var want string
	switch {
	case a.max < 0:
		want = fmt.Sprintf("at least %d %s", a.min, pluralArguments(a.min))
	case a.min == a.max:
		want = fmt.Sprintf("%d %s", a.min, pluralArguments(a.min))
	default:
		want = fmt.Sprintf("%d to %d arguments", a.min, a.max)
	}
	return fmt.Sprintf("builtin `%s` takes %s, got %d", name, want, got)
}

func pluralArguments(n int) string {
	if n == 1 {
		return "argument"
	}
	return "arguments"
}

// builtinArities is built once at init from the registry. A builtin whose
// signature does not parse is simply absent, which keeps the original property
// that anything unknown is never arity-checked.
var builtinArities = deriveBuiltinArities()

func deriveBuiltinArities() map[string]builtinArity {
	arities := make(map[string]builtinArity, len(builtin.Builtins))

	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		signature, _, _, ok := builtin.TeachingDoc(def.Name)
		if !ok {
			continue
		}
		_, params, ok := builtin.ParseSignature(signature)
		if !ok {
			continue
		}
		minArgs, maxArgs := builtin.SignatureArity(params)
		arities[def.Name] = builtinArity{min: minArgs, max: maxArgs}
	}

	return arities
}

func builtinArityFor(name string) (builtinArity, bool) {
	a, ok := builtinArities[name]
	return a, ok
}
