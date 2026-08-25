package analyzer

import (
	"testing"

	"mutant/builtin"
)

// TestEveryBuiltinHasADerivedArity requires the derived table to cover the whole
// registry.
//
// deriveBuiltinArities skips any builtin whose signature will not parse, which
// is the right behaviour at runtime — an unknown contract must never be checked
// — but it makes a malformed signature invisible: the builtin quietly stops
// being arity-checked instead of failing anything. Asserting full coverage is
// what turns that silence into a test failure.
func TestEveryBuiltinHasADerivedArity(t *testing.T) {
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		if _, ok := builtinArityFor(def.Name); !ok {
			signature, _, _, hasDoc := builtin.TeachingDoc(def.Name)
			t.Errorf("builtin %q has no derived arity (teaching doc present: %v, signature %q); it will never be arity-checked",
				def.Name, hasDoc, signature)
		}
	}

	if len(builtinArities) == 0 {
		t.Fatal("no arities were derived; the registry or the metadata lookup is broken")
	}
	t.Logf("derived argument-count contracts for %d of %d builtins", len(builtinArities), len(builtin.Builtins))
}

// handVerifiedArities is the table this file's contracts used to be: every entry
// was written by reading the builtin's Go source, before anything was derived
// from the signature strings.
//
// It is kept as an independent witness. The derived table now comes from the
// signatures, so a signature that drifts would take the derived arity with it
// and no self-consistent check would notice. These values were not derived from
// the signatures, so they still disagree when one changes.
var handVerifiedArities = map[string]builtinArity{
	// math (verified against builtin/math_builtins.go)
	"abs":   {1, 1},
	"sqrt":  {1, 1},
	"pow":   {2, 2},
	"mod":   {2, 2},
	"clamp": {3, 3},
	"floor": {1, 1},
	"ceil":  {1, 1},
	"round": {1, 1},
	"min":   {1, -1},
	"max":   {1, -1},

	// core / collections / conversion (verified against builtin/*.go)
	"len":       {1, 1},
	"first":     {1, 1},
	"last":      {1, 1},
	"push":      {2, 2},
	"sort":      {1, 1},
	"contains":  {2, 2},
	"keys":      {1, 1},
	"values":    {1, 1},
	"to_int":    {1, 1},
	"to_float":  {1, 1},
	"to_string": {1, 1},
	"type_of":   {1, 1},
}

func TestDerivedAritiesMatchHandVerifiedOnes(t *testing.T) {
	for name, want := range handVerifiedArities {
		got, ok := builtinArityFor(name)
		if !ok {
			t.Errorf("builtin %q has no derived arity but was hand-verified as {min:%d max:%d}", name, want.min, want.max)
			continue
		}
		if got != want {
			signature, _, _, _ := builtin.TeachingDoc(name)
			t.Errorf("builtin %q: derived {min:%d max:%d} from signature %q disagrees with the hand-verified {min:%d max:%d}",
				name, got.min, got.max, signature, want.min, want.max)
		}
	}
	t.Logf("cross-checked %d hand-verified arities against the derived table", len(handVerifiedArities))
}
