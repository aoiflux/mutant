package analyzer

import "fmt"

// Curated, hand-authored argument-count contracts for a subset of builtins.
// Mutant's builtin metadata carries no machine-readable arity — each builtin
// validates len(args) imperatively in Go — so, exactly like builtin_types.go,
// this is a high-confidence, hand-verified subset. A builtin appears here ONLY
// when its arity was confirmed by reading its implementation; anything absent is
// never arity-checked, so the diagnostic cannot produce a false positive.
//
// min is the smallest legal argument count; max is the largest, or -1 for an
// unbounded/variadic tail. Grow this table over time; never add an entry you
// have not verified against the builtin's source.

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

var builtinArities = map[string]builtinArity{
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

func builtinArityFor(name string) (builtinArity, bool) {
	a, ok := builtinArities[name]
	return a, ok
}
