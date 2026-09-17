package evaluator

import (
	"mutant/builtin"
	"mutant/sema"
)

var builtins = buildBuiltinMap()

// semaResolver is the one decision procedure for what a name refers to.
// It holds no state, so one instance serves the whole package.
var semaResolver = sema.NewResolver()

func buildBuiltinMap() map[string]*builtin.BuiltIn {
	entries := make(map[string]*builtin.BuiltIn, len(builtin.Builtins))
	for _, entry := range builtin.Builtins {
		if entry.Name == "" || entry.Builtin == nil {
			continue
		}
		entries[entry.Name] = entry.Builtin
	}
	return entries
}
