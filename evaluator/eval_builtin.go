package evaluator

import "mutant/builtin"

var builtins = buildBuiltinMap()

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
