package evaluator

import (
	"mutant/builtin"
	"mutant/object"
	"mutant/sema"
)

var builtins = buildBuiltinMap()

// semaResolver is the one decision procedure for what a name refers to.
// It holds no state, so one instance serves the whole package.
var semaResolver = sema.NewResolver()

// resolveBuiltin is the one place in this engine where a name becomes a builtin.
//
// There are two callers because the language has two spellings for the same
// builtin -- `fs.write` and `fs_write` -- not because there are two policies.
// The flat name is the key for both; the spelling is only what a refusal repeats
// back, so the author reads the words they actually wrote.
//
// A name the registry does not hold comes back as (nil, false) rather than as an
// error. That is what keeps "identifier not found: x" byte-identical for a name
// that is not a builtin at all: the refusal below can only fire for a name that
// IS one.
func resolveBuiltin(flat, spelling string, env *object.Environment) (object.Object, bool) {
	fn, registered := builtins[flat]
	if !registered {
		return nil, false
	}
	if !env.InMacroExpansion() || builtin.MacroSafe(flat) {
		return fn, true
	}
	return newError("%s is not available at macro expansion time, because %s",
		spelling, builtin.MacroRefusal(flat)), true
}

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
