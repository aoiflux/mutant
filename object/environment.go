package object

import "sort"

type Environment struct {
	store map[string]Object
	outer *Environment

	// macroExpansion marks an environment a macro body is being evaluated in.
	// The evaluator refuses every builtin that is not macro-safe while it is
	// set, because a macro body runs while the compiler is running: before the
	// program starts, before a password is asked for, and before any of the run
	// time's controls exist.
	//
	// It is deliberately unexported. object.Macro and object.Function are both
	// gob-registered and both carry an exported Env, and gob refuses to encode
	// them today only because this struct has no exported field at all. One
	// exported marker here would quietly make a captured environment chain
	// encodable, and no test would notice.
	macroExpansion bool
}

func NewEnvironment() *Environment {
	s := make(map[string]Object)
	return &Environment{store: s, outer: nil}
}

// NewEnclosedEnvironement opens a scope inside another one.
//
// The macro-expansion mark is copied forward rather than looked up through
// outer, so the check costs nothing at each name resolution. This is the only
// chaining constructor, which is what makes the mark impossible for a
// descendant to shed: a function a macro body defines, a loop body, a match
// arm and the environment unquote evaluates in all come through here.
func NewEnclosedEnvironement(outer *Environment) *Environment {
	env := NewEnvironment()
	env.outer = outer
	if outer != nil {
		env.macroExpansion = outer.macroExpansion
	}
	return env
}

// NewMacroExpansionEnvironment opens a scope in which only macro-safe builtins
// resolve. The evaluator is the only caller: it wraps rather than marks what it
// was handed, so an environment a caller owns is never marked and the run time
// cannot reach the restriction.
func NewMacroExpansionEnvironment(outer *Environment) *Environment {
	env := NewEnclosedEnvironement(outer)
	env.macroExpansion = true
	return env
}

// InMacroExpansion reports whether this scope is inside a macro body.
func (e *Environment) InMacroExpansion() bool { return e != nil && e.macroExpansion }

func (e *Environment) Get(name string) (Object, bool) {
	obj, ok := e.store[name]
	if (!ok) && (e.outer != nil) {
		obj, ok = e.outer.Get(name)
	}
	return obj, ok
}

func (e *Environment) Set(name string, val Object) Object {
	e.store[name] = val
	return val
}

func (e *Environment) Update(name string, val Object) (Object, bool) {
	if _, ok := e.store[name]; ok {
		e.store[name] = val
		return val, true
	}

	if e.outer != nil {
		return e.outer.Update(name, val)
	}

	return nil, false
}

// Keys returns all currently defined symbols in this environment chain.
func (e *Environment) Keys() []string {
	seen := make(map[string]struct{})
	for current := e; current != nil; current = current.outer {
		for key := range current.store {
			seen[key] = struct{}{}
		}
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
