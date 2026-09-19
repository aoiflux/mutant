package sema

import (
	"sort"

	"mutant/ast"
)

// The other half of cross-module resolution: a name written bare.
//
// `ns.member` is a reach into a named module, and resolve.go decides it. A bare
// name is a different question with a far narrower answer -- and the answer is
// not the one a name-matching index gives.
//
// A struct name, an enum name and a macro name cross a module boundary bare.
// Values do not: an import binds one namespace, so `helper()` in the importing
// file is "undefined variable: helper" however plainly the imported file
// declares `helper`. Types do, because they never enter the symbol table at
// all: structDefinitions and enumDefinitions are flat, program-wide maps on the
// Compiler, kept unambiguous by claimTypeName rather than by scope. Macros do
// for a third reason -- generator.buildByteCode fills one macroEnv for the
// whole program -- and they are the one of the three that can legitimately be
// ambiguous, because nothing plays claimTypeName's part for them.
//
// A macro is also the exact opposite of a type in the other direction: a type
// name can at least be READ from a namespace in some editors' habits and is
// simply refused, whereas `ns.twice` is refused because the macro's declaration
// is deleted from the program before the module's scope is built. See
// MacroFact.
//
// Two consequences that are easy to get wrong, both read off the compiler
// rather than reasoned about:
//
//   - A type is NOT filtered by the underscore rule. `struct _Secret` in one
//     module is usable bare from another, because IsModulePrivate is a
//     symbol-table rule and a type name never reaches the symbol table. An
//     editor that refused it would be refusing a program that builds.
//
//   - The compiler is more permissive than this, deliberately not followed.
//     Modules compile in post-order, so a type declared in a sibling that
//     happens to compile first is visible too -- which makes the program's
//     meaning depend on the order two import lines were written in. Swapping
//     two imports in an entry file turns a working program into "undefined
//     struct type: Q". The closure is the order-independent subset: a module
//     the importer actually reaches is always compiled before it, so every
//     answer given here is one the compiler gives as well, whatever order
//     anything else in the program is written in.

// ResolveTopLevel finds the declaration a bare name written in fromKey refers
// to, when that declaration lives in another file.
//
// It searches the closure of fromKey -- the modules fromKey reaches through its
// own imports, transitively -- and excludes fromKey itself, because a name a
// file declares is the file-local walk's answer to give and it knows more about
// scopes than this does.
//
// An ambiguous name is refused rather than guessed at. Two modules in one
// closure declaring the same type name is a program claimTypeName refuses
// outright, so pointing at either would be pointing into a program that does
// not build.
func (w *Workspace) ResolveTopLevel(fromKey, name string) (TypeFact, string, bool) {
	if fromKey == "" || name == "" {
		return TypeFact{}, "", false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	reachable, _ := w.closureLocked(fromKey)

	var (
		found TypeFact
		owner string
	)
	for _, key := range reachable {
		if key == fromKey {
			continue
		}
		facts, known := w.facts[key]
		if !known {
			continue
		}
		declared, declares := facts.Types[name]
		if !declares {
			continue
		}
		if owner != "" {
			return TypeFact{}, "", false
		}
		found, owner = declared, key
	}

	if owner == "" {
		return TypeFact{}, "", false
	}
	return found, owner, true
}

// ResolveMacro finds the macro a bare name written in fromKey refers to, when
// the definition lives in another file.
//
// It is ResolveTopLevel's sibling and searches the same closure for the same
// reason. It refuses an ambiguous answer, but not for ResolveTopLevel's reason:
// two modules in one closure declaring one macro name is a program that BUILDS.
// macroEnv is one environment and the last definition compiled wins, so which
// one a call means depends on the order two import lines were written in.
// Pointing at either would be presenting an order-dependent answer as a fact;
// ProvidesBareName still reports the name as provided, so nothing squiggles.
func (w *Workspace) ResolveMacro(fromKey, name string) (MacroFact, string, bool) {
	if fromKey == "" || name == "" {
		return MacroFact{}, "", false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	reachable, _ := w.closureLocked(fromKey)

	var (
		found MacroFact
		owner string
	)
	for _, key := range reachable {
		if key == fromKey {
			continue
		}
		facts, known := w.facts[key]
		if !known {
			continue
		}
		declared, declares := facts.Macros[name]
		if !declares {
			continue
		}
		if owner != "" {
			return MacroFact{}, "", false
		}
		found, owner = declared, key
	}

	if owner == "" {
		return MacroFact{}, "", false
	}
	return found, owner, true
}

// ProvidesBareName reports whether anything fromKey reaches declares this name
// in a form that crosses a module boundary written bare.
//
// It exists for the one caller that must not be told "no" on an ambiguity: the
// undefined rule. Two modules declaring one struct name is refused by
// claimTypeName and two declaring one macro name is accepted, and in neither
// case is "undefined identifier" the sentence the build prints -- so the rule's
// question is "could this name come from somewhere I can see?", not "which
// declaration is it?".
//
// fromKey itself is excluded, as it is in ResolveTopLevel: what a file declares
// is the file-local walk's answer to give, and it knows about scopes.
func (w *Workspace) ProvidesBareName(fromKey, name string) bool {
	if fromKey == "" || name == "" {
		return false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	reachable, _ := w.closureLocked(fromKey)
	for _, key := range reachable {
		if key == fromKey {
			continue
		}
		facts, known := w.facts[key]
		if !known {
			continue
		}
		if _, declares := facts.Types[name]; declares {
			return true
		}
		if _, declares := facts.Macros[name]; declares {
			return true
		}
	}

	// Nothing found -- but "not found" and "not there" are the same sentence
	// only when the closure is whole. An import the workspace could not resolve
	// is a module whose declarations are invisible, and answering no from that
	// picture is how a name that is perfectly well declared gets reported as
	// undefined. That answer is Provisional, and a Provisional answer renders
	// nothing.
	return !w.closureIsCompleteLocked(fromKey)
}

// closureIsCompleteLocked reports whether every import reachable from key named
// a module this workspace has facts for.
//
// It walks rather than caching a flag, for the reason Importers does: the
// alternative is a second thing to invalidate, and it is only ever reached on
// the path where a diagnostic is about to be raised -- never on a keystroke.
func (w *Workspace) closureIsCompleteLocked(key string) bool {
	reachable, _ := w.closureLocked(key)
	for _, current := range reachable {
		facts, known := w.facts[current]
		if !known {
			return false
		}
		for _, imported := range facts.Imports {
			if _, resolved := w.resolveImport(current, imported.Spelling); !resolved {
				return false
			}
		}
	}
	return true
}

// BareNamesFrom returns the names targetKey contributes to fromKey without a
// namespace: its types and its macros.
//
// This is what makes an `import` whose alias is never read still a used import.
// Deleting the line would take `Point` and `twice` with it, so calling it
// unused would be advising a change that breaks the build.
func (w *Workspace) BareNamesFrom(fromKey, targetKey string) []string {
	if fromKey == "" || targetKey == "" || fromKey == targetKey {
		return nil
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	facts, known := w.facts[targetKey]
	if !known {
		return nil
	}

	names := make([]string, 0, len(facts.Types)+len(facts.Macros))
	for name := range facts.Types {
		names = append(names, name)
	}
	for name := range facts.Macros {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TypeDefinition is ResolveTopLevel turned into something an editor can jump
// to: the file the declaration is in, and its range within that file.
func (w *Workspace) TypeDefinition(fromKey, name string) (uri string, declRange ast.Range, ok bool) {
	declared, owner, found := w.ResolveTopLevel(fromKey, name)
	if !found || !declared.DeclRange.IsValid() {
		return "", ast.Range{}, false
	}
	target, known := w.URIOf(owner)
	if !known || target == "" {
		return "", ast.Range{}, false
	}
	return target, declared.DeclRange, true
}

// Importers returns every indexed module whose closure contains targetKey,
// targetKey itself included, in a deterministic order.
//
// This is the reverse of Closure and it is computed here rather than stored.
// A stored reverse index is the one structure in this package that could go
// stale: it would have to be maintained on every edit to any import line in the
// workspace, and the cost of getting that wrong is a find-references that
// quietly misses a file. Recomputing costs one closure walk per indexed module,
// paid on an explicit user action rather than on a keystroke.
func (w *Workspace) Importers(targetKey string) []string {
	if targetKey == "" {
		return nil
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	importers := make([]string, 0, 4)
	for key := range w.facts {
		reachable, _ := w.closureLocked(key)
		for _, reached := range reachable {
			if reached == targetKey {
				importers = append(importers, key)
				break
			}
		}
	}
	sort.Strings(importers)
	if len(importers) == 0 {
		return nil
	}
	return importers
}

// AliasesFor returns the namespaces fromKey binds to targetKey.
//
// Usually one, but nothing stops a file importing the same module twice under
// two names, and a find-references that only looked for the first would miss
// every use written through the second.
func (w *Workspace) AliasesFor(fromKey, targetKey string) []string {
	if fromKey == "" || targetKey == "" {
		return nil
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	aliases := make([]string, 0, 2)
	for alias, bound := range w.bindingsLocked(fromKey) {
		if bound == targetKey {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	if len(aliases) == 0 {
		return nil
	}
	return aliases
}
