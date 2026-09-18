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
// Only a struct or enum name crosses a module boundary bare. Values do not: an
// import binds one namespace, so `helper()` in the importing file is "undefined
// variable: helper" however plainly the imported file declares `helper`. Types
// do, because they never enter the symbol table at all: structDefinitions and
// enumDefinitions are flat, program-wide maps on the Compiler, kept unambiguous
// by claimTypeName rather than by scope.
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
