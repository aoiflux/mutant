package analyzer

import (
	mast "mutant/ast"
)

// This file holds the one thing every builtin-aware rule needs once a builtin
// can be spelled two ways.
//
// `fs.read(p)` and `fs_read(p)` are the same call. The compiler folds the
// first into the second by deriving the name rather than consulting a table,
// so every family works without a list to maintain. The rules here have to
// make the same fold, in one place: each of them found its callee with a bare
// `call.Function.(*mast.Identifier)`, which a dotted call fails, so every
// builtin check went silent on the spelling the module system encourages.
//
// Going silent is the polite half of that failure. The loud half is
// unclosedResource, which would report a handle closed by `ntfs.close(h)` as
// leaked -- a warning telling an author their correct code is wrong, which is
// the one thing that rule promises never to do.

// builtinCallee resolves the builtin a call names, in either spelling.
//
// bound reports whether a name is already taken in the caller's own notion of
// scope -- a let, a parameter, an import namespace. It decides whether
// `fs.read` is a builtin call at all, and each rule models scope differently
// (a declarationScope walk, a file-wide set, nothing), so it is a parameter
// rather than something this helper works out. A nil bound models no
// shadowing, which is what the rules with no scope model do today.
//
// anchor is what a diagnostic should hang its range on: the identifier for the
// bare form, the whole field expression for the dotted one, so the squiggle
// covers `fs.read` rather than just `fs`.
func builtinCallee(fn mast.Expression, bound func(string) bool) (name string, anchor mast.Node, ok bool) {
	switch node := fn.(type) {
	case *mast.Identifier:
		if node == nil || node.Value == "" {
			return "", nil, false
		}
		if bound != nil && bound(node.Value) {
			return "", nil, false
		}
		// Deliberately not filtered through isLiveBuiltin: every caller
		// already checks the name against its own table, and some of those
		// tables are not subsets of the registry in the way a filter here
		// would assume.
		return node.Value, node, true

	case *mast.FieldExpression:
		if node == nil || node.Field == nil || node.Field.Value == "" {
			return "", nil, false
		}
		namespace, isIdent := node.Left.(*mast.Identifier)
		if !isIdent || namespace == nil || namespace.Value == "" {
			// a.b.c, f().x and arr[0].x are field access on a value, never a
			// namespace.
			return "", nil, false
		}
		if bound != nil && bound(namespace.Value) {
			// A variable, parameter or import namespace called `fs` wins, the
			// same way it wins in the compiler.
			return "", nil, false
		}

		derived := namespace.Value + "_" + node.Field.Value
		// This gate is not optional. Without it every `p.x(...)` in the file
		// becomes a call to a builtin named "p_x", and each rule would then be
		// deciding on a name that does not exist.
		if !isLiveBuiltin(derived) {
			return "", nil, false
		}
		return derived, node, true
	}

	return "", nil, false
}

// builtinNameSet is the registry as a set, built once.
//
// builtin.GetBuiltinByName falls back to a linear scan of the whole registry
// on a miss, and a miss is the normal case here: most field access is on a
// struct rather than a namespace, and these rules ask about every call in the
// file on every keystroke.
var builtinNameSet = liveBuiltinNames()

// isLiveBuiltin reports whether name is a builtin in this build.
func isLiveBuiltin(name string) bool {
	_, ok := builtinNameSet[name]
	return ok
}

// importNamespaces returns the set of names the file's imports bind.
//
// Imports are top level only, so this does not walk into bodies. A namespace
// that came out empty is skipped rather than registered, so a half-typed
// `import "` cannot make the empty string a bound name.
func importNamespaces(statements []mast.Statement) map[string]struct{} {
	namespaces := make(map[string]struct{}, 2)
	for _, stmt := range statements {
		imp, ok := stmt.(*mast.ImportStatement)
		if !ok || imp == nil {
			continue
		}
		if name := imp.Namespace(); name != "" {
			namespaces[name] = struct{}{}
		}
	}
	return namespaces
}

// boundInNamespaces builds a bound predicate for a rule whose only model of
// scope is the file's imports.
func boundInNamespaces(namespaces map[string]struct{}) func(string) bool {
	if len(namespaces) == 0 {
		return nil
	}
	return func(name string) bool {
		_, imported := namespaces[name]
		return imported
	}
}
