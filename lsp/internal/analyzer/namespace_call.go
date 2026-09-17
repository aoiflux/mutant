package analyzer

import (
	"fmt"
	"sort"
	"strings"

	lsp "github.com/tliron/glsp/protocol_3_16"

	mast "mutant/ast"
	"mutant/sema"
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
		// Whether this is a builtin call at all is sema's decision, and asking
		// it is the point: the fold used to be derived here, again in
		// compiler.compileFieldExpression, and again in the evaluator, and the
		// three disagreed. Each asked "is this name already taken?" of a
		// different thing, so `rand.int` was painted as a builtin here, ran
		// under the evaluator, and would not compile. One answer now serves all
		// three.
		//
		// bound becomes sema's Bound unchanged, which keeps the gate this arm
		// has always had: without it every `p.x(...)` in the file would be a
		// call to a builtin named "p_x", and every rule downstream would be
		// deciding about a name that does not exist. A variable, parameter or
		// import namespace called `fs` still wins.
		folded := semaResolver.ResolveField(sema.ScopeCtx{Bound: bound}, namespace.Value, node.Field.Value)
		if folded.Kind != sema.FieldBuiltinFold {
			return "", nil, false
		}
		return folded.Builtin, node, true
	}

	return "", nil, false
}

// boundAt is the `bound` predicate for the surfaces that have a Snapshot and a
// position: a let, a parameter or an import namespace visible there beats the
// derived builtin, exactly as it does in the compiler.
func (s *Snapshot) boundAt(pos lsp.Position) func(string) bool {
	if s == nil {
		return nil
	}
	var imports map[string]struct{}
	if s.Program != nil {
		imports = importNamespaces(s.Program.Statements)
	}
	visible := s.VisibleBindingsAt(pos)
	if len(imports) == 0 && len(visible) == 0 {
		return nil
	}

	return func(name string) bool {
		if _, imported := imports[name]; imported {
			return true
		}
		for _, b := range visible {
			if b.ident != nil && b.ident.Value == name {
				return true
			}
		}
		return false
	}
}

// namespacedBuiltinAt resolves the builtin named by the dotted expression at
// pos, whichever half of it the cursor is in.
//
// It finds the enclosing field expression the way NodeAt finds anything else --
// the smallest ranged node containing the position -- because NodeAt itself
// hands back the innermost node, which for `hash.blake2` is the bare identifier
// `blake2` and carries no hint that there is a namespace in front of it.
//
// onField separates the two questions: the cursor on `blake2` is asking about
// the function, the cursor on `hash` about the family.
func (s *Snapshot) namespacedBuiltinAt(pos lsp.Position) (name string, onField bool, ok bool) {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return "", false, false
	}

	var best *mast.FieldExpression
	bestSize := int(^uint(0) >> 1)
	for node, rng := range s.Program.NodePositions {
		field, isField := node.(*mast.FieldExpression)
		if !isField || field == nil || !rng.IsValid() || !contains(rng, pos) {
			continue
		}
		if size := rng.End.Offset - rng.Start.Offset; size < bestSize {
			best, bestSize = field, size
		}
	}
	if best == nil {
		return "", false, false
	}

	resolved, _, found := builtinCallee(best, s.boundAt(pos))
	if !found {
		return "", false, false
	}

	// The field's own range is the narrower of the two, so it is asked about
	// first; anything else inside the expression is the namespace.
	if best.Field != nil {
		if rng, has := s.Program.NodePositions[mast.Node(best.Field)]; has && rng.IsValid() && contains(rng, pos) {
			return resolved, true, true
		}
	}
	return resolved, false, true
}

// builtinFamilyHoverText is the card for the other half: the cursor on `hash`
// rather than on `blake2`.
//
// There is no builtin called `hash`, so without this the namespace hovered as a
// bare identifier -- the answer that sends a reader looking for a variable that
// does not exist. It lists what is in the family, because "what else is in
// here" is what someone hovering a namespace is actually asking.
func builtinFamilyHoverText(namespace string) (string, bool) {
	members := builtinFamilyMembers(namespace)
	if len(members) == 0 {
		return "", false
	}
	sort.Strings(members)

	var out strings.Builder
	fmt.Fprintf(&out, "builtin family `%s`\n\n", namespace)
	fmt.Fprintf(&out, "%d builtins. `%s.%s` and `%s_%s` are the same function.\n\n",
		len(members), namespace, members[0], namespace, members[0])
	out.WriteString("**Members**\n\n")
	for _, member := range members {
		fmt.Fprintf(&out, "- `%s.%s`\n", namespace, member)
	}
	return out.String(), true
}

// builtinNameSet is the registry as a set, built once.
//
// builtin.GetBuiltinByName falls back to a linear scan of the whole registry
// on a miss, and a miss is the normal case here: most field access is on a
// struct rather than a namespace, and these rules ask about every call in the
// file on every keystroke.
var builtinNameSet = liveBuiltinNames()

// semaResolver is the one decision procedure for what a name refers to.
// It holds no state, so one instance serves the whole package.
var semaResolver = sema.NewResolver()

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
