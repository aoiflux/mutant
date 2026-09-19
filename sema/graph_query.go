package sema

import (
	"sort"

	"mutant/ast"
)

// Everything a consumer asks a Graph. All of it is a lookup: the walk already
// happened, once, in BuildFile.
//
// Positions are 1-based line and column, which is what ast.Range holds. The
// language server converts from its own 0-based coordinates at the boundary,
// and this package stays free of the editor protocol.

// NodeFor returns the declaration with the given identity.
func (g *Graph) NodeFor(id DeclID) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	node, found := g.nodes[id]
	return node, found
}

// Declarations returns every declaration in the file, in source order.
func (g *Graph) Declarations() []*Node {
	if g == nil {
		return nil
	}
	return g.decls
}

// TopLevel returns the declarations in the file's top-level scope, in source
// order. Type names are included: they are declared at the top level even
// though they live in their own table.
func (g *Graph) TopLevel() []*Node {
	if g == nil {
		return nil
	}
	top := make([]*Node, 0, len(g.Root.order)+len(g.typeOrder()))
	top = append(top, g.Root.order...)
	top = append(top, g.typeOrder()...)
	return top
}

// Imports returns the file's import statements in source order.
func (g *Graph) Imports() []ImportEdge {
	if g == nil {
		return nil
	}
	return g.imports
}

// References returns every recorded use in the file, in source order.
//
// It is the whole-file form of UsesOf, for a consumer that walks the graph
// rather than asking about one declaration: the export writes an edge per
// reference, and asking UsesOf once per declaration would visit the list once
// per declaration to produce the same set.
func (g *Graph) References() []Ref {
	if g == nil {
		return nil
	}
	return g.refList
}

// DeclarationAt returns the declaration whose own identifier is under the
// position -- the cursor is on the name being declared, not on a use of it.
func (g *Graph) DeclarationAt(line, column int) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	at := lastStartingAtOrBefore(len(g.declOrder), line, column, func(i int) ast.Range {
		return g.declOrder[i].DeclRange
	})
	if at < 0 || !rangeContains(g.declOrder[at].DeclRange, line, column) {
		return nil, false
	}
	return g.declOrder[at], true
}

// ReferenceAt returns the use under the position.
func (g *Graph) ReferenceAt(line, column int) (Ref, bool) {
	if g == nil {
		return Ref{}, false
	}
	at := lastStartingAtOrBefore(len(g.refList), line, column, func(i int) ast.Range {
		return g.refList[i].UseRange
	})
	if at < 0 || !rangeContains(g.refList[at].UseRange, line, column) {
		return Ref{}, false
	}
	return g.refList[at], true
}

// lastStartingAtOrBefore is the index of the last range that starts at or
// before the position, over a slice already sorted by start, and -1 when none
// does. Identifier ranges do not nest, so the one range that can contain a
// position is the last one that starts at or before it.
func lastStartingAtOrBefore(n, line, column int, rangeAt func(int) ast.Range) int {
	found := sort.Search(n, func(i int) bool {
		start := rangeAt(i).Start
		return before(line, column, start.Line, start.Column)
	})
	return found - 1
}

// FieldNameAt returns the field identifier under the position, for any `a.x`
// written in the file, whether or not the graph could say which declaration it
// refers to.
//
// It is what a caller asks after Resolve has come back empty: "the cursor is on
// a field name, even though nothing here knows whose". The language server
// answers such a position with the name itself rather than with nothing, so
// that a struct whose type it could not infer still hovers as a field.
func (g *Graph) FieldNameAt(line, column int) (*ast.Identifier, ast.Range, bool) {
	if g == nil {
		return nil, ast.Range{}, false
	}
	for _, field := range g.fields {
		if rangeContains(field.rng, line, column) {
			return field.ident, field.rng, true
		}
	}
	return nil, ast.Range{}, false
}

// Resolve returns the declaration the position refers to: the declaration
// itself when the cursor is on the name being declared, and otherwise the
// declaration the use under the cursor refers to.
//
// A use is checked before a declaration because the two ranges never overlap
// and checking uses first is the common case.
func (g *Graph) Resolve(line, column int) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	if ref, found := g.ReferenceAt(line, column); found {
		if node, known := g.nodes[ref.Target]; known {
			return node, true
		}
	}
	return g.DeclarationAt(line, column)
}

// UsesOf returns every place the declaration is used, in source order, not
// counting the declaration itself.
func (g *Graph) UsesOf(id DeclID) []ast.Range {
	if g == nil || id.IsZero() {
		return nil
	}
	return g.usesByTarget[id]
}

// VisibleAt returns the declarations in scope at a position, innermost first
// where two scopes bind one name.
//
// A declaration written later in the file is not in scope at an earlier
// position, which is why the position is needed rather than just the scope: the
// walk binds names as it reaches them, so completion at the top of a file must
// not offer a name declared at the bottom of it.
func (g *Graph) VisibleAt(line, column int) []*Node {
	if g == nil {
		return nil
	}

	visible := make([]*Node, 0, 16)
	taken := make(map[string]struct{}, 16)

	for scope := g.scopeAt(line, column); scope != nil; scope = scope.Parent {
		for i := len(scope.order) - 1; i >= 0; i-- {
			node := scope.order[i]
			if !startsAtOrBefore(node.Anchor(), line, column) {
				continue
			}
			if _, already := taken[node.Name]; already {
				continue
			}
			taken[node.Name] = struct{}{}
			visible = append(visible, node)
		}
	}

	// Type names are file-global rather than scoped, so they are appended
	// rather than reached by walking up. A value of the same name shadows
	// them here for the same reason it does in the compiler: a bare name in
	// value position is never a type.
	for _, node := range g.typeOrder() {
		if !startsAtOrBefore(node.Anchor(), line, column) {
			continue
		}
		if _, already := taken[node.Name]; already {
			continue
		}
		taken[node.Name] = struct{}{}
		visible = append(visible, node)
	}

	return visible
}

// scopeAt returns the innermost scope covering the position.
func (g *Graph) scopeAt(line, column int) *Scope {
	scope := g.Root
	for {
		next := (*Scope)(nil)
		for _, child := range scope.Children {
			if child.Range.IsValid() && rangeContains(child.Range, line, column) {
				next = child
				break
			}
		}
		if next == nil {
			return scope
		}
		scope = next
	}
}

func (g *Graph) typeOrder() []*Node {
	if g == nil || g.Types == nil {
		return nil
	}
	return g.Types.order
}

// TypeNamed returns the struct or enum declared under a name, and its members.
func (g *Graph) TypeNamed(name string) (*Node, []*Node, bool) {
	if g == nil || g.Types == nil || name == "" {
		return nil, nil, false
	}
	for i := len(g.Types.order) - 1; i >= 0; i-- {
		declared := g.Types.order[i]
		if declared.Name != name {
			continue
		}
		return declared, g.membersOf(declared), true
	}
	return nil, nil, false
}

func (g *Graph) membersOf(declared *Node) []*Node {
	if g == nil || declared == nil || g.Types == nil {
		return nil
	}
	want := g.Types.Path.Child(segmentFor(declared, declared.Name))
	for _, child := range g.Types.Children {
		if child.Path == want {
			return child.order
		}
	}
	return nil
}

// --- builder-side scope and type helpers -----------------------------------

func (b *builder) types() *Scope {
	if b.g.Types == nil {
		b.g.Types = &Scope{Path: ScopeType}
	}
	return b.g.Types
}

func (b *builder) memberScope(segment string, owner *Node) *Scope {
	types := b.types()
	want := types.Path.Child(segment)
	for _, child := range types.Children {
		if child.Path == want {
			return child
		}
	}
	child := &Scope{Path: want, Parent: types, Owner: owner}
	types.Children = append(types.Children, child)
	return child
}

// lookupType finds a struct or enum by name. The most recent declaration wins,
// matching the scope chain: in a file mid-edit with two `struct Point`, the
// second is the one the cursor below it means.
func (b *builder) lookupType(name string, kind NodeKind) *Node {
	if b.g.Types == nil || name == "" {
		return nil
	}
	for i := len(b.g.Types.order) - 1; i >= 0; i-- {
		declared := b.g.Types.order[i]
		if declared.Name == name && declared.Kind == kind {
			return declared
		}
	}
	return nil
}

func (b *builder) lookupMember(declared *Node, member *ast.Identifier) *Node {
	if declared == nil || member == nil {
		return nil
	}
	for _, candidate := range b.g.membersOf(declared) {
		if candidate.Name == member.Value {
			return candidate
		}
	}
	return nil
}

// --- position arithmetic ----------------------------------------------------

// rangeContains mirrors the language server's own ContainsPosition, including
// its treatment of the end position as inside the range: a cursor immediately
// after an identifier is still on that identifier, which is what an editor
// means by the word.
func rangeContains(r ast.Range, line, column int) bool {
	if !r.IsValid() {
		return false
	}
	if before(line, column, r.Start.Line, r.Start.Column) {
		return false
	}
	if !before(line, column, r.End.Line, r.End.Column) &&
		!(line == r.End.Line && column == r.End.Column) {
		return false
	}
	return true
}

func startsAtOrBefore(r ast.Range, line, column int) bool {
	return !before(line, column, r.Start.Line, r.Start.Column)
}

func startsBefore(a, b ast.Range) bool {
	return before(a.Start.Line, a.Start.Column, b.Start.Line, b.Start.Column)
}

func before(lineA, columnA, lineB, columnB int) bool {
	if lineA != lineB {
		return lineA < lineB
	}
	return columnA < columnB
}
