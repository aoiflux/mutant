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

// UnboundUses returns every use of a name the file declares nowhere, in source
// order.
//
// It is the whole-file list because that is how the one caller asks: a rule
// reporting undefined names wants all of them, and nothing wants to ask about
// one position. See Unbound for what the list does and does not claim -- in
// particular that a builtin is declared nowhere and so appears here.
func (g *Graph) UnboundUses() []Unbound {
	if g == nil {
		return nil
	}
	return g.unbound
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

// EnclosingDeclarationAt returns the declaration whose scope contains the
// position: the function a call is written inside.
//
// There is no answer at the top level of a file, and that is a real answer
// rather than a missing one -- a call written at the top level is made by the
// file, not by anything the file declares. A caller that needs to name it has
// to name it itself; the graph will not invent a declaration that is not
// there.
//
// An anonymous literal is skipped, because it declares nothing: a call inside
// `map(xs, fn(x) { helper(x); })` belongs to whatever declares the map call.
// That is Ref.From's rule, and this is the same question asked of a position
// rather than of a reference -- which is what a use the graph did not record,
// such as a reach into another module, needs.
func (g *Graph) EnclosingDeclarationAt(line, column int) (*Node, bool) {
	if g == nil || g.Root == nil {
		return nil, false
	}
	scope := g.scopeAt(line, column)
	if scope == nil || scope.enclosing == nil {
		return nil, false
	}
	return scope.enclosing, true
}

// LocalScopeAt is the file-local half of a name decision at a position.
//
// It exists so that there is one answer to "what has this file bound here",
// rather than one per caller. The language server used to assemble it from a
// name match over VisibleAt, and that was wrong in a way no single-package test
// could show: VisibleAt returns type names, because a bare `Point` has to
// resolve to the struct that declares it, and counting one as a binding made
// the editor disagree with the compiler about every program that declares a
// struct named after a builtin family.
//
// A type name is not a value binding, and the split here is structural rather
// than a filter: values, functions, parameters, loop bindings and import
// aliases live in the scope tree, struct and enum names live in Types, and only
// the scope tree is walked. That mirrors the compiler exactly -- a type name
// never enters the symbol table, which is what its Bound reads -- so
// `struct rand { int }; rand.int` folds to rand_int in the editor for the same
// reason it does in a build.
//
// Enums are supplied separately because ResolveField asks about them first:
// `Colour.Red` predates modules and is not a field read on a value.
func (g *Graph) LocalScopeAt(line, column int) LocalScope {
	if g == nil {
		return LocalScope{}
	}
	// The covering scope is found once here rather than once per name. The
	// descent looks at the children of every scope on the way down, and at a
	// file's top level those are every function in the file; the builtin-call
	// rules ask about one name per call site, so paying the descent per
	// question made a keystroke cost grow with the square of the document.
	scope := g.scopeAt(line, column)
	return LocalScope{
		Bound: func(name string) bool { return valueBoundIn(scope, name, line, column) },
		Enums: g.EnumDeclared,
	}
}

// valueBoundIn reports whether name is bound to a value at the position, looking
// outwards from scope: the ScopeCtx.Bound predicate.
//
// It must not report true for a bare builtin, and cannot: builtins are not
// declarations and never enter a scope. That exclusion is commit a901ce4, and
// it is now a property of where things are stored rather than a test somebody
// has to remember to write.
//
// The position is part of the question and not a refinement of it. A name
// declared below the use is not bound at it, which is what a file looks like
// while it is being written -- and while it is being written is when the editor
// is asked the most questions.
func valueBoundIn(scope *Scope, name string, line, column int) bool {
	if name == "" {
		return false
	}
	for ; scope != nil; scope = scope.Parent {
		if declared, exists := scope.first[name]; exists &&
			startsAtOrBefore(declared.Anchor(), line, column) {
			return true
		}
	}
	return false
}

// EnumDeclared reports whether this file declares an enum under a name.
//
// It is file-local, and deliberately: an enum reached through an import is
// visible to the compiler, whose enumDefinitions map is program-wide, and not
// to a single file's graph. parity/bare_name_parity_test.go records that gap as
// the behaviour it is, rather than closing it here where only half the program
// is in hand.
func (g *Graph) EnumDeclared(name string) bool {
	declared, _, found := g.TypeNamed(name)
	return found && declared.Kind == KindEnum
}

// scopeAt returns the innermost scope covering the position.
func (g *Graph) scopeAt(line, column int) *Scope {
	scope := g.Root
	for {
		next := childCovering(scope, line, column)
		if next == nil {
			return scope
		}
		scope = next
	}
}

// childCovering is the child of scope that contains the position, or nil.
//
// Children are in source order and do not overlap, so there is only ever one
// candidate: the last one that starts at or before the position. Everything
// after it starts later, and everything before it ended before it began. The
// containment check still runs, because the candidate may simply have closed
// before the position -- a position between two functions is in neither.
//
// It is a search rather than a scan because the scan was over every function
// in the file, once per name any rule asked about.
func childCovering(scope *Scope, line, column int) *Scope {
	children := scope.Children
	at := sort.Search(len(children), func(i int) bool {
		return !startsAtOrBefore(children[i].Range, line, column)
	}) - 1
	if at < 0 {
		return nil
	}
	if child := children[at]; rangeContains(child.Range, line, column) {
		return child
	}
	return nil
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
