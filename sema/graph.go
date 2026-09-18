package sema

import (
	"sort"
	"strconv"

	"mutant/ast"
)

// A Graph is what the names written in one file mean.
//
// It exists because the language server used to answer that question five
// separate times, with five hand-written recursive switches over the AST:
// resolveStatement/resolveExpression for go-to-definition, scopeAt*/advance*
// for the bindings visible at a position, referenceCollector for
// find-references, structTypeNameIn* for a field's owning type, and
// importNamespaces for the one thing none of the others knew about. Each of
// them re-encoded, independently, which nodes declare a name and which nodes
// are a child of which. A node type missing from one of them is not a
// compile error; it is a silently wrong answer, and there was one:
// *ast.ImportStatement appears in none of the five, so an import alias was not
// a binding. It could not be completed, it had no definition to go to, and
// VisibleBindingsAt did not list it -- while the doc comment above the caller
// said it did.
//
// This is that walk, once. Everything else is a lookup.
//
// # What it is not
//
// It holds no types. Whether a binding contains a Point is inference, it is
// per-snapshot and heuristic, and it belongs in the analyzer -- putting it here
// would invite the compiler to depend on a guess. The graph answers only
// questions with a definite answer: which declaration a name refers to, which
// declarations are in scope at a position, and where a declaration is used.
//
// It holds nothing from another file. Every ast.Node and every ast.Range in a
// Graph belongs to the module named by Module. A reference to another module is
// carried as a DeclID, which is a value, so a graph rebuilt after a keystroke
// cannot leave a pointer into a tree that no longer exists. A cross-module
// lookup that misses is a missing answer, never a wrong one.
type Graph struct {
	// Module is the CanonicalKey of the file, "" for a scratch buffer.
	Module string

	// Root is the file's top-level scope. It has no Range: it covers the file.
	Root *Scope

	// Types is the file's struct and enum declarations, and is nil in a file
	// that declares none. It is kept apart from Root because a type name is
	// not in the scope chain -- see typeStatement.
	Types *Scope

	nodes   map[DeclID]*Node
	decls   []*Node
	refList []Ref
	imports []ImportEdge
	fields  []fieldName

	// usesByTarget is the reverse of refList, and declOrder is decls sorted by
	// position. Both are built once at the end of BuildFile rather than on
	// demand, because a Graph is immutable afterwards and is read from more
	// than one goroutine -- an index built lazily would need a lock on every
	// query to save work on the queries that never happen.
	//
	// They are here because the callers ask in bulk. The unused-declaration
	// rules ask "is this used?" once per top-level declaration, so a file with
	// four hundred of them scanned every reference in itself four hundred
	// times: 88ms of the keystroke path, and growing with the square of the
	// file. The graph is what made that one question cheap; it has to make the
	// four hundredth cheap too.
	usesByTarget map[DeclID][]ast.Range
	declOrder    []*Node
}

// fieldName is the `x` of an `a.x`, recorded whether or not it resolved.
//
// Where a field name IS is a question about positions, which the walk answers.
// What it MEANS may not be: which field of which struct `p.x` names depends on
// what p holds. Recording the position separately is what lets a caller say
// "the cursor is on a field" without the graph having to claim which one.
type fieldName struct {
	ident *ast.Identifier
	rng   ast.Range
}

// StructOf names the struct a declaration holds, and "" when that is unknown or
// the caller does not know how to tell.
//
// It is the one thing a Graph is told rather than works out, and it is a
// function for the same reason ScopeCtx's members are: the answer lives
// somewhere different for each caller. The language server has an inference
// pass and a syntactic fallback; the compiler has neither and passes nil, which
// simply leaves `p.x` unresolved.
//
// It is handed the declaration's own identifier, never a use, so that a caller
// can answer it without first asking the graph what the use refers to -- which
// would be a cycle, since that is the question being answered.
type StructOf func(declaration *ast.Identifier) string

// NodeKind is what a declaration declares.
//
// It is not SymKind. SymKind describes a module's exports -- what another file
// can reach -- and has four members because that is all that crosses a module
// boundary. A graph node is a declaration anywhere in a file, including the
// ones that cross nothing: a parameter, a loop binding, an import alias.
type NodeKind uint8

const (
	KindValue NodeKind = iota
	KindFunction
	KindParam
	KindLoopBind
	KindNamespace
	KindStruct
	KindEnum
	KindField
	KindVariant
)

func (k NodeKind) String() string {
	switch k {
	case KindValue:
		return "value"
	case KindFunction:
		return "function"
	case KindParam:
		return "param"
	case KindLoopBind:
		return "loop binding"
	case KindNamespace:
		return "namespace"
	case KindStruct:
		return "struct"
	case KindEnum:
		return "enum"
	case KindField:
		return "field"
	case KindVariant:
		return "variant"
	}
	return "unknown"
}

// Node is one declaration.
type Node struct {
	ID   DeclID
	Kind NodeKind
	Name string

	// Ident is the identifier that declares the name, and is nil for exactly
	// one kind of declaration: `import "lib/report.mut";` binds `report`
	// without writing it, so there is no identifier to point at. DeclRange
	// covers the path literal in that case, which is the nearest thing in the
	// source that names the module.
	Ident *ast.Identifier

	// DeclRange is the range of the name itself, file-local, and is the zero
	// value when the name is not written anywhere -- which happens for exactly
	// one declaration, `import "lib/report.mut";`, where the namespace
	// `report` is derived from the path.
	//
	// That distinction is not pedantry. Rename replaces the text at every
	// range it is given, so handing it the path literal of a derived import
	// would turn `import "lib/report.mut";` into `import "newname";` and break
	// the program it was asked to tidy. Anything that EDITS reads this and
	// skips the declaration when it is absent; anything that merely POINTS
	// reads Anchor.
	DeclRange ast.Range

	// FullRange is the whole declaration -- the statement, not the name. It is
	// what an editor calls a symbol's range, as against its selectionRange.
	FullRange ast.Range

	// Scope is where the declaration lives.
	Scope *Scope

	// Target is set only for KindNamespace: the CanonicalKey of the module the
	// alias names, or "" when the import has not resolved to an indexed file.
	// An alias with no target is still a binding -- what is unknown is the
	// module's contents, not the fact that it is a module.
	Target string
}

// Ref is one use of a declaration.
type Ref struct {
	// Use is the node that refers. It is ast.Node rather than *ast.Identifier
	// because a later step records a whole FieldExpression referring to a
	// folded builtin, where no single identifier is the reference.
	Use      ast.Node
	UseRange ast.Range

	// Target is the declaration referred to.
	Target DeclID

	// InCallPosition reports that Use is the Function of a CallExpression. It
	// is a field on the reference rather than a separate set of call edges
	// because a separate set can drift out of step with this one and a field
	// cannot.
	InCallPosition bool
}

// ImportEdge is one `import` statement.
type ImportEdge struct {
	// From is the importing module's key; To is the imported module's key, and
	// is "" when the import does not resolve to an indexed file.
	From, To string

	// Alias is the name bound, already through ImportStatement.Namespace.
	// Spelling is the path exactly as written.
	Alias, Spelling string

	Range     ast.Range
	Statement *ast.ImportStatement
}

// Scope is a region of the file over which a set of declarations is in effect.
//
// Mutant has fewer scopes than its syntax suggests, and the graph must not
// invent the missing ones. A block does not open a scope: `{ let x = 1; }`
// leaves `x` bound afterwards. A `for (v in xs)` binding is defined in the
// enclosing scope, not the body, which is what the VM does with either loop
// form. Only a function literal and a macro literal open a scope, because only
// they have parameters.
type Scope struct {
	Path     ScopePath
	Parent   *Scope
	Children []*Scope

	// Range is the source this scope covers, and is the zero value at the root,
	// which covers the file.
	Range ast.Range

	// order is every declaration made in this scope, in source order. It is a
	// slice rather than a map because two declarations of one name are two
	// declarations -- `let x = 1; let x = 2;` -- and which one a position sees
	// depends on where the position is.
	order []*Node

	// latest is the declaration each name currently resolves to, which is the
	// most recent one the walk has reached.
	//
	// It is redundant with order, and it is here because without it every
	// reference scans the enclosing scope's declarations. At the top level of
	// a large file that scan is over every function in it, which made the walk
	// quadratic in file size: a two thousand line document cost 6.5ms to build
	// rather than the 600us it costs now. The five walks this replaced kept a
	// map for the same reason.
	latest map[string]*Node
}

// BuildFile builds the graph for one parsed file.
//
// It never fails and never returns nil. A file that did not parse cleanly still
// produces a graph over whatever the parser recovered, because that is the file
// the author is looking at.
//
// The workspace is optional and is read exactly once, for the module each
// import alias names. Passing nil yields a graph in which every alias is still
// a binding with no target -- which is what the REPL, the playground and a
// single-file analysis want.
//
// structOf is optional too. Passing nil leaves every `p.x` unresolved, which is
// honest: without it there is nothing in the file that says which struct p
// holds. It takes a fourth parameter rather than hiding behind a second
// constructor because a caller that skips it is choosing to get less, and that
// should be visible at the call.
func BuildFile(moduleKey string, program *ast.Program, w *Workspace, structOf StructOf) *Graph {
	g := &Graph{
		Module: moduleKey,
		Root:   &Scope{Path: ScopeTopLevel},
		nodes:  make(map[DeclID]*Node, 16),
	}
	if program == nil {
		return g
	}

	var targets map[string]string
	if w != nil && moduleKey != "" {
		targets = w.Namespaces(moduleKey)
	}

	b := &builder{
		g:        g,
		program:  program,
		scope:    g.Root,
		seq:      make(map[string]uint16, 16),
		anon:     make(map[*Scope]int, 4),
		targets:  targets,
		structOf: structOf,
	}
	for _, stmt := range program.Statements {
		b.statement(stmt)
	}

	// Sorted rather than left in walk order. HashLiteral.Pairs is a Go map, so
	// the walk reaches the uses inside a hash literal in a different order on
	// every run -- the same non-determinism that made HashLiteral.String
	// disagree with itself and two clone tests fail at random. Find-references
	// over a hash literal returned its locations shuffled for the same reason.
	// Sorting once here is cheaper than making every walk order-stable and
	// cannot be forgotten by a later case.
	sort.SliceStable(g.refList, func(i, j int) bool {
		return startsBefore(g.refList[i].UseRange, g.refList[j].UseRange)
	})

	g.usesByTarget = make(map[DeclID][]ast.Range, len(g.decls))
	for _, ref := range g.refList {
		g.usesByTarget[ref.Target] = append(g.usesByTarget[ref.Target], ref.UseRange)
	}

	g.declOrder = make([]*Node, 0, len(g.decls))
	for _, node := range g.decls {
		if node.DeclRange.IsValid() {
			g.declOrder = append(g.declOrder, node)
		}
	}
	sort.SliceStable(g.declOrder, func(i, j int) bool {
		return startsBefore(g.declOrder[i].DeclRange, g.declOrder[j].DeclRange)
	})
	return g
}

type builder struct {
	g        *Graph
	program  *ast.Program
	scope    *Scope
	seq      map[string]uint16
	anon     map[*Scope]int
	targets  map[string]string
	structOf StructOf
}

func (b *builder) rangeOf(node ast.Node) (ast.Range, bool) {
	if node == nil || b.program == nil {
		return ast.Range{}, false
	}
	rng, ok := b.program.RangeOf(node)
	if !ok || !rng.IsValid() {
		return ast.Range{}, false
	}
	return rng, true
}

// declare records a declaration in the current scope and returns it.
func (b *builder) declare(name string, ident *ast.Identifier, rng ast.Range, kind NodeKind) *Node {
	return b.declareIn(b.scope, name, ident, rng, rng, kind)
}

// declareIn records a declaration. declRange is the name; fullRange is the
// whole declaration. They are the same range for everything except an import,
// where the name may not have been written at all.
func (b *builder) declareIn(scope *Scope, name string, ident *ast.Identifier, declRange, fullRange ast.Range, kind NodeKind) *Node {
	if scope == nil || name == "" || (!declRange.IsValid() && !fullRange.IsValid()) {
		return nil
	}

	key := string(scope.Path) + ModuleSeparator + name
	seq := b.seq[key]
	b.seq[key] = seq + 1

	node := &Node{
		ID:        DeclID{Module: b.g.Module, Scope: scope.Path, Name: name, Seq: seq},
		Kind:      kind,
		Name:      name,
		Ident:     ident,
		DeclRange: declRange,
		FullRange: fullRange,
		Scope:     scope,
	}
	scope.order = append(scope.order, node)
	if scope.latest == nil {
		scope.latest = make(map[string]*Node, 8)
	}
	scope.latest[name] = node
	b.g.nodes[node.ID] = node
	b.g.decls = append(b.g.decls, node)
	return node
}

// lookup finds the declaration a name refers to at the point the walk has
// reached: the most recent declaration of that name in the innermost scope that
// has one.
//
// Most recent, not first, and this is load-bearing. `let x = 1; let x = 2; x;`
// refers to the second, and the two are separate declarations with separate
// identities, so renaming one must not rename the other.
func (b *builder) lookup(name string) *Node {
	for scope := b.scope; scope != nil; scope = scope.Parent {
		if declared, bound := scope.latest[name]; bound {
			return declared
		}
	}
	return nil
}

// reference records that ident refers to whatever is bound at this point in the
// walk. An unbound name records nothing: a name with no declaration has no
// reference to record, and inventing one is how a jump into an unrelated file
// starts.
func (b *builder) reference(ident *ast.Identifier, inCall bool) {
	if ident == nil {
		return
	}
	rng, ok := b.rangeOf(ident)
	if !ok {
		return
	}
	target := b.lookup(ident.Value)
	if target == nil {
		return
	}
	b.record(ident, rng, target.ID, inCall)
}

// record stores a reference in one flat list and nothing else.
//
// There is deliberately no map from the referring node to its reference. One
// was written and had no caller: every consumer asks by position or by target,
// and both of those are indexed at the end of the build. Keeping an unused
// index is not free here -- it is an interface-keyed map write per identifier
// in the file, on a walk that is already allocation-bound.
func (b *builder) record(use ast.Node, rng ast.Range, target DeclID, inCall bool) {
	b.g.refList = append(b.g.refList, Ref{
		Use: use, UseRange: rng, Target: target, InCallPosition: inCall,
	})
}

// push opens a scope. segment names it after the declaration it belongs to
// where there is one, and after an ordinal otherwise, never after a position:
// a position-based identity changes on every keystroke above it, which would
// make a rename mid-edit rename the wrong thing.
func (b *builder) push(segment string, rng ast.Range) {
	child := &Scope{Path: b.scope.Path.Child(segment), Parent: b.scope, Range: rng}
	b.scope.Children = append(b.scope.Children, child)
	b.scope = child
}

func (b *builder) pop() {
	if b.scope.Parent != nil {
		b.scope = b.scope.Parent
	}
}

// segmentFor names a scope after the declaration that owns it. The sequence
// number is included when it is not the first, so two sibling functions with
// one name do not hand their parameters the same identity.
func segmentFor(node *Node, fallback string) string {
	if node == nil {
		return fallback
	}
	if node.Seq() == 0 {
		return node.Name
	}
	return node.Name + "#" + strconv.FormatUint(uint64(node.Seq()), 10)
}

// Anchor is where to point at this declaration: the name where one is written,
// and the whole declaration otherwise. Go-to-definition uses it; rename must
// not.
func (n *Node) Anchor() ast.Range {
	if n == nil {
		return ast.Range{}
	}
	if n.DeclRange.IsValid() {
		return n.DeclRange
	}
	return n.FullRange
}

// Seq is the declaration's sequence number within its scope.
func (n *Node) Seq() uint16 {
	if n == nil {
		return 0
	}
	return n.ID.Seq
}

func (b *builder) anonSegment(prefix string) string {
	n := b.anon[b.scope]
	b.anon[b.scope] = n + 1
	return prefix + "#" + strconv.Itoa(n)
}
