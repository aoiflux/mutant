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
	unbound []Unbound

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

	// FullRange is the statement that declares the name, where a statement
	// declares it, and the name itself where none does. It is what an editor
	// calls a symbol's range, as against its selectionRange, and DeclRange is
	// contained by it whenever both exist.
	//
	// Four statements declare: `let`, `struct`, `enum` and `import`. For
	// those FullRange reaches over the whole statement, including a `let`
	// that binds several names -- `let value, err = read(p);` is one
	// declaration of two names, which is what Grouped records.
	//
	// It is the name alone in two cases. A parameter and a loop binding are
	// declared by an expression or a loop header rather than by a statement:
	// `fn(a, b)` is a value and `for (k, v in xs)` is a loop, and neither is
	// the declaration of `a` or of `k`. A struct field and an enum variant
	// are parts of the type their statement declares rather than things it
	// declares beside it, so the statement is `Point`'s declaration and not
	// `x`'s. That is the same line the analyzer's own documentSymbol draws
	// when it gives a child symbol a range equal to its name.
	FullRange ast.Range

	// Scope is where the declaration lives.
	Scope *Scope

	// Target is set only for KindNamespace: the CanonicalKey of the module the
	// alias names, or "" when the import has not resolved to an indexed file.
	// An alias with no target is still a binding -- what is unknown is the
	// module's contents, not the fact that it is a module.
	Target string

	// Grouped reports whether the statement that made this declaration bound
	// more than one name: `let text, err = read(path);`.
	//
	// That is not a stylistic detail in Mutant, it is the shape of the error
	// idiom, so rules downstream have to tell it from a plain let. It is
	// recorded here because a caller cannot recover it afterwards -- the names
	// of one `let` become separate nodes, and nothing else they carry says they
	// came from one statement -- and because it is a fact about the
	// declaration, of the same kind as Kind.
	Grouped bool
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

	// From is the declaration the use sits inside, and is nil at the top level
	// of the file. Anonymous literals declare nothing, so a use inside one
	// belongs to the nearest declaration that does.
	//
	// It is a pointer rather than a DeclID for two reasons. A Graph never
	// points outside its own module, so there is nothing here a pointer could
	// dangle into -- the rule that keeps cross-module references as values
	// does not apply within one file. And a DeclID is three strings and an
	// ordinal; storing one per reference on a walk that is already
	// allocation-bound costs more than the fact is worth.
	//
	// With InCallPosition it is a call graph without a second traversal: a
	// call is an edge From -> Target. That is what `mutant graph export`
	// writes, and what a call hierarchy would read.
	From *Node
}

// UnboundKind says what a name's absence means. It is about the position the
// name was written in rather than about the name, because the position is what
// decides: `nope` on its own is a variable nobody declared, `nope` in
// `nope.thing` may be a builtin family with a misspelled member, and `Nope` in
// `Nope{x: 1}` is a struct type, looked up in a different table from either.
type UnboundKind uint8

const (
	// UnboundValue is a name standing on its own: `foo;`, `f(foo)`, `foo + 1`.
	UnboundValue UnboundKind = iota

	// UnboundReceiver is the left of a field access: `nope` of `nope.thing`.
	UnboundReceiver

	// UnboundType is the name of a struct literal: `Nope` of `Nope{x: 1}`.
	//
	// It is separate from UnboundValue because the two are answered from
	// different tables -- see typeStatement -- so `let Nope = 1;` does not give
	// `Nope{x: 1}` a type, and the compiler refuses that program with
	// "undefined struct type: Nope" while the name is plainly bound.
	UnboundType
)

func (k UnboundKind) String() string {
	switch k {
	case UnboundValue:
		return "value"
	case UnboundReceiver:
		return "receiver"
	case UnboundType:
		return "type"
	}
	return "unbound"
}

// Unbound is a use of a name that this file declares nowhere.
//
// This is the plan's RefUnresolved, in the shape the rest of the package forced
// it into. It is deliberately NOT a Ref in the reference list: every consumer of
// References and UsesOf assumes Target names a declaration, so a reference with
// no target would have to be skipped by each of them in turn -- definition,
// find-references, rename, the export -- and the one that forgot would jump
// somewhere it had invented. Kept in a list of its own it cannot be reached by
// any of them, and the caller that wants the misses asks for them by name.
//
// "This file declares no such name" is exactly what is recorded, and it is
// narrower than "this name means nothing". A builtin is declared nowhere, so
// `len` is in this list, and `len` means something. That is not an oversight:
// the graph is a fact about the file, whereas which names the runtime provides
// is the builtin registry's business, and ResolveField already answers it.
// Deciding it here would put a second copy of the registry's opinion in the
// walk, which is what this package exists to prevent.
//
// Nor does it contradict ScopeCtx.Bound, which reports false for a bare builtin
// on purpose -- see the a901ce4 note there. Bound answers "is this name TAKEN,
// so that `rand.int` must be a field access rather than a fold", and a builtin
// does not take a name. This answers "did the file declare it", and a builtin is
// not declared. Both are false of `rand` at once, and they are different
// questions.
type Unbound struct {
	// Name is the name that resolved to nothing.
	Name string

	Kind UnboundKind

	// Use is the identifier and UseRange is its range. For UnboundReceiver that
	// is the left of the field access -- `nope` of `nope.thing` -- and not the
	// whole expression.
	Use      ast.Node
	UseRange ast.Range

	// Member is the name written after the dot, and WholeRange covers
	// `nope.thing` entire. Both are set for UnboundReceiver only.
	//
	// They are recorded because the two halves are one mistake and a caller
	// cannot recover the second from the first: the graph holds no map from a
	// node to its parent, so a caller given `nope` alone cannot see that a dot
	// follows it. Which matters -- `hash.blake3` is a real builtin and `hash`
	// alone is not a name at all.
	Member     string
	WholeRange ast.Range

	// InCall reports that the name was the function of a call. It is set for
	// UnboundValue only, and it exists because `quote(x)` and `quote` are not
	// the same claim: the first is a macro special form the evaluator gives
	// meaning to, the second is a name the compiler refuses.
	InCall bool
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

	// Owner is the declaration that opened this scope: the function a
	// parameter belongs to, the struct a field belongs to. It is nil at the
	// root, and nil for an anonymous literal, which opens a scope without
	// declaring anything.
	//
	// It is the other half of Parent. Parent says which scope encloses this
	// one; Owner says which declaration does, which is the question a nesting
	// view asks -- an outline, a call hierarchy, the CONTAINS edge of an
	// export. Recorded here because the walk knows it for free and anything
	// else would have to work it out again from positions.
	Owner *Node

	// Range is the source this scope covers, and is the zero value at the root,
	// which covers the file.
	Range ast.Range

	// order is every declaration made in this scope, in source order. It is a
	// slice rather than a map because two declarations of one name are two
	// declarations -- `let x = 1; let x = 2;` -- and which one a position sees
	// depends on where the position is.
	order []*Node

	// enclosing is Owner where there is one and the parent's enclosing
	// otherwise, so the declaration a use belongs to is a field read rather
	// than a walk up the chain. It is filled in at push, because a scope's
	// parent never changes afterwards.
	enclosing *Node

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

	// first is the earliest declaration of each name here, and is what makes
	// "is this name bound at a position" a map lookup.
	//
	// The earliest is the one worth keeping, because the question is whether
	// ANY declaration of the name stands at or before the position and order is
	// source order: if one does, the earliest does. latest cannot answer it --
	// `let x = 1; f(); let x = 2;` binds x at the call, and latest names the
	// declaration below it.
	//
	// It is the same bargain latest struck, for the same reason. Without it a
	// Bound query at a file's top level scans every top-level declaration in
	// the file, and the builtin-call rules ask one per call site.
	first map[string]*Node
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

	// The misses, for the same reason: a diagnostic list whose order depends on
	// Go's map iteration reports the same file differently on consecutive runs.
	sort.SliceStable(g.unbound, func(i, j int) bool {
		return startsBefore(g.unbound[i].UseRange, g.unbound[j].UseRange)
	})

	// Scopes, for the same reason and one more: scopeAt finds the scope
	// covering a position by searching the children, and a search needs what it
	// searches to be in order. A function literal written inside a hash literal
	// is reached whenever the map hands it over, so without this the search
	// would find the right scope on most runs and a random ancestor on the
	// rest -- which reads as the editor occasionally forgetting a parameter.
	sortScopes(g.Root)

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

// sortScopes puts every scope's children in source order, depth first.
//
// Siblings do not overlap -- a scope written inside another is that scope's
// child, not its sibling -- so source order is also a total order over the
// positions they cover, which is what lets scopeAt binary-search them.
func sortScopes(scope *Scope) {
	if scope == nil || len(scope.Children) == 0 {
		return
	}
	sort.SliceStable(scope.Children, func(i, j int) bool {
		return startsBefore(scope.Children[i].Range, scope.Children[j].Range)
	})
	for _, child := range scope.Children {
		sortScopes(child)
	}
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

// declare records a declaration that no statement makes -- a parameter, a
// loop binding, a struct field, an enum variant -- in the current scope. For
// those the name is the whole of it.
//
// A declaration that reaches further than its name calls declareIn directly
// with both ranges. Node.FullRange says which are which.
func (b *builder) declare(name string, ident *ast.Identifier, rng ast.Range, kind NodeKind) *Node {
	return b.declareIn(b.scope, name, ident, rng, rng, kind)
}

// spanning is the range a declaration reaches over: the statement when the
// walk could find one, and the name when it could not. A declaration always
// ends up with a FullRange, because something has to be able to point at it.
func spanning(name, statement ast.Range) ast.Range {
	if statement.IsValid() {
		return statement
	}
	return name
}

// declareIn records a declaration. declRange is the name; fullRange is how far
// the declaration reaches.
//
// They are separate parameters rather than one range and a flag because an
// import can have a fullRange and no declRange at all: `import "lib/report.mut";`
// binds `report` without the word appearing anywhere.
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
		scope.first = make(map[string]*Node, 8)
	}
	scope.latest[name] = node
	if _, seen := scope.first[name]; !seen {
		scope.first[name] = node
	}
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
// walk.
//
// A name with no declaration records no REFERENCE -- it has none, and inventing
// one is how a jump into an unrelated file starts -- but it is not forgotten
// either. It goes in the unbound list instead, which nothing that jumps can
// reach. A rule that reports undefined names wants exactly the misses, and
// before this it had to walk the file again to find them, with its own second
// account of which nodes declare a name.
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
		b.noteUnbound(ident, rng, UnboundValue, inCall)
		return
	}
	b.record(ident, rng, target.ID, inCall)
}

// noteUnbound records a use of a name this file declares nowhere. See Unbound
// for why it is kept apart from the references.
func (b *builder) noteUnbound(ident *ast.Identifier, rng ast.Range, kind UnboundKind, inCall bool) {
	b.g.unbound = append(b.g.unbound, Unbound{
		Name: ident.Value, Kind: kind, Use: ident, UseRange: rng, InCall: inCall,
	})
}

// unboundReceiver records `nope` of `nope.thing` where nope is bound to
// nothing, keeping the member and the whole expression's range beside it.
func (b *builder) unboundReceiver(left *ast.Identifier, node *ast.FieldExpression) {
	rng, ok := b.rangeOf(left)
	if !ok {
		return
	}
	miss := Unbound{Name: left.Value, Kind: UnboundReceiver, Use: left, UseRange: rng}
	if node.Field != nil {
		miss.Member = node.Field.Value
	}
	miss.WholeRange, _ = b.rangeOf(node)
	b.g.unbound = append(b.g.unbound, miss)
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
		From: b.enclosing(),
	})
}

// enclosing is the declaration the walk is currently inside: the nearest scope
// that has an owner. The search skips anonymous literals, which open a scope
// and declare nothing, so a use inside `map(xs, fn(x) { helper(x); })` is
// attributed to whatever declares the map call rather than to nothing.
func (b *builder) enclosing() *Node {
	return b.scope.enclosing
}

// push opens a scope. segment names it after the declaration it belongs to
// where there is one, and after an ordinal otherwise, never after a position:
// a position-based identity changes on every keystroke above it, which would
// make a rename mid-edit rename the wrong thing.
func (b *builder) push(segment string, rng ast.Range, owner *Node) {
	enclosing := owner
	if enclosing == nil {
		enclosing = b.scope.enclosing
	}
	child := &Scope{
		Path: b.scope.Path.Child(segment), Parent: b.scope, Range: rng,
		Owner: owner, enclosing: enclosing,
	}
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
