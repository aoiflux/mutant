package analyzer

import (
	mast "mutant/ast"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// A call hierarchy is the graph read as a call graph, which it already is.
//
// Every reference the walk records carries two things beyond its target: the
// declaration it is written inside, and whether it stands in the function
// position of a call. Together those are an edge -- From calls Target -- and
// sema.Ref's own doc says so, which is why there is no second traversal here
// and no separate set of call edges to drift out of step with the references.
//
// Everything in this file is file-local. A call into another module is written
// `alias.name(...)`, and the graph holds nothing from another file on purpose,
// so those edges are assembled by the server from the workspace index. The
// split is deliberate: a Graph that could name a declaration in a file it has
// not got is a Graph that can hand out a stale pointer.

// CallNode is one end of a call edge: the declaration, and where the calls that
// make it an edge are written.
//
// It is expressed in ranges rather than in a sema.DeclID because the protocol
// hands the item back on the next request, after any number of edits. A DeclID
// is valid only inside the Graph that minted it and must not outlive one query,
// so the position is what travels and the declaration is resolved afresh each
// time -- the same contract go-to-definition works under.
type CallNode struct {
	Name string
	Kind lsp.SymbolKind

	// Range is the whole declaration; SelectionRange is its name. They are what
	// an editor calls an item's range and selectionRange, and they differ for
	// exactly one declaration -- an import whose alias was never written.
	Range          mast.Range
	SelectionRange mast.Range

	// CallRanges are the places the call is written. For an incoming call they
	// are inside the caller; for an outgoing call they are inside the
	// declaration the hierarchy started from. Either way the editor highlights
	// them, so they are the call sites and never the declaration.
	CallRanges []mast.Range
}

// CallHierarchyRootAt returns the declaration a call hierarchy starting at this
// position is about.
//
// The cursor may be on the declaration itself or on any use of it, because both
// are how a reader asks "who calls this": the name in the signature, and the
// name at a call. Resolve answers both.
func (s *Snapshot) CallHierarchyRootAt(pos lsp.Position) (CallNode, bool) {
	node, ok := s.callHierarchyNodeAt(pos)
	if !ok {
		return CallNode{}, false
	}
	return callNodeFor(node, nil), true
}

// IncomingCalls returns the declarations in this file that call the one at the
// position, each with the call sites that make it so.
func (s *Snapshot) IncomingCalls(pos lsp.Position) []CallNode {
	graph, node, ok := s.callHierarchyContext(pos)
	if !ok {
		return nil
	}

	// A file's top level can call things and is not a declaration, so its calls
	// are collected under a zero caller and reported separately. The server
	// names it after the file, which is the only thing that can.
	byCaller := make(map[*sema.Node][]mast.Range, 4)
	order := make([]*sema.Node, 0, 4)
	for _, ref := range graph.References() {
		if !ref.InCallPosition || ref.Target != node.ID || ref.From == nil {
			continue
		}
		if _, seen := byCaller[ref.From]; !seen {
			order = append(order, ref.From)
		}
		byCaller[ref.From] = append(byCaller[ref.From], ref.UseRange)
	}

	calls := make([]CallNode, 0, len(order))
	for _, caller := range order {
		calls = append(calls, callNodeFor(caller, byCaller[caller]))
	}
	return calls
}

// OutgoingCalls returns the declarations in this file that the one at the
// position calls.
//
// A recursive call appears here, and should: `let f = fn() { f(); };` is a call
// from f to f, and a hierarchy that hid it would be hiding the thing a reader
// opened it to find.
func (s *Snapshot) OutgoingCalls(pos lsp.Position) []CallNode {
	graph, node, ok := s.callHierarchyContext(pos)
	if !ok {
		return nil
	}

	byCallee := make(map[*sema.Node][]mast.Range, 4)
	order := make([]*sema.Node, 0, 4)
	for _, ref := range graph.References() {
		if !ref.InCallPosition || ref.From != node {
			continue
		}
		callee, found := graph.NodeFor(ref.Target)
		if !found || callee == nil {
			continue
		}
		if _, seen := byCallee[callee]; !seen {
			order = append(order, callee)
		}
		byCallee[callee] = append(byCallee[callee], ref.UseRange)
	}

	calls := make([]CallNode, 0, len(order))
	for _, callee := range order {
		calls = append(calls, callNodeFor(callee, byCallee[callee]))
	}
	return calls
}

// EnclosingCallNodeAt names the declaration a position is written inside, for a
// call the graph did not record -- a reach into another module, which is
// resolved by the workspace rather than by this file's walk.
//
// It returns false at the top level, where there is no declaration to name.
func (s *Snapshot) EnclosingCallNodeAt(line, column int) (CallNode, bool) {
	graph := s.Graph()
	if graph == nil {
		return CallNode{}, false
	}
	node, ok := graph.EnclosingDeclarationAt(line, column)
	if !ok {
		return CallNode{}, false
	}
	return callNodeFor(node, nil), true
}

// DeclarationCallNode names a top-level declaration of this file by name, which
// is how a cross-module call site asks about the member it reaches.
func (s *Snapshot) DeclarationCallNode(name string) (CallNode, bool) {
	graph := s.Graph()
	if graph == nil || name == "" {
		return CallNode{}, false
	}
	for _, node := range graph.TopLevel() {
		if node != nil && node.Name == name {
			return callNodeFor(node, nil), true
		}
	}
	return CallNode{}, false
}

func (s *Snapshot) callHierarchyContext(pos lsp.Position) (*sema.Graph, *sema.Node, bool) {
	node, ok := s.callHierarchyNodeAt(pos)
	if !ok {
		return nil, nil, false
	}
	return s.Graph(), node, true
}

// callHierarchyNodeAt resolves a position to the declaration a hierarchy is
// about, and refuses the kinds that cannot be one.
//
// A struct, an enum, a field and a variant are refused because nothing calls
// them: `Point` in `Point{x: 1}` is a type, and offering a call hierarchy for
// it would offer an empty one. A let and a parameter are NOT refused, because a
// function in Mutant is a value: `let f = fn() {...}` declares a value, a
// parameter can hold one, and both are called by name.
func (s *Snapshot) callHierarchyNodeAt(pos lsp.Position) (*sema.Node, bool) {
	graph := s.Graph()
	if graph == nil {
		return nil, false
	}
	line, column := tokenPosition(pos)
	node, ok := graph.Resolve(line, column)
	if !ok || node == nil {
		return nil, false
	}
	switch node.Kind {
	case sema.KindStruct, sema.KindEnum, sema.KindField, sema.KindVariant, sema.KindNamespace:
		return nil, false
	}
	return node, true
}

func callNodeFor(node *sema.Node, callRanges []mast.Range) CallNode {
	return CallNode{
		Name:           node.Name,
		Kind:           symbolKindFor(node.Kind),
		Range:          node.FullRange,
		SelectionRange: node.Anchor(),
		CallRanges:     callRanges,
	}
}

// symbolKindFor is completionKindFor's sibling for the other of the protocol's
// two kind enumerations. They are separate enumerations in LSP with separate
// numbering, so one cannot be cast to the other.
func symbolKindFor(kind sema.NodeKind) lsp.SymbolKind {
	switch kind {
	case sema.KindFunction:
		return lsp.SymbolKindFunction
	case sema.KindNamespace:
		return lsp.SymbolKindModule
	case sema.KindStruct:
		return lsp.SymbolKindStruct
	case sema.KindEnum:
		return lsp.SymbolKindEnum
	case sema.KindField:
		return lsp.SymbolKindField
	case sema.KindVariant:
		return lsp.SymbolKindEnumMember
	}
	return lsp.SymbolKindVariable
}
