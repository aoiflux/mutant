package analyzer

import (
	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Definition, references and the bindings visible at a position, answered by
// asking sema.Graph rather than by walking the tree.
//
// This file was 1547 lines and five recursive switches over every AST node
// type: one to resolve a definition, one to collect references, one pair to
// rebuild the scope at a position, and one to find the struct a binding holds.
// They agreed with each other only by being written carefully, and a node type
// missing from one of them was a silently wrong answer rather than a build
// failure. *ast.ImportStatement was missing from all five, which is why an
// import alias could not be completed, had no definition to go to, and was not
// listed by VisibleBindingsAt while the comment above isBoundAt said it was.
//
// The walk now happens once, in sema.BuildFile, and everything here is a
// lookup. What remains in this package is the one question the graph refuses:
// which struct a value holds, which is inference. See struct_type.go.

// binding is what the cursor refers to, in the vocabulary the editor protocol
// uses.
//
// It is a view of a sema.Node rather than a second model of one. sema does not
// import the editor protocol and must not -- it is read by the compiler too --
// so the translation from NodeKind to CompletionItemKind happens here, once.
type binding struct {
	// name is the name bound. ident is the identifier that binds it, and is
	// nil when the author never wrote the name: `import "lib/report.mut";`
	// binds `report` with no `report` in the file.
	//
	// Both are here because the callers want different things. Anything that
	// asks "is this name in scope?" or offers a completion wants the name, and
	// asking it of ident silently skips every derived import alias. Anything
	// that looks a declaration up by identity -- an inferred type, a function
	// literal, the comment above it -- wants the node, and correctly finds
	// nothing when there is not one.
	name  string
	ident *mast.Identifier
	rng   mast.Range
	kind  lsp.CompletionItemKind

	// named reports that rng is the name itself rather than the declaration
	// around it. It is false for exactly one declaration: the namespace of an
	// `import "lib/report.mut";`, which binds `report` without the word
	// appearing in the file. Anything that edits text has to ask.
	named bool
}

// Graph returns this document's name graph, building it once on first use.
//
// It follows the same lazy pattern as the inferred type map: an analysis that
// only lints never pays for it, and one that answers a position question pays
// for it once however many questions follow.
//
// Nothing reachable from the build may call this. The build asks structHeldBy
// which struct a declaration holds, structHeldBy may run the inference pass,
// and a sync.Once that re-enters itself deadlocks rather than recursing -- a
// language server that stops answering, with no error anywhere. Inference does
// not ask the graph anything today and must not start: it works out what a name
// is WORTH, which needs no answer to which declaration it is. If that ever has
// to change, the fix is to give the oracle a syntactic answer only, not to make
// this re-entrant.
func (s *Snapshot) Graph() *sema.Graph {
	if s == nil {
		return nil
	}
	s.graphOnce.Do(func() {
		s.graph = sema.BuildFile(s.ModuleKey, s.Program, s.workspace, s.structHeldBy)
	})
	return s.graph
}

func (s *Snapshot) DefinitionLocation(uri lsp.DocumentUri, pos lsp.Position) (*lsp.Location, bool) {
	resolved, ok := s.resolveDefinition(pos)
	if !ok {
		return nil, false
	}
	return &lsp.Location{URI: uri, Range: localprotocol.ToLSPRange(resolved.rng)}, true
}

// ReferenceLocations returns every place in this document that refers to
// whatever the position refers to.
//
// The declaration comes first and the uses follow in source order, which is the
// order they are written in: resolution is forward-only, so nothing can refer
// to a declaration written below it except a function calling itself, whose
// declaration is still above the call.
func (s *Snapshot) ReferenceLocations(uri lsp.DocumentUri, pos lsp.Position, includeDeclaration bool) ([]lsp.Location, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	graph := s.Graph()
	declared, ok := graph.Resolve(tokenPosition(pos))
	if !ok {
		// Deliberately not the self-referring field that resolveDefinition
		// falls back to. A field whose owning struct is unknown has no
		// occurrences to report, and hover depends on hearing that: it asks
		// for references to decide whether the name really is a field, and
		// `hash.blake2` -- which is the builtin hash_blake2, not a field --
		// must fall through to the builtin card rather than be described as
		// one.
		return nil, false
	}

	locations := make([]lsp.Location, 0, 4)
	// DeclRange rather than Anchor, deliberately. These locations are what
	// rename turns into edits, and a declaration whose name is not written --
	// the namespace of an `import "lib/report.mut";` -- has no text to
	// replace. Offering the statement's range instead would rewrite the path.
	if includeDeclaration && declared.DeclRange.IsValid() {
		locations = append(locations, lsp.Location{
			URI:   uri,
			Range: localprotocol.ToLSPRange(declared.DeclRange),
		})
	}
	for _, use := range graph.UsesOf(declared.ID) {
		locations = append(locations, lsp.Location{
			URI:   uri,
			Range: localprotocol.ToLSPRange(use),
		})
	}

	if len(locations) == 0 {
		return nil, false
	}
	return locations, true
}

// VisibleBindingsAt returns what the author has bound at a position: a let, a
// parameter, a loop binding, an import namespace, a struct or an enum name.
//
// The import namespace is not a figure of speech here. It was in this comment
// before it was in the answer.
func (s *Snapshot) VisibleBindingsAt(pos lsp.Position) []binding {
	if s == nil || s.Program == nil {
		return nil
	}

	nodes := s.Graph().VisibleAt(tokenPosition(pos))
	bindings := make([]binding, 0, len(nodes))
	for _, node := range nodes {
		bindings = append(bindings, bindingOf(node))
	}
	return bindings
}

// structHeldBy is the sema.StructOf the graph is built with: the name of the
// struct a declaration holds, so that `p.x` resolves to Point's field rather
// than to Vector's.
//
// Two sources, cheapest first. structTypeNameForDeclaration reads the statement
// that declares the binding and needs no inference pass; TypeOf runs one, and
// reaches a struct that arrived through a function's return or through another
// binding. Neither is consulted unless a field expression is actually walked.
//
// This runs INSIDE Graph's sync.Once, so neither source may ask for the graph.
// See the note on Graph: the failure would be a deadlock, not a stack overflow,
// and a deadlocked language server reports nothing at all.
func (s *Snapshot) structHeldBy(declaration *mast.Identifier) string {
	if declaration == nil {
		return ""
	}
	if name, ok := s.structTypeNameForDeclaration(declaration); ok {
		return name
	}
	if held, ok := s.TypeOf(declaration); ok && held.Kind == TypeStruct {
		return held.Name
	}
	return ""
}

// resolveDefinition is the declaration the position refers to.
//
// The fallback is the one answer that is not a declaration: a field name whose
// owning struct nothing could work out resolves to itself, so the editor
// reports "this is a field called x" rather than reporting nothing. It is the
// honest answer to `p.x` where p's type is unknown -- the name is certainly a
// field, and which one is certainly not known.
func (s *Snapshot) resolveDefinition(pos lsp.Position) (binding, bool) {
	if s == nil || s.Program == nil {
		return binding{}, false
	}

	graph := s.Graph()
	if declared, ok := graph.Resolve(tokenPosition(pos)); ok {
		return bindingOf(declared), true
	}
	if field, rng, ok := graph.FieldNameAt(tokenPosition(pos)); ok {
		return binding{name: field.Value, ident: field, rng: rng, kind: lsp.CompletionItemKindField, named: true}, true
	}
	return binding{}, false
}

// RenameableAt reports whether the name at a position can be renamed by
// editing text.
//
// It is false for one thing: a namespace bound by an import that does not write
// it. `import "lib/report.mut";` binds `report` with no `report` anywhere in
// the file, so renaming it would edit every use and leave the binding behind --
// each edit a step towards a program that no longer compiles. The author's fix
// is to give the import an explicit alias first, which is an edit they make and
// not one an editor can invent on their behalf.
func (s *Snapshot) RenameableAt(pos lsp.Position) bool {
	resolved, ok := s.resolveDefinition(pos)
	return ok && resolved.named
}

func (s *Snapshot) identifierRange(ident *mast.Identifier) (mast.Range, bool) {
	if ident == nil || s == nil || s.Program == nil {
		return mast.Range{}, false
	}
	return s.Program.RangeOf(ident)
}

func bindingOf(node *sema.Node) binding {
	if node == nil {
		return binding{}
	}
	return binding{
		name:  node.Name,
		ident: node.Ident,
		rng:   node.Anchor(),
		kind:  completionKindFor(node.Kind),
		named: node.DeclRange.IsValid(),
	}
}

// completionKindFor is the whole of the translation between what sema knows a
// declaration to be and what the editor protocol calls it.
func completionKindFor(kind sema.NodeKind) lsp.CompletionItemKind {
	switch kind {
	case sema.KindFunction:
		return lsp.CompletionItemKindFunction
	case sema.KindNamespace:
		return lsp.CompletionItemKindModule
	case sema.KindStruct:
		return lsp.CompletionItemKindStruct
	case sema.KindEnum:
		return lsp.CompletionItemKindEnum
	case sema.KindField:
		return lsp.CompletionItemKindField
	case sema.KindVariant:
		return lsp.CompletionItemKindEnumMember
	}
	// A let, a parameter and a loop binding are all a variable to an editor.
	return lsp.CompletionItemKindVariable
}

// tokenPosition converts an editor position to the coordinates ast.Range holds.
// The protocol counts lines and characters from zero; the lexer counts lines and
// columns from one.
func tokenPosition(pos lsp.Position) (line, column int) {
	return int(pos.Line) + 1, int(pos.Character) + 1
}
