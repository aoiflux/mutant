package analyzer

import (
	"sort"
	"strings"

	mast "mutant/ast"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// The cross-module half of name resolution, which the language server has never
// had. It asks sema exactly what the compiler asks it, so an answer the editor
// gives is an answer the build will agree with.

// moduleMemberSource marks these as the compiler's own refusals rather than a
// lint: they are things the build will reject, not style advice.
const moduleMemberSource = "mutant-modules"

// localScopeAt is what the workspace cannot know: which names this file has
// bound at pos, and which enums it declares.
//
// The split is the whole design. Everything file-local comes from the
// snapshot's own scope walk, everything cross-module from the workspace, and
// one resolver puts them together with the precedence the compiler uses.
func (s *Snapshot) localScopeAt(pos lsp.Position) sema.LocalScope {
	return sema.LocalScope{
		Bound: func(name string) bool { return s.isBoundAt(name, pos) },
		Enums: func(name string) bool {
			_, declared := s.enumVariantNames(name)
			return declared
		},
	}
}

// startOf is the LSP position an ast.Range begins at. Ranges are 1-based in the
// AST and 0-based in the protocol.
func startOf(rng mast.Range) lsp.Position {
	return lsp.Position{
		Line:      lsp.UInteger(rng.Start.Line - 1),
		Character: lsp.UInteger(rng.Start.Column - 1),
	}
}

// namespaceField is one `ns.member` in the document, with the range to report
// at. Left is always an identifier: `a.b.c` is a field read on a value, not a
// reach into a module, and the module rules have nothing to say about it.
type namespaceField struct {
	node  *mast.FieldExpression
	rng   mast.Range
	left  string
	field string
}

// namespaceFields collects every `ident.member` in the document, in source
// order.
//
// Source order matters: NodePositions is a map, and diagnostics built by
// ranging over it would arrive in a different order on every keystroke, which
// clients render as the list flickering.
func (s *Snapshot) namespaceFields() []namespaceField {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil
	}

	fields := make([]namespaceField, 0, 8)
	for node, rng := range s.Program.NodePositions {
		field, isField := node.(*mast.FieldExpression)
		if !isField || field == nil || field.Field == nil {
			continue
		}
		left, isIdent := field.Left.(*mast.Identifier)
		if !isIdent || left == nil {
			continue
		}
		fields = append(fields, namespaceField{node: field, rng: rng, left: left.Value, field: field.Field.Value})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].rng.Start.Offset < fields[j].rng.Start.Offset
	})
	return fields
}

// fieldExpressionAt returns the innermost `ident.member` the position falls
// inside, so `a.b.c` answers about `.c` when the cursor is on `c`.
func (s *Snapshot) fieldExpressionAt(pos lsp.Position) (namespaceField, bool) {
	var (
		best  namespaceField
		found bool
	)
	for _, candidate := range s.namespaceFields() {
		if !contains(candidate.rng, pos) {
			continue
		}
		span := candidate.rng.End.Offset - candidate.rng.Start.Offset
		if !found || span < best.rng.End.Offset-best.rng.Start.Offset {
			best, found = candidate, true
		}
	}
	return best, found
}

// ModuleMemberTarget names the declaration `ns.member` refers to: the module it
// lives in, its name there, and where it is written.
//
// Go-to-definition wants only the last of those. Find-references and rename want
// the identity, because "every use of this" is a question about a declaration
// and not about a place -- the same declaration is reached through a different
// alias in every file that imports it, and under two aliases in a file that
// imports it twice.
//
// It answers only for a Certain resolution. A module the workspace has not read
// yet yields Provisional, and the editor must then show nothing: a jump to a
// guess is worse than no jump, because the user cannot tell the difference until
// they are already looking at the wrong file.
func (s *Snapshot) ModuleMemberTarget(pos lsp.Position) (moduleKey, name string, declaration lsp.Location, ok bool) {
	if s == nil || s.workspace == nil || s.ModuleKey == "" {
		return "", "", lsp.Location{}, false
	}
	field, found := s.fieldExpressionAt(pos)
	if !found {
		return "", "", lsp.Location{}, false
	}

	owner, uri, declRange, resolved := s.workspace.DefinitionOf(
		s.ModuleKey, s.localScopeAt(pos), field.left, field.field,
	)
	if !resolved || uri == "" || !declRange.IsValid() {
		return "", "", lsp.Location{}, false
	}
	return owner, field.field, lsp.Location{
		URI:   lsp.DocumentUri(uri),
		Range: toLSPRange(declRange),
	}, true
}

// ModuleMemberDefinition locates the declaration `ns.member` refers to, when the
// position sits on such an expression and ns is an import namespace.
func (s *Snapshot) ModuleMemberDefinition(pos lsp.Position) (lsp.Location, bool) {
	_, _, declaration, ok := s.ModuleMemberTarget(pos)
	if !ok {
		return lsp.Location{}, false
	}
	return declaration, true
}

// ModuleMemberDiagnostics reports the reaches into another module that the
// compiler will refuse: a private name, and a name the module does not declare.
//
// The sentence is sema's, unchanged, so the squiggle and the build error are
// the same words rather than two phrasings of one rule.
//
// Nothing is reported for a module the workspace has not read. The underscore
// rule is about the name and holds regardless, but "declares no such name"
// about an unread file would be a refusal invented out of ignorance -- sema
// marks that case Provisional and it never reaches here.
func (s *Snapshot) ModuleMemberDiagnostics() []lsp.Diagnostic {
	if s == nil || s.workspace == nil || s.ModuleKey == "" {
		return nil
	}

	var diagnostics []lsp.Diagnostic
	for _, field := range s.namespaceFields() {
		// The scope is taken at the expression's own start. That is exact for
		// the question being asked: whether `ns` is an import namespace is a
		// property of the file, not of the point inside it.
		resolved := s.workspace.ResolveField(
			s.ModuleKey, s.localScopeAt(startOf(field.rng)), field.left, field.field,
		)
		if resolved.Kind != sema.FieldRefused || resolved.Refusal == nil {
			continue
		}

		severity := lsp.DiagnosticSeverityError
		source := moduleMemberSource
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    toLSPRange(field.rng),
			Severity: &severity,
			Source:   &source,
			Message:  resolved.Refusal.Error(),
		})
	}
	return diagnostics
}

// ModuleMemberHover describes the declaration `ns.member` refers to.
//
// It names the module, because that is the thing the reader cannot see from
// where they are standing -- the point of an import is that the code is
// elsewhere.
//
// A function shows its parameter names and no types. Mutant has no parameter
// annotations, and this package's inferred kinds are per-snapshot and
// explicitly heuristic; one file's guess about another file's function would be
// a guess presented as a fact. Nor is the declaration's leading comment shown:
// carrying it would mean holding text from a file this document does not own,
// and it is not in ModuleFacts today.
func (s *Snapshot) ModuleMemberHover(pos lsp.Position) (string, mast.Range, bool) {
	if s == nil || s.workspace == nil || s.ModuleKey == "" {
		return "", mast.Range{}, false
	}
	field, ok := s.fieldExpressionAt(pos)
	if !ok {
		return "", mast.Range{}, false
	}

	export, declaredIn, found := s.workspace.MemberFact(
		s.ModuleKey, s.localScopeAt(pos), field.left, field.field,
	)
	if !found {
		return "", mast.Range{}, false
	}

	signature := export.Name
	kind := "value"
	if export.Kind == sema.SymFunction {
		kind = "function"
		signature += "(" + strings.Join(export.Params, ", ") + ")"
	}

	text := "```mutant\n" + signature + "\n```\n\n" +
		kind + " `" + export.Name + "`, declared in `" + declaredIn + "`"
	return text, field.rng, true
}
