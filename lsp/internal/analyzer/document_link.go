package analyzer

import (
	mast "mutant/ast"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// StringLiteralRef is a string literal's inner-text range (quotes excluded) and
// decoded value. The server uses these to turn string literals that name
// existing files into clickable document links.
type StringLiteralRef struct {
	Range lsp.Range
	Value string
}

// StringLiteralRefs returns every string literal in the document.
func (s *Snapshot) StringLiteralRefs() []StringLiteralRef {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil
	}
	var refs []StringLiteralRef
	for node, rng := range s.Program.NodePositions {
		lit, ok := node.(*mast.StringLiteral)
		if !ok || lit == nil || lit.Value == "" || !rng.IsValid() {
			continue
		}
		start := lsp.Position{Line: uint32(rng.Start.Line - 1), Character: uint32(rng.Start.Column - 1)}
		end := lsp.Position{Line: uint32(rng.End.Line - 1), Character: uint32(rng.End.Column - 1)}
		// Trim the surrounding quotes for a single-line literal so the underline
		// covers just the path text.
		if start.Line == end.Line && end.Character >= start.Character+2 {
			start.Character++
			end.Character--
		}
		refs = append(refs, StringLiteralRef{Range: lsp.Range{Start: start, End: end}, Value: lit.Value})
	}
	return refs
}
