package analyzer

import (
	"sort"

	mast "mutant/ast"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// FoldingRanges returns the collapsible regions of the document: every
// multi-line block/brace-delimited construct (function/if/else/for bodies,
// struct and enum bodies, and multi-line array/hash literals) plus runs of
// consecutive `//` line comments. Lines are zero-based, as the LSP requires.
func (s *Snapshot) FoldingRanges() []lsp.FoldingRange {
	if s == nil || s.Program == nil {
		return nil
	}

	var ranges []lsp.FoldingRange

	// Structural folds: any recorded node that spans more than one line and is
	// one of the brace/bracket-delimited constructs.
	if s.Program.NodePositions != nil {
		for node, rng := range s.Program.NodePositions {
			if !rng.IsValid() || rng.End.Line <= rng.Start.Line {
				continue
			}
			if !isFoldableNode(node) {
				continue
			}
			ranges = append(ranges, lsp.FoldingRange{
				StartLine: uint32(rng.Start.Line - 1),
				EndLine:   uint32(rng.End.Line - 1),
			})
		}
	}

	ranges = append(ranges, commentFoldingRanges(s.Program.Comments)...)

	if len(ranges) == 0 {
		return nil
	}

	// Deterministic order (NodePositions iteration is random) and drop exact
	// duplicates (e.g. a function literal body and its enclosing block sharing
	// the same span).
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].StartLine != ranges[j].StartLine {
			return ranges[i].StartLine < ranges[j].StartLine
		}
		return ranges[i].EndLine < ranges[j].EndLine
	})
	compact := ranges[:0:0]
	for _, r := range ranges {
		if n := len(compact); n > 0 && compact[n-1].StartLine == r.StartLine && compact[n-1].EndLine == r.EndLine {
			continue
		}
		compact = append(compact, r)
	}
	return compact
}

// isFoldableNode reports whether a node is a multi-line construct worth folding.
func isFoldableNode(node mast.Node) bool {
	switch node.(type) {
	case *mast.BlockStatement, // fn / if / else / for bodies
		*mast.StructStatement,
		*mast.EnumStatement,
		*mast.ArrayLiteral,
		*mast.HashLiteral:
		return true
	default:
		return false
	}
}

// commentFoldingRanges coalesces runs of consecutive `//` line comments into a
// single foldable region each. A run must span at least two lines to fold.
func commentFoldingRanges(comments []token.Comment) []lsp.FoldingRange {
	var out []lsp.FoldingRange
	kind := string(lsp.FoldingRangeKindComment)

	i := 0
	for i < len(comments) {
		if comments[i].Kind != token.LineComment {
			i++
			continue
		}
		start := i
		for i+1 < len(comments) &&
			comments[i+1].Kind == token.LineComment &&
			comments[i+1].Start.Line == comments[i].Start.Line+1 {
			i++
		}
		if comments[i].Start.Line > comments[start].Start.Line {
			out = append(out, lsp.FoldingRange{
				StartLine: uint32(comments[start].Start.Line - 1),
				EndLine:   uint32(comments[i].Start.Line - 1),
				Kind:      &kind,
			})
		}
		i++
	}
	return out
}
