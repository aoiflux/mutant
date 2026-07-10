package protocol

import (
	mast "mutant/ast"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func ToLSPPosition(pos token.Position) lsp.Position {
	if !pos.IsValid() {
		return lsp.Position{}
	}

	return lsp.Position{
		Line:      lsp.UInteger(pos.Line - 1),
		Character: lsp.UInteger(pos.Column - 1),
	}
}

func ToLSPRange(rng mast.Range) lsp.Range {
	return lsp.Range{
		Start: ToLSPPosition(rng.Start),
		End:   ToLSPPosition(rng.End),
	}
}

func ContainsPosition(rng mast.Range, pos lsp.Position) bool {
	line := int(pos.Line) + 1
	col := int(pos.Character) + 1
	if before(line, col, rng.Start.Line, rng.Start.Column) {
		return false
	}
	if !before(line, col, rng.End.Line, rng.End.Column) && !(line == rng.End.Line && col == rng.End.Column) {
		return false
	}
	return true
}

func before(lineA, colA, lineB, colB int) bool {
	if lineA != lineB {
		return lineA < lineB
	}
	return colA < colB
}
