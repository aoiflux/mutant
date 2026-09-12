package ast

import (
	"testing"

	"mutant/token"
)

func pos(line, column, offset int) token.Position {
	return token.Position{Line: line, Column: column, Offset: offset}
}

func TestPositionShift(t *testing.T) {
	got := pos(3, 5, 40).Shift(10, 200)
	want := pos(13, 5, 240)
	if got != want {
		t.Fatalf("shifted = %+v, want %+v", got, want)
	}
}

// TestPositionShiftLeavesInvalidAlone pins the rule that "unknown" survives
// linking. A node with no recorded position must not acquire a plausible one
// just because its module was linked after another; a fabricated line sends a
// reader to code that has nothing to do with the failure.
func TestPositionShiftLeavesInvalidAlone(t *testing.T) {
	for _, p := range []token.Position{{}, {Line: 0, Column: 4, Offset: 9}} {
		if got := p.Shift(10, 200); got != p {
			t.Fatalf("an invalid position moved: %+v -> %+v", p, got)
		}
	}
}

func TestProgramShiftPositionsMovesEveryTable(t *testing.T) {
	node := &Identifier{Value: "x"}
	macroNode := &Identifier{Value: "y"}

	program := &Program{
		NodePositions: map[Node]Range{
			node: {Start: pos(1, 1, 0), End: pos(1, 2, 1)},
		},
		Comments: []token.Comment{
			{Kind: token.LineComment, Text: "// hi", Start: pos(2, 1, 10), End: pos(2, 6, 15)},
		},
		MacroExpansions: map[Node]MacroOrigin{
			macroNode: {
				Call:       Range{Start: pos(3, 1, 20), End: pos(3, 4, 23)},
				Definition: Range{Start: pos(4, 1, 30), End: pos(4, 9, 38)},
			},
		},
	}

	program.ShiftPositions(100, 1000)

	if got := program.NodePositions[node]; got.Start != pos(101, 1, 1000) || got.End != pos(101, 2, 1001) {
		t.Fatalf("NodePositions not shifted: %+v", got)
	}
	if got := program.Comments[0]; got.Start != pos(102, 1, 1010) || got.End != pos(102, 6, 1015) {
		t.Fatalf("Comments not shifted: %+v", got)
	}
	origin := program.MacroExpansions[macroNode]
	if origin.Call.Start != pos(103, 1, 1020) || origin.Call.End != pos(103, 4, 1023) {
		t.Fatalf("MacroExpansions.Call not shifted: %+v", origin.Call)
	}
	if origin.Definition.Start != pos(104, 1, 1030) || origin.Definition.End != pos(104, 9, 1038) {
		t.Fatalf("MacroExpansions.Definition not shifted: %+v", origin.Definition)
	}
}

// TestProgramShiftPositionsByZeroIsANoOp lets the entry module run through the
// same path as every other module instead of being special-cased.
func TestProgramShiftPositionsByZeroIsANoOp(t *testing.T) {
	node := &Identifier{Value: "x"}
	original := Range{Start: pos(1, 1, 0), End: pos(1, 2, 1)}
	program := &Program{NodePositions: map[Node]Range{node: original}}

	program.ShiftPositions(0, 0)

	if got := program.NodePositions[node]; got != original {
		t.Fatalf("a zero shift changed a position: %+v", got)
	}
}

func TestProgramShiftPositionsHandlesNilReceiverAndTables(t *testing.T) {
	var nilProgram *Program
	nilProgram.ShiftPositions(1, 1)

	empty := &Program{}
	empty.ShiftPositions(1, 1)

	if len(empty.NodePositions) != 0 || len(empty.Comments) != 0 || len(empty.MacroExpansions) != 0 {
		t.Fatal("shifting an empty program invented entries")
	}
}
