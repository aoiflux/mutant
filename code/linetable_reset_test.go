package code

import (
	"bytes"
	"testing"
)

// buildReset is build's sibling for a table whose position is optional per
// construct. Every entry goes through AddOrReset, so an entry carrying no line
// is encoded as the end of the previous entry's coverage instead of being
// dropped.
func buildReset(t *testing.T, entries ...[3]int) LineTable {
	t.Helper()
	var b LineTableBuilder
	for _, e := range entries {
		b.AddOrReset(e[0], e[1], e[2])
	}
	return b.Build()
}

// At answers with the last entry at or before an offset, so a table with no way
// to record the end of an entry's coverage reports the last macro a program
// expanded as the origin of every instruction after it.
func TestLineTableResetEndsThePreviousEntrysCoverage(t *testing.T) {
	table := buildReset(t,
		[3]int{0, 7, 3},  // instructions a macro defined on line 7 produced
		[3]int{10, 0, 0}, // and here the expansion ends
		[3]int{20, 9, 1}, // a second expansion, from a different definition
	)

	for _, ip := range []int{0, 5, 9} {
		line, col, ok := table.At(ip)
		if !ok || line != 7 || col != 3 {
			t.Errorf("At(%d) = %d:%d (ok=%v), want 7:3", ip, line, col, ok)
		}
	}

	for _, ip := range []int{10, 15, 19} {
		if line, _, ok := table.At(ip); ok {
			t.Errorf("At(%d) = line %d, want unknown: the reset at ip 10 ended the entry at ip 0", ip, line)
		}
	}

	for _, ip := range []int{20, 999} {
		line, col, ok := table.At(ip)
		if !ok || line != 9 || col != 1 {
			t.Errorf("At(%d) = %d:%d (ok=%v), want 9:1", ip, line, col, ok)
		}
	}
}

// Nothing is in force before the first entry, and At already reports unknown
// there, so a reset ahead of any position must cost no bytes at all -- most
// programs never expand a macro and their macro table has to stay empty.
func TestLineTableLeadingResetsAreDropped(t *testing.T) {
	if table := buildReset(t, [3]int{0, 0, 0}, [3]int{4, 0, 0}); table != nil {
		t.Errorf("Build() = %v, want nil: no entry carried a position", table)
	}

	withLeading := buildReset(t, [3]int{0, 0, 0}, [3]int{4, 5, 1})
	plain := build(t, [3]int{4, 5, 1})
	if !bytes.Equal(withLeading, plain) {
		t.Errorf("a leading reset was encoded: %v, want %v", withLeading, plain)
	}
}

// One reset ends the coverage; a second says the same thing again. The dedup
// that keeps a statement's dozen instructions down to one entry has to cover
// resets too, or every instruction outside a macro costs an entry.
func TestLineTableConsecutiveResetsCollapse(t *testing.T) {
	once := buildReset(t, [3]int{0, 7, 3}, [3]int{10, 0, 0})
	thrice := buildReset(t, [3]int{0, 7, 3}, [3]int{10, 0, 0}, [3]int{12, 0, 0}, [3]int{14, 0, 0})

	if !bytes.Equal(once, thrice) {
		t.Errorf("three consecutive resets encoded as %v, want the one entry %v", thrice, once)
	}
}

// The main line table keeps the opposite contract: an instruction the compiler
// synthesised carries no position and must inherit the enclosing construct's,
// which is what dropping the call achieves. Changing that would turn every
// injected security check into a hole in the table.
func TestLineTableAddStillInheritsForAnUnpositionedInstruction(t *testing.T) {
	var b LineTableBuilder
	b.Add(0, 7, 3)
	b.Add(10, 0, 0)
	table := b.Build()

	line, col, ok := table.At(10)
	if !ok || line != 7 || col != 3 {
		t.Errorf("At(10) = %d:%d (ok=%v), want 7:3 inherited from ip 0", line, col, ok)
	}
}

// Remap moves a table through a pass that moved the instructions. A reset has
// to move with the rest: dropping it would re-extend the entry before it over
// everything the pass shifted, which is the whole defect again, arriving by a
// different route in any build with polymorphism on -- which is every ordinary
// one.
func TestLineTableRemapKeepsResets(t *testing.T) {
	table := buildReset(t, [3]int{0, 7, 3}, [3]int{10, 0, 0}, [3]int{20, 9, 1})

	moved := table.Remap(map[int]int{0: 0, 10: 14, 20: 30})
	if moved.Empty() {
		t.Fatal("Remap dropped the whole table")
	}

	if line, _, ok := moved.At(14); ok {
		t.Errorf("At(14) after remap = line %d, want unknown: the reset moved from ip 10 to ip 14", line)
	}
	if line, _, ok := moved.At(13); !ok || line != 7 {
		t.Errorf("At(13) after remap = line %d (ok=%v), want 7", line, ok)
	}
	if line, _, ok := moved.At(30); !ok || line != 9 {
		t.Errorf("At(30) after remap = line %d (ok=%v), want 9", line, ok)
	}
}

// A reset must never look like a line with code on it, because the reverse
// index is what an editor asks which lines can hold a breakpoint.
func TestLineIndexIgnoresResets(t *testing.T) {
	index := BuildLineIndex(buildReset(t, [3]int{0, 7, 3}, [3]int{10, 0, 0}, [3]int{20, 9, 1}))

	for _, line := range index.Lines() {
		if line <= 0 {
			t.Errorf("Lines() = %v, want no line 0: a reset is not a line of source", index.Lines())
			break
		}
	}
	if ip, bound, ok := index.At(7); !ok || ip != 0 || bound != 7 {
		t.Errorf("At(7) = ip %d bound %d (ok=%v), want ip 0 bound 7", ip, bound, ok)
	}
}
