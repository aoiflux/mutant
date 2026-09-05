package code

import "testing"

func build(t *testing.T, entries ...[3]int) LineTable {
	t.Helper()
	var b LineTableBuilder
	for _, e := range entries {
		b.Add(e[0], e[1], e[2])
	}
	return b.Build()
}

func at(t *testing.T, table LineTable, ip int) (int, int, bool) {
	t.Helper()
	return table.At(ip)
}

func TestLineTableRoundTrip(t *testing.T) {
	table := build(t, [3]int{0, 1, 1}, [3]int{10, 2, 5}, [3]int{25, 7, 3})

	cases := []struct {
		ip        int
		line, col int
	}{
		{0, 1, 1},
		{5, 1, 1},   // between entries: the entry at or before ip wins
		{9, 1, 1},   // last byte before the next entry
		{10, 2, 5},  // exactly on an entry
		{24, 2, 5},  //
		{25, 7, 3},  //
		{999, 7, 3}, // past the end: the final entry still covers it
	}

	for _, c := range cases {
		line, col, ok := at(t, table, c.ip)
		if !ok {
			t.Fatalf("At(%d): not found, want %d:%d", c.ip, c.line, c.col)
		}
		if line != c.line || col != c.col {
			t.Errorf("At(%d) = %d:%d, want %d:%d", c.ip, line, col, c.line, c.col)
		}
	}
}

// A position that moves backwards is ordinary: the compiler emits a loop's jump
// after its body, attributed to the `for` on an earlier line. The line delta is
// signed for exactly this.
func TestLineTableHandlesBackwardsPositions(t *testing.T) {
	table := build(t, [3]int{0, 10, 4}, [3]int{6, 3, 20}, [3]int{12, 10, 4})

	for _, c := range []struct{ ip, line, col int }{{0, 10, 4}, {6, 3, 20}, {12, 10, 4}} {
		line, col, ok := at(t, table, c.ip)
		if !ok || line != c.line || col != c.col {
			t.Errorf("At(%d) = %d:%d (ok=%v), want %d:%d", c.ip, line, col, ok, c.line, c.col)
		}
	}
}

// The compression: a statement compiling to many instructions costs one entry.
func TestLineTableRecordsOnlyPositionChanges(t *testing.T) {
	var repeated LineTableBuilder
	for ip := 0; ip < 200; ip += 2 {
		repeated.Add(ip, 1, 1)
	}
	table := repeated.Build()

	if len(table) > 4 {
		t.Errorf("100 instructions on one line encoded to %d bytes, want a single entry", len(table))
	}

	line, col, ok := at(t, table, 150)
	if !ok || line != 1 || col != 1 {
		t.Errorf("At(150) = %d:%d (ok=%v), want 1:1", line, col, ok)
	}
}

func TestLineTableReportsUnknownBeforeFirstEntry(t *testing.T) {
	// Instructions the compiler emitted before it had any position to attribute.
	table := build(t, [3]int{8, 4, 2})

	if _, _, ok := at(t, table, 0); ok {
		t.Error("At(0) resolved against a table whose first entry is at ip 8")
	}
	if _, _, ok := at(t, table, 7); ok {
		t.Error("At(7) resolved against a table whose first entry is at ip 8")
	}
	if _, _, ok := at(t, table, 8); !ok {
		t.Error("At(8) did not resolve the entry recorded at ip 8")
	}
}

func TestLineTableEmpty(t *testing.T) {
	var b LineTableBuilder
	table := b.Build()

	if table != nil {
		t.Errorf("Build() on an empty builder = %v, want nil", table)
	}
	if !table.Empty() {
		t.Error("Empty() = false on a nil table")
	}
	if _, _, ok := table.At(0); ok {
		t.Error("At(0) resolved against an empty table")
	}
}

// A stripped table and a never-populated one must be indistinguishable: that is
// what makes StripDebugInfo leak nothing about what was removed.
func TestLineTableDropsUnpositionedAndOutOfOrderEntries(t *testing.T) {
	var b LineTableBuilder
	b.Add(0, 0, 0)   // no position recorded for the node
	b.Add(4, -1, 12) // likewise
	b.Add(-1, 3, 1)  // negative ip
	if got := b.Build(); got != nil {
		t.Errorf("Build() = %v, want nil: no entry carried a position", got)
	}

	var c LineTableBuilder
	c.Add(10, 5, 1)
	c.Add(2, 9, 1) // ip moves backwards -- dropped, not encoded
	table := c.Build()

	line, _, ok := table.At(10)
	if !ok || line != 5 {
		t.Errorf("At(10) = line %d (ok=%v), want 5", line, ok)
	}
	if line, _, ok := table.At(2); ok {
		t.Errorf("At(2) = line %d, want unknown: the out-of-order entry should have been dropped", line)
	}
}
