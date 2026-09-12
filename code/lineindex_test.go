package code

import "testing"

func TestALineIndexFindsWhereALineStarts(t *testing.T) {
	index := BuildLineIndex(build(t,
		[3]int{0, 1, 1},
		[3]int{6, 2, 1},
		[3]int{9, 2, 14}, // a second column on line 2
		[3]int{20, 3, 1},
	))

	cases := []struct {
		line  int
		ip    int
		bound int
	}{
		{line: 1, ip: 0, bound: 1},
		{line: 2, ip: 6, bound: 2}, // the lower of line 2's two offsets
		{line: 3, ip: 20, bound: 3},
	}

	for _, tc := range cases {
		ip, bound, ok := index.At(tc.line)
		if !ok {
			t.Fatalf("line %d was not found", tc.line)
		}
		if ip != tc.ip || bound != tc.bound {
			t.Errorf("line %d resolved to ip %d on line %d, want ip %d on line %d",
				tc.line, ip, bound, tc.ip, tc.bound)
		}
	}
}

// A breakpoint on a blank line, a comment, or a declaration that emitted
// nothing has to land somewhere, and the caller has to be told where -- an
// editor that leaves the marker on line 4 while the program stops on line 7 is
// lying about both.
func TestALineWithNoCodeBindsForward(t *testing.T) {
	index := BuildLineIndex(build(t,
		[3]int{0, 2, 1},
		[3]int{8, 7, 1},
	))

	for _, line := range []int{3, 4, 5, 6, 7} {
		ip, bound, ok := index.At(line)
		if !ok {
			t.Fatalf("line %d bound to nothing", line)
		}
		if bound != 7 || ip != 8 {
			t.Errorf("line %d bound to ip %d on line %d, want ip 8 on line 7", line, ip, bound)
		}
	}
}

// Past the last line with code there is no instruction left to stop at, so the
// only honest answer is that the breakpoint cannot be placed.
func TestALineAfterTheLastInstructionBindsToNothing(t *testing.T) {
	index := BuildLineIndex(build(t, [3]int{0, 1, 1}, [3]int{4, 9, 1}))

	if _, _, ok := index.At(10); ok {
		t.Error("a line past the end of the program was given an instruction")
	}
	if _, _, ok := index.At(0); ok {
		t.Error("line 0 resolved; lines are 1-based")
	}
}

// A stream compiled without positions and one stripped of them are the same
// empty table, and both have to answer "I do not know" rather than guess.
func TestAnEmptyTableIndexesToNothing(t *testing.T) {
	for name, table := range map[string]LineTable{"nil": nil, "empty": {}} {
		index := BuildLineIndex(table)
		if !index.Empty() {
			t.Errorf("%s table produced a non-empty index", name)
		}
		if _, _, ok := index.At(1); ok {
			t.Errorf("%s table answered a lookup", name)
		}
		if lines := index.Lines(); lines != nil {
			t.Errorf("%s table reported lines %v", name, lines)
		}
	}
}

// The index is built once and queried for the life of a debug session, so a
// caller that sorts or appends to what Lines returns must not be able to
// corrupt every later answer.
func TestLinesHandsBackACopy(t *testing.T) {
	index := BuildLineIndex(build(t, [3]int{0, 3, 1}, [3]int{4, 1, 1}))

	first := index.Lines()
	if len(first) != 2 || first[0] != 1 || first[1] != 3 {
		t.Fatalf("lines came back as %v, want [1 3] ascending", first)
	}

	first[0] = 99
	if second := index.Lines(); second[0] != 1 {
		t.Errorf("writing to the returned slice changed the index: %v", second)
	}
}

// Emission is monotonic in the offset and not in the line: a `for` post section
// is emitted after the body that follows it in the source, so an index that
// assumed ascending lines would binary-search a slice that is not sorted and
// answer the wrong line without ever reporting a failure.
func TestLinesArriveOutOfOrderAndAreSorted(t *testing.T) {
	index := BuildLineIndex(build(t,
		[3]int{0, 10, 1},
		[3]int{3, 11, 1},
		[3]int{7, 10, 20}, // back to line 10: the loop's post section
		[3]int{11, 12, 1},
	))

	lines := index.Lines()
	for i := 1; i < len(lines); i++ {
		if lines[i-1] >= lines[i] {
			t.Fatalf("lines are not ascending and de-duplicated: %v", lines)
		}
	}

	ip, bound, ok := index.At(10)
	if !ok || ip != 0 || bound != 10 {
		t.Errorf("line 10 resolved to ip %d on line %d, want its first offset 0", ip, bound)
	}
}

// The shared decoder is what At, Remap and BuildLineIndex all read the format
// through, so a truncated table has to leave every one of them with the entries
// that did decode rather than taking one of them down.
func TestATruncatedTableDecodesAsFarAsItCan(t *testing.T) {
	full := build(t, [3]int{0, 1, 1}, [3]int{5, 2, 1}, [3]int{9, 3, 1})
	cut := full[:len(full)-1]

	index := BuildLineIndex(cut)
	if index.Empty() {
		t.Fatal("a truncated table decoded to nothing at all")
	}
	if _, _, ok := index.At(1); !ok {
		t.Error("the entries before the truncation were lost")
	}

	// And the forward lookup agrees with it rather than panicking.
	if _, _, ok := cut.At(0); !ok {
		t.Error("At lost the entries before the truncation")
	}
}
