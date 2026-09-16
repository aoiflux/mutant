package code

import "sort"

// A LineIndex is the reverse of a LineTable: it answers "which instruction does
// this source line start at", which is the question a breakpoint asks and the
// only one the table itself cannot answer. LineTable is a delta sequence with
// no index, built to be decoded forwards from offset zero; walking it per query
// would be fine for the handful of frames a traceback renders and wrong for an
// editor that sets thirty breakpoints on every keystroke. So the whole table is
// decoded once and the answers kept.
//
// The lines are the ones the table records, which for a linked program are
// lines of the concatenated source blob rather than of any one file. Turning a
// file and a line into a blob line is the caller's job -- ByteCode.ModuleAt
// does the inverse -- and this type knows only about the blob.
type LineIndex struct {
	// firstIP holds the lowest recorded offset for each line. Lowest rather
	// than any, because a line compiles to a run of instructions and a
	// breakpoint belongs at the start of it: stopping in the middle of `total =
	// total + weigh(x)` would show the line as pending when half of it has
	// already run.
	firstIP map[int]int

	// lines is the same line numbers, ascending, so a line that emitted nothing
	// can be answered with the next one that did. Kept sorted at build time;
	// every query is a binary search over it.
	lines []int
}

// BuildLineIndex decodes t once and returns its reverse index.
//
// A table with no entries yields an index that finds nothing, which is the
// correct answer for a stream compiled without positions and for one stripped
// of them -- the same indistinguishability LineTable.At preserves.
func BuildLineIndex(t LineTable) *LineIndex {
	index := &LineIndex{firstIP: make(map[int]int, 32)}

	t.forEach(func(entry lineEntry) bool {
		if _, seen := index.firstIP[entry.line]; seen {
			// Decoding runs forwards and offsets never decrease, so the first
			// sighting of a line is already its lowest offset. A later entry
			// for the same line is a second column on it, not an earlier
			// instruction.
			return true
		}
		index.firstIP[entry.line] = entry.ip
		index.lines = append(index.lines, entry.line)
		return true
	})

	// Emission is monotonic in the offset but not in the line: a function
	// literal's body compiles into its own stream, and a `for` post section is
	// emitted after the body it precedes in the source. So the line numbers
	// arrive out of order and are sorted rather than assumed.
	sort.Ints(index.lines)
	return index
}

// At returns the first instruction offset belonging to line, together with the
// line that offset actually came from.
//
// A line that emitted no instruction -- blank, a comment, a declaration that
// compiles to nothing -- binds forward to the next line that did, and the bound
// line comes back so the caller can report where the breakpoint really landed
// instead of claiming it landed where it was asked for. A line past the last
// one with code binds to nothing and reports not-found: there is no instruction
// after it to stop at, and a breakpoint that can never be hit is worse than one
// that was refused.
func (ix *LineIndex) At(line int) (ip, bound int, ok bool) {
	if ix == nil || len(ix.lines) == 0 || line <= 0 {
		return 0, 0, false
	}

	at := sort.SearchInts(ix.lines, line)
	if at >= len(ix.lines) {
		return 0, 0, false
	}

	bound = ix.lines[at]
	return ix.firstIP[bound], bound, true
}

// Lines returns the lines that have code, ascending. It is what an editor asks
// for when it wants to show which lines can hold a breakpoint at all.
//
// A copy: the index is built once and queried many times, often from a
// long-lived debug session, and handing out the backing slice would let one
// caller's sort or append corrupt every later answer.
func (ix *LineIndex) Lines() []int {
	if ix == nil || len(ix.lines) == 0 {
		return nil
	}
	out := make([]int, len(ix.lines))
	copy(out, ix.lines)
	return out
}

// Empty reports whether the index has nothing to find, which is true exactly
// when the table it was built from was empty.
func (ix *LineIndex) Empty() bool { return ix == nil || len(ix.lines) == 0 }
