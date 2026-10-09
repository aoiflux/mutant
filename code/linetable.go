package code

// A LineTable maps an offset in an instruction stream back to the source
// position that produced it. One table belongs to each stream: the main
// program's, and every compiled function's.
//
// The encoding is a delta-varint sequence, the same shape Go's pcln table uses
// and for the same reason -- a table with one fixed-width entry per instruction
// is larger than the instructions it describes. Each entry is three varints:
//
//	uvarint(ipDelta)  bytes advanced since the previous entry, never negative
//	varint(lineDelta) signed, zig-zag encoded by binary.PutVarint
//	varint(colDelta)  signed, likewise
//
// An entry is written only where the position changes, so a statement that
// compiles to a dozen instructions costs one entry rather than twelve. In
// practice that keeps a table to single-digit percent of the stream it
// annotates.
//
// An entry whose accumulated line is zero is a reset: it records where the
// previous entry's coverage ended rather than a position of its own, and At
// reports "unknown" for every offset it covers. Only the tables whose position
// is optional per construct carry them -- the macro table and the end table,
// written through AddOrReset -- and they are what stops the last macro a
// program expanded being reported as the origin of everything compiled after
// it. The encoding does not change for them, so a reset is just another
// three-varint entry to anything that decodes one, a runtime older than this
// paragraph included: it reads line 0, and every consumer of a position
// already treats a zero line as no position at all.
//
// The zero value is a table with no entries, which is what every stream
// compiled before positions existed has and what every stream deliberately
// stripped of them has. Lookups against it report "unknown" rather than
// guessing, so the two are indistinguishable to a consumer -- which is
// intended. See ByteCode.StripDebugInfo.

import "encoding/binary"

// LineTable is the encoded form. It is a byte slice so that gob stores it as
// one opaque field rather than as a slice of structs.
type LineTable []byte

// Empty reports whether the table carries no positions at all.
func (t LineTable) Empty() bool { return len(t) == 0 }

// At returns the source position covering ip: the position of the last entry
// recorded at or before it. ok is false when the table is empty, when ip falls
// before its first entry -- which happens for instructions the compiler emitted
// while it had no position to attribute them to -- and when the entry covering
// ip is a reset, which is how the macro and end tables say that the construct
// an offset belongs to has no macro origin and no recorded end.
//
// Lookup is a forward decode rather than a binary search. The table has no
// index, and the frame counts a traceback walks are small; the cost is paid
// once per frame on a path that is already failing.
func (t LineTable) At(ip int) (line, col int, ok bool) {
	if len(t) == 0 || ip < 0 {
		return 0, 0, false
	}

	var found bool
	t.forEach(func(entry lineEntry) bool {
		if entry.ip > ip {
			// Either nothing covers ip at all, or the previous entry does and
			// this one is where its coverage ends. Both stop the walk.
			return false
		}
		line, col, found = entry.line, entry.col, true
		return true
	})

	// A reset carries line 0 and marks where the entry before it stopped
	// covering the stream, so an offset it covers has no position -- the same
	// answer as an offset ahead of the first entry, and the same answer an
	// empty table gives. Returning the zero with ok true instead would hand
	// every caller a line 0 that passes its ok check.
	if !found || line <= 0 {
		return 0, 0, false
	}
	return line, col, true
}

// lineEntry is one decoded entry: the offset the entry begins at and the
// position recorded for it, with the deltas already accumulated.
type lineEntry struct {
	ip   int
	line int
	col  int
}

// forEach decodes the table from the start and hands each entry to visit in
// emission order, stopping early when visit returns false.
//
// It is where the decode loop lives, so that At, Remap and BuildLineIndex read
// the same format the one way rather than three times each with its own copy of
// the varint arithmetic. A malformed entry ends the walk rather than reporting
// an error: a table is debug information, every caller is already answering
// some other question, and the entries that did decode are worth more than a
// failure that discards them.
func (t LineTable) forEach(visit func(lineEntry) bool) {
	var (
		entry lineEntry
		pos   int
	)

	for pos < len(t) {
		ipDelta, n := binary.Uvarint(t[pos:])
		if n <= 0 {
			return
		}
		pos += n

		lineDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			return
		}
		pos += n

		colDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			return
		}
		pos += n

		entry.ip += int(ipDelta)
		entry.line += int(lineDelta)
		entry.col += int(colDelta)

		if !visit(entry) {
			return
		}
	}
}

// Remap rewrites every entry's instruction offset through offsets, which maps
// an old instruction start to its new one. It is what lets a line table survive
// a pass that moves instructions without moving the source they came from.
//
// An entry whose offset is not in the map is dropped: it described an
// instruction the pass did not account for, and a table that guesses is worse
// than one that reports nothing. Remapping preserves order because the maps
// this is used with are monotonic -- instructions may move apart but never past
// one another.
//
// Dropping a reset is the one case where dropping is not neutral: it re-extends
// the entry before it over everything the pass shifted. The maps this is used
// with name every instruction start, which is where every entry sits, so no
// reset is ever the entry that goes missing.
func (t LineTable) Remap(offsets map[int]int) LineTable {
	if len(t) == 0 || offsets == nil {
		return nil
	}

	var out LineTableBuilder
	t.forEach(func(entry lineEntry) bool {
		if moved, ok := offsets[entry.ip]; ok {
			// AddOrReset rather than Add, so that a reset survives the move
			// instead of being taken for an entry with nothing in it. A table
			// that holds no resets -- the main line table -- cannot tell the
			// two apart.
			out.AddOrReset(moved, entry.line, entry.col)
		}
		return true
	})

	return out.Build()
}

// LineTableBuilder accumulates entries in the order the compiler emits
// instructions. Its zero value is ready to use.
type LineTableBuilder struct {
	buf     []byte
	lastIP  int
	lastLn  int
	lastCol int
	started bool
}

// Add records that the instruction beginning at ip came from line:col.
//
// It drops three kinds of call rather than rejecting them, because the caller
// is a compiler emitting instructions and none of these is worth failing a
// compile over:
//
//   - line <= 0, meaning the node carried no position. Instructions the
//     compiler synthesised on its own behalf are the common case, and dropping
//     the call is what makes them inherit the position of the construct they
//     were emitted for.
//   - a position identical to the previous entry, which is the compression.
//   - an ip before the previous entry's. Emission is monotonic, so this cannot
//     happen; the guard is here so a future caller that violates the invariant
//     produces a short table rather than one that decodes into nonsense.
func (b *LineTableBuilder) Add(ip, line, col int) {
	if line <= 0 {
		return
	}
	b.add(ip, line, col)
}

// AddOrReset is Add for a table whose position is optional per construct: it
// records line:col exactly as Add does, and records the absence of one as a
// reset entry instead of dropping the call.
//
// Dropping is right for the main line table, where "no position" means the
// instruction was synthesised and belongs to whatever construct the compiler
// was working on. It is wrong for the macro table and the end table, where the
// construct being compiled genuinely has no macro origin or no end the parser
// recorded: there the last entry would stay in force and At would answer with
// it, so the first macro a program expanded was reported as the origin of every
// instruction after it, and a construct with no end was underlined with the
// span of the one before it.
//
// A reset ahead of any real entry is dropped rather than encoded. There is no
// coverage to end, and At already reports unknown for an offset before the
// first entry, so encoding one would spend bytes saying what an empty table
// says -- which matters, because most programs expand no macro at all and
// their macro table has to stay empty.
func (b *LineTableBuilder) AddOrReset(ip, line, col int) {
	if line <= 0 {
		if !b.started {
			return
		}
		b.add(ip, 0, 0)
		return
	}
	b.add(ip, line, col)
}

// add encodes one entry, under the guards that hold whether the entry carries a
// position or ends the previous entry's coverage. A reset arrives here as line
// 0 column 0, so the dedup below collapses a run of them to the single entry
// that says what they all say.
func (b *LineTableBuilder) add(ip, line, col int) {
	if ip < 0 {
		return
	}
	if b.started {
		if ip < b.lastIP {
			return
		}
		if line == b.lastLn && col == b.lastCol {
			return
		}
	}

	var scratch [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(scratch[:], uint64(ip-b.lastIP))
	b.buf = append(b.buf, scratch[:n]...)

	n = binary.PutVarint(scratch[:], int64(line-b.lastLn))
	b.buf = append(b.buf, scratch[:n]...)

	n = binary.PutVarint(scratch[:], int64(col-b.lastCol))
	b.buf = append(b.buf, scratch[:n]...)

	b.lastIP, b.lastLn, b.lastCol, b.started = ip, line, col, true
}

// Build returns the encoded table, or nil when nothing was recorded. A nil
// table gob-encodes to nothing, so a program compiled without positions costs
// no bytes in the artifact.
func (b *LineTableBuilder) Build() LineTable {
	if len(b.buf) == 0 {
		return nil
	}
	out := make(LineTable, len(b.buf))
	copy(out, b.buf)
	return out
}
