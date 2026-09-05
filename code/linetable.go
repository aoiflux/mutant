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
// recorded at or before it. ok is false when the table is empty or when ip
// falls before its first entry, which happens for instructions the compiler
// emitted while it had no position to attribute them to.
//
// Lookup is a forward decode rather than a binary search. The table has no
// index, and the frame counts a traceback walks are small; the cost is paid
// once per frame on a path that is already failing.
func (t LineTable) At(ip int) (line, col int, ok bool) {
	if len(t) == 0 || ip < 0 {
		return 0, 0, false
	}

	var (
		curIP   int
		curLine int
		curCol  int
		found   bool
		pos     int
	)

	for pos < len(t) {
		ipDelta, n := binary.Uvarint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		lineDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		colDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		nextIP := curIP + int(ipDelta)
		if found && nextIP > ip {
			break
		}
		if !found && nextIP > ip {
			// The first entry already starts past ip: nothing covers it.
			return 0, 0, false
		}

		curIP = nextIP
		curLine += int(lineDelta)
		curCol += int(colDelta)
		found = true
	}

	if !found {
		return 0, 0, false
	}
	return curLine, curCol, true
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
func (t LineTable) Remap(offsets map[int]int) LineTable {
	if len(t) == 0 || offsets == nil {
		return nil
	}

	var (
		out     LineTableBuilder
		curIP   int
		curLine int
		curCol  int
		pos     int
	)

	for pos < len(t) {
		ipDelta, n := binary.Uvarint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		lineDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		colDelta, n := binary.Varint(t[pos:])
		if n <= 0 {
			break
		}
		pos += n

		curIP += int(ipDelta)
		curLine += int(lineDelta)
		curCol += int(colDelta)

		if moved, ok := offsets[curIP]; ok {
			out.Add(moved, curLine, curCol)
		}
	}

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
//     compiler synthesised on its own behalf are the common case.
//   - a position identical to the previous entry, which is the compression.
//   - an ip before the previous entry's. Emission is monotonic, so this cannot
//     happen; the guard is here so a future caller that violates the invariant
//     produces a short table rather than one that decodes into nonsense.
func (b *LineTableBuilder) Add(ip, line, col int) {
	if line <= 0 || ip < 0 {
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
