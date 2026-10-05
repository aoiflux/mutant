package analyzer

import (
	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// This file is the whole of this package's position arithmetic.
//
// LSP 3.16 measures Position.character in UTF-16 code units; Mutant's lexer
// measures columns in bytes and the AST carries that byte column everywhere. The
// two numbers are equal on an ASCII line and on no other, so a position that
// crosses the protocol boundary has to be converted, and until this file existed
// it was not: every range sent out and every position read in was taken
// verbatim, so from the first non-ASCII character of a line onwards -- a string
// or a comment is enough -- everything was off by one unit per extra UTF-8 byte.
//
// The rule now is that nothing in this package converts a position by hand.
// Anything that needs to goes through a Snapshot, which owns the index, and the
// free functions that used to do it without one are gone so that a new site
// cannot quietly reintroduce the arithmetic.

// Mapper is this document's byte-column-to-UTF-16 index, built once on first
// use.
//
// A nil Snapshot yields a nil Mapper, which answers in byte columns rather than
// panicking: an editor session survives a path that forgot its mapper, and is
// then wrong only in the way this server was wrong before any of this existed.
func (s *Snapshot) Mapper() *localprotocol.Mapper {
	if s == nil {
		return nil
	}
	s.mapperOnce.Do(func() { s.mapper = localprotocol.NewMapper(s.Source) })
	return s.mapper
}

// Range is the protocol range for an AST range.
func (s *Snapshot) Range(rng mast.Range) lsp.Range {
	return s.Mapper().Range(rng)
}

// Position is the protocol position for one AST position.
func (s *Snapshot) Position(pos token.Position) lsp.Position {
	return s.Mapper().Position(pos)
}

// PositionAt is the protocol position for a 0-based line and 0-based byte
// column, which is what a rule scanning the source bytes itself has in hand.
func (s *Snapshot) PositionAt(line, byteCol int) lsp.Position {
	return s.Mapper().PositionAt(line, byteCol)
}

// Contains reports whether an AST range covers a protocol position.
func (s *Snapshot) Contains(rng mast.Range, pos lsp.Position) bool {
	return s.Mapper().ContainsPosition(rng, pos)
}

// TokenPosition converts a protocol position to the 1-based line and 1-based
// byte column that the AST and the name graph are measured in.
//
// It is the inbound half, and it had been missing entirely: every caller added
// one to Position.character and used the result as a byte column.
func (s *Snapshot) TokenPosition(pos lsp.Position) (line, column int) {
	return s.Mapper().TokenPosition(pos)
}

// ByteOffset is the offset into Source that a protocol position names, and
// whether it names one at all.
func (s *Snapshot) ByteOffset(pos lsp.Position) (int, bool) {
	return s.Mapper().ByteOffset(pos)
}

// utf16Len is the number of UTF-16 code units s encodes to, which is the unit
// both Position.character and a semantic token's length are measured in. It
// replaces len([]rune(s)), a rune count, which differs for every rune outside
// the basic multilingual plane.
func utf16Len(s string) uint32 {
	return uint32(localprotocol.UTF16Len(s))
}

// rangeContains reports whether an AST range covers a 1-based line and byte
// column. It converts nothing: both sides are already in the AST's own
// coordinates.
//
// A caller asking this of every node in the document calls TokenPosition once,
// outside its loop, and then this. Snapshot.Contains is the one-shot form for a
// caller with a single range to test.
func rangeContains(rng mast.Range, line, column int) bool {
	return localprotocol.RangeContains(rng, line, column)
}
