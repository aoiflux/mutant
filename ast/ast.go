package ast

import (
	"bytes"

	"mutant/token"
)

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
	statementNode()
}

type Expression interface {
	Node
	expressionNode()
}

// Range identifies a contiguous piece of source code by its start (inclusive)
// and end (exclusive) positions.
type Range struct {
	Start token.Position
	End   token.Position
}

// IsValid reports whether both endpoints of the range are populated.
func (r Range) IsValid() bool { return r.Start.IsValid() && r.End.IsValid() }

// Program is the root of a parsed Mutant source file.
//
// NodePositions is a side-table populated by the parser that maps AST nodes
// to the source range they occupy. It is intentionally decoupled from the
// individual node structs so downstream consumers (compiler, evaluator, VM)
// remain untouched and existing tests that construct nodes directly still
// work. Consumers that don't need positions can ignore the map; consumers
// that do should prefer RangeOf which is nil-safe.
type Program struct {
	Statements    []Statement
	NodePositions map[Node]Range
}

// RangeOf returns the source range recorded for n during parsing.
// The ok result is false when the map is nil, when n was never registered
// (e.g. a hand-constructed node in a test), or when the recorded range is
// not valid. Callers should treat a false result as "position unknown".
func (p *Program) RangeOf(n Node) (Range, bool) {
	if p == nil || p.NodePositions == nil || n == nil {
		return Range{}, false
	}
	r, ok := p.NodePositions[n]
	if !ok || !r.IsValid() {
		return Range{}, false
	}
	return r, true
}

func (p *Program) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	}
	return ""
}

func (p *Program) String() string {
	var out bytes.Buffer

	for _, s := range p.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}
