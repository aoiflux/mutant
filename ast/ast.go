package ast

import (
	"bytes"

	"mutant/token"
)

type Node interface {
	TokenLiteral() string
	String() string
}

// Statement is a Mutant statement node.
//
// RequiresSemicolon reports whether canonical Mutant source terminates this
// statement with `;`. Mutant mandates semicolons — there is no automatic
// insertion as in Go — so this is the single source of truth shared by the
// parser (which reports a missing `;` as a recoverable error) and the
// formatter (which emits one during AST-to-text printing). Statements whose
// canonical form already ends in a closing brace — blocks, `for` loops,
// `struct`/`enum` declarations, and expression statements wrapping an `if` —
// report false.
type Statement interface {
	Node
	statementNode()
	RequiresSemicolon() bool
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
// Comments holds the comment trivia the lexer skipped, in source order. It
// is a side-table for the same reason NodePositions is: the compiler,
// evaluator and VM are indifferent to comments, while the formatter needs
// them to reproduce authored documentation around the code it prints.
type Program struct {
	Statements    []Statement
	NodePositions map[Node]Range
	Comments      []token.Comment
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
