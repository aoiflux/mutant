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

	// MacroExpansions records, for a node a macro produced, both ends of the
	// story: where the macro was called and where it was defined. It is a
	// third side-table for the same reason as the two above.
	//
	// The call site is also written into NodePositions, so an expanded node
	// reports the line the user actually wrote. That alone is not enough to
	// debug macro-heavy code -- when the generated code is wrong, the line the
	// user wrote is not where the bug is -- so the definition site is kept
	// here alongside it.
	MacroExpansions map[Node]MacroOrigin

	// Parenthesized records the expressions the author wrote inside brackets.
	// The tree keeps no node for a pair of brackets, since precedence is
	// already in its shape, so this fourth side table is the only record of
	// the ones written for clarity. The formatter reads it to print back the
	// brackets that were written, and no others.
	Parenthesized map[Node]bool
}

// MacroOrigin locates a macro expansion at both of its sources: Call is the
// range of the call the user wrote, Definition the range of the macro body
// that produced the code.
type MacroOrigin struct {
	Call       Range
	Definition Range
}

// MacroOriginOf returns the expansion recorded for n, if n came from a macro.
func (p *Program) MacroOriginOf(n Node) (MacroOrigin, bool) {
	if p == nil || p.MacroExpansions == nil || n == nil {
		return MacroOrigin{}, false
	}
	origin, ok := p.MacroExpansions[n]
	return origin, ok
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

// IsParenthesized reports whether the author wrote n inside brackets. A node
// inside two pairs, ((a + b)), is recorded once: the tree cannot tell two
// pairs from one, and one pair is all the grouping means.
func (p *Program) IsParenthesized(n Node) bool {
	if p == nil || p.Parenthesized == nil || n == nil {
		return false
	}
	return p.Parenthesized[n]
}

func (p *Program) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	}
	return ""
}

// missingNode is what a String() prints where a child should be and is not.
//
// It is printed rather than the child being skipped because skipping is a
// silent drop: `f(1, , 2)` rendered as `(1, 2)`, which reads as an honest call
// of two arguments, and `1 + ;` would render as `(1 + )` whether the operand
// was missing or the renderer dropped it. The marker is not valid source in any
// position, so output holding one cannot be mistaken for a program.
const missingNode = "<missing>"

// render prints one child of a node.
//
// A tree that came back from a parse with errors has holes in it: when no
// prefix function claims the current token parseExpression appends an error and
// returns nil, and the node that asked for the operand keeps that nil as a
// child. Dereferencing one was a nil panic in ten of this package's String()
// methods -- `1 + ;`, `-;`, `!` and `f()[-,] = 1;` each produced one -- and the
// language server died of it rather than reporting a diagnostic, because it
// calls String() on an assignment's target to lint it and nothing between that
// call and the jsonrpc2 reader goroutine recovers (M26-LEX-010).
//
// Every String() in this package also tolerates a nil receiver. That is the
// other half of the same invariant and it is not redundant: a child field whose
// type is a concrete pointer -- FunctionLiteral.Body, IfExpression.Consequence,
// LetStatement.Name -- becomes a NON-nil interface holding a typed nil when it
// is passed to a parameter of type Node, so the check here cannot see it. The
// receiver guard is where that one is caught.
func render(n Node) string {
	if n == nil {
		return missingNode
	}
	return n.String()
}

func (p *Program) String() string {
	if p == nil {
		return missingNode
	}
	var out bytes.Buffer

	for _, s := range p.Statements {
		out.WriteString(render(s))
	}

	return out.String()
}
