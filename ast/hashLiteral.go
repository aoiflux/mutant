package ast

import (
	"bytes"
	"mutant/token"
	"strings"
)

// HashPair is one `key: value` of a hash literal, in the position the author
// wrote it.
//
// The pairs are a slice and not a map from key expression to value expression,
// which is what they were until M26-CMP-010 and M26-LEX-004. A map keyed by
// node pointer throws the written order away, and that order is not
// decoration: both engines evaluate the pairs in it, so it decides which of two
// keys or values has its side effects first, and where one key is written twice
// it decides which of the two values the hash ends up holding. With the order
// gone the compiler reconstructed one by sorting on key.String(), and two keys
// that render alike -- a key written twice, or a string beside an identifier
// spelled the same way, because StringLiteral.String() renders a string without
// its quotes -- tied and fell through to Go map iteration. One source then
// compiled to different bytecode on different builds: `{"k": 1, "k": 2}["k"]`
// came out 2 on twenty of twenty-four builds and 1 on the other four.
//
// A slice is also what makes every reader of Pairs say which half it means.
// `for key, value := range pairs` does not compile against a slice, so each
// walk over a hash literal in the parser, the compiler, the evaluator, sema and
// the language server had to be made to say so rather than silently taking an
// index for a key.
type HashPair struct {
	Key   Expression
	Value Expression
}

type HashLiteral struct {
	Token token.Token
	Pairs []HashPair
}

func (hl *HashLiteral) expressionNode()      {}
func (hl *HashLiteral) TokenLiteral() string { return hl.Token.Literal }

// String renders the pairs in the order they were written, which is the order
// both engines evaluate them in.
//
// It used to sort by key, because Pairs was a map and ranging it rendered a
// different string on each call -- which made both clone tests coin flips, one
// of them reporting that "rewriting the clone changed the original" when
// nothing had been rewritten. Clone and Modify carry the order over now, so the
// rendering is stable because the tree is ordered and not because this function
// imposes an order the tree does not have. object.Hash.Inspect still sorts: a
// hash VALUE has no written order to show.
func (hl *HashLiteral) String() string {
	var out bytes.Buffer

	pairs := make([]string, 0, len(hl.Pairs))
	for _, pair := range hl.Pairs {
		pairs = append(pairs, pair.Key.String()+":"+pair.Value.String())
	}

	out.WriteString("{")
	out.WriteString(strings.Join(pairs, ", "))
	out.WriteString("}")

	return out.String()
}
