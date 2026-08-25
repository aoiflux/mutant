package ast

import (
	"bytes"
	"mutant/token"
	"sort"
	"strings"
)

type HashLiteral struct {
	Token token.Token
	Pairs map[Expression]Expression
}

func (hl *HashLiteral) expressionNode()      {}
func (hl *HashLiteral) TokenLiteral() string { return hl.Token.Literal }

// Pairs is a map, so ranging it renders a different string on each call. That is
// not cosmetic. Clone and Modify rebuild the map, so two printings of one tree,
// or of a tree and its copy, disagreed at random -- which is what made both
// clone tests fail on roughly half of all CI runs, one of them reporting that
// "rewriting the clone changed the original" when nothing had been rewritten.
//
// Sorting by key is the answer the rest of the language already gives: the
// compiler sorts hash-literal keys by key.String() before emitting them, and
// object.Hash.Inspect sorts by key before printing. Printing them in that same
// order means this renders the order the pairs are actually compiled and later
// displayed in, rather than inventing a third one.
//
// The value breaks a tie between two keys that render alike. Duplicate keys are
// separate map entries with no order the compiler defines either, so the point
// is only that this function never has two answers.
func (hl *HashLiteral) String() string {
	var out bytes.Buffer

	keys := make([]Expression, 0, len(hl.Pairs))
	for key := range hl.Pairs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if left, right := keys[i].String(), keys[j].String(); left != right {
			return left < right
		}
		return hl.Pairs[keys[i]].String() < hl.Pairs[keys[j]].String()
	})

	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key.String()+":"+hl.Pairs[key].String())
	}

	out.WriteString("{")
	out.WriteString(strings.Join(pairs, ", "))
	out.WriteString("}")

	return out.String()
}
