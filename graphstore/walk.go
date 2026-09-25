package graphstore

import (
	"time"

	"github.com/aoiflux/graphene/store"
)

// The walk budget every graphene traversal a script can start runs under.
//
// graphene's Budget exists because depth does not bound anything: "a single
// node of degree 100 000 puts 100 000 entries in a visited set at depth one",
// and without a budget "the only symptom is the process growing until it
// stops". It refuses rather than truncating, and returns nothing partial.
//
// The limits are fixed rather than taken as an argument, because this is a
// decision about not losing an examiner's session to a graph whose shape is
// data, and a default of "unlimited" is the wrong one to leave lying where a
// script can inherit it by omission. They are generous enough that reaching one
// means the question was wrong rather than that the graph was large, and each
// caller's refusal says so rather than handing back a partial walk that reads
// like a complete answer.
const (
	// WalkMaxNodes bounds the nodes one walk may visit. A walk that reaches two
	// million has read most of a large store, which is a question to narrow --
	// to a set of ids, or a lower depth -- rather than one to answer.
	//
	//mutant:limit count
	WalkMaxNodes = 2_000_000

	// WalkMaxEdges bounds the edges one walk may read. It is four times the node
	// bound because a walk reads every edge of every node it visits, and a node
	// worth walking from has more than one.
	//
	//mutant:limit count
	WalkMaxEdges = 8_000_000

	// WalkMaxTime bounds one walk's wall time. It is set well above the
	// platform's clock granularity on purpose: graphene's own note is that on
	// Windows the runtime reads the interrupt time, which advances at the timer
	// tick -- 15.6 ms by default -- so a deadline in the microseconds is a
	// deadline in name only; a probe with MaxTime 1ns completed a 201-node walk
	// and reported no error at all.
	//
	//mutant:limit duration
	WalkMaxTime = 60 * time.Second
)

// WalkBudget is the budget every traversal runs under.
func WalkBudget() store.Budget {
	return store.Budget{
		MaxNodes: WalkMaxNodes,
		MaxEdges: WalkMaxEdges,
		MaxTime:  WalkMaxTime,
	}
}

// ReversedHops lists the 0-based hops of a path that ran against their edge.
//
// graphene's path searches walk an edge either way, so a path from a file back
// to the image that contains it is found like any other. Hop i ran backwards
// when its edge points from the node the hop reached back to the node it left,
// and a reading of the path as provenance has to know which hops did. A path
// whose nodes and edges do not line up -- one more node than edges -- has no
// hop to mark past the shorter of the two.
func ReversedHops(nodes []*store.Node, edges []*store.Edge) []int {
	reversed := []int{}
	for i, edge := range edges {
		if i+1 < len(nodes) && edge.Src == nodes[i+1].ID && edge.Dst == nodes[i].ID {
			reversed = append(reversed, i)
		}
	}
	return reversed
}
