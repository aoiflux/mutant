package graphstore

import (
	"fmt"
	"time"

	"github.com/aoiflux/graphene"
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

// walkClockInterval is how many charges pass between two reads of the clock
// when a budget sets MaxTime. It is graphene's own cadence, for graphene's
// reason: a clock read on every step of a walk that charges once per node and
// once per edge cost it about a fifth of its time, and sixteen steps is five or
// six nodes of overshoot.
//
//mutant:limit count
const walkClockInterval = 16

// Reach is what a Walk found: the nodes in the order it reached them, origin
// first, and every edge it crossed, each once, in the order it first crossed it.
type Reach struct {
	Nodes []store.NodeID
	Edges []store.EdgeID
}

// Walk is a breadth-first walk from origin that keeps every edge it crosses.
//
// graphene's BFS keeps one edge per neighbour per expansion -- "matching
// Neighbours" -- so of three edges from a process to one file it returns the
// first and drops the other two, and nothing in its result says so. A walk read
// as "how is this related to that" then under-reports exactly where the
// relationship is strongest. This one keeps them: every edge of an expanded
// node in dir is in Edges, the parallel ones and those back to a node already
// reached included.
//
// Otherwise it is the same walk: the same levels, the same nodes in the same
// order, a node at maxDepth reached but not expanded, and an edge whose far end
// the store cannot resolve dropped with it. It is charged the way graphene
// charges its own -- each node reached and each distinct edge crossed -- and
// refuses with store.ErrBudgetExceeded rather than returning what it had.
//
// maxDepth must not be negative. graphene reads a negative depth as zero, an
// answer to a question nobody asked, so this refuses it and a caller refuses it
// first. An origin the store does not hold is a *store.ErrNotFound.
func Walk(g *graphene.Graph, origin store.NodeID, maxDepth int, dir store.Direction,
	edgeTypes []store.EdgeType, budget store.Budget) (Reach, error) {
	if maxDepth < 0 {
		return Reach{}, fmt.Errorf("a walk's depth must not be negative, got %d", maxDepth)
	}
	meter, err := newWalkMeter(budget)
	if err != nil {
		return Reach{}, err
	}

	// The graph's own store rather than the graph: *graphene.Graph promotes only
	// the methods of the interface it embeds, so asking it for the adjacency
	// fast path would always say no.
	reader := g.GraphStore
	adjacency, _ := reader.(store.AdjacencyReader)
	exists := func(id store.NodeID) bool {
		if adjacency != nil {
			return adjacency.NodeExists(id)
		}
		_, err := reader.GetNode(id)
		return err == nil
	}

	if !exists(origin) {
		return Reach{}, &store.ErrNotFound{Kind: "node", ID: uint64(origin)}
	}
	if err := meter.node(); err != nil {
		return Reach{}, err
	}

	reach := Reach{Nodes: []store.NodeID{origin}, Edges: []store.EdgeID{}}
	visited := map[store.NodeID]struct{}{origin: {}}
	// Walking one way, an edge is met only when the one node it leaves -- or,
	// inbound, reaches -- is expanded, and a node is expanded once, so no edge
	// is met twice. Walking both ways it is met from each end, and only then
	// is a set of the edges already crossed worth its allocations.
	var crossed map[store.EdgeID]struct{}
	if dir == store.DirectionBoth {
		crossed = map[store.EdgeID]struct{}{}
	}
	current := []store.NodeID{origin}
	var next []store.NodeID
	var steps []store.IncidentEdge

	for depth := 0; depth < maxDepth && len(current) > 0; depth++ {
		next = next[:0]
		for _, id := range current {
			steps, err = incidentSteps(reader, adjacency, steps[:0], id, dir, edgeTypes)
			if err != nil {
				return Reach{}, err
			}
			for _, step := range steps {
				_, seen := visited[step.Neighbour]
				if !seen && !exists(step.Neighbour) {
					continue
				}
				first := true
				if crossed != nil {
					_, done := crossed[step.Edge]
					first = !done
					crossed[step.Edge] = struct{}{}
				}
				if first {
					if err := meter.edge(); err != nil {
						return Reach{}, err
					}
					reach.Edges = append(reach.Edges, step.Edge)
				}
				if seen {
					continue
				}
				if err := meter.node(); err != nil {
					return Reach{}, err
				}
				visited[step.Neighbour] = struct{}{}
				reach.Nodes = append(reach.Nodes, step.Neighbour)
				next = append(next, step.Neighbour)
			}
		}
		current, next = next, current
	}
	return reach, nil
}

// incidentSteps lists the edges of id in dir, each with the node at its far
// end, through the store's allocation-free path when it has one.
func incidentSteps(reader store.GraphReader, adjacency store.AdjacencyReader, dst []store.IncidentEdge,
	id store.NodeID, dir store.Direction, edgeTypes []store.EdgeType) ([]store.IncidentEdge, error) {
	if adjacency != nil {
		return adjacency.IncidentEdges(dst, id, dir, edgeTypes)
	}
	edges, err := reader.EdgesOf(id, dir, edgeTypes)
	if err != nil {
		return dst, err
	}
	for _, edge := range edges {
		far := edge.Dst
		if edge.Src != id {
			far = edge.Src
		}
		dst = append(dst, store.IncidentEdge{Edge: edge.ID, Neighbour: far, Weight: edge.Weight})
	}
	return dst, nil
}

// walkMeter charges a Walk against its budget, with graphene's words for what
// was exceeded so a caller's refusal reads the same whichever walk stopped.
type walkMeter struct {
	budget   store.Budget
	nodes    int
	edges    int
	charges  int
	deadline time.Time
}

func newWalkMeter(budget store.Budget) (*walkMeter, error) {
	meter := &walkMeter{budget: budget}
	switch {
	case budget.MaxTime < 0:
		// graphene's reading too: a negative MaxTime is a deadline already
		// passed, not an absent one.
		return nil, fmt.Errorf("%w: the walk's deadline had passed before it began", store.ErrBudgetExceeded)
	case budget.MaxTime > 0:
		meter.deadline = time.Now().Add(budget.MaxTime)
	}
	return meter, nil
}

func (m *walkMeter) node() error {
	m.nodes++
	if m.budget.MaxNodes > 0 && m.nodes > m.budget.MaxNodes {
		return fmt.Errorf("%w: visited more than %d nodes", store.ErrBudgetExceeded, m.budget.MaxNodes)
	}
	return m.tick()
}

func (m *walkMeter) edge() error {
	m.edges++
	if m.budget.MaxEdges > 0 && m.edges > m.budget.MaxEdges {
		return fmt.Errorf("%w: crossed more than %d edges", store.ErrBudgetExceeded, m.budget.MaxEdges)
	}
	return m.tick()
}

func (m *walkMeter) tick() error {
	m.charges++
	if m.deadline.IsZero() || m.charges%walkClockInterval != 0 {
		return nil
	}
	if time.Now().After(m.deadline) {
		return fmt.Errorf("%w: ran longer than %s", store.ErrBudgetExceeded, m.budget.MaxTime)
	}
	return nil
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
