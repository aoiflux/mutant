package builtin

// Reading the ledger back, and the four ways a read can be quietly wrong.
//
// Everything this family has added so far writes or proves. `ledger_add_node`
// commits an attributed record, `ledger_prove_node` produces an inclusion
// proof, `ledger_custody` accounts for one entity across six histories, and
// the redaction file destroys content and records that it did. None of them
// hands a record back. A ledger opened by Mutant has been, until this file,
// write-only: a script could put evidence into it and prove that it was there,
// and could not ask it anything.
//
// So this file is the read side. Two accessors, three walks, a matcher, a
// query, a plan, and the index declarations that decide how the query is
// answered.
//
// # A read is a claim, and four of these could make a false one silently
//
// This is the whole reason the file is shaped the way it is. Each of the four
// was found by running the library rather than by reading it, and each one
// returns a wrong answer rather than an error.
//
// **1. Declaring an index changes the answer.** graphene says so in one line of
// DeclareOrderedProperty's doc and it is easy to read past: an undeclared key
// compares range predicates numerically when both sides parse as numbers, and
// a declared key compares them byte-wise. Those are different questions. Over
// the values 9, 10, 1x, 100, 2:
//
//	between "2" and "100", key not declared -> 9, 10, 100, 2
//	between "2" and "100", key declared     -> nothing at all
//
// Four records become none. Not reordered, not slower -- an empty result set,
// produced by a decision an examiner made about performance, on a query whose
// text did not change. That is absence of evidence manufactured by a schema
// change, and it is the most dangerous single fact in this file.
//
// It is reported twice. `ledger_declare_ordered` compares the key's existing
// values under both rules before it declares anything and returns
// `order_differs` with the pair that swaps; `ledger_query_nodes` returns
// `comparison`, naming the rule that actually answered the query it just ran.
//
// **2. A truncated provenance chain is indistinguishable from a complete one.**
// `ProvenanceChain` documents that "if no root is reached within maxDepth,
// Chain contains the deepest path found" -- so a walk stopped by its depth
// limit returns the same shape as a walk that reached the origin of the
// evidence. `ledger_provenance` therefore reads the last node's inbound edges
// after the walk and reports `stopped_at` as `root`, `depth` or `cycle`.
// `complete` is true for exactly one of those three.
//
// **3. Provenance through a DAG follows one parent and drops the rest.** A
// node with two inbound edges has two ancestries; the walk picks one and says
// nothing about the other. It is called a chain and it is one path through
// something that is frequently not a chain. `branch_points` names every node
// on the returned chain that had another parent, and which parents were not
// followed -- so "this artefact came from that image" cannot be read off a
// result that also had another answer.
//
// **4. An unlabelled pattern node with no scope matches nothing, by design.**
// graphene's candidate builder says so in a comment and returns no error:
//
//	// Unsupported without scope -- caller should always provide scope
//	// for full-graph searches to avoid loading all node IDs.
//
// A script asking "find me any two connected things" is told there are none.
// `ledger_patterns` refuses that pattern instead.
//
// # And one that is not silent, because it is a crash
//
// A pattern edge naming a pattern node that does not exist panics inside
// graphene -- `index out of range [7] with length 1` -- which takes the process
// down and the session with it. Every pattern is validated here before it is
// handed over: node positions, edge endpoints, label ranges and the 2..20 size
// graphene documents.
//
// # Refusal, not truncation -- and the walks carry a budget they did not ask for
//
// graphene's Budget exists because depth does not bound anything: "a single
// node of degree 100 000 puts 100 000 entries in a visited set at depth one",
// and without a budget "the only symptom is the process growing until it
// stops". It refuses rather than truncating, and returns nothing partial.
//
// Every walk here is bounded, with the limits fixed rather than taken as an
// argument, for the reason `ledger_open`'s posture is fixed: this is a decision
// about not losing an examiner's session to a graph whose shape is data, and a
// default of "unlimited" is the wrong one to leave lying where a script can
// inherit it by omission. The limits are generous enough that reaching one
// means the question was wrong, and the refusal says so rather than handing
// back a partial walk that reads like a complete answer.
//
// `MaxTime` is set well above the platform's clock granularity on purpose.
// graphene's own note is that on Windows the runtime reads the interrupt time,
// which advances at the timer tick -- 15.6 ms by default -- so a deadline in
// the microseconds is a deadline in name only; a probe with `MaxTime: 1ns`
// completed a 201-node walk and reported no error at all.
//
// # Properties come back as BYTES
//
// `ledger_add_node` accepts STRING or BYTES and stores bytes. Once committed
// the two are the same blob and the store does not record which was written, so
// rendering a property as a STRING on the way out would invent a distinction
// the ledger does not hold and would be lossy for any value that is not valid
// UTF-8. `bytes_to_string` is one call away for a caller who knows what they
// wrote -- and it is that one and not `to_string`, which renders a BYTES value
// as hex because `Inspect` is the de-facto identity function in both engines.
//
// # An absence is an answer, except where it is a refusal
//
// `ledger_path` returns `found: false` when two entities are not connected,
// because "these are not related" is a finding and folding it into the error
// channel would make a script's error branch mean both "not connected" and
// "bad handle". A source or destination that the ledger does not hold is a
// refusal, and -- as in `ledger_prove_node` -- it distinguishes an id that was
// never here from one a redaction removed, by reading the redaction ledger
// before answering.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene/store"
	"github.com/aoiflux/graphene/traversal"
	"github.com/vmihailenco/msgpack/v5"

	"mutant/object"
)

// The fixed walk budget. See the header: these are not arguments because
// "unlimited" is the wrong thing for a script to inherit by omission, and they
// are generous because reaching one should mean the question was wrong rather
// than that the graph was large.
const (
	ledgerWalkMaxNodes = 2_000_000
	ledgerWalkMaxEdges = 8_000_000
	ledgerWalkMaxTime  = 60 * time.Second
)

// ledgerPatternMinNodes and ledgerPatternMaxNodes are graphene's documented
// range for a pattern ("a small query graph (2-20 nodes)"). Checked here
// because the lower bound is not enforced there -- a one-node pattern returns
// every node of its label, which is a query rather than a match -- and the
// upper bound is where backtracking stops being something a caller can wait
// for.
const (
	ledgerPatternMinNodes = 2
	ledgerPatternMaxNodes = 20
)

// ledgerWalkBudget is the budget every traversal in this file runs under.
func ledgerWalkBudget() store.Budget {
	return store.Budget{
		MaxNodes: ledgerWalkMaxNodes,
		MaxEdges: ledgerWalkMaxEdges,
		MaxTime:  ledgerWalkMaxTime,
	}
}

// ledgerBudgetRefusal turns graphene's budget error into one that says what
// was refused and that nothing partial is being returned.
//
// The distinction matters more here than the limit does: a caller who reads
// "budget exceeded" as "here is what I found so far" has the one belief this
// error exists to prevent.
func ledgerBudgetRefusal(err error, op string) *object.Error {
	return newError("%s: the walk was stopped by this language's fixed traversal budget (%d nodes, %d edges, %s) and nothing partial is returned -- a truncated walk that reads like a complete one is the failure this refuses. graphene: %s. Narrow the question: scope it to a set of ids, or lower the depth",
		op, ledgerWalkMaxNodes, ledgerWalkMaxEdges, ledgerWalkMaxTime, err.Error())
}

// ledgerReadRefusal is the not-found path for every read in this file.
//
// It consults the redaction ledger for the same reason ledger_prove_node does:
// an id that a court order removed and an id that was never written are the
// same *ErrNotFound to graphene, and telling an examiner their evidence never
// existed when the ledger holds a signed record of its removal is the worst
// answer this family can give.
func ledgerReadRefusal(session *ledgerSession, err error, nodeID store.NodeID, edgeID store.EdgeID, op string) *object.Error {
	var notFound *store.ErrNotFound
	if !errors.As(err, &notFound) {
		return newError("%s: %s", op, err.Error())
	}

	subject := fmt.Sprintf("node %d", nodeID)
	if edgeID != 0 {
		subject = fmt.Sprintf("edge %d", edgeID)
	}

	switch record, cascaded, found := ledgerLastRedaction(session, nodeID, edgeID); {
	case found && cascaded:
		return newError("%s: %s is not here because redaction %d took it as collateral when node %d was removed at %s: %q. Its removal is recorded and provable -- see ledger_prove_edge_redaction", op, subject, record.Seq, record.NodeID, formatTime(ledgerTime(record.UnixNano)), record.Reason)
	case found:
		return newError("%s: %s is not here because it was redacted at %s by actor %d (%s): %q. A redaction is recorded, not undone -- see ledger_redactions", op, subject, formatTime(ledgerTime(record.UnixNano)), record.ActorID, record.Scope.String(), record.Reason)
	}
	return newError("%s: this ledger has no %s, and no record of ever having had one. Check the id against what ledger_add_node or ledger_add_edge returned", op, subject)
}

// ledgerDecodeProperties reads back the blob ledgerPropertyBlob wrote.
//
// The mirror of that encoder, and deliberately written against it rather than
// against a generic msgpack decode: the blob is a map of string to bytes whose
// key order is part of the version hash, and decoding it into map[string]any
// would render a value that happens to be valid UTF-8 as a string and the
// identical bytes beside it as bytes.
func ledgerDecodeProperties(blob []byte) (map[string][]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	decoder := msgpack.NewDecoder(bytes.NewReader(blob))
	count, err := decoder.DecodeMapLen()
	if err != nil {
		return nil, err
	}
	props := make(map[string][]byte, count)
	for i := 0; i < count; i++ {
		key, err := decoder.DecodeString()
		if err != nil {
			return nil, err
		}
		value, err := decoder.DecodeBytes()
		if err != nil {
			return nil, err
		}
		props[key] = value
	}
	return props, nil
}

// ledgerPropertiesObject renders decoded properties as a hash of BYTES.
func ledgerPropertiesObject(props map[string][]byte) object.Object {
	out := make(map[string]object.Object, len(props))
	for key, value := range props {
		buf := make([]byte, len(value))
		copy(buf, value)
		out[key] = &object.Bytes{Value: buf}
	}
	return makeHashObject(out)
}

// ledgerLabelList renders node or edge labels as the integers a script passed
// in, rather than as graphene's internal type numbers.
//
// db_add_node takes a label in 0..127 and adds graphene's custom base to it;
// handing the raw value back would give a script a number it cannot pass to
// the builtin it came from.
func ledgerLabelList[T ~uint16](labels []T, base T) object.Object {
	elements := make([]object.Object, 0, len(labels))
	for _, label := range labels {
		if label >= base {
			elements = append(elements, intObj(int64(label-base)))
			continue
		}
		// A built-in graphene type, which no Mutant builtin can write. Reported
		// as a negative so it cannot be mistaken for a custom offset and fed
		// back in as one.
		elements = append(elements, intObj(-int64(label)))
	}
	return &object.Array{Elements: elements}
}

// ledgerNodeObject renders one node record.
func ledgerNodeObject(node *store.Node) (object.Object, error) {
	props, err := ledgerDecodeProperties(node.Properties)
	if err != nil {
		return nil, err
	}
	return makeHashObject(map[string]object.Object{
		"id":             intObj(int64(node.ID)),
		"labels":         ledgerLabelList(node.Labels, store.NodeTypeCustomBase),
		"properties":     ledgerPropertiesObject(props),
		"property_count": intObj(int64(len(props))),
		"property_bytes": intObj(int64(len(node.Properties))),
		"redactable":     boolObj(len(node.Properties) > 0),
	}), nil
}

// ledgerEdgeObject renders one edge record.
func ledgerEdgeObject(edge *store.Edge) (object.Object, error) {
	props, err := ledgerDecodeProperties(edge.Properties)
	if err != nil {
		return nil, err
	}
	return makeHashObject(map[string]object.Object{
		"id":             intObj(int64(edge.ID)),
		"src":            intObj(int64(edge.Src)),
		"dst":            intObj(int64(edge.Dst)),
		"labels":         ledgerLabelList(edge.Labels, store.EdgeTypeCustomBase),
		"weight":         floatObj(float64(edge.Weight)),
		"properties":     ledgerPropertiesObject(props),
		"property_count": intObj(int64(len(props))),
		"property_bytes": intObj(int64(len(edge.Properties))),
		"redactable":     boolObj(len(edge.Properties) > 0),
	}), nil
}

// LedgerNode reads one node record back.
func LedgerNode(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerNode)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerNode, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	node, err := session.graph.GetNode(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerReadRefusal(session, err, nodeID, 0, BuiltinNameLedgerNode))
	}
	rendered, err := ledgerNodeObject(node)
	if err != nil {
		return resultAndError(nil, newError("%s: node %d has a property blob this language cannot decode: %s", BuiltinNameLedgerNode, nodeID, err.Error()))
	}
	return resultAndError(rendered, nil)
}

// LedgerEdge reads one edge record back.
func LedgerEdge(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerEdge)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeID, errObj := ledgerEdgeArg(args[1], BuiltinNameLedgerEdge, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	edge, err := session.graph.GetEdge(edgeID)
	if err != nil {
		return resultAndError(nil, ledgerReadRefusal(session, err, 0, edgeID, BuiltinNameLedgerEdge))
	}
	rendered, err := ledgerEdgeObject(edge)
	if err != nil {
		return resultAndError(nil, newError("%s: edge %d has a property blob this language cannot decode: %s", BuiltinNameLedgerEdge, edgeID, err.Error()))
	}
	return resultAndError(rendered, nil)
}

// ledgerInboundParents returns the distinct nodes one inbound hop from id.
//
// Distinct, because two edges between the same pair are one ancestry for the
// purpose of asking whether a chain had a choice to make.
func ledgerInboundParents(session *ledgerSession, id store.NodeID) ([]store.NodeID, error) {
	edges, err := session.graph.EdgesOf(id, store.DirectionInbound, nil)
	if err != nil {
		return nil, err
	}
	seen := make(map[store.NodeID]struct{}, len(edges))
	parents := make([]store.NodeID, 0, len(edges))
	for _, edge := range edges {
		if _, ok := seen[edge.Src]; ok {
			continue
		}
		seen[edge.Src] = struct{}{}
		parents = append(parents, edge.Src)
	}
	return parents, nil
}

// LedgerProvenance walks inbound edges from one entity back towards the
// evidence it came from, and says why the walk stopped.
func LedgerProvenance(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerProvenance)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	origin, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerProvenance, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	depthArg, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", BuiltinNameLedgerProvenance, args[2].Type()))
	}
	if depthArg.Value <= 0 {
		return resultAndError(nil, newError("%s: maxDepth must be positive, got %d. graphene silently substitutes 64 for a non-positive depth, which is a limit the caller did not choose and would be reported here as the one they did", BuiltinNameLedgerProvenance, depthArg.Value))
	}
	if depthArg.Value > math.MaxInt32 {
		return resultAndError(nil, newError("%s: maxDepth %d is larger than this walk can be asked for", BuiltinNameLedgerProvenance, depthArg.Value))
	}

	// Checked before the walk so that a missing origin is refused with the
	// redaction-aware message rather than graphene's bare "node not found".
	if _, err := session.graph.GetNode(origin); err != nil {
		return resultAndError(nil, ledgerReadRefusal(session, err, origin, 0, BuiltinNameLedgerProvenance))
	}

	result, err := session.graph.ProvenanceChainCtx(ledgerContext(), origin, int(depthArg.Value), nil, ledgerWalkBudget())
	if err != nil {
		if errors.Is(err, store.ErrBudgetExceeded) {
			return resultAndError(nil, ledgerBudgetRefusal(err, BuiltinNameLedgerProvenance))
		}
		return resultAndError(nil, ledgerReadRefusal(session, err, origin, 0, BuiltinNameLedgerProvenance))
	}

	chain := make([]object.Object, 0, len(result.Chain))
	onChain := make(map[store.NodeID]struct{}, len(result.Chain))
	for _, node := range result.Chain {
		rendered, err := ledgerNodeObject(node)
		if err != nil {
			return resultAndError(nil, newError("%s: node %d has a property blob this language cannot decode: %s", BuiltinNameLedgerProvenance, node.ID, err.Error()))
		}
		chain = append(chain, rendered)
		onChain[node.ID] = struct{}{}
	}

	// Why the walk stopped. graphene returns the deepest path it found either
	// way, so this is the only thing separating "reached the source" from
	// "ran out of depth", and the two are different claims about evidence.
	stoppedAt := "root"
	if len(result.Chain) > 0 {
		last := result.Chain[len(result.Chain)-1].ID
		parents, err := ledgerInboundParents(session, last)
		if err != nil {
			return resultAndError(nil, newError("%s: reading the inbound edges of node %d to decide why the walk stopped: %s", BuiltinNameLedgerProvenance, last, err.Error()))
		}
		if len(parents) > 0 {
			stoppedAt = "cycle"
			for _, parent := range parents {
				if _, seen := onChain[parent]; !seen {
					stoppedAt = "depth"
					break
				}
			}
		}
	}

	// Every place the chain had more than one ancestry and reported one.
	branchPoints := make([]object.Object, 0)
	for i, node := range result.Chain {
		parents, err := ledgerInboundParents(session, node.ID)
		if err != nil {
			return resultAndError(nil, newError("%s: reading the inbound edges of node %d: %s", BuiltinNameLedgerProvenance, node.ID, err.Error()))
		}
		if len(parents) < 2 {
			continue
		}
		followed := store.NodeID(0)
		if i+1 < len(result.Chain) {
			followed = result.Chain[i+1].ID
		}
		dropped := make([]object.Object, 0, len(parents)-1)
		for _, parent := range parents {
			if parent == followed {
				continue
			}
			dropped = append(dropped, intObj(int64(parent)))
		}
		if len(dropped) == 0 {
			continue
		}
		branchPoints = append(branchPoints, makeHashObject(map[string]object.Object{
			"node":         intObj(int64(node.ID)),
			"followed":     intObj(int64(followed)),
			"not_followed": &object.Array{Elements: dropped},
			"parents":      intObj(int64(len(parents))),
		}))
	}

	root := int64(0)
	if len(result.Chain) > 0 {
		root = int64(result.Chain[len(result.Chain)-1].ID)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"origin":             intObj(int64(origin)),
		"root":               intObj(root),
		"chain":              &object.Array{Elements: chain},
		"length":             intObj(int64(len(result.Chain))),
		"hops":               intObj(int64(len(result.Edges))),
		"max_depth":          intObj(depthArg.Value),
		"stopped_at":         stringObj(stoppedAt),
		"complete":           boolObj(stoppedAt == "root"),
		"branch_points":      &object.Array{Elements: branchPoints},
		"branch_point_count": intObj(int64(len(branchPoints))),
	}), nil)
}

// ledgerCostModels is the set of readings ledger_path will take of an edge.
//
// Named readings rather than a callback, and that is a deliberate refusal of
// the more flexible design. graphene's EdgeCost contract is three obligations
// -- non-negative, deterministic, cheap -- and a function written in Mutant can
// satisfy none of them by construction. graphene checks the first: a negative
// or NaN cost is refused, by edge id. It cannot check the second, and a probe
// confirmed the consequence: a cost function returning a different value each
// time it is asked about the same edge produces a path, with no error, that is
// not the cheapest path and was not costed by the numbers reported for it. The
// third is not a footnote either -- the callback runs once per incident edge
// examined, on Dijkstra's inner loop, and `builtin/resource.go` already
// records that the VM and the evaluator drive a closure through two different
// paths, so the same script would be costing its evidence differently under
// the two engines.
//
// A named model is checkable, identical under both engines, and can be
// reported in the result beside the number it produced.
var ledgerCostModels = map[string]string{
	"hops":       "every step costs 1, so the cheapest path is the one with fewest edges -- what ShortestPath answers, taken through the weighted search so the result carries a cost",
	"weight":     "the edge's weight is the distance, so a heavier edge is further away",
	"similarity": "1 - weight, so a more similar edge is closer; the reading graphene documents for EdgeTypeSimilarTo, whose weight is a similarity score",
}

// ledgerCostFor builds the cost function for a named model, and a closure that
// reports the first edge whose weight the model could not read.
//
// The offending edge is captured rather than pre-validated because validating
// would mean walking every edge in the store to answer a question about the
// few a path touches. graphene refuses the negative cost the moment it sees it
// and names the edge; this is what turns that into a sentence naming the model
// as well.
func ledgerCostFor(model string) (store.EdgeCost, func() (store.EdgeID, float32, bool)) {
	var badEdge store.EdgeID
	var badWeight float32
	bad := false
	note := func(e store.IncidentEdge) {
		if !bad {
			badEdge, badWeight, bad = e.Edge, e.Weight, true
		}
	}
	report := func() (store.EdgeID, float32, bool) { return badEdge, badWeight, bad }

	switch model {
	case "hops":
		return func(store.IncidentEdge) float64 { return 1 }, report
	case "weight":
		return func(e store.IncidentEdge) float64 {
			if e.Weight < 0 {
				note(e)
			}
			return float64(e.Weight)
		}, report
	default: // "similarity"
		return func(e store.IncidentEdge) float64 {
			if e.Weight < 0 || e.Weight > 1 {
				note(e)
			}
			return 1 - float64(e.Weight)
		}, report
	}
}

// ledgerPathCost totals a model's cost over the edges of a finished path.
//
// Recomputed from the returned records rather than accumulated during the
// walk, because graphene's PathResult carries the path and not its price, and
// a number assembled some other way could disagree with the path beside it.
func ledgerPathCost(model string, edges []*store.Edge) float64 {
	total := 0.0
	for _, edge := range edges {
		switch model {
		case "hops":
			total += 1
		case "weight":
			total += float64(edge.Weight)
		default:
			total += 1 - float64(edge.Weight)
		}
	}
	return total
}

// LedgerPath finds the cheapest path between two entities under a named cost
// model.
func LedgerPath(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerPath)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	src, errObj := ledgerNodeArg(args[1], BuiltinNameLedgerPath, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	dst, errObj := ledgerNodeArg(args[2], BuiltinNameLedgerPath, 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	modelArg, ok := args[3].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `%s` must be STRING, got %s", BuiltinNameLedgerPath, args[3].Type()))
	}
	model := strings.ToLower(strings.TrimSpace(modelArg.Value))
	if _, ok := ledgerCostModels[model]; !ok {
		return resultAndError(nil, newError("%s: %q is not a cost model. This language names its readings of an edge rather than taking a function, because a cost must be non-negative, deterministic and cheap and a function written here can be none of those. Use one of: %s", BuiltinNameLedgerPath, modelArg.Value, ledgerCostModelNames()))
	}

	for position, id := range []store.NodeID{src, dst} {
		if _, err := session.graph.GetNode(id); err != nil {
			refusal := ledgerReadRefusal(session, err, id, 0, BuiltinNameLedgerPath)
			return resultAndError(nil, newError("%s (argument %d)", refusal.Message, position+2))
		}
	}

	cost, badEdge := ledgerCostFor(model)
	result, err := session.graph.ShortestWeightedPathCtx(ledgerContext(), src, dst, nil, cost, ledgerWalkBudget())
	switch {
	case errors.Is(err, traversal.ErrNoPath):
		// An answer, not a failure. See the header.
		return resultAndError(makeHashObject(map[string]object.Object{
			"found":      boolObj(false),
			"src":        intObj(int64(src)),
			"dst":        intObj(int64(dst)),
			"cost_model": stringObj(model),
			"cost":       floatObj(0),
			"hops":       intObj(0),
			"nodes":      &object.Array{Elements: []object.Object{}},
			"edges":      &object.Array{Elements: []object.Object{}},
		}), nil)
	case errors.Is(err, store.ErrBudgetExceeded):
		return resultAndError(nil, ledgerBudgetRefusal(err, BuiltinNameLedgerPath))
	case err != nil:
		if id, weight, ok := badEdge(); ok {
			return resultAndError(nil, newError("%s: the %q cost model cannot read edge %d, whose weight is %g. %s. graphene: %s", BuiltinNameLedgerPath, model, id, weight, ledgerCostModels[model], err.Error()))
		}
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerPath, err.Error()))
	}

	nodes := make([]object.Object, 0, len(result.Nodes))
	for _, node := range result.Nodes {
		rendered, err := ledgerNodeObject(node)
		if err != nil {
			return resultAndError(nil, newError("%s: node %d has a property blob this language cannot decode: %s", BuiltinNameLedgerPath, node.ID, err.Error()))
		}
		nodes = append(nodes, rendered)
	}
	edges := make([]object.Object, 0, len(result.Edges))
	for _, edge := range result.Edges {
		rendered, err := ledgerEdgeObject(edge)
		if err != nil {
			return resultAndError(nil, newError("%s: edge %d has a property blob this language cannot decode: %s", BuiltinNameLedgerPath, edge.ID, err.Error()))
		}
		edges = append(edges, rendered)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"found":      boolObj(true),
		"src":        intObj(int64(src)),
		"dst":        intObj(int64(dst)),
		"cost_model": stringObj(model),
		"cost":       floatObj(ledgerPathCost(model, result.Edges)),
		"hops":       intObj(int64(len(result.Edges))),
		"nodes":      &object.Array{Elements: nodes},
		"edges":      &object.Array{Elements: edges},
	}), nil)
}

func ledgerCostModelNames() string {
	names := make([]string, 0, len(ledgerCostModels))
	for name := range ledgerCostModels {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ledgerNodeIDList reads an ARRAY of node ids, preserving order and reporting
// how many duplicates it removed.
func ledgerNodeIDList(arg object.Object, op string, position int) ([]store.NodeID, int, *object.Error) {
	array, ok := arg.(*object.Array)
	if !ok {
		return nil, 0, newError("argument %d to `%s` must be ARRAY, got %s", position, op, arg.Type())
	}
	seen := make(map[store.NodeID]struct{}, len(array.Elements))
	ids := make([]store.NodeID, 0, len(array.Elements))
	duplicates := 0
	for i, element := range array.Elements {
		value, ok := element.(*object.Integer)
		if !ok {
			return nil, 0, newError("%s: element %d of argument %d must be INTEGER, got %s", op, i, position, element.Type())
		}
		if value.Value <= 0 {
			return nil, 0, newError("%s: element %d of argument %d is %d; a node id is positive", op, i, position, value.Value)
		}
		id := store.NodeID(value.Value)
		if _, ok := seen[id]; ok {
			duplicates++
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, duplicates, nil
}

// LedgerSubgraph returns the entities named and every relationship among them.
func LedgerSubgraph(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerSubgraph)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ids, duplicates, errObj := ledgerNodeIDList(args[1], BuiltinNameLedgerSubgraph, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if len(ids) == 0 {
		return resultAndError(nil, newError("%s: the id list is empty. An induced subgraph over nothing is not an empty subgraph, it is a question with no subject", BuiltinNameLedgerSubgraph))
	}

	// Every id is checked first. graphene's InducedSubgraph fetches nodes in
	// order and returns the first error, so one absent id fails the whole call
	// with a message naming only that id -- and an induced subgraph is the
	// claim "these are all the relationships among these entities", which is
	// false rather than incomplete if one of them is missing.
	missing := make([]object.Object, 0)
	var firstErr error
	var firstMissing store.NodeID
	for _, id := range ids {
		if _, err := session.graph.GetNode(id); err != nil {
			if firstErr == nil {
				firstErr, firstMissing = err, id
			}
			missing = append(missing, intObj(int64(id)))
		}
	}
	if firstErr != nil {
		refusal := ledgerReadRefusal(session, firstErr, firstMissing, 0, BuiltinNameLedgerSubgraph)
		if len(missing) > 1 {
			return resultAndError(nil, newError("%s. %d of the %d ids given are not in this ledger; an induced subgraph is the claim that these are all the relationships among these entities, which a missing entity makes false rather than incomplete", refusal.Message, len(missing), len(ids)))
		}
		return resultAndError(nil, refusal)
	}

	nodeRecords, edgeRecords, err := session.graph.InducedSubgraph(ids)
	if err != nil {
		return resultAndError(nil, ledgerReadRefusal(session, err, 0, 0, BuiltinNameLedgerSubgraph))
	}

	nodes := make([]object.Object, 0, len(nodeRecords))
	for _, node := range nodeRecords {
		rendered, err := ledgerNodeObject(node)
		if err != nil {
			return resultAndError(nil, newError("%s: node %d has a property blob this language cannot decode: %s", BuiltinNameLedgerSubgraph, node.ID, err.Error()))
		}
		nodes = append(nodes, rendered)
	}
	edges := make([]object.Object, 0, len(edgeRecords))
	for _, edge := range edgeRecords {
		rendered, err := ledgerEdgeObject(edge)
		if err != nil {
			return resultAndError(nil, newError("%s: edge %d has a property blob this language cannot decode: %s", BuiltinNameLedgerSubgraph, edge.ID, err.Error()))
		}
		edges = append(edges, rendered)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"nodes":      &object.Array{Elements: nodes},
		"edges":      &object.Array{Elements: edges},
		"node_count": intObj(int64(len(nodes))),
		"edge_count": intObj(int64(len(edges))),
		"requested":  intObj(int64(len(ids) + duplicates)),
		"duplicates": intObj(int64(duplicates)),
	}), nil)
}

// ledgerContext is the context every bounded walk in this file runs under.
//
// Background rather than a cancellable one: nothing in this language can
// interrupt a builtin mid-call, so a context that could be cancelled would be
// a channel nobody ever writes to. The budget is what bounds these walks, and
// it is the one that can.
func ledgerContext() context.Context { return context.Background() }

// ledgerLabelSet reads an ARRAY of label offsets as graphene types.
func ledgerLabelSet[T ~uint16](arg object.Object, op, what string, convert func(object.Object) (T, object.Object)) ([]T, *object.Error) {
	array, ok := arg.(*object.Array)
	if !ok {
		return nil, newError("%s: %s must be ARRAY, got %s", op, what, arg.Type())
	}
	labels := make([]T, 0, len(array.Elements))
	for i, element := range array.Elements {
		converted, errObj := convert(element)
		if errObj != nil {
			return nil, newError("%s: %s element %d: %s", op, what, i, errObj.Inspect())
		}
		labels = append(labels, converted)
	}
	return labels, nil
}

// ledgerPatternFrom reads and validates a pattern.
//
// Validation is not politeness here. A pattern edge naming a pattern node that
// does not exist panics inside graphene's matcher -- "index out of range [7]
// with length 1" -- which ends the process, not the call. And an unlabelled
// pattern node with no scope is documented inside graphene as unsupported and
// returns no matches and no error, so a script asking a question it cannot
// answer is told the answer is none.
func ledgerPatternFrom(arg object.Object, scope []store.NodeID, op string) (*traversal.Pattern, *object.Error) {
	hash, ok := arg.(*object.Hash)
	if !ok {
		return nil, newError("argument 2 to `%s` must be HASH, got %s", op, arg.Type())
	}

	nodesValue, ok := hashValueByStringKey(hash, "nodes")
	if !ok {
		return nil, newError("%s: the pattern needs a `nodes` key: an ARRAY of {\"id\": <position>, \"labels\": [<label>]}", op)
	}
	nodeArray, ok := nodesValue.(*object.Array)
	if !ok {
		return nil, newError("%s: the pattern's `nodes` must be ARRAY, got %s", op, nodesValue.Type())
	}
	if len(nodeArray.Elements) < ledgerPatternMinNodes {
		return nil, newError("%s: a pattern needs at least %d nodes, got %d. A one-node pattern is every node carrying its label, which is ledger_query_nodes rather than a match", op, ledgerPatternMinNodes, len(nodeArray.Elements))
	}
	if len(nodeArray.Elements) > ledgerPatternMaxNodes {
		return nil, newError("%s: a pattern is at most %d nodes and this one has %d. Beyond that the backtracking search is not something a caller can wait for; scope the search and ask a smaller question", op, ledgerPatternMaxNodes, len(nodeArray.Elements))
	}

	pattern := &traversal.Pattern{Nodes: make([]traversal.PatternNode, 0, len(nodeArray.Elements))}
	for i, element := range nodeArray.Elements {
		node, ok := element.(*object.Hash)
		if !ok {
			return nil, newError("%s: pattern node %d must be HASH, got %s", op, i, element.Type())
		}
		// The id is required to equal the position. graphene never reads
		// PatternNode.ID -- its matcher indexes candidates and mappings by
		// position -- so a pattern whose ids were written in another order
		// would match a shape the script did not describe, silently.
		if idValue, ok := hashValueByStringKey(node, "id"); ok {
			id, ok := idValue.(*object.Integer)
			if !ok {
				return nil, newError("%s: pattern node %d has a non-INTEGER id", op, i)
			}
			if id.Value != int64(i) {
				return nil, newError("%s: pattern node at position %d declares id %d. A pattern node's id is its position -- graphene matches by position and never reads the id -- so the two must agree or the edges name different nodes than they appear to", op, i, id.Value)
			}
		}

		var labels []store.NodeType
		if labelsValue, ok := hashValueByStringKey(node, "labels"); ok {
			parsed, errObj := ledgerLabelSet(labelsValue, op, fmt.Sprintf("pattern node %d `labels`", i),
				func(o object.Object) (store.NodeType, object.Object) { return dbNodeTypeFromObject(o) })
			if errObj != nil {
				return nil, errObj
			}
			labels = parsed
		}
		if len(labels) == 0 && scope == nil {
			return nil, newError("%s: pattern node %d has no labels and the search has no scope. graphene builds no candidates for that node and the whole pattern then matches nothing, reported as an answer rather than as a refusal -- give the node a label, or scope the search to a set of ids", op, i)
		}
		pattern.Nodes = append(pattern.Nodes, traversal.PatternNode{ID: i, Labels: labels})
	}

	if edgesValue, ok := hashValueByStringKey(hash, "edges"); ok {
		edgeArray, ok := edgesValue.(*object.Array)
		if !ok {
			return nil, newError("%s: the pattern's `edges` must be ARRAY, got %s", op, edgesValue.Type())
		}
		for i, element := range edgeArray.Elements {
			edge, ok := element.(*object.Hash)
			if !ok {
				return nil, newError("%s: pattern edge %d must be HASH, got %s", op, i, element.Type())
			}
			src, errObj := ledgerPatternEndpoint(edge, "src", i, len(pattern.Nodes), op)
			if errObj != nil {
				return nil, errObj
			}
			dst, errObj := ledgerPatternEndpoint(edge, "dst", i, len(pattern.Nodes), op)
			if errObj != nil {
				return nil, errObj
			}
			var labels []store.EdgeType
			if labelsValue, ok := hashValueByStringKey(edge, "labels"); ok {
				parsed, errObj := ledgerLabelSet(labelsValue, op, fmt.Sprintf("pattern edge %d `labels`", i),
					func(o object.Object) (store.EdgeType, object.Object) { return dbEdgeTypeFromObject(o) })
				if errObj != nil {
					return nil, errObj
				}
				labels = parsed
			}
			pattern.Edges = append(pattern.Edges, traversal.PatternEdge{
				SrcPatternID: src, DstPatternID: dst, Labels: labels,
			})
		}
	}
	if len(pattern.Edges) == 0 {
		return nil, newError("%s: the pattern has no edges. Every node then matches independently and the result is the cross product of their candidate sets, which is not a subgraph match", op)
	}
	return pattern, nil
}

// ledgerPatternEndpoint reads one end of a pattern edge and bounds it.
//
// The bound is the crash guard: graphene indexes its mapping slice with this
// number and does not check it.
func ledgerPatternEndpoint(edge *object.Hash, key string, index, nodes int, op string) (int, *object.Error) {
	value, ok := hashValueByStringKey(edge, key)
	if !ok {
		return 0, newError("%s: pattern edge %d needs a `%s`", op, index, key)
	}
	number, ok := value.(*object.Integer)
	if !ok {
		return 0, newError("%s: pattern edge %d `%s` must be INTEGER, got %s", op, index, key, value.Type())
	}
	if number.Value < 0 || number.Value >= int64(nodes) {
		return 0, newError("%s: pattern edge %d names pattern node %d as its %s, and the pattern has %d nodes (0..%d). graphene indexes its mapping with that number without checking it, so this would panic rather than fail", op, index, number.Value, key, nodes, nodes-1)
	}
	return int(number.Value), nil
}

// LedgerPatterns finds every subgraph matching a shape.
func LedgerPatterns(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerPatterns)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var scope []store.NodeID
	scoped := false
	if _, isArray := args[2].(*object.Array); isArray {
		ids, _, errObj := ledgerNodeIDList(args[2], BuiltinNameLedgerPatterns, 3)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		// An empty array is a scope containing nothing, which is a different
		// request from no scope at all and matches nothing. nil means "search
		// the whole graph", which graphene only supports for labelled nodes.
		scope, scoped = ids, true
		if len(ids) == 0 {
			scope = []store.NodeID{}
		}
	} else if integer, ok := args[2].(*object.Integer); !ok || integer.Value != 0 {
		return resultAndError(nil, newError("argument 3 to `%s` must be ARRAY of node ids, or 0 for the whole graph, got %s", BuiltinNameLedgerPatterns, args[2].Type()))
	}

	pattern, errObj := ledgerPatternFrom(args[1], scope, BuiltinNameLedgerPatterns)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	maxArg, ok := args[3].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `%s` must be INTEGER, got %s", BuiltinNameLedgerPatterns, args[3].Type()))
	}
	if maxArg.Value < 0 {
		return resultAndError(nil, newError("%s: maxMatches must not be negative, got %d. Use 0 for no cap", BuiltinNameLedgerPatterns, maxArg.Value))
	}

	matches, err := session.graph.FindPatternsCtx(ledgerContext(), pattern, scope, int(maxArg.Value), ledgerWalkBudget())
	if err != nil {
		if errors.Is(err, store.ErrBudgetExceeded) {
			return resultAndError(nil, ledgerBudgetRefusal(err, BuiltinNameLedgerPatterns))
		}
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerPatterns, err.Error()))
	}

	rendered := make([]object.Object, 0, len(matches))
	for _, match := range matches {
		mapping := make([]object.Object, 0, len(match.Mapping))
		for _, id := range match.Mapping {
			mapping = append(mapping, intObj(int64(id)))
		}
		rendered = append(rendered, &object.Array{Elements: mapping})
	}

	// A cap that was reached is a truncation, and a truncated match set read as
	// a complete one is the same mistake ledger_provenance's stopped_at exists
	// to prevent. graphene caps output and reports nothing about having done so.
	capped := maxArg.Value > 0 && int64(len(matches)) == maxArg.Value

	return resultAndError(makeHashObject(map[string]object.Object{
		"matches":      &object.Array{Elements: rendered},
		"count":        intObj(int64(len(matches))),
		"capped":       boolObj(capped),
		"max_matches":  intObj(maxArg.Value),
		"scoped":       boolObj(scoped),
		"scope_size":   intObj(int64(len(scope))),
		"pattern_size": intObj(int64(len(pattern.Nodes))),
	}), nil)
}

// ledgerFilterOps maps this language's spelling of a comparison onto
// graphene's, and records which of them the comparison rule reaches.
//
// `prefix` and `contains` are string operations in both rules and compare the
// same way either way; the five range operators are the ones a declaration
// changes the meaning of.
var ledgerFilterOps = map[string]struct {
	op      store.PropertyOp
	ordered bool
}{
	"eq":       {store.PropertyOpEqual, false},
	"prefix":   {store.PropertyOpPrefix, false},
	"contains": {store.PropertyOpContains, false},
	"gt":       {store.PropertyOpGreaterThan, true},
	"gte":      {store.PropertyOpGreaterThanOrEqual, true},
	"lt":       {store.PropertyOpLessThan, true},
	"lte":      {store.PropertyOpLessThanOrEqual, true},
	"between":  {store.PropertyOpBetweenInclusive, true},
}

func ledgerFilterOpNames() string {
	names := make([]string, 0, len(ledgerFilterOps))
	for name := range ledgerFilterOps {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ledgerQueryValue reads a filter value as bytes, accepting the same two types
// ledger_add_node accepts for a property.
func ledgerQueryValue(value object.Object, op, what string) ([]byte, *object.Error) {
	switch typed := value.(type) {
	case *object.String:
		return []byte(typed.Value), nil
	case *object.Bytes:
		buf := make([]byte, len(typed.Value))
		copy(buf, typed.Value)
		return buf, nil
	default:
		return nil, newError("%s: %s must be STRING or BYTES, got %s", op, what, value.Type())
	}
}

// ledgerQueryFrom reads a node query, and reports which of its filters are
// range comparisons -- the ones whose meaning depends on a declaration.
func ledgerQueryFrom(arg object.Object, op string) (store.NodeQuery, []store.PropertyFilter, *object.Error) {
	var query store.NodeQuery
	hash, ok := arg.(*object.Hash)
	if !ok {
		return query, nil, newError("argument 2 to `%s` must be HASH, got %s", op, arg.Type())
	}

	if value, ok := hashValueByStringKey(hash, "types"); ok {
		types, errObj := ledgerLabelSet(value, op, "`types`",
			func(o object.Object) (store.NodeType, object.Object) { return dbNodeTypeFromObject(o) })
		if errObj != nil {
			return query, nil, errObj
		}
		query.Types = types
	}
	if value, ok := hashValueByStringKey(hash, "ids"); ok {
		ids, _, errObj := ledgerNodeIDList(value, op, 2)
		if errObj != nil {
			return query, nil, errObj
		}
		query.IDs = ids
	}

	var ranged []store.PropertyFilter
	if value, ok := hashValueByStringKey(hash, "filters"); ok {
		array, ok := value.(*object.Array)
		if !ok {
			return query, nil, newError("%s: `filters` must be ARRAY, got %s", op, value.Type())
		}
		for i, element := range array.Elements {
			filterHash, ok := element.(*object.Hash)
			if !ok {
				return query, nil, newError("%s: filter %d must be HASH, got %s", op, i, element.Type())
			}
			keyValue, ok := hashValueByStringKey(filterHash, "key")
			if !ok {
				return query, nil, newError("%s: filter %d needs a `key`", op, i)
			}
			key, ok := keyValue.(*object.String)
			if !ok {
				return query, nil, newError("%s: filter %d `key` must be STRING, got %s", op, i, keyValue.Type())
			}
			opValue, ok := hashValueByStringKey(filterHash, "op")
			if !ok {
				return query, nil, newError("%s: filter %d needs an `op`, one of: %s", op, i, ledgerFilterOpNames())
			}
			opName, ok := opValue.(*object.String)
			if !ok {
				return query, nil, newError("%s: filter %d `op` must be STRING, got %s", op, i, opValue.Type())
			}
			spec, ok := ledgerFilterOps[strings.ToLower(strings.TrimSpace(opName.Value))]
			if !ok {
				return query, nil, newError("%s: filter %d has op %q, which is not one of: %s", op, i, opName.Value, ledgerFilterOpNames())
			}
			rawValue, ok := hashValueByStringKey(filterHash, "value")
			if !ok {
				return query, nil, newError("%s: filter %d needs a `value`", op, i)
			}
			value, errObj := ledgerQueryValue(rawValue, op, fmt.Sprintf("filter %d `value`", i))
			if errObj != nil {
				return query, nil, errObj
			}
			filter := store.PropertyFilter{Key: key.Value, Op: spec.op, Value: value}
			if spec.op == store.PropertyOpBetweenInclusive {
				upperValue, ok := hashValueByStringKey(filterHash, "value_upper")
				if !ok {
					return query, nil, newError("%s: filter %d is a `between` and needs a `value_upper`. graphene treats a between with no upper bound as matching nothing rather than as an error", op, i)
				}
				upper, errObj := ledgerQueryValue(upperValue, op, fmt.Sprintf("filter %d `value_upper`", i))
				if errObj != nil {
					return query, nil, errObj
				}
				filter.ValueUpper = upper
			}
			query.Filters = append(query.Filters, filter)
			if spec.ordered {
				ranged = append(ranged, filter)
			}
		}
	}

	if value, ok := hashValueByStringKey(hash, "mode"); ok {
		mode, ok := value.(*object.String)
		if !ok {
			return query, nil, newError("%s: `mode` must be STRING, got %s", op, value.Type())
		}
		switch strings.ToLower(strings.TrimSpace(mode.Value)) {
		case "all":
			query.FilterMode = store.MatchAll
		case "any":
			query.FilterMode = store.MatchAny
		default:
			return query, nil, newError("%s: `mode` is %q; it is \"all\" (every filter must match) or \"any\" (at least one)", op, mode.Value)
		}
	}
	if value, ok := hashValueByStringKey(hash, "order"); ok {
		order, ok := value.(*object.String)
		if !ok {
			return query, nil, newError("%s: `order` must be STRING, got %s", op, value.Type())
		}
		switch strings.ToLower(strings.TrimSpace(order.Value)) {
		case "asc":
			query.Order = store.QueryOrderAsc
		case "desc":
			query.Order = store.QueryOrderDesc
		default:
			return query, nil, newError("%s: `order` is %q; it is \"asc\" or \"desc\", and orders by id rather than by any property", op, order.Value)
		}
	}
	for _, spec := range []struct {
		key   string
		field *int
	}{{"offset", &query.Offset}, {"limit", &query.Limit}} {
		value, ok := hashValueByStringKey(hash, spec.key)
		if !ok {
			continue
		}
		number, ok := value.(*object.Integer)
		if !ok {
			return query, nil, newError("%s: `%s` must be INTEGER, got %s", op, spec.key, value.Type())
		}
		if number.Value < 0 {
			return query, nil, newError("%s: `%s` must not be negative, got %d", op, spec.key, number.Value)
		}
		*spec.field = int(number.Value)
	}
	return query, ranged, nil
}

// ledgerComparisonFor names the rule that answered a query's range filters.
//
// The single most important field this file returns. The rule is a property of
// the key's declaration and not of the query text, so two identical queries
// against the same data return different sets depending on a schema decision
// made elsewhere, possibly by somebody else, possibly for performance.
func ledgerComparisonFor(session *ledgerSession, ranged []store.PropertyFilter) (string, []string) {
	if len(ranged) == 0 {
		return "none", nil
	}
	declared, _ := session.graph.OrderedProperties()
	isDeclared := make(map[string]bool, len(declared))
	for _, key := range declared {
		isDeclared[key] = true
	}
	keys := make([]string, 0, len(ranged))
	seen := make(map[string]bool, len(ranged))
	byteWise, numeric := 0, 0
	for _, filter := range ranged {
		if !seen[filter.Key] {
			seen[filter.Key] = true
			keys = append(keys, filter.Key)
		}
		if isDeclared[filter.Key] {
			byteWise++
		} else {
			numeric++
		}
	}
	sort.Strings(keys)
	switch {
	case byteWise > 0 && numeric > 0:
		return "mixed", keys
	case byteWise > 0:
		return "bytes", keys
	default:
		return "numeric-then-bytes", keys
	}
}

// LedgerQueryNodes answers a node query, and says which comparison rule
// answered it.
func LedgerQueryNodes(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerQueryNodes)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	query, ranged, errObj := ledgerQueryFrom(args[1], BuiltinNameLedgerQueryNodes)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	ids, err := session.graph.QueryNodeIDs(query)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerQueryNodes, err.Error()))
	}

	elements := make([]object.Object, 0, len(ids))
	for _, id := range ids {
		elements = append(elements, intObj(int64(id)))
	}
	comparison, keys := ledgerComparisonFor(session, ranged)
	rangeKeys := make([]object.Object, 0, len(keys))
	for _, key := range keys {
		rangeKeys = append(rangeKeys, stringObj(key))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ids":           &object.Array{Elements: elements},
		"count":         intObj(int64(len(ids))),
		"comparison":    stringObj(comparison),
		"range_keys":    &object.Array{Elements: rangeKeys},
		"range_filters": intObj(int64(len(ranged))),
		"limited":       boolObj(query.Limit > 0 && len(ids) == query.Limit),
		"limit":         intObj(int64(query.Limit)),
		"offset":        intObj(int64(query.Offset)),
	}), nil)
}

// LedgerExplainQuery reports how the planner resolved a query.
func LedgerExplainQuery(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerExplainQuery)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	query, _, errObj := ledgerQueryFrom(args[1], BuiltinNameLedgerExplainQuery)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	plan, err := session.graph.ExplainNodeQuery(query)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerExplainQuery, err.Error()))
	}

	residuals := make([]object.Object, 0, len(plan.Residuals))
	for _, residual := range plan.Residuals {
		residuals = append(residuals, makeHashObject(map[string]object.Object{
			"key":   stringObj(residual.Key),
			"op":    stringObj(ledgerOpName(residual.Op)),
			"probe": boolObj(residual.Probe),
			"cost":  intObj(int64(residual.Cost)),
		}))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"driver":         stringObj(plan.Driver.String()),
		"driver_key":     stringObj(plan.DriverKey),
		"driver_filters": intObj(int64(plan.DriverFilters.Count())),
		"candidates":     intObj(int64(plan.Candidates)),
		"results":        intObj(int64(plan.Results)),
		"residuals":      &object.Array{Elements: residuals},
		"residual_count": intObj(int64(len(plan.Residuals))),
		"scanned":        boolObj(plan.Driver == store.DriverScan),
		"plan":           stringObj(plan.String()),
	}), nil)
}

// ledgerOpName is the inverse of ledgerFilterOps, for rendering a plan.
func ledgerOpName(op store.PropertyOp) string {
	for name, spec := range ledgerFilterOps {
		if spec.op == op {
			return name
		}
	}
	return "unknown"
}

// ledgerTargetArg reads the node-or-edge side a declaration applies to.
func ledgerTargetArg(arg object.Object, op string, position int) (bool, *object.Error) {
	value, ok := arg.(*object.String)
	if !ok {
		return false, newError("argument %d to `%s` must be STRING, got %s", position, op, arg.Type())
	}
	switch strings.ToLower(strings.TrimSpace(value.Value)) {
	case "node":
		return false, nil
	case "edge":
		return true, nil
	default:
		return false, newError("%s: target is %q; it is \"node\" or \"edge\". The two index spaces are separate in graphene and a key declared on one is not declared on the other", op, value.Value)
	}
}

// ledgerPropertyKeyArg reads and bounds a property key.
func ledgerPropertyKeyArg(arg object.Object, op string, position int) (string, *object.Error) {
	value, ok := arg.(*object.String)
	if !ok {
		return "", newError("argument %d to `%s` must be STRING, got %s", position, op, arg.Type())
	}
	if strings.TrimSpace(value.Value) == "" {
		return "", newError("%s: a property key must not be empty", op)
	}
	return value.Value, nil
}

// ledgerOrderDisagreement finds two values under a key that the two comparison
// rules put in different orders, or reports that none exist.
//
// Exact rather than a sample, and it needs no sort under the rule that has no
// valid order. The two rules can only disagree about a pair that both parse as
// numbers -- graphene's scan rule falls back to byte comparison the moment
// either side fails to parse -- so sorting the parseable values numerically
// (which is a valid order) and looking for a byte-order inversion between
// neighbours finds a disagreeing pair if one exists, and finds it in n log n.
func ledgerOrderDisagreement(values [][]byte) (lower, higher []byte, found bool) {
	type numeric struct {
		raw []byte
		val float64
	}
	parsed := make([]numeric, 0, len(values))
	for _, value := range values {
		number, err := strconv.ParseFloat(string(value), 64)
		if err != nil {
			continue
		}
		parsed = append(parsed, numeric{raw: value, val: number})
	}
	sort.SliceStable(parsed, func(i, j int) bool { return parsed[i].val < parsed[j].val })
	for i := 1; i < len(parsed); i++ {
		if bytes.Compare(parsed[i-1].raw, parsed[i].raw) > 0 {
			return parsed[i-1].raw, parsed[i].raw, true
		}
	}
	return nil, nil, false
}

// ledgerDistinctValues collects the distinct values indexed under one key.
func ledgerDistinctValues(session *ledgerSession, key string, edgeSide bool) [][]byte {
	seen := make(map[string]struct{})
	var values [][]byte
	collect := func(k string, value []byte) bool {
		if k != key {
			return true
		}
		if _, ok := seen[string(value)]; ok {
			return true
		}
		seen[string(value)] = struct{}{}
		buf := make([]byte, len(value))
		copy(buf, value)
		values = append(values, buf)
		return true
	}
	if edgeSide {
		session.graph.ForEachEdgeProperty(func(_ store.EdgeID, k string, value []byte) bool {
			return collect(k, value)
		})
		return values
	}
	session.graph.ForEachNodeProperty(func(_ store.NodeID, k string, value []byte) bool {
		return collect(k, value)
	})
	return values
}

// LedgerDeclareOrdered declares a key ordered, and says what that does to the
// answers.
func LedgerDeclareOrdered(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerDeclareOrdered)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	key, errObj := ledgerPropertyKeyArg(args[1], BuiltinNameLedgerDeclareOrdered, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeSide, errObj := ledgerTargetArg(args[2], BuiltinNameLedgerDeclareOrdered, 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// Read before declaring. Afterwards the question cannot be asked: the key
	// is compared byte-wise from that point on and the rule this is comparing
	// against no longer applies to it.
	values := ledgerDistinctValues(session, key, edgeSide)
	lower, higher, differs := ledgerOrderDisagreement(values)

	var err error
	if edgeSide {
		err = session.graph.DeclareOrderedEdgeProperty(key)
	} else {
		err = session.graph.DeclareOrderedNodeProperty(key)
	}
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerDeclareOrdered, err.Error()))
	}

	example := makeHashObject(nil)
	if differs {
		example = makeHashObject(map[string]object.Object{
			"numerically_lower": &object.Bytes{Value: lower},
			"byte_wise_lower":   &object.Bytes{Value: higher},
		})
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"key":             stringObj(key),
		"target":          stringObj(ledgerTargetName(edgeSide)),
		"declared":        boolObj(true),
		"comparison":      stringObj("bytes"),
		"was":             stringObj("numeric-then-bytes"),
		"distinct_values": intObj(int64(len(values))),
		"order_differs":   boolObj(differs),
		"example":         example,
	}), nil)
}

func ledgerTargetName(edgeSide bool) string {
	if edgeSide {
		return "edge"
	}
	return "node"
}

// LedgerDeclareUnique makes an indexed value into a name.
func LedgerDeclareUnique(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerDeclareUnique)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	key, errObj := ledgerPropertyKeyArg(args[1], BuiltinNameLedgerDeclareUnique, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeSide, errObj := ledgerTargetArg(args[2], BuiltinNameLedgerDeclareUnique, 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var err error
	if edgeSide {
		err = session.graph.DeclareUniqueEdgeProperty(key)
	} else {
		err = session.graph.DeclareUniqueProperty(key)
	}
	if err != nil {
		// graphene's message names the value and every id holding it, which is
		// the whole answer -- passed through rather than summarised.
		return resultAndError(nil, newError("%s: %s. A unique declaration is checked against what is already written, so this is a statement about the evidence rather than about the schema", BuiltinNameLedgerDeclareUnique, err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"key":      stringObj(key),
		"target":   stringObj(ledgerTargetName(edgeSide)),
		"declared": boolObj(true),
		"checked":  boolObj(true),
	}), nil)
}

// LedgerDeclareUniqueEdge constrains how many edges of one type may join a
// pair of entities.
func LedgerDeclareUniqueEdge(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerDeclareUniqueEdge)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeType, typeErr := dbEdgeTypeFromObject(args[1])
	if typeErr != nil {
		return resultAndError(nil, newError("argument 2 to `%s`: %s", BuiltinNameLedgerDeclareUniqueEdge, typeErr.Inspect()))
	}

	if err := session.graph.DeclareUniqueEdge(edgeType); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerDeclareUniqueEdge, err.Error()))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"edge_type": intObj(int64(edgeType - store.EdgeTypeCustomBase)),
		"declared":  boolObj(true),
		"checked":   boolObj(true),
		"enforced":  stringObj("at commit: a second edge of this type between the same pair is refused by ledger_add_edge, not by this call"),
	}), nil)
}

// LedgerDeclareComposite declares one key tuple, which serves a conjunction of
// equality filters over exactly those keys.
func LedgerDeclareComposite(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerDeclareComposite)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	array, ok := args[1].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be ARRAY of STRING, got %s", BuiltinNameLedgerDeclareComposite, args[1].Type()))
	}
	keys := make([]string, 0, len(array.Elements))
	for i, element := range array.Elements {
		value, ok := element.(*object.String)
		if !ok {
			return resultAndError(nil, newError("%s: key %d must be STRING, got %s", BuiltinNameLedgerDeclareComposite, i, element.Type()))
		}
		if strings.TrimSpace(value.Value) == "" {
			return resultAndError(nil, newError("%s: key %d is empty", BuiltinNameLedgerDeclareComposite, i))
		}
		keys = append(keys, value.Value)
	}
	edgeSide, errObj := ledgerTargetArg(args[2], BuiltinNameLedgerDeclareComposite, 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var err error
	if edgeSide {
		err = session.graph.DeclareCompositeEdgeProperties(keys)
	} else {
		err = session.graph.DeclareCompositeNodeProperties(keys)
	}
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerDeclareComposite, err.Error()))
	}

	rendered := make([]object.Object, 0, len(keys))
	for _, key := range keys {
		rendered = append(rendered, stringObj(key))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"keys":     &object.Array{Elements: rendered},
		"target":   stringObj(ledgerTargetName(edgeSide)),
		"declared": boolObj(true),
		"serves":   stringObj("a conjunction of equality filters over exactly these keys; a query naming fewer of them, or any range comparison, is driven some other way"),
	}), nil)
}

// LedgerIndexes reports every declaration in force.
func LedgerIndexes(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerIndexes)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	orderedNode, orderedEdge := session.graph.OrderedProperties()
	uniqueNode, uniqueEdge := session.graph.UniqueProperties()
	compositeNode, compositeEdge := session.graph.CompositeProperties()

	edgeTypes := make([]object.Object, 0)
	for _, edgeType := range session.graph.UniqueEdges() {
		edgeTypes = append(edgeTypes, intObj(int64(edgeType-store.EdgeTypeCustomBase)))
	}

	count := len(orderedNode) + len(orderedEdge) + len(uniqueNode) + len(uniqueEdge) +
		len(compositeNode) + len(compositeEdge) + len(edgeTypes)

	return resultAndError(makeHashObject(map[string]object.Object{
		"ordered_node_keys":   ledgerStringArray(orderedNode),
		"ordered_edge_keys":   ledgerStringArray(orderedEdge),
		"unique_node_keys":    ledgerStringArray(uniqueNode),
		"unique_edge_keys":    ledgerStringArray(uniqueEdge),
		"composite_node_keys": ledgerTupleArray(compositeNode),
		"composite_edge_keys": ledgerTupleArray(compositeEdge),
		"unique_edge_types":   &object.Array{Elements: edgeTypes},
		"count":               intObj(int64(count)),
	}), nil)
}

func ledgerStringArray(values []string) object.Object {
	elements := make([]object.Object, 0, len(values))
	for _, value := range values {
		elements = append(elements, stringObj(value))
	}
	return &object.Array{Elements: elements}
}

func ledgerTupleArray(tuples [][]string) object.Object {
	elements := make([]object.Object, 0, len(tuples))
	for _, tuple := range tuples {
		elements = append(elements, ledgerStringArray(tuple))
	}
	return &object.Array{Elements: elements}
}
