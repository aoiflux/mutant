package builtin

// Reading the ledger under a view.
//
// `ledger_under_view(ledger, view)` returns a second handle to an open ledger,
// through which the reads show what the view shows and nothing else: the
// script nodes classified in the view's case within the classes it grants
// (ledger_classify.go), the case's own Case and Record nodes, and the
// Classification nodes of the classes it grants -- and an edge only when both
// its ends are shown and it is a script's edge, an IN_CASE or a CLASSIFIED_AS.
// A report built through it carries what that view's recipient may be given,
// and no walk through it crosses a node it does not show.
//
// # It fails closed
//
// Every builtin that takes a ledger refuses a handle under a view, except the
// reads in ledgerViewReads -- which resolve their handle with
// ledgerReadHandleArg -- and ledger_close. ledgerHandleArg, which everything
// else resolves with, every writer included, refuses one by name. So a builtin
// added to the family later refuses a filtered handle until somebody decides it
// can read through one, rather than reading the whole ledger through a handle
// that says it is filtered.
//
// # What a read under a view cannot say
//
// A node the view does not show, one the ledger does not hold and one a
// redaction removed get one answer, and nothing a read under a view returns
// counts what it withheld: a count is information. So ledger_query_nodes
// answers index_keys_known false -- whether a key is indexed anywhere says
// whether a withheld node holds it -- and a walk's `complete`, `found` and
// `stopped_at` are claims about what the view shows: a root under a view is a
// node with no parent the view shows. Each such read says which view it
// answered under.
//
// # The graphene trap this is built around
//
// graphene's walks take a store.GraphReader, and its walker and pattern matcher
// use store.AdjacencyReader -- IncidentEdges and NodeExists -- instead of
// EdgesOf when the reader they are handed has it. A filter that embedded the
// snapshot it reads would promote both, and every walk would read the
// unfiltered adjacency through a handle that says it is filtered.
// ledgerViewReader keeps its snapshot in a field and has the twelve reader
// methods and no others (TestTheViewReaderIsOnlyAGraphReader).
//
// # Not access control
//
// The program holding a handle under a view holds the ledger's own handle too.
// What the view limits is what a read through it returns, and so what a report
// built from those reads can carry to the view's recipient. It keeps nothing
// from anybody.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// ledgerView is a ledger read under a view: ledger_under_view's handle.
type ledgerView struct {
	// parent is the ledger's own handle, resolved on every read, so a view of
	// a ledger that has since been closed refuses rather than reading a store
	// that is gone.
	parent int64
	path   string
	view   caseView
	// grants is the view's tags, lowercased, fixed when the handle was made.
	grants  map[string]bool
	caseUID string
	caseID  string
}

// ledgerViewReads are the reads a handle under a view may be passed to. Every
// other builtin that takes a ledger refuses one, except ledger_close.
var ledgerViewReads = []string{
	BuiltinNameLedgerNode, BuiltinNameLedgerEdge, BuiltinNameLedgerProvenance, BuiltinNameLedgerPath,
	BuiltinNameLedgerSubgraph, BuiltinNameLedgerPatterns, BuiltinNameLedgerQueryNodes, BuiltinNameLedgerProveNode,
}

// LedgerViewReads is ledgerViewReads, for the editor's rule that a handle under
// a view goes nowhere else.
func LedgerViewReads() []string { return slices.Clone(ledgerViewReads) }

// RefusesLedgerViewHandle reports whether a builtin refuses a handle under a
// view: every builtin that takes a ledger as its first argument does, except
// the reads in ledgerViewReads and ledger_close. The editor's
// filteredLedgerHandle rule asks it, and
// TestEveryBuiltinTakingALedgerRefusesAHandleUnderAViewUnlessItReadsThroughOne
// holds it to what each builtin does.
func RefusesLedgerViewHandle(name string) bool {
	doc, ok := builtinDocs[name]
	if !ok || len(doc.params) == 0 || strings.TrimSuffix(doc.params[0].name, "?") != "ledger" {
		return false
	}
	return name != BuiltinNameLedgerClose && !slices.Contains(ledgerViewReads, name)
}

// ledgerViewRefusal is every other builtin's answer to a handle under a view.
func ledgerViewRefusal(op string, handle int64, v *ledgerView) *object.Error {
	return newError("%s: handle %d is ledger %s read under view %q, and %s does not read under a view; only %s "+
		"do, and ledger_close drops such a handle. Pass the ledger's own handle (%d), knowing that nothing it "+
		"returns is filtered", op, handle, v.path, v.view.Label, op, strings.Join(ledgerViewReads, ", "), v.parent)
}

// ledgerReading is the ledger a read reads, and the view it reads it under:
// nil when the read was handed the ledger's own handle.
type ledgerReading struct {
	session *ledgerSession
	view    *ledgerView
}

// ledgerReadHandleArg resolves argument one of a read that takes a handle
// under a view as well as the ledger's own.
func ledgerReadHandleArg(arg object.Object, op string) (ledgerReading, *object.Error) {
	handle, ok := arg.(*object.Integer)
	if !ok {
		return ledgerReading{}, newError("argument 1 to `%s` must be INTEGER, got %s", op, arg.Type())
	}
	if value, found := ledgerHandles.Load(handle.Value); found {
		if view, isView := value.(*ledgerView); isView {
			session, open := ledgerGet(view.parent)
			if !open {
				return ledgerReading{}, newError("%s: handle %d reads ledger %s under view %q, and the ledger's "+
					"own handle (%d) has been closed", op, handle.Value, view.path, view.view.Label, view.parent)
			}
			return ledgerReading{session: session, view: view}, nil
		}
	}
	session, errObj := ledgerHandleArg(arg, op)
	if errObj != nil {
		return ledgerReading{}, errObj
	}
	return ledgerReading{session: session}, nil
}

// viewLabel is the view a read answered under, and "" for the ledger's own
// handle.
func (r ledgerReading) viewLabel() string {
	if r.view == nil {
		return ""
	}
	return r.view.view.Label
}

// reader is what a read reads through, and done releases it. For the ledger's
// own handle it is the ledger's store -- the value graphene's own walk methods
// hand the traversal package, whose adjacency fast path the Graph wrapping it
// does not promote. Under a view it is ledgerViewReader over a snapshot, so the
// decisions about what is shown and the walk that uses them read one graph.
func (r ledgerReading) reader(op string) (store.GraphReader, func(), *object.Error) {
	if r.view == nil {
		return r.session.graph.GraphStore, func() {}, nil
	}
	snapshot, err := r.session.graph.Snapshot()
	if err != nil {
		return nil, nil, newError("%s: %s", op, err.Error())
	}
	reader := &ledgerViewReader{snapshot: snapshot, view: r.view, shown: map[store.NodeID]bool{}}
	return reader, func() { _ = snapshot.Close() }, nil
}

// missing is a read's answer to an id it could not read. The ledger's own
// handle says whether a redaction removed it (ledgerReadRefusal); a handle
// under a view says only that the view does not show it, which is also all it
// says of an id the ledger never held.
func (r ledgerReading) missing(err error, nodeID store.NodeID, edgeID store.EdgeID, op string) *object.Error {
	if r.view == nil {
		return ledgerReadRefusal(r.session, err, nodeID, edgeID, op)
	}
	var notFound *store.ErrNotFound
	if !errors.As(err, &notFound) {
		return newError("%s: %s", op, err.Error())
	}
	subject := fmt.Sprintf("node %d", nodeID)
	if edgeID != 0 {
		subject = fmt.Sprintf("edge %d", edgeID)
	}
	return newError("%s: %s is not visible under view %q: the ledger does not hold it, or holds it and the view "+
		"does not show it, and a read under a view does not say which", op, subject, r.view.view.Label)
}

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

// ledgerViewReader answers graphene's reader interface from one snapshot, with
// every node and edge the view does not show taken out. It keeps the snapshot
// in a field rather than embedding it; see the file header.
type ledgerViewReader struct {
	snapshot store.GraphReader
	view     *ledgerView
	// shown is every decision this read has made, by node id.
	shown map[store.NodeID]bool
}

var _ store.GraphReader = (*ledgerViewReader)(nil)

// errLedgerViewCount is the answer to a count under a view: a count of what the
// ledger holds is a count of what the view withholds too. No graphene walk
// asks for one.
var errLedgerViewCount = errors.New("a read under a view does not count what the ledger holds")

func (r *ledgerViewReader) GetNode(id store.NodeID) (*store.Node, error) {
	node, err := r.snapshot.GetNode(id)
	if err != nil {
		return nil, err
	}
	shown, err := r.showsNode(node)
	if err != nil {
		return nil, err
	}
	if !shown {
		return nil, &store.ErrNotFound{Kind: "node", ID: uint64(id)}
	}
	return node, nil
}

func (r *ledgerViewReader) GetEdge(id store.EdgeID) (*store.Edge, error) {
	edge, err := r.snapshot.GetEdge(id)
	if err != nil {
		return nil, err
	}
	shown, err := r.showsEdge(edge)
	if err != nil {
		return nil, err
	}
	if !shown {
		return nil, &store.ErrNotFound{Kind: "edge", ID: uint64(id)}
	}
	return edge, nil
}

// Neighbours is built on EdgesOf rather than filtering the snapshot's answer:
// that answer keeps one edge per neighbour, and if it kept one the view does
// not show, a neighbour joined by another edge the view does show would be
// lost.
func (r *ledgerViewReader) Neighbours(id store.NodeID, dir store.Direction, edgeTypes []store.EdgeType) ([]store.NeighbourResult, error) {
	edges, err := r.EdgesOf(id, dir, edgeTypes)
	if err != nil || len(edges) == 0 {
		return nil, err
	}
	seen := make(map[store.NodeID]bool, len(edges))
	out := make([]store.NeighbourResult, 0, len(edges))
	for _, edge := range edges {
		far := edge.Dst
		if far == id {
			far = edge.Src
		}
		if seen[far] {
			continue
		}
		seen[far] = true
		node, err := r.snapshot.GetNode(far)
		if err != nil {
			return nil, err
		}
		out = append(out, store.NeighbourResult{Node: node, Edge: edge})
	}
	return out, nil
}

// EdgesOf answers a node the view does not show as the snapshot answers one it
// does not hold: no edges.
func (r *ledgerViewReader) EdgesOf(id store.NodeID, dir store.Direction, edgeTypes []store.EdgeType) ([]*store.Edge, error) {
	shown, err := r.showsNodeID(id)
	if err != nil || !shown {
		return nil, err
	}
	edges, err := r.snapshot.EdgesOf(id, dir, edgeTypes)
	if err != nil {
		return nil, err
	}
	out := make([]*store.Edge, 0, len(edges))
	for _, edge := range edges {
		shown, err := r.showsEdge(edge)
		if err != nil {
			return nil, err
		}
		if shown {
			out = append(out, edge)
		}
	}
	return out, nil
}

func (r *ledgerViewReader) NodesByType(t store.NodeType) ([]store.NodeID, error) {
	return r.keepNodes(r.snapshot.NodesByType(t))
}

func (r *ledgerViewReader) EdgesByType(t store.EdgeType) ([]store.EdgeID, error) {
	return r.keepEdges(r.snapshot.EdgesByType(t))
}

func (r *ledgerViewReader) NodesByProperty(key string, value []byte) ([]store.NodeID, error) {
	return r.keepNodes(r.snapshot.NodesByProperty(key, value))
}

func (r *ledgerViewReader) EdgesByProperty(key string, value []byte) ([]store.EdgeID, error) {
	return r.keepEdges(r.snapshot.EdgesByProperty(key, value))
}

func (r *ledgerViewReader) QueryNodeIDs(q store.NodeQuery) ([]store.NodeID, error) {
	offset, limit := q.Offset, q.Limit
	q.Offset, q.Limit = 0, 0
	ids, err := r.snapshot.QueryNodeIDs(q)
	if err != nil {
		return nil, err
	}
	return ledgerViewPage(ids, offset, limit, r.showsNodeID)
}

func (r *ledgerViewReader) QueryEdgeIDs(q store.EdgeQuery) ([]store.EdgeID, error) {
	offset, limit := q.Offset, q.Limit
	q.Offset, q.Limit = 0, 0
	ids, err := r.snapshot.QueryEdgeIDs(q)
	if err != nil {
		return nil, err
	}
	return ledgerViewPage(ids, offset, limit, r.showsEdgeID)
}

func (r *ledgerViewReader) NodeCount() (uint64, error) { return 0, errLedgerViewCount }

func (r *ledgerViewReader) EdgeCount() (uint64, error) { return 0, errLedgerViewCount }

// ledgerViewPage keeps a query's shown ids and only then applies its offset and
// limit. Applied first, they would count what the view does not show, and a
// page cut short by withheld ids says how many there were.
func ledgerViewPage[ID any](ids []ID, offset, limit int, shows func(ID) (bool, error)) ([]ID, error) {
	out := make([]ID, 0)
	for _, id := range ids {
		shown, err := shows(id)
		if err != nil {
			return nil, err
		}
		if !shown {
			continue
		}
		if offset > 0 {
			offset--
			continue
		}
		out = append(out, id)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

// keepNodes keeps the shown ids of a posting, in its order.
func (r *ledgerViewReader) keepNodes(ids []store.NodeID, err error) ([]store.NodeID, error) {
	if err != nil {
		return nil, err
	}
	return ledgerViewPage(ids, 0, 0, r.showsNodeID)
}

func (r *ledgerViewReader) keepEdges(ids []store.EdgeID, err error) ([]store.EdgeID, error) {
	if err != nil {
		return nil, err
	}
	return ledgerViewPage(ids, 0, 0, r.showsEdgeID)
}

// showsNodeID decides whether the view shows the node with this id. One the
// snapshot does not hold is not shown, and that is not an error.
func (r *ledgerViewReader) showsNodeID(id store.NodeID) (bool, error) {
	if shown, decided := r.shown[id]; decided {
		return shown, nil
	}
	node, err := r.snapshot.GetNode(id)
	var notFound *store.ErrNotFound
	switch {
	case errors.As(err, &notFound):
		r.shown[id] = false
		return false, nil
	case err != nil:
		return false, err
	}
	return r.showsNode(node)
}

func (r *ledgerViewReader) showsNode(node *store.Node) (bool, error) {
	if shown, decided := r.shown[node.ID]; decided {
		return shown, nil
	}
	shown, err := r.decide(node)
	if err != nil {
		return false, err
	}
	r.shown[node.ID] = shown
	return shown, nil
}

// decide is the rule for a node; see the file header.
func (r *ledgerViewReader) decide(node *store.Node) (bool, error) {
	if ledgerScriptNodeLabels(node.Labels) {
		classification, err := classificationRead(r.snapshot, r.view.caseUID, node.ID)
		if err != nil {
			// Named without the chain's detail: the reader of this refusal may
			// be reading under the view, and the ledger's own handle says why.
			return false, fmt.Errorf("the classification of node %d in case %s cannot be read, so whether view "+
				"%q shows it is not decided; ledger_classifications on the ledger's own handle says why", node.ID,
				r.view.caseID, r.view.view.Label)
		}
		tags := classification.tags()
		if len(tags) == 0 {
			// Never classified, or classified as holding nothing.
			return false, nil
		}
		for _, tag := range tags {
			if !r.view.grants[tag] {
				return false, nil
			}
		}
		return true, nil
	}
	if len(node.Labels) != 1 {
		return false, nil
	}
	var key string
	switch node.Labels[0] {
	case disclosureNodeCase:
		key = "case.uid"
	case disclosureNodeRecord:
		key = "record.case_uid"
	case disclosureNodeClass:
		key = "class.tag"
	default:
		return false, nil
	}
	props, err := ledgerDecodeProperties(node.Properties)
	if err != nil {
		return false, fmt.Errorf("node %d has a property blob this language cannot decode: %w", node.ID, err)
	}
	if key == "class.tag" {
		return r.view.grants[string(props[key])], nil
	}
	return string(props[key]) == r.view.caseUID, nil
}

// ledgerViewSchemaEdge reports the schema edges a view shows between two nodes
// it shows: a record's or a granted class's IN_CASE, and a record's
// CLASSIFIED_AS to a class the view grants.
func ledgerViewSchemaEdge(labels []store.EdgeType) bool {
	return len(labels) == 1 && (labels[0] == disclosureEdgeInCase || labels[0] == disclosureEdgeClassifiedAs)
}

func (r *ledgerViewReader) showsEdge(edge *store.Edge) (bool, error) {
	if !ledgerScriptEdgeLabels(edge.Labels) && !ledgerViewSchemaEdge(edge.Labels) {
		return false, nil
	}
	for _, end := range [2]store.NodeID{edge.Src, edge.Dst} {
		shown, err := r.showsNodeID(end)
		if err != nil || !shown {
			return false, err
		}
	}
	return true, nil
}

func (r *ledgerViewReader) showsEdgeID(id store.EdgeID) (bool, error) {
	edge, err := r.snapshot.GetEdge(id)
	var notFound *store.ErrNotFound
	switch {
	case errors.As(err, &notFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return r.showsEdge(edge)
}

// ---------------------------------------------------------------------------
// ledger_under_view
// ---------------------------------------------------------------------------

// ledgerViewTermsLocked finds a declared view of the open case, and the case
// whose classifications it reads. The caller holds the store lock.
func ledgerViewTermsLocked(op, name, canonical string) (caseView, string, string, *object.Error) {
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return caseView{}, "", "", errObj
	}
	if session.caseUID == "" {
		return caseView{}, "", "", newError("%s: no case key is open; a view shows the nodes classified in its "+
			"case, and a case is found in its ledger by the identity its key file carries. Call "+
			"`case_key_open(path)` first", op)
	}
	view, found := viewByCanonicalLocked(session, canonical)
	if !found {
		return caseView{}, "", "", viewUndeclared(op, session, name)
	}
	return view, strings.ToLower(session.caseUID), session.ID, nil
}

// LedgerUnderView returns a handle through which the reads show a ledger as a
// view shows it: ledger_under_view(ledger, view).
func LedgerUnderView(args ...object.Object) object.Object {
	op := BuiltinNameLedgerUnderView
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	name, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	canonical, errObj := canonicalLabel(op, "view name", name)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.RLock()
	view, caseUID, caseID, errObj := ledgerViewTermsLocked(op, name, canonical)
	custodyStore.RUnlock()
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	v := &ledgerView{parent: ledger.handle, path: ledger.path, view: view, grants: viewGrantedTags(view),
		caseUID: caseUID, caseID: caseID}
	handle := atomic.AddInt64(&ledgerHandleCounter, 1)
	ledgerHandles.Store(handle, v)

	custodyRecordArtifact(op, fmt.Sprintf("ledger %s read under view %q through handle %d", ledger.path, view.Label,
		handle), map[string]any{
		"path":          ledger.path,
		"view":          view.Label,
		"handle":        fmt.Sprintf("%d", handle),
		"ledger_handle": fmt.Sprintf("%d", ledger.handle),
		"grants":        strings.Join(view.Classes, ", "),
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":  intObj(handle),
		"ledger":  intObj(ledger.handle),
		"path":    stringObj(ledger.path),
		"view":    stringObj(view.Label),
		"grants":  stringListObj(view.Classes),
		"case_id": stringObj(caseID),
		"reads":   stringListObj(ledgerViewReads),
		// The program holding this handle holds the ledger's own as well.
		"access_control": boolObj(false),
	}), nil)
}
