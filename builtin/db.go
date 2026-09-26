package builtin

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"
	"github.com/aoiflux/graphene/traversal"

	"mutant/graphstore"
	"mutant/object"
)

var (
	dbHandleCounter int64
	// dbHandles maps int64 → *graphene.Graph.
	//
	// There is deliberately no lock around graph operations. graphene documents
	// both bundled backends as safe for concurrent use — the in-memory store is
	// a thread-safe GraphStore, the disk store carries its own RWMutex — and
	// every method takes the locks it needs internally. A single process-wide
	// mutex here also serialised unrelated handles against each other, which
	// matters under net_serve where many handlers run at once.
	//
	// What the library does *not* offer is snapshot isolation: a sequence of
	// calls is not a transaction, and an ID returned by a query may already be
	// gone by the time it is used. Each db_* builtin is a single store call, so
	// that is not a concern here; a builtin that ever spans several calls would
	// need graphene's own Begin/Commit rather than a lock.
	dbHandles sync.Map
	// dbDiskStores maps the handle of each db_open_disk store to a
	// *dbDiskStore, so the end of a program can name a store it forgot to
	// close and db_stats can say how a store was opened. An in-memory graph has
	// nothing on disk to leave unclean and is not in it.
	dbDiskStores sync.Map
)

// dbDiskStore is what a disk-backed handle remembers about how it was opened.
type dbDiskStore struct {
	path string
	// readOnly is set by db_open_disk's read_only option, and lockFree is the
	// reason such a read took no lock, or empty when it took one. See
	// graphstore.OpenForReading.
	readOnly bool
	lockFree string
}

const DATA = 0

// dbDefaultNodeType is the type db_add_node uses when a script names none, and
// the one db_add_artifact has always used.
func dbDefaultNodeType() store.NodeType {
	return store.CustomNodeType(uint16(DATA))
}

func dbTypeFromEnumValue(enumValue *object.EnumValue, kind string) (int64, object.Object) {
	if enumValue.Value == nil || enumValue.Value.Type() == object.NULL_OBJ {
		if strings.EqualFold(enumValue.Tag, "DATA") {
			return DATA, nil
		}
		return 0, newError("%s type enum value must carry INTEGER payload in range 0..127 or use tag DATA", kind)
	}

	intValue, ok := enumValue.Value.(*object.Integer)
	if !ok {
		return 0, newError("%s type enum payload must be INTEGER, got %s", kind, enumValue.Value.Type())
	}
	if intValue.Value < 0 || intValue.Value > 127 {
		return 0, newError("%s type must be in range 0..127, got %d", kind, intValue.Value)
	}
	return intValue.Value, nil
}

func dbNodeTypeFromObject(arg object.Object) (store.NodeType, object.Object) {
	switch value := arg.(type) {
	case *object.Integer:
		// 0 is accepted: it is the DATA type that db_add_node uses when no type
		// is given, and the DATA enum tag produces it too. Rejecting it here
		// while accepting it everywhere else meant db_add_node(h, 0) errored
		// where db_add_node(h) succeeded with the very same type.
		if value.Value < 0 || value.Value > 127 {
			return 0, newError("node type must be in range 0..127, got %d", value.Value)
		}
		return store.CustomNodeType(uint16(value.Value)), nil
	case *object.EnumValue:
		enumType, errObj := dbTypeFromEnumValue(value, "node")
		if errObj != nil {
			return 0, errObj
		}
		return store.CustomNodeType(uint16(enumType)), nil
	default:
		return 0, newError("node type must be INTEGER or ENUM_VALUE, got %s", arg.Type())
	}
}

func dbEdgeTypeFromObject(arg object.Object) (store.EdgeType, object.Object) {
	switch value := arg.(type) {
	case *object.Integer:
		// 0 is accepted for the same reason as node types above.
		if value.Value < 0 || value.Value > 127 {
			return 0, newError("edge type must be in range 0..127, got %d", value.Value)
		}
		return store.CustomEdgeType(uint16(value.Value)), nil
	case *object.EnumValue:
		enumType, errObj := dbTypeFromEnumValue(value, "edge")
		if errObj != nil {
			return 0, errObj
		}
		return store.CustomEdgeType(uint16(enumType)), nil
	default:
		return 0, newError("edge type must be INTEGER or ENUM_VALUE, got %s", arg.Type())
	}
}

func dbGet(handle int64) (*graphene.Graph, bool) {
	v, ok := dbHandles.Load(handle)
	if !ok {
		return nil, false
	}
	g, ok := v.(*graphene.Graph)
	return g, ok
}

func DbOpen(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	g := graphene.NewInMemory()
	handle := atomic.AddInt64(&dbHandleCounter, 1)
	dbHandles.Store(handle, g)
	return resultAndError(intObj(handle), nil)
}

func DbOpenDisk(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_open_disk` must be STRING, got %s", args[0].Type()))
	}

	// A forensic ledger is a graphene store too, and opening one here would
	// open it with no signer. The write that followed would commit unsigned,
	// and graphene would then refuse to replay the log under the ledger's own
	// posture -- "commit N carries no signature and signed commits are
	// required" -- leaving a ledger that no strict open ever accepts again.
	// That is detection rather than prevention, and what it detects is a store
	// nobody can open, so the refusal happens here instead.
	//
	// It guards Mutant against itself and nothing more: another process is
	// stopped by graphene's own lock while the ledger is open, and by nothing
	// once it is closed.
	if ledgerIsMarked(path.Value) {
		return resultAndError(nil, newError("db_open_disk: %s is a Mutant forensic ledger; open it with ledger_open, because opening it here would write unsigned commits into a store that requires signed ones", path.Value))
	}
	if errObj := dbRefuseForeignLabels(path.Value); errObj != nil {
		return resultAndError(nil, errObj)
	}

	opts := disk.Options{}
	readOnly := false
	if len(args) == 2 {
		parsed, readOnlyOpt, errObj := dbOpenOptions(args[1])
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		opts, readOnly = parsed, readOnlyOpt
	}

	opened := &dbDiskStore{path: path.Value, readOnly: readOnly}
	var g *graphene.Graph
	var err error
	if readOnly {
		// Never creates a store, never takes a writer's lock, and says when it
		// could take no lock at all -- which db_stats then reports.
		g, opened.lockFree, err = graphstore.OpenForReadingWith(path.Value, opts)
	} else {
		g, err = graphene.OpenWithOptions(path.Value, opts)
	}
	if err != nil {
		return resultAndError(nil, newError("db_open_disk: %s", err.Error()))
	}
	handle := atomic.AddInt64(&dbHandleCounter, 1)
	dbDiskStores.Store(handle, opened)
	dbHandles.Store(handle, g)
	return resultAndError(intObj(handle), nil)
}

// dbOpenOptions maps the optional second argument of db_open_disk onto the
// store's open-time options.
//
// Only the memory ceiling is exposed, and deliberately. The store has a large
// options surface -- signing, audit, retention, redaction, roles -- and every
// one of those is a forensic-integrity decision that belongs in its own
// builtin with its own contract, not in an untyped hash a script assembles.
// Memory is different: a script that ingests a large graph either fits in the
// ceiling it is running under or is killed, and nothing else in the language
// lets it say so.
//
// An unknown key is refused rather than ignored. A misspelled option that is
// silently dropped reads as a store running under a budget it does not have.
//
// read_only is the one option that is not a store option: it chooses how the
// store is opened at all, so it comes back on its own.
func dbOpenOptions(arg object.Object) (disk.Options, bool, *object.Error) {
	opts := disk.Options{}
	readOnly := false

	hash, ok := arg.(*object.Hash)
	if !ok {
		return opts, false, newError("argument 2 to `db_open_disk` must be HASH, got %s", arg.Type())
	}

	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return opts, false, newError("db_open_disk: option keys must be STRING, got %s", pair.Key.Type())
		}
		switch key.Value {
		case "memory_budget":
			budget, ok := pair.Value.(*object.Integer)
			if !ok {
				return opts, false, newError("db_open_disk: memory_budget must be INTEGER, got %s", pair.Value.Type())
			}
			if budget.Value < 0 {
				return opts, false, newError("db_open_disk: memory_budget must not be negative, got %d", budget.Value)
			}
			opts.MemoryBudget = budget.Value
		case "discover_memory_budget":
			discover, ok := pair.Value.(*object.Boolean)
			if !ok {
				return opts, false, newError("db_open_disk: discover_memory_budget must be BOOLEAN, got %s", pair.Value.Type())
			}
			opts.DiscoverMemoryBudget = discover.Value
		case "verify_on_open":
			verify, ok := pair.Value.(*object.Boolean)
			if !ok {
				return opts, false, newError("db_open_disk: verify_on_open must be BOOLEAN, got %s", pair.Value.Type())
			}
			opts.VerifyOnOpen = verify.Value
		case "read_only":
			value, ok := pair.Value.(*object.Boolean)
			if !ok {
				return opts, false, newError("db_open_disk: read_only must be BOOLEAN, got %s", pair.Value.Type())
			}
			readOnly = value.Value
		default:
			return opts, false, newError("db_open_disk: unknown option %q; known options are memory_budget, discover_memory_budget, verify_on_open, read_only", key.Value)
		}
	}

	return opts, readOnly, nil
}

func DbClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument to `db_close` must be INTEGER, got %s", args[0].Type()))
	}
	// LoadAndDelete claims the handle atomically, so two concurrent db_close
	// calls cannot both reach Close on the same graph.
	value, found := dbHandles.LoadAndDelete(h.Value)
	if !found {
		return resultAndError(nil, newError("db_close: invalid handle %d", h.Value))
	}
	g, ok := value.(*graphene.Graph)
	if !ok {
		return resultAndError(nil, newError("db_close: invalid handle %d", h.Value))
	}
	// The side journal db_timeline reads is keyed by handle and lives in
	// Go memory, not in the graph. Handles come from a counter that never
	// repeats, so a process that opens and closes graphs -- which is every
	// net_serve handler -- grew that map for as long as it ran. Dropped
	// before Close so the events go even if Close reports an error: the
	// handle is already out of dbHandles by this point and nothing can ask
	// for them again.
	dbTimelineForget(h.Value)
	dbDiskStores.Delete(h.Value)

	if err := g.Close(); err != nil {
		return resultAndError(nil, newError("db_close: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func DbAddNode(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_add_node` must be INTEGER, got %s", args[0].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_add_node: invalid handle %d", h.Value))
	}

	nodeType := store.CustomNodeType(uint16(DATA))
	if len(args) == 2 {
		parsedType, errObj := dbNodeTypeFromObject(args[1])
		if errObj != nil {
			return resultAndError(nil, newError("argument 2 to `db_add_node`: %s", errObj.Inspect()))
		}
		nodeType = parsedType
	}

	nodeID, err := g.AddNode(&store.Node{
		Labels: []store.NodeType{nodeType},
	})
	if err != nil {
		return resultAndError(nil, newError("db_add_node: %s", err.Error()))
	}
	return resultAndError(intObj(int64(nodeID)), nil)
}

// dbAddIndexedNode creates one node and registers every indexed property it
// carries, in a single transaction.
//
// db_add_artifact used to do this as one AddNode followed by one
// IndexNodeProperty per attribute, each its own commit and its own fsync, and
// each with its error discarded -- so a node could end up in the graph
// carrying half the properties the script asked for, and answer queries as
// though that were the whole of it. The file header already named the remedy:
// a builtin that spans several store calls needs graphene's own Begin/Commit
// rather than a lock.
//
// Tx.AddNode hands back the reserved id straight away, so the entries can name
// the node they describe inside the same transaction. Entries are framed in
// sorted key order, which makes two identical ingests write identical bytes --
// something the per-call loop could not promise, because a hash is walked in
// whatever order it is walked.
func dbAddIndexedNode(handle int64, nodeType store.NodeType, props map[string][]byte) (int64, error) {
	g, found := dbGet(handle)
	if !found {
		return 0, fmt.Errorf("invalid handle %d", handle)
	}

	tx := g.Begin()
	nodeID := tx.AddNode(&store.Node{Labels: []store.NodeType{nodeType}})
	tx.IndexNodeProperties(nodeID, props)
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int64(nodeID), nil
}

func DbAddEdge(args ...object.Object) object.Object {
	if len(args) != 3 && len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_add_edge` must be INTEGER, got %s", args[0].Type()))
	}
	src, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_add_edge` must be INTEGER, got %s", args[1].Type()))
	}
	dst, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `db_add_edge` must be INTEGER, got %s", args[2].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_add_edge: invalid handle %d", h.Value))
	}

	edgeType := store.CustomEdgeType(uint16(DATA))
	if len(args) == 4 {
		parsedType, errObj := dbEdgeTypeFromObject(args[3])
		if errObj != nil {
			return resultAndError(nil, newError("argument 4 to `db_add_edge`: %s", errObj.Inspect()))
		}
		edgeType = parsedType
	}

	edgeID, err := g.AddEdge(&store.Edge{
		Src:    store.NodeID(src.Value),
		Dst:    store.NodeID(dst.Value),
		Labels: []store.EdgeType{edgeType},
	})
	if err != nil {
		return resultAndError(nil, newError("db_add_edge: %s", err.Error()))
	}
	return resultAndError(intObj(int64(edgeID)), nil)
}

func DbIndexProp(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_index_prop` must be INTEGER, got %s", args[0].Type()))
	}
	nodeID, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_index_prop` must be INTEGER, got %s", args[1].Type()))
	}
	key, ok := args[2].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `db_index_prop` must be STRING, got %s", args[2].Type()))
	}
	val, ok := args[3].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `db_index_prop` must be STRING, got %s", args[3].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_index_prop: invalid handle %d", h.Value))
	}
	// graphene's IndexNodeProperty does not look for the node, so a mistyped
	// or stale id wrote an entry pointing at nothing and this reported
	// success. The node is looked for first.
	//
	// Not through a transaction, although a commit checks the node itself:
	// on a disk store a commit is an fsync, and a direct write is an append
	// made durable at the next one. Measured, that took one call from about
	// 5us to 430us, and a script indexing ten thousand properties from under a
	// second to over four -- to close a window between the check and the write
	// that nothing can reach, because no db_* builtin deletes a node and
	// graphene's lock keeps every other writer out of the store.
	if _, err := g.GetNode(store.NodeID(nodeID.Value)); err != nil {
		return resultAndError(nil, newError("db_index_prop: node %d does not exist, so nothing was indexed. Check the id against what db_add_node or db_add_artifact returned", nodeID.Value))
	}
	if err := g.IndexNodeProperty(store.NodeID(nodeID.Value), key.Value, []byte(val.Value)); err != nil {
		return resultAndError(nil, newError("db_index_prop: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func DbQueryNodes(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_query_nodes` must be INTEGER, got %s", args[0].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_query_nodes: invalid handle %d", h.Value))
	}

	nodeType := store.CustomNodeType(uint16(DATA))
	if len(args) == 2 {
		parsedType, errObj := dbNodeTypeFromObject(args[1])
		if errObj != nil {
			return resultAndError(nil, newError("argument 2 to `db_query_nodes`: %s", errObj.Inspect()))
		}
		nodeType = parsedType
	}

	ids, err := g.QueryNodeIDs(store.NodeQuery{
		Types: []store.NodeType{nodeType},
	})
	if err != nil {
		return resultAndError(nil, newError("db_query_nodes: %s", err.Error()))
	}
	elements := make([]object.Object, 0, len(ids))
	for _, id := range ids {
		elements = append(elements, intObj(int64(id)))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func DbBFS(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_bfs` must be INTEGER, got %s", args[0].Type()))
	}
	originID, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_bfs` must be INTEGER, got %s", args[1].Type()))
	}
	depth, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `db_bfs` must be INTEGER, got %s", args[2].Type()))
	}
	// graphene reads a negative depth as zero and walks nothing past the
	// origin, which answers a question the script did not ask.
	if depth.Value < 0 {
		return resultAndError(nil, newError("%s: depth must not be negative, got %d. 0 is the origin alone", BuiltinNameDbBfs, depth.Value))
	}
	if depth.Value > math.MaxInt32 {
		return resultAndError(nil, newError("%s: depth %d is larger than this walk can be asked for", BuiltinNameDbBfs, depth.Value))
	}
	dir, errObj := dbDirectionArg(args[3], BuiltinNameDbBfs, 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_bfs: invalid handle %d", h.Value))
	}

	// graphstore.Walk rather than graphene's BFS, which keeps one edge per
	// neighbour and so dropped all but one of any parallel edges without
	// saying so; and under the walk budget, which graphene's BFS is not.
	reach, err := graphstore.Walk(g, store.NodeID(originID.Value), int(depth.Value), dir, nil, graphstore.WalkBudget())
	if err != nil {
		var notFound *store.ErrNotFound
		switch {
		case errors.Is(err, store.ErrBudgetExceeded):
			return resultAndError(nil, walkBudgetRefusal(err, BuiltinNameDbBfs))
		case errors.As(err, &notFound):
			return resultAndError(nil, newError("%s: node %d does not exist", BuiltinNameDbBfs, originID.Value))
		}
		return resultAndError(nil, newError("db_bfs: %s", err.Error()))
	}

	nodeElems := make([]object.Object, 0, len(reach.Nodes))
	for _, id := range reach.Nodes {
		nodeElems = append(nodeElems, intObj(int64(id)))
	}
	edgeElems := make([]object.Object, 0, len(reach.Edges))
	for _, id := range reach.Edges {
		edgeElems = append(edgeElems, intObj(int64(id)))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"nodes": &object.Array{Elements: nodeElems},
		"edges": &object.Array{Elements: edgeElems},
	}), nil)
}

func DbShortestPath(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_shortest_path` must be INTEGER, got %s", args[0].Type()))
	}
	srcID, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_shortest_path` must be INTEGER, got %s", args[1].Type()))
	}
	dstID, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `db_shortest_path` must be INTEGER, got %s", args[2].Type()))
	}

	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_shortest_path: invalid handle %d", h.Value))
	}

	// Named before the search, so a missing endpoint is a refusal that says
	// which one, and never the empty path that means "not connected".
	for position, id := range []int64{srcID.Value, dstID.Value} {
		if _, err := g.GetNode(store.NodeID(id)); err != nil {
			return resultAndError(nil, newError("%s: node %d (argument %d) does not exist", BuiltinNameDbShortestPath, id, position+2))
		}
	}

	path, err := g.ShortestPathCtx(ledgerContext(), store.NodeID(srcID.Value), store.NodeID(dstID.Value), nil, graphstore.WalkBudget())
	switch {
	case errors.Is(err, traversal.ErrNoPath):
		// "Not connected" is an answer, and the one this builtin has always
		// documented as an empty array; it was an error.
		return resultAndError(&object.Array{Elements: []object.Object{}}, nil)
	case errors.Is(err, store.ErrBudgetExceeded):
		return resultAndError(nil, walkBudgetRefusal(err, BuiltinNameDbShortestPath))
	case err != nil:
		return resultAndError(nil, newError("db_shortest_path: %s", err.Error()))
	}

	elements := make([]object.Object, 0, len(path.Nodes))
	for _, n := range path.Nodes {
		elements = append(elements, intObj(int64(n.ID)))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func DbStats(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument to `db_stats` must be INTEGER, got %s", args[0].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_stats: invalid handle %d", h.Value))
	}
	stats, err := g.Stats()
	if err != nil {
		return resultAndError(nil, newError("db_stats: %s", err.Error()))
	}
	out := map[string]object.Object{
		"nodes": intObj(int64(stats.NodeCount)),
		"edges": intObj(int64(stats.EdgeCount)),
		// has_storage is false on the in-memory backend, which has no delta,
		// WAL or compaction to report on.
		"has_storage": boolObj(stats.HasStorage),
	}
	if stats.HasStorage {
		// Everything written since the last compaction stays in memory and is
		// replayed at every open, so a store that is never compacted degrades
		// in memory, open time and read speed with no error to signal it.
		// These are the figures that make that visible.
		out["delta_records"] = intObj(int64(stats.Storage.DeltaRecords()))
		out["csr_records"] = intObj(int64(stats.Storage.CSRRecords()))
		out["deleted_nodes"] = intObj(int64(stats.Storage.DeletedNodes))
		out["deleted_edges"] = intObj(int64(stats.Storage.DeletedEdges))
		out["wal_bytes"] = intObj(stats.Storage.WALBytes)
		out["commit_seq"] = intObj(int64(stats.Storage.CommitSeq))
		out["last_compact"] = stringObj(formatTime(stats.Storage.LastCompact))
	}

	// How the store was opened: read_only for db_open_disk's read_only
	// option, and lock_free as the reason such a read could take no lock --
	// empty when it took one, and always for a handle that can write.
	out["read_only"] = boolObj(false)
	out["lock_free"] = stringObj("")
	if value, onDisk := dbDiskStores.Load(h.Value); onDisk {
		opened := value.(*dbDiskStore)
		out["read_only"] = boolObj(opened.readOnly)
		out["lock_free"] = stringObj(opened.lockFree)
	}

	return resultAndError(makeHashObject(out), nil)
}

// DbCompact merges a disk-backed store's delta layer into its image and
// truncates the WAL.
//
// db_stats has always reported delta_records and wal_bytes -- the two figures
// that say a store is overdue -- and both the reference and db.go's own
// comment told the reader to compact, while nothing in the language could.
// Everything written since the last compaction stays resident and is replayed
// at every open, so a long-lived store degraded in memory and open time with
// no error to signal it and no way to act on the numbers.
//
// Compacting an in-memory handle is a no-op rather than an error: an
// in-memory graph has no delta to merge, and a script that compacts on a
// schedule should not have to know which kind of handle it was given.
// has_storage says which happened.
func DbCompact(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument to `db_compact` must be INTEGER, got %s", args[0].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_compact: invalid handle %d", h.Value))
	}

	// Read before, compact, read after. The two figures are what makes the
	// call worth reporting on: "it ran" is not evidence that anything moved.
	before, hadStorage := dbDeltaRecords(g)

	if err := g.Compact(); err != nil {
		return resultAndError(nil, newError("db_compact: %s", err.Error()))
	}

	after, _ := dbDeltaRecords(g)

	// The Merkle root of the image the compaction just wrote, and of the one
	// it replaced. The same figures ledger_compact reports, and for the same
	// reason: they are the store's identity at this moment, which a script can
	// write down and a later verify can be held to. Empty for an in-memory
	// handle, which writes no image.
	snapshotRoot, prevRoot := "", ""
	if forensic, ok := g.Forensics(); ok {
		if roots, err := forensic.SnapshotRoots(); err == nil {
			snapshotRoot, prevRoot = ledgerHash(roots.Snapshot), ledgerHash(roots.PrevRoot)
		}
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"has_storage":          boolObj(hadStorage),
		"delta_records_before": intObj(before),
		"delta_records_after":  intObj(after),
		"snapshot_root":        stringObj(snapshotRoot),
		"prev_root":            stringObj(prevRoot),
	}), nil)
}

// dbDeltaRecords reports the uncompacted record count, and whether the handle
// has a storage layer to report one at all. A Stats error is reported as no
// storage rather than propagated: this is instrumentation on a compaction, and
// failing the compaction because the figure describing it could not be read
// would be the tail wagging the dog.
func dbDeltaRecords(g *graphene.Graph) (int64, bool) {
	stats, err := g.Stats()
	if err != nil || stats == nil || !stats.HasStorage {
		return 0, false
	}
	return int64(stats.Storage.DeltaRecords()), true
}

// dbDirections are the readings of an edge's direction that db_bfs and
// db_relations take. Their metadata lists this, and the editor warns on a
// literal outside it before the program runs.
var dbDirections = []string{"out", "in", "both"}

// dbDirectionArg reads a direction argument, and refuses a word it does not
// know. It used to read any such word as "both", so a misspelled "outbound"
// walked every edge in either direction and reported nothing wrong.
func dbDirectionArg(arg object.Object, op string, position int) (store.Direction, *object.Error) {
	word, ok := arg.(*object.String)
	if !ok {
		return 0, newError("argument %d to `%s` must be STRING, got %s", position, op, arg.Type())
	}
	switch choiceFold(word.Value) {
	case "out":
		return store.DirectionOutbound, nil
	case "in":
		return store.DirectionInbound, nil
	case "both":
		return store.DirectionBoth, nil
	}
	return 0, newError("%s: %q is not a direction. Use \"out\" for the edges leaving a node, \"in\" for those arriving at it, or \"both\"", op, word.Value)
}

// dbDirectionName is the word dbDirectionArg reads as dir.
func dbDirectionName(dir store.Direction) string {
	switch dir {
	case store.DirectionOutbound:
		return "out"
	case store.DirectionInbound:
		return "in"
	}
	return "both"
}
