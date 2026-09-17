package builtin

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

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
)

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

	opts := disk.Options{}
	if len(args) == 2 {
		parsed, errObj := dbOpenOptions(args[1])
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		opts = parsed
	}

	g, err := graphene.OpenWithOptions(path.Value, opts)
	if err != nil {
		return resultAndError(nil, newError("db_open_disk: %s", err.Error()))
	}
	handle := atomic.AddInt64(&dbHandleCounter, 1)
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
func dbOpenOptions(arg object.Object) (disk.Options, *object.Error) {
	opts := disk.Options{}

	hash, ok := arg.(*object.Hash)
	if !ok {
		return opts, newError("argument 2 to `db_open_disk` must be HASH, got %s", arg.Type())
	}

	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return opts, newError("db_open_disk: option keys must be STRING, got %s", pair.Key.Type())
		}
		switch key.Value {
		case "memory_budget":
			budget, ok := pair.Value.(*object.Integer)
			if !ok {
				return opts, newError("db_open_disk: memory_budget must be INTEGER, got %s", pair.Value.Type())
			}
			if budget.Value < 0 {
				return opts, newError("db_open_disk: memory_budget must not be negative, got %d", budget.Value)
			}
			opts.MemoryBudget = budget.Value
		case "discover_memory_budget":
			discover, ok := pair.Value.(*object.Boolean)
			if !ok {
				return opts, newError("db_open_disk: discover_memory_budget must be BOOLEAN, got %s", pair.Value.Type())
			}
			opts.DiscoverMemoryBudget = discover.Value
		case "verify_on_open":
			verify, ok := pair.Value.(*object.Boolean)
			if !ok {
				return opts, newError("db_open_disk: verify_on_open must be BOOLEAN, got %s", pair.Value.Type())
			}
			opts.VerifyOnOpen = verify.Value
		default:
			return opts, newError("db_open_disk: unknown option %q; known options are memory_budget, discover_memory_budget, verify_on_open", key.Value)
		}
	}

	return opts, nil
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
	err := g.IndexNodeProperty(store.NodeID(nodeID.Value), key.Value, []byte(val.Value))
	if err != nil {
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
	dirStr, ok := args[3].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `db_bfs` must be STRING, got %s", args[3].Type()))
	}

	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_bfs: invalid handle %d", h.Value))
	}

	dir := dbParseDirection(dirStr.Value)
	result, err := g.BFS(store.NodeID(originID.Value), int(depth.Value), dir, nil)
	if err != nil {
		return resultAndError(nil, newError("db_bfs: %s", err.Error()))
	}

	nodeElems := make([]object.Object, 0, len(result.Nodes))
	for _, n := range result.Nodes {
		nodeElems = append(nodeElems, intObj(int64(n.ID)))
	}
	edgeElems := make([]object.Object, 0, len(result.Edges))
	for _, e := range result.Edges {
		edgeElems = append(edgeElems, intObj(int64(e.ID)))
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

	path, err := g.ShortestPath(store.NodeID(srcID.Value), store.NodeID(dstID.Value), nil)
	if err != nil {
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
	return resultAndError(makeHashObject(map[string]object.Object{
		"has_storage":          boolObj(hadStorage),
		"delta_records_before": intObj(before),
		"delta_records_after":  intObj(after),
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

func dbParseDirection(s string) store.Direction {
	switch s {
	case "in":
		return store.DirectionInbound
	case "out":
		return store.DirectionOutbound
	default:
		return store.DirectionBoth
	}
}
