package builtin

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

var (
	dbHandleCounter int64
	dbHandles       sync.Map // int64 → *graphene.Graph
)

const DATA = 0

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
		if value.Value < 1 || value.Value > 127 {
			return 0, newError("node type must be in range 1..127, got %d", value.Value)
		}
		return store.CustomNodeType(uint8(value.Value)), nil
	case *object.EnumValue:
		enumType, errObj := dbTypeFromEnumValue(value, "node")
		if errObj != nil {
			return 0, errObj
		}
		return store.CustomNodeType(uint8(enumType)), nil
	default:
		return 0, newError("node type must be INTEGER or ENUM_VALUE, got %s", arg.Type())
	}
}

func dbEdgeTypeFromObject(arg object.Object) (store.EdgeType, object.Object) {
	switch value := arg.(type) {
	case *object.Integer:
		if value.Value < 1 || value.Value > 127 {
			return 0, newError("edge type must be in range 1..127, got %d", value.Value)
		}
		return store.CustomEdgeType(uint8(value.Value)), nil
	case *object.EnumValue:
		enumType, errObj := dbTypeFromEnumValue(value, "edge")
		if errObj != nil {
			return 0, errObj
		}
		return store.CustomEdgeType(uint8(enumType)), nil
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
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `db_open_disk` must be STRING, got %s", args[0].Type()))
	}
	g, err := graphene.Open(path.Value)
	if err != nil {
		return resultAndError(nil, newError("db_open_disk: %s", err.Error()))
	}
	handle := atomic.AddInt64(&dbHandleCounter, 1)
	dbHandles.Store(handle, g)
	return resultAndError(intObj(handle), nil)
}

func DbClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	h, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument to `db_close` must be INTEGER, got %s", args[0].Type()))
	}
	g, found := dbGet(h.Value)
	if !found {
		return resultAndError(nil, newError("db_close: invalid handle %d", h.Value))
	}
	dbHandles.Delete(h.Value)
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

	nodeType := store.CustomNodeType(uint8(DATA))
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

	edgeType := store.CustomEdgeType(uint8(DATA))
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

	nodeType := store.CustomNodeType(uint8(DATA))
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
	return resultAndError(makeHashObject(map[string]object.Object{
		"nodes": intObj(int64(stats.NodeCount)),
		"edges": intObj(int64(stats.EdgeCount)),
	}), nil)
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
