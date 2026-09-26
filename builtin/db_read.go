package builtin

// Reading a db_* store back.
//
// Everything the family had written it could not read. db_index_prop and
// db_add_artifact put properties in graphene's index and nothing could look a
// node up by one; db_add_relation's relation was not stored at all; and the
// only way to learn what a store held was to have been the program that wrote
// it. These five read it.
//
// # The index is the record
//
// db_* never writes a node's property blob -- every property it takes goes into
// graphene's index, and only there -- so the index is what these read, through
// graphene's NodePropertyEntries and EdgePropertyEntries. Two things follow
// that a script would not guess.
//
//   - A key can hold more than one value on one node. db_index_prop adds an
//     entry; it does not replace one, so indexing "status" as "open" and then
//     as "closed" leaves both, and db_find finds the node under either. db_node
//     shows such a key as an ARRAY of every value and names it in
//     multi_valued, rather than picking one and hiding the other.
//   - A query on a key the store never indexed matches nothing, with no error,
//     whatever the records say. db_find says so in key_indexed rather than
//     handing back the same empty list a real "no match" gets.
//
// Values come back as STRING, which is what db_index_prop and db_add_artifact
// store, and as BYTES only when they are not valid UTF-8 -- written by some
// other program -- because a STRING would print them as noise.

import (
	"sort"
	"unicode/utf8"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/global"
	"mutant/graphstore"
	"mutant/object"
)

// dbGraphArg reads the handle argument every db_* read takes first.
func dbGraphArg(arg object.Object, op string) (*graphene.Graph, *object.Error) {
	h, ok := arg.(*object.Integer)
	if !ok {
		return nil, newError("argument 1 to `%s` must be INTEGER, got %s", op, arg.Type())
	}
	g, found := dbGet(h.Value)
	if !found {
		return nil, newError("%s: invalid handle %d", op, h.Value)
	}
	return g, nil
}

// dbPropertyValue renders one indexed value. See the file header.
func dbPropertyValue(value []byte) object.Object {
	if utf8.Valid(value) {
		return stringObj(string(value))
	}
	return &object.Bytes{Value: append([]byte(nil), value...)}
}

// dbProperties renders an entity's index entries, which graphene returns
// sorted by key and then value and without duplicates. A key with one value
// maps to it; a key with several maps to an ARRAY of them all, and is named in
// the second result.
func dbProperties(entries []store.PropertyEntry) (map[string]object.Object, object.Object) {
	properties := map[string]object.Object{}
	multi := []object.Object{}
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].Key == entries[i].Key {
			j++
		}
		key := entries[i].Key
		if j-i == 1 {
			properties[key] = dbPropertyValue(entries[i].Value)
		} else {
			values := make([]object.Object, 0, j-i)
			for _, entry := range entries[i:j] {
				values = append(values, dbPropertyValue(entry.Value))
			}
			properties[key] = &object.Array{Elements: values}
			multi = append(multi, stringObj(key))
		}
		i = j
	}
	return properties, &object.Array{Elements: multi}
}

// dbEntryGrouper is the one capability db_node and db_relations need of a
// store. Both bundled backends have it; a store without it would answer every
// entity with no properties, which is the answer "none were indexed" gets, so
// it is refused instead.
func dbEntryGrouper(g *graphene.Graph, op string) *object.Error {
	if _, ok := g.GraphStore.(store.PropertyEntryGrouper); !ok {
		return newError("%s: this store cannot list one entity's indexed properties, so an empty answer could not be told from one with none", op)
	}
	return nil
}

// dbKeysIndexed reports which of keys the store's index has ever held.
func dbKeysIndexed(g *graphene.Graph, op string, keys ...string) (map[string]bool, *object.Error) {
	missing, known := graphstore.UnindexedKeys(g, keys)
	if !known {
		return nil, newError("%s: this store cannot list the keys its index holds, so an empty answer could not be told from a key that was never indexed", op)
	}
	indexed := make(map[string]bool, len(keys))
	for _, key := range keys {
		indexed[key] = true
	}
	for _, key := range missing {
		indexed[key] = false
	}
	return indexed, nil
}

// dbLabelNumber renders a graphene label as the number a script passed to
// db_add_node or db_add_edge, or as a negative for a built-in graphene type no
// db_* builtin writes; see ledgerLabelList.
func dbLabelNumber[T ~uint16](label, base T) int64 {
	if label >= base {
		return int64(label - base)
	}
	return -int64(label)
}

// DbFind returns the nodes whose indexed key holds value.
func DbFind(args ...object.Object) object.Object {
	if len(args) != 3 && len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	g, errObj := dbGraphArg(args[0], BuiltinNameDbFind)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	key, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING, got %s", BuiltinNameDbFind, args[1].Type()))
	}
	if key.Value == "" {
		return resultAndError(nil, newError("%s: the key is empty", BuiltinNameDbFind))
	}
	var value []byte
	switch v := args[2].(type) {
	case *object.String:
		value = []byte(v.Value)
	case *object.Bytes:
		value = v.Value
	default:
		return resultAndError(nil, newError("argument 3 to `%s` must be STRING or BYTES, got %s", BuiltinNameDbFind, args[2].Type()))
	}
	query := store.NodeQuery{Filters: []store.PropertyFilter{{Key: key.Value, Op: store.PropertyOpEqual, Value: value}}}
	if len(args) == 4 {
		nodeType, errObj := dbNodeTypeFromObject(args[3])
		if errObj != nil {
			return resultAndError(nil, newError("argument 4 to `%s`: %s", BuiltinNameDbFind, errObj.Inspect()))
		}
		query.Types = []store.NodeType{nodeType}
	}

	indexed, errObj := dbKeysIndexed(g, BuiltinNameDbFind, key.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ids, err := g.QueryNodeIDs(query)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbFind, err.Error()))
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	nodes := make([]object.Object, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, intObj(int64(id)))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"nodes":       &object.Array{Elements: nodes},
		"count":       intObj(int64(len(nodes))),
		"key_indexed": boolObj(indexed[key.Value]),
	}), nil)
}

// DbNode reads one node back: its type and everything indexed about it.
func DbNode(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	g, errObj := dbGraphArg(args[0], BuiltinNameDbNode)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	id, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameDbNode, args[1].Type()))
	}
	if errObj := dbEntryGrouper(g, BuiltinNameDbNode); errObj != nil {
		return resultAndError(nil, errObj)
	}
	// The record first: graphene's index is not versioned, so an entity's
	// entries can outlive it, and entries alone would answer for a node that
	// is gone.
	node, err := g.GetNode(store.NodeID(id.Value))
	if err != nil {
		return resultAndError(nil, newError("%s: node %d does not exist", BuiltinNameDbNode, id.Value))
	}
	entries := g.NodePropertyEntries(node.ID)
	properties, multi := dbProperties(entries)
	labels := make([]object.Object, 0, len(node.Labels))
	for _, label := range node.Labels {
		labels = append(labels, intObj(dbLabelNumber(label, store.NodeTypeCustomBase)))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"id":             intObj(int64(node.ID)),
		"labels":         &object.Array{Elements: labels},
		"properties":     makeHashObject(properties),
		"property_count": intObj(int64(len(entries))),
		"multi_valued":   multi,
		"blob_bytes":     intObj(int64(len(node.Properties))),
	}), nil)
}

// DbRelations lists the edges of one node in one direction, each with the
// relation db_add_relation stored on it.
func DbRelations(args ...object.Object) object.Object {
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	g, errObj := dbGraphArg(args[0], BuiltinNameDbRelations)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	id, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameDbRelations, args[1].Type()))
	}
	dir, errObj := dbDirectionArg(args[2], BuiltinNameDbRelations, 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := dbEntryGrouper(g, BuiltinNameDbRelations); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if _, err := g.GetNode(store.NodeID(id.Value)); err != nil {
		return resultAndError(nil, newError("%s: node %d does not exist", BuiltinNameDbRelations, id.Value))
	}
	edges, err := g.EdgesOf(store.NodeID(id.Value), dir, nil)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbRelations, err.Error()))
	}
	// The same bound a walk runs under: one node's edges are one hop of one.
	if len(edges) > graphstore.WalkMaxEdges {
		return resultAndError(nil, newError("%s: node %d has %d edges in that direction, more than the %d a walk may cross, and none are returned. Ask of a narrower node",
			BuiltinNameDbRelations, id.Value, len(edges), graphstore.WalkMaxEdges))
	}
	// Ordered by edge id, which is the order they were added in on both
	// backends; adjacency order is not, once a store has been compacted.
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	relations := make([]object.Object, 0, len(edges))
	unlabelled := 0
	for i, edge := range edges {
		// A self-loop is one edge both ways, and is listed once.
		if i > 0 && edges[i-1].ID == edge.ID {
			continue
		}
		properties, _ := dbProperties(g.EdgePropertyEntries(edge.ID))
		// An edge with no relation reads as null: every edge db_add_edge
		// wrote, and every one db_add_relation wrote before the relation
		// was stored, which cannot be recovered now.
		relation, labelled := properties[dbRelationKey]
		if !labelled {
			relation = global.Null
			unlabelled++
		}
		labels := make([]object.Object, 0, len(edge.Labels))
		for _, label := range edge.Labels {
			labels = append(labels, intObj(dbLabelNumber(label, store.EdgeTypeCustomBase)))
		}
		relations = append(relations, makeHashObject(map[string]object.Object{
			"edge_id":    intObj(int64(edge.ID)),
			"src":        intObj(int64(edge.Src)),
			"dst":        intObj(int64(edge.Dst)),
			"relation":   relation,
			"labels":     &object.Array{Elements: labels},
			"properties": makeHashObject(properties),
		}))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"node":       intObj(id.Value),
		"direction":  stringObj(dbDirectionName(dir)),
		"relations":  &object.Array{Elements: relations},
		"count":      intObj(int64(len(relations))),
		"unlabelled": intObj(int64(unlabelled)),
	}), nil)
}

// DbSchema reports what a store holds: how many of each type, which keys its
// index has held, and how many edges carry each relation.
func DbSchema(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	g, errObj := dbGraphArg(args[0], BuiltinNameDbSchema)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	stats, err := g.Stats()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbSchema, err.Error()))
	}
	nodeTypes, err := g.CountNodesByType()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbSchema, err.Error()))
	}
	edgeTypes, err := g.CountEdgesByType()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbSchema, err.Error()))
	}
	nodeKeys, nodeKnown := g.NodePropKeys()
	edgeKeys, edgeKnown := g.EdgePropKeys()
	if !nodeKnown || !edgeKnown {
		return resultAndError(nil, newError("%s: this store cannot list the keys its index holds", BuiltinNameDbSchema))
	}
	relations, err := g.CountEdgesByProperty(dbRelationKey)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameDbSchema, err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"nodes":      intObj(int64(stats.NodeCount)),
		"edges":      intObj(int64(stats.EdgeCount)),
		"node_types": dbTypeCounts(nodeTypes, store.NodeTypeCustomBase),
		"edge_types": dbTypeCounts(edgeTypes, store.EdgeTypeCustomBase),
		"node_keys":  ledgerStringArray(nodeKeys),
		"edge_keys":  ledgerStringArray(edgeKeys),
		"relations":  dbRelationCounts(relations),
	}), nil)
}

// dbTypeCounts renders a count per label as [{type, count}], in label order.
func dbTypeCounts[T ~uint16](counts map[T]uint64, base T) object.Object {
	labels := make([]T, 0, len(counts))
	for label := range counts {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i] < labels[j] })
	rows := make([]object.Object, 0, len(labels))
	for _, label := range labels {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"type":  intObj(dbLabelNumber(label, base)),
			"count": intObj(int64(counts[label])),
		}))
	}
	return &object.Array{Elements: rows}
}

// dbRelationCounts renders a count per relation as [{relation, count}], in
// byte order of the relation.
func dbRelationCounts(counts map[string]uint64) object.Object {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]object.Object, 0, len(names))
	for _, name := range names {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"relation": dbPropertyValue([]byte(name)),
			"count":    intObj(int64(counts[name])),
		}))
	}
	return &object.Array{Elements: rows}
}

// DbVerify cross-checks a store's indexes against its records.
//
// checked and consistent are two fields rather than one, because a store that
// cannot verify itself would otherwise report exactly what a sound one does.
// values_checked is always false and is there to be read: graphene checks the
// index's structure -- postings, adjacency, that no entry outlives its entity --
// and not that an indexed value still says what the script meant, which only
// the script knows.
func DbVerify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	g, errObj := dbGraphArg(args[0], BuiltinNameDbVerify)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	_, verifies := g.GraphStore.(store.IndexVerifier)
	_, verifiesCtx := g.GraphStore.(store.IndexVerifierCtx)
	checked := verifies || verifiesCtx
	problem := ""
	if checked {
		if err := g.VerifyIndexes(); err != nil {
			problem = err.Error()
		}
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"checked":        boolObj(checked),
		"consistent":     boolObj(checked && problem == ""),
		"problem":        stringObj(problem),
		"values_checked": boolObj(false),
	}), nil)
}
