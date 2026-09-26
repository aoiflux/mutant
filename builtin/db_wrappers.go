package builtin

import (
	"errors"
	"sync"
	"unicode/utf8"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// dbRelationKey is the edge property db_add_relation indexes a relation
// under, and db_relations and db_schema read it back from.
const dbRelationKey = "relation"

var dbTimelineStore = struct {
	sync.Mutex
	events map[int64][]object.Object
}{
	events: map[int64][]object.Object{},
}

func DbAddArtifact(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	handleObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_add_artifact` must be INTEGER, got %s", args[0].Type()))
	}
	typeObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_add_artifact` must be STRING, got %s", args[1].Type()))
	}

	props := map[string][]byte{"artifact_type": []byte(typeObj.Value)}

	if len(args) == 3 {
		attrs, ok := args[2].(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("argument 3 to `db_add_artifact` must be HASH, got %s", args[2].Type()))
		}
		if errObj := refuseClassified(BuiltinNameDbAddArtifact, args...); errObj != nil {
			return resultAndError(nil, errObj)
		}
		if errObj := dbAttrProps(BuiltinNameDbAddArtifact, 3, attrs, props); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

	// One transaction: the node and everything indexed about it land together
	// or not at all. The per-property loop this replaces discarded each
	// indexing error, so a half-indexed artifact was reported as a whole one.
	nodeID, err := dbAddIndexedNode(handleObj.Value, dbDefaultNodeType(), props)
	if err != nil {
		return resultAndError(nil, newError("db_add_artifact: %s", err.Error()))
	}

	dbTimelineAppend(handleObj.Value, makeHashObject(map[string]object.Object{
		"action":        stringObj("add_artifact"),
		"node_id":       intObj(nodeID),
		"artifact_type": stringObj(typeObj.Value),
	}))

	return resultAndError(makeHashObject(map[string]object.Object{
		"node_id":       intObj(nodeID),
		"artifact_type": stringObj(typeObj.Value),
		"indexed_props": intObj(int64(len(props))),
	}), nil)
}

// DbAddRelation joins two nodes with an edge that carries its relation.
//
// It used to add a plain DATA edge and send the relation only to db_timeline's
// journal, which lives in this process and db_close clears. A store reopened,
// or read by anything but the program that wrote it, held edges with no
// relation at all, while the reference said they were labelled. The edge and
// its relation now land in one transaction: the relation indexed on the edge
// under dbRelationKey, where db_relations and db_schema read it back, and each
// attribute beside it as attr_<key>, the way db_add_artifact stores a node's.
//
// A relation is a name a reader matches on, so an empty one, or one that is
// not valid UTF-8 -- which prints as the same replacement characters as a
// different invalid one -- is refused rather than stored.
func DbAddRelation(args ...object.Object) object.Object {
	if len(args) != 4 && len(args) != 5 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4 or 5", len(args)))
	}
	handleObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_add_relation` must be INTEGER, got %s", args[0].Type()))
	}
	srcObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `db_add_relation` must be INTEGER, got %s", args[1].Type()))
	}
	dstObj, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `db_add_relation` must be INTEGER, got %s", args[2].Type()))
	}
	relObj, ok := args[3].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `db_add_relation` must be STRING, got %s", args[3].Type()))
	}
	if relObj.Value == "" {
		return resultAndError(nil, newError("%s: the relation is empty; name what joins the two nodes", BuiltinNameDbAddRelation))
	}
	if !utf8.ValidString(relObj.Value) {
		return resultAndError(nil, newError("%s: the relation is not valid UTF-8, so it would print the same as a different one; name it in text", BuiltinNameDbAddRelation))
	}

	props := map[string][]byte{dbRelationKey: []byte(relObj.Value)}
	if len(args) == 5 {
		attrs, ok := args[4].(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("argument 5 to `db_add_relation` must be HASH, got %s", args[4].Type()))
		}
		if errObj := refuseClassified(BuiltinNameDbAddRelation, args...); errObj != nil {
			return resultAndError(nil, errObj)
		}
		if errObj := dbAttrProps(BuiltinNameDbAddRelation, 5, attrs, props); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

	g, found := dbGet(handleObj.Value)
	if !found {
		return resultAndError(nil, newError("db_add_relation: invalid handle %d", handleObj.Value))
	}
	// One transaction, as dbAddIndexedNode does for a node: the edge and what
	// is indexed about it land together or not at all. Its endpoints are
	// checked at commit, under the store's lock.
	tx := g.Begin()
	edgeID := tx.AddEdge(&store.Edge{
		Src:    store.NodeID(srcObj.Value),
		Dst:    store.NodeID(dstObj.Value),
		Labels: []store.EdgeType{store.CustomEdgeType(uint16(DATA))},
	})
	tx.IndexEdgeProperties(edgeID, props)
	if err := tx.Commit(); err != nil {
		var invalid *store.ErrInvalidEdge
		if errors.As(err, &invalid) {
			return resultAndError(nil, newError("%s: node %d does not exist, so no relation was added", BuiltinNameDbAddRelation, invalid.MissingID))
		}
		return resultAndError(nil, newError("db_add_relation: %s", err.Error()))
	}

	dbTimelineAppend(handleObj.Value, makeHashObject(map[string]object.Object{
		"action":   stringObj("add_relation"),
		"src":      intObj(srcObj.Value),
		"dst":      intObj(dstObj.Value),
		"relation": stringObj(relObj.Value),
		"edge_id":  intObj(int64(edgeID)),
	}))

	return resultAndError(makeHashObject(map[string]object.Object{
		"edge_id":       intObj(int64(edgeID)),
		"src":           intObj(srcObj.Value),
		"dst":           intObj(dstObj.Value),
		"relation":      stringObj(relObj.Value),
		"created":       boolObj(true),
		"indexed_props": intObj(int64(len(props))),
	}), nil)
}

// dbAttrProps adds each attribute of a script's attrs hash to props as
// attr_<key>, stored as the value's Inspect rendering. For a buffer that is the
// whole buffer in hex, and graphene keeps property entries in its write-ahead
// log, so the caller refuses classified plaintext before this runs.
//
// A key that is not a STRING is refused. db_add_artifact used to skip one, and
// reported the node with fewer properties than the script gave it and nothing
// to say which had gone.
func dbAttrProps(op string, position int, attrs *object.Hash, props map[string][]byte) *object.Error {
	for _, pair := range attrs.Pairs {
		keyObj, ok := pair.Key.(*object.String)
		if !ok {
			return newError("%s: argument %d has a %s key; attribute keys are property names and must be STRING", op, position, pair.Key.Type())
		}
		props["attr_"+keyObj.Value] = []byte(pair.Value.Inspect())
	}
	return nil
}

func DbQuery(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	return DbQueryNodes(args...)
}

func DbTimeline(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handleObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `db_timeline` must be INTEGER, got %s", args[0].Type()))
	}

	dbTimelineStore.Lock()
	events := dbTimelineStore.events[handleObj.Value]
	copied := make([]object.Object, len(events))
	copy(copied, events)
	dbTimelineStore.Unlock()

	return resultAndError(&object.Array{Elements: copied}, nil)
}

// dbTimelineForget drops one handle's events. db_close is the only caller:
// a handle is gone the moment it is closed, so the events are unreachable
// and holding them only costs memory.
func dbTimelineForget(handle int64) {
	dbTimelineStore.Lock()
	delete(dbTimelineStore.events, handle)
	dbTimelineStore.Unlock()
}

func dbTimelineAppend(handle int64, event object.Object) {
	dbTimelineStore.Lock()
	dbTimelineStore.events[handle] = append(dbTimelineStore.events[handle], event)
	dbTimelineStore.Unlock()
}
