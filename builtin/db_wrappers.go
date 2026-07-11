package builtin

import (
	"sync"

	"mutant/object"
)

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

	nodeResult := DbAddNode(handleObj)
	nodePayload, errObj := dbUnwrapPair(nodeResult)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, ok := nodePayload.(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("db_add_artifact: unexpected node id payload type %T", nodePayload))
	}

	_, _ = dbUnwrapPair(DbIndexProp(handleObj, nodeID, stringObj("artifact_type"), typeObj))
	indexed := int64(1)

	if len(args) == 3 {
		attrs, ok := args[2].(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("argument 3 to `db_add_artifact` must be HASH, got %s", args[2].Type()))
		}
		for _, pair := range attrs.Pairs {
			keyObj, ok := pair.Key.(*object.String)
			if !ok {
				continue
			}
			val := stringObj(pair.Value.Inspect())
			_, _ = dbUnwrapPair(DbIndexProp(handleObj, nodeID, stringObj("attr_"+keyObj.Value), val))
			indexed++
		}
	}

	dbTimelineAppend(handleObj.Value, makeHashObject(map[string]object.Object{
		"action":        stringObj("add_artifact"),
		"node_id":       intObj(nodeID.Value),
		"artifact_type": stringObj(typeObj.Value),
	}))

	return resultAndError(makeHashObject(map[string]object.Object{
		"node_id":       intObj(nodeID.Value),
		"artifact_type": stringObj(typeObj.Value),
		"indexed_props": intObj(indexed),
	}), nil)
}

func DbAddRelation(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
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

	edgeResult := DbAddEdge(handleObj, srcObj, dstObj)
	edgePayload, errObj := dbUnwrapPair(edgeResult)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	edgeID, ok := edgePayload.(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("db_add_relation: unexpected edge id payload type %T", edgePayload))
	}

	dbTimelineAppend(handleObj.Value, makeHashObject(map[string]object.Object{
		"action":   stringObj("add_relation"),
		"src":      intObj(srcObj.Value),
		"dst":      intObj(dstObj.Value),
		"relation": stringObj(relObj.Value),
		"edge_id":  intObj(edgeID.Value),
	}))

	return resultAndError(makeHashObject(map[string]object.Object{
		"edge_id":  intObj(edgeID.Value),
		"src":      intObj(srcObj.Value),
		"dst":      intObj(dstObj.Value),
		"relation": stringObj(relObj.Value),
		"created":  boolObj(true),
	}), nil)
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

func dbTimelineAppend(handle int64, event object.Object) {
	dbTimelineStore.Lock()
	dbTimelineStore.events[handle] = append(dbTimelineStore.events[handle], event)
	dbTimelineStore.Unlock()
}

func dbUnwrapPair(value object.Object) (object.Object, *object.Error) {
	pair, ok := value.(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		return nil, newError("db wrapper expected MultiValue result")
	}
	result := pair.Values[0]
	errValue := pair.Values[1]
	if errValue == nil || errValue.Type() == object.NULL_OBJ {
		return result, nil
	}
	errObj, ok := errValue.(*object.Error)
	if !ok {
		return nil, newError("db wrapper expected Error in second result slot")
	}
	return nil, errObj
}
