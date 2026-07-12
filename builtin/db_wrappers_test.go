package builtin

import (
	"testing"

	"mutant/object"
)

func TestDbOpenDiskPersistsAcrossCloseAndReopen(t *testing.T) {
	dir := t.TempDir()

	openPayload, errObj := unwrapPair(t, DbOpenDisk(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("db_open_disk error: %s", errObj.Inspect())
	}
	openHandle, ok := openPayload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open_disk payload type: %T", openPayload)
	}

	_, errObj = unwrapPair(t, DbAddNode(openHandle))
	if errObj != nil {
		t.Fatalf("db_add_node error: %s", errObj.Inspect())
	}

	_, errObj = unwrapPair(t, DbClose(openHandle))
	if errObj != nil {
		t.Fatalf("db_close error: %s", errObj.Inspect())
	}

	reopenPayload, errObj := unwrapPair(t, DbOpenDisk(stringObj(dir)))
	if errObj != nil {
		t.Fatalf("db_open_disk reopen error: %s", errObj.Inspect())
	}
	reopenHandle, ok := reopenPayload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open_disk reopen payload type: %T", reopenPayload)
	}
	defer func() {
		_, _ = unwrapPair(t, DbClose(reopenHandle))
	}()

	statsPayload, errObj := unwrapPair(t, DbStats(reopenHandle))
	if errObj != nil {
		t.Fatalf("db_stats reopen error: %s", errObj.Inspect())
	}
	statsHash := dbwMustHash(t, statsPayload)
	if dbwMustHashInt(t, statsHash, "nodes") < 1 {
		t.Fatalf("expected persisted node count after reopen")
	}
}

func TestDbWrappersArtifactRelationQueryTimeline(t *testing.T) {
	openPayload, errObj := unwrapPair(t, DbOpen())
	if errObj != nil {
		t.Fatalf("db_open error: %s", errObj.Inspect())
	}
	handle, ok := openPayload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open payload type: %T", openPayload)
	}
	defer func() {
		_, _ = unwrapPair(t, DbClose(handle))
	}()

	a1Payload, errObj := unwrapPair(t, DbAddArtifact(handle, stringObj("process"), makeHashObject(map[string]object.Object{
		"pid":  intObj(1337),
		"name": stringObj("evil.exe"),
	})))
	if errObj != nil {
		t.Fatalf("db_add_artifact #1 error: %s", errObj.Inspect())
	}
	a1 := dbwMustHash(t, a1Payload)
	n1 := dbwMustHashInt(t, a1, "node_id")

	a2Payload, errObj := unwrapPair(t, DbAddArtifact(handle, stringObj("file"), makeHashObject(map[string]object.Object{
		"path": stringObj("C:/Temp/drop.bin"),
	})))
	if errObj != nil {
		t.Fatalf("db_add_artifact #2 error: %s", errObj.Inspect())
	}
	a2 := dbwMustHash(t, a2Payload)
	n2 := dbwMustHashInt(t, a2, "node_id")

	_, errObj = unwrapPair(t, DbAddRelation(handle, intObj(n1), intObj(n2), stringObj("writes")))
	if errObj != nil {
		t.Fatalf("db_add_relation error: %s", errObj.Inspect())
	}

	queryPayload, errObj := unwrapPair(t, DbQuery(handle))
	if errObj != nil {
		t.Fatalf("db_query error: %s", errObj.Inspect())
	}
	queryArr, ok := queryPayload.(*object.Array)
	if !ok {
		t.Fatalf("db_query payload type: %T", queryPayload)
	}
	if len(queryArr.Elements) < 2 {
		t.Fatalf("expected at least 2 nodes from db_query")
	}

	timelinePayload, errObj := unwrapPair(t, DbTimeline(handle))
	if errObj != nil {
		t.Fatalf("db_timeline error: %s", errObj.Inspect())
	}
	timelineArr, ok := timelinePayload.(*object.Array)
	if !ok {
		t.Fatalf("db_timeline payload type: %T", timelinePayload)
	}
	if len(timelineArr.Elements) != 3 {
		t.Fatalf("expected 3 timeline events, got=%d", len(timelineArr.Elements))
	}
}

func TestDbWrapperErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{name: "add artifact bad handle type", call: func() object.Object { return DbAddArtifact(stringObj("x"), stringObj("process")) }},
		{name: "add relation bad arg type", call: func() object.Object { return DbAddRelation(intObj(1), stringObj("x"), intObj(2), stringObj("rel")) }},
		{name: "query wrong args", call: func() object.Object { return DbQuery() }},
		{name: "timeline wrong handle", call: func() object.Object { return DbTimeline(stringObj("x")) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, tt.call())
			if errObj == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func dbwMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	h, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return h
}

func dbwMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}

func dbwMustHashInt(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	obj := dbwMustHashValue(t, hash, key)
	i, ok := obj.(*object.Integer)
	if !ok {
		t.Fatalf("key %s is not INTEGER: %T", key, obj)
	}
	return i.Value
}
