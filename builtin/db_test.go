package builtin

import (
	"testing"

	"mutant/object"
)

func dbInt(t *testing.T, res object.Object) int64 {
	t.Helper()
	payload, errObj := unwrapPair(t, res)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}
	i, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("expected INTEGER, got %T (%s)", payload, payload.Inspect())
	}
	return i.Value
}

func TestDbLifecycle(t *testing.T) {
	handle := dbInt(t, DbOpen())

	// add two DATA nodes and an edge between them.
	id1 := dbInt(t, DbAddNode(intObj(handle)))
	id2 := dbInt(t, DbAddNode(intObj(handle)))
	if id1 == id2 {
		t.Fatalf("node IDs should be distinct: %d == %d", id1, id2)
	}
	if _, errObj := unwrapPair(t, DbAddEdge(intObj(handle), intObj(id1), intObj(id2))); errObj != nil {
		t.Fatalf("db_add_edge error: %s", errObj.Inspect())
	}

	// query all nodes -> at least the two we added.
	qPayload, errObj := unwrapPair(t, DbQueryNodes(intObj(handle)))
	if errObj != nil {
		t.Fatalf("db_query_nodes error: %s", errObj.Inspect())
	}
	nodes, ok := qPayload.(*object.Array)
	if !ok || len(nodes.Elements) < 2 {
		t.Fatalf("db_query_nodes should return >=2 nodes, got %T (%s)", qPayload, qPayload.Inspect())
	}

	// stats + bfs return hashes without error.
	if statsPayload, errObj := unwrapPair(t, DbStats(intObj(handle))); errObj != nil {
		t.Fatalf("db_stats error: %s", errObj.Inspect())
	} else if _, ok := statsPayload.(*object.Hash); !ok {
		t.Fatalf("db_stats payload type: %T", statsPayload)
	}

	bfsPayload, errObj := unwrapPair(t, DbBFS(intObj(handle), intObj(id1), intObj(2), stringObj("out")))
	if errObj != nil {
		t.Fatalf("db_bfs error: %s", errObj.Inspect())
	}
	if _, ok := bfsPayload.(*object.Hash); !ok {
		t.Fatalf("db_bfs payload type: %T", bfsPayload)
	}

	// close, then a post-close operation must fail (invalid handle).
	if _, errObj := unwrapPair(t, DbClose(intObj(handle))); errObj != nil {
		t.Fatalf("db_close error: %s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, DbStats(intObj(handle))); errObj == nil {
		t.Fatal("db_stats on a closed handle should error")
	}
}

func TestDbErrors(t *testing.T) {
	// operations on an invalid handle error.
	if _, errObj := unwrapPair(t, DbAddNode(intObj(999999))); errObj == nil {
		t.Fatal("db_add_node on invalid handle should error")
	}
	// wrong arg types.
	if _, errObj := unwrapPair(t, DbClose(stringObj("x"))); errObj == nil {
		t.Fatal("db_close with non-integer handle should error")
	}
	// db_bfs requires exactly 4 args.
	handle := dbInt(t, DbOpen())
	defer DbClose(intObj(handle))
	if _, errObj := unwrapPair(t, DbBFS(intObj(handle), intObj(0))); errObj == nil {
		t.Fatal("db_bfs with wrong arg count should error")
	}
}
