package builtin

import (
	"sync"
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

// TestDbConcurrentOperations exercises the db_* builtins from many goroutines at
// once. There is no lock in db.go any more — graphene documents both backends as
// safe for concurrent use — so this is the check that the removal holds. Run it
// under -race to get the real signal.
func TestDbConcurrentOperations(t *testing.T) {
	const goroutines, perGoroutine = 8, 25

	// Two handles, so the test also covers unrelated graphs being used at once —
	// the case the old process-wide mutex serialised for no reason.
	handles := []int64{dbInt(t, DbOpen()), dbInt(t, DbOpen())}
	defer func() {
		for _, h := range handles {
			DbClose(intObj(h))
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan string, goroutines*perGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			handle := handles[g%len(handles)]
			for i := 0; i < perGoroutine; i++ {
				payload, errObj := unwrapPairNoFatal(DbAddNode(intObj(handle)))
				if errObj != nil {
					errs <- "db_add_node: " + errObj.Inspect()
					return
				}
				if _, ok := payload.(*object.Integer); !ok {
					errs <- "db_add_node did not return an INTEGER"
					return
				}
				if _, errObj := unwrapPairNoFatal(DbQueryNodes(intObj(handle))); errObj != nil {
					errs <- "db_query_nodes: " + errObj.Inspect()
					return
				}
				if _, errObj := unwrapPairNoFatal(DbStats(intObj(handle))); errObj != nil {
					errs <- "db_stats: " + errObj.Inspect()
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}

	// Every node added must be visible.
	for _, h := range handles {
		payload, errObj := unwrapPair(t, DbStats(intObj(h)))
		if errObj != nil {
			t.Fatalf("db_stats: %s", errObj.Inspect())
		}
		want := int64(goroutines / len(handles) * perGoroutine)
		if got := hInt(t, payload.(*object.Hash), "nodes"); got != want {
			t.Errorf("handle %d: nodes = %d, want %d", h, got, want)
		}
	}
}

// TestDbNodeTypeZeroMatchesDefault pins the fix for db_add_node(h, 0) erroring
// while db_add_node(h) succeeded — both mean the DATA type.
func TestDbNodeTypeZeroMatchesDefault(t *testing.T) {
	handle := dbInt(t, DbOpen())
	defer DbClose(intObj(handle))

	if _, errObj := unwrapPair(t, DbAddNode(intObj(handle), intObj(0))); errObj != nil {
		t.Errorf("db_add_node with explicit type 0 should succeed: %s", errObj.Inspect())
	}
	if _, errObj := unwrapPair(t, DbAddNode(intObj(handle), intObj(128))); errObj == nil {
		t.Error("db_add_node with type 128 should error (out of range)")
	}
	if _, errObj := unwrapPair(t, DbAddNode(intObj(handle), intObj(-1))); errObj == nil {
		t.Error("db_add_node with type -1 should error (out of range)")
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
