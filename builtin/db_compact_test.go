package builtin

import (
	"testing"

	"mutant/object"
)

// openDiskHandle opens a disk-backed graph in a temp directory and returns its
// handle, closing it when the test ends.
func openDiskHandle(t *testing.T) *object.Integer {
	t.Helper()
	payload, errObj := unwrapPair(t, DbOpenDisk(stringObj(t.TempDir())))
	if errObj != nil {
		t.Fatalf("db_open_disk error: %s", errObj.Inspect())
	}
	handle, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open_disk payload type: %T", payload)
	}
	t.Cleanup(func() { _, _ = unwrapPair(t, DbClose(handle)) })
	return handle
}

// TestDbCompactReducesTheDelta is the reason db_compact exists. db_stats has
// always reported delta_records and wal_bytes -- the figures that say a store is
// overdue -- and both the capability reference and db.go's own comment told the
// reader to compact, while nothing in the language could.
//
// Asserted on the figure moving, not on the call returning: "it ran" is not
// evidence that anything was merged.
func TestDbCompactReducesTheDelta(t *testing.T) {
	handle := openDiskHandle(t)

	for i := 0; i < 64; i++ {
		if _, errObj := unwrapPair(t, DbAddNode(handle)); errObj != nil {
			t.Fatalf("db_add_node error: %s", errObj.Inspect())
		}
	}

	payload, errObj := unwrapPair(t, DbCompact(handle))
	if errObj != nil {
		t.Fatalf("db_compact error: %s", errObj.Inspect())
	}

	if storage := hashField(t, payload, "has_storage"); storage.Inspect() != "true" {
		t.Fatalf("a disk-backed handle reported has_storage %s", storage.Inspect())
	}

	before, ok := hashField(t, payload, "delta_records_before").(*object.Integer)
	if !ok {
		t.Fatal("delta_records_before is not an INTEGER")
	}
	after, ok := hashField(t, payload, "delta_records_after").(*object.Integer)
	if !ok {
		t.Fatal("delta_records_after is not an INTEGER")
	}

	if before.Value == 0 {
		t.Fatalf("64 nodes produced a delta of 0; the figure is not measuring anything")
	}
	if after.Value >= before.Value {
		t.Fatalf("compaction did not shrink the delta: %d before, %d after", before.Value, after.Value)
	}
}

// TestDbCompactSurvivesTheDataItMerged. A compaction that loses records would
// also shrink the delta, so the figure alone is not enough.
func TestDbCompactSurvivesTheDataItMerged(t *testing.T) {
	handle := openDiskHandle(t)

	const nodes = 16
	for i := 0; i < nodes; i++ {
		if _, errObj := unwrapPair(t, DbAddNode(handle)); errObj != nil {
			t.Fatalf("db_add_node error: %s", errObj.Inspect())
		}
	}

	if _, errObj := unwrapPair(t, DbCompact(handle)); errObj != nil {
		t.Fatalf("db_compact error: %s", errObj.Inspect())
	}

	payload, errObj := unwrapPair(t, DbQueryNodes(handle))
	if errObj != nil {
		t.Fatalf("db_query_nodes error: %s", errObj.Inspect())
	}
	found, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("db_query_nodes payload type: %T", payload)
	}
	if len(found.Elements) != nodes {
		t.Fatalf("compaction changed the graph: %d nodes before, %d after", nodes, len(found.Elements))
	}
}

// TestDbCompactOnAnInMemoryHandleIsANoOp. A script that compacts on a schedule
// should not have to know which kind of handle it was given, so this reports
// rather than refuses -- and has_storage is how it reports.
func TestDbCompactOnAnInMemoryHandleIsANoOp(t *testing.T) {
	payload, errObj := unwrapPair(t, DbOpen())
	if errObj != nil {
		t.Fatalf("db_open error: %s", errObj.Inspect())
	}
	handle, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open payload type: %T", payload)
	}
	defer func() { _, _ = unwrapPair(t, DbClose(handle)) }()

	report, errObj := unwrapPair(t, DbCompact(handle))
	if errObj != nil {
		t.Fatalf("db_compact refused an in-memory handle: %s", errObj.Inspect())
	}
	if storage := hashField(t, report, "has_storage"); storage.Inspect() != "false" {
		t.Fatalf("an in-memory handle reported has_storage %s", storage.Inspect())
	}
}

// TestDbCompactRejectsABadHandle keeps db_compact's refusals the same shape as
// every other db_ builtin's.
func TestDbCompactRejectsABadHandle(t *testing.T) {
	for _, args := range [][]object.Object{
		{},
		{intObj(1), intObj(2)},
		{stringObj("not a handle")},
		{intObj(1 << 40)},
	} {
		if _, errObj := unwrapPair(t, DbCompact(args...)); errObj == nil {
			t.Errorf("db_compact accepted %v", args)
		}
	}
}

// TestDbCloseForgetsTheTimeline is the leak. The journal db_timeline reads is
// keyed by handle and lives in Go memory rather than in the graph, and handles
// come from a counter that never repeats -- so a process that opens and closes
// graphs, which is every net_serve handler, grew that map for as long as it ran.
func TestDbCloseForgetsTheTimeline(t *testing.T) {
	payload, errObj := unwrapPair(t, DbOpen())
	if errObj != nil {
		t.Fatalf("db_open error: %s", errObj.Inspect())
	}
	handle, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open payload type: %T", payload)
	}

	if _, errObj := unwrapPair(t, DbAddArtifact(handle, stringObj("file"))); errObj != nil {
		t.Fatalf("db_add_artifact error: %s", errObj.Inspect())
	}

	dbTimelineStore.Lock()
	recorded := len(dbTimelineStore.events[handle.Value])
	dbTimelineStore.Unlock()
	if recorded == 0 {
		t.Fatal("db_add_artifact recorded no timeline event; the test is not measuring anything")
	}

	if _, errObj := unwrapPair(t, DbClose(handle)); errObj != nil {
		t.Fatalf("db_close error: %s", errObj.Inspect())
	}

	dbTimelineStore.Lock()
	_, held := dbTimelineStore.events[handle.Value]
	dbTimelineStore.Unlock()
	if held {
		t.Fatal("db_close left the handle's timeline events behind")
	}
}

// TestDbAddArtifactIndexesEveryAttribute. The per-property loop this replaced
// discarded each indexing error, so a node could carry half of what the script
// asked for and answer queries as though that were the whole of it. One
// transaction means all of them or none.
func TestDbAddArtifactIndexesEveryAttribute(t *testing.T) {
	payload, errObj := unwrapPair(t, DbOpen())
	if errObj != nil {
		t.Fatalf("db_open error: %s", errObj.Inspect())
	}
	handle, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open payload type: %T", payload)
	}
	defer func() { _, _ = unwrapPair(t, DbClose(handle)) }()

	attrs := makeHashObject(map[string]object.Object{
		"path":   stringObj("/tmp/evidence.bin"),
		"sha256": stringObj("deadbeef"),
		"size":   intObj(4096),
	})

	report, errObj := unwrapPair(t, DbAddArtifact(handle, stringObj("file"), attrs))
	if errObj != nil {
		t.Fatalf("db_add_artifact error: %s", errObj.Inspect())
	}

	indexed, ok := hashField(t, report, "indexed_props").(*object.Integer)
	if !ok {
		t.Fatal("indexed_props is not an INTEGER")
	}
	// artifact_type plus the three attributes.
	if indexed.Value != 4 {
		t.Fatalf("indexed_props is %d, want 4", indexed.Value)
	}

	if _, ok := hashField(t, report, "node_id").(*object.Integer); !ok {
		t.Fatal("node_id is not an INTEGER")
	}
}

// TestDbOpenDiskOptions covers the memory ceiling db_open_disk can now be given.
// v0.4.0 of the engine had no memory budget, batch cap or compaction policy of
// any kind, so a script that ingested a large graph either fitted in whatever
// the process was allowed or was killed, with nothing in the language to say so.
func TestDbOpenDiskOptions(t *testing.T) {
	opts := makeHashObject(map[string]object.Object{
		"memory_budget": intObj(64 << 20),
	})

	payload, errObj := unwrapPair(t, DbOpenDisk(stringObj(t.TempDir()), opts))
	if errObj != nil {
		t.Fatalf("db_open_disk with options: %s", errObj.Inspect())
	}
	handle, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("db_open_disk payload type: %T", payload)
	}
	defer func() { _, _ = unwrapPair(t, DbClose(handle)) }()

	if _, errObj := unwrapPair(t, DbAddNode(handle)); errObj != nil {
		t.Fatalf("a budgeted store refused an ordinary write: %s", errObj.Inspect())
	}
}

// TestDbOpenDiskRejectsBadOptions. A misspelled option that is silently dropped
// reads as a store running under a budget it does not have, so an unknown key is
// an error rather than ignored.
func TestDbOpenDiskRejectsBadOptions(t *testing.T) {
	for name, opts := range map[string]object.Object{
		"unknown key":      makeHashObject(map[string]object.Object{"memory_bugdet": intObj(1)}),
		"wrong value type": makeHashObject(map[string]object.Object{"memory_budget": stringObj("64MB")}),
		"negative budget":  makeHashObject(map[string]object.Object{"memory_budget": intObj(-1)}),
		"not a hash":       stringObj("memory_budget=1"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, errObj := unwrapPair(t, DbOpenDisk(stringObj(t.TempDir()), opts)); errObj == nil {
				t.Error("db_open_disk accepted it")
			}
		})
	}
}
