package builtin

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"mutant/graphstore"
	"mutant/object"
)

// dbRefused fails unless result is an error whose message contains want.
func dbRefused(t *testing.T, result object.Object, want string) {
	t.Helper()
	value, errObj := unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("the call succeeded with %s; want a refusal containing %q", value.Inspect(), want)
	}
	if !strings.Contains(errObj.Message, want) {
		t.Fatalf("the refusal %q does not contain %q", errObj.Message, want)
	}
}

// dbIDs reads an ARRAY of node or edge ids.
func dbIDs(t *testing.T, elements []object.Object) []int64 {
	t.Helper()
	ids := make([]int64, 0, len(elements))
	for _, element := range elements {
		id, ok := element.(*object.Integer)
		if !ok {
			t.Fatalf("an id is %s, want INTEGER", element.Type())
		}
		ids = append(ids, id.Value)
	}
	return ids
}

func dbOpenMemory(t *testing.T) *object.Integer {
	t.Helper()
	handle := intObj(dbInt(t, DbOpen()))
	t.Cleanup(func() { DbClose(handle) })
	return handle
}

func dbOpenDiskAt(t *testing.T, dir string, opts ...object.Object) *object.Integer {
	t.Helper()
	args := append([]object.Object{stringObj(dir)}, opts...)
	return intObj(dbInt(t, DbOpenDisk(args...)))
}

func dbNodeID(t *testing.T, handle *object.Integer) *object.Integer {
	t.Helper()
	return intObj(dbInt(t, DbAddNode(handle)))
}

// The relation used to go only to db_timeline's in-process journal. It is now
// on the edge, and a store written, closed and opened again still says it.
func TestARelationIsStoredOnItsEdgeAndReadBackAfterAReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	handle := dbOpenDiskAt(t, dir)
	proc, file := dbNodeID(t, handle), dbNodeID(t, handle)
	added := mustHash(t, DbAddRelation(handle, proc, file, stringObj("wrote"),
		makeHashObject(map[string]object.Object{"bytes": intObj(4096)})))
	if got := mustHashIntValue(t, added, "indexed_props"); got != 2 {
		t.Fatalf("indexed_props = %d, want the relation and one attribute", got)
	}
	edgeID := mustHashIntValue(t, added, "edge_id")
	mustValue(t, DbClose(handle))

	reopened := dbOpenDiskAt(t, dir)
	defer DbClose(reopened)
	listed := mustHash(t, DbRelations(reopened, proc, stringObj("out")))
	relations := mustHashArrayValue(t, listed, "relations")
	if len(relations) != 1 || mustHashIntValue(t, listed, "unlabelled") != 0 {
		t.Fatalf("db_relations after a reopen gave %s", listed.Inspect())
	}
	relation := relations[0].(*object.Hash)
	if mustHashStringValue(t, relation, "relation") != "wrote" || mustHashIntValue(t, relation, "edge_id") != edgeID ||
		mustHashIntValue(t, relation, "src") != proc.Value || mustHashIntValue(t, relation, "dst") != file.Value {
		t.Fatalf("the relation read back as %s", relation.Inspect())
	}
	properties := mustHashValue(t, relation, "properties").(*object.Hash)
	if mustHashStringValue(t, properties, "attr_bytes") != "4096" {
		t.Fatalf("the attribute read back as %s", properties.Inspect())
	}

	schema := mustHash(t, DbSchema(reopened))
	counts := mustHashArrayValue(t, schema, "relations")
	if len(counts) != 1 || mustHashStringValue(t, counts[0].(*object.Hash), "relation") != "wrote" ||
		mustHashIntValue(t, counts[0].(*object.Hash), "count") != 1 {
		t.Fatalf("db_schema counts the relations as %s", schema.Inspect())
	}
}

func TestARelationThatNamesNothingOrANodeThatIsNotThereIsRefused(t *testing.T) {
	handle := dbOpenMemory(t)
	a, b := dbNodeID(t, handle), dbNodeID(t, handle)
	dbRefused(t, DbAddRelation(handle, a, b, stringObj("")), "empty")
	dbRefused(t, DbAddRelation(handle, a, b, stringObj("wr\xffote")), "UTF-8")
	dbRefused(t, DbAddRelation(handle, a, intObj(9999), stringObj("wrote")), "node 9999 does not exist")
	dbRefused(t, DbAddRelation(handle, a, b, stringObj("wrote"),
		makeHashObject(map[string]object.Object{"size": intObj(1)}), intObj(0)), "wrong number of arguments")

	secret := &object.Bytes{Value: []byte("classified plaintext"), Classified: &object.Classification{
		RecordUID: "r", Tags: []string{strings.Repeat("ab", 16)}, Labels: []string{"pii"}}}
	dbRefused(t, DbAddRelation(handle, a, b, stringObj("wrote"),
		makeHashObject(map[string]object.Object{"content": secret})), "classified")

	// None of those wrote an edge.
	if edges := mustHashIntValue(t, mustHash(t, DbStats(handle)), "edges"); edges != 0 {
		t.Fatalf("refused relations left %d edges behind", edges)
	}
}

// A hash key that is not a STRING used to be skipped, and the artifact was
// reported with fewer properties than the script gave it.
func TestAnAttributeKeyThatIsNotAStringIsRefusedRatherThanDropped(t *testing.T) {
	handle := dbOpenMemory(t)
	attrs := &object.Hash{Pairs: map[object.HashKey]object.HashPair{}}
	key := intObj(7)
	attrs.Pairs[key.HashKey()] = object.HashPair{Key: key, Value: stringObj("x")}
	dbRefused(t, DbAddArtifact(handle, stringObj("file"), attrs), "INTEGER key")
	a, b := dbNodeID(t, handle), dbNodeID(t, handle)
	dbRefused(t, DbAddRelation(handle, a, b, stringObj("wrote"), attrs), "INTEGER key")
}

func TestDbIndexPropRefusesAMissingNode(t *testing.T) {
	handle := dbOpenMemory(t)
	dbRefused(t, DbIndexProp(handle, intObj(424242), stringObj("name"), stringObj("x")), "node 424242 does not exist")
	found := mustHash(t, DbFind(handle, stringObj("name"), stringObj("x")))
	if mustHashBoolValue(t, found, "key_indexed") {
		t.Fatal("the refused index entry was written anyway")
	}

	node := dbNodeID(t, handle)
	if value := mustValue(t, DbIndexProp(handle, node, stringObj("name"), stringObj("x"))); value.Inspect() != "true" {
		t.Fatalf("indexing a live node returned %s", value.Inspect())
	}
}

func TestDbFindSaysWhenAKeyWasNeverIndexed(t *testing.T) {
	handle := dbOpenMemory(t)
	first := mustHashIntValue(t, mustHash(t, DbAddArtifact(handle, stringObj("file"),
		makeHashObject(map[string]object.Object{"path": stringObj("/tmp/a")}))), "node_id")
	second := mustHashIntValue(t, mustHash(t, DbAddArtifact(handle, stringObj("file"))), "node_id")
	typed := dbInt(t, DbAddNode(handle, intObj(5)))
	mustValue(t, DbIndexProp(handle, intObj(typed), stringObj("artifact_type"), stringObj("file")))

	found := mustHash(t, DbFind(handle, stringObj("artifact_type"), stringObj("file")))
	if got := dbIDs(t, mustHashArrayValue(t, found, "nodes")); !reflect.DeepEqual(got, []int64{first, second, typed}) ||
		mustHashIntValue(t, found, "count") != 3 || !mustHashBoolValue(t, found, "key_indexed") {
		t.Fatalf("db_find by artifact_type gave %s", found.Inspect())
	}
	// Restricted to one type.
	found = mustHash(t, DbFind(handle, stringObj("artifact_type"), stringObj("file"), intObj(5)))
	if got := dbIDs(t, mustHashArrayValue(t, found, "nodes")); !reflect.DeepEqual(got, []int64{typed}) {
		t.Fatalf("db_find restricted to type 5 gave %v", got)
	}
	// A BYTES value is compared as the same bytes.
	found = mustHash(t, DbFind(handle, stringObj("attr_path"), &object.Bytes{Value: []byte("/tmp/a")}))
	if got := dbIDs(t, mustHashArrayValue(t, found, "nodes")); !reflect.DeepEqual(got, []int64{first}) {
		t.Fatalf("db_find by a BYTES value gave %v", got)
	}

	// Nothing matches in both of these, and only one of them is a real "no".
	absent := mustHash(t, DbFind(handle, stringObj("artifact_type"), stringObj("registry")))
	never := mustHash(t, DbFind(handle, stringObj("artifact_typo"), stringObj("file")))
	if mustHashIntValue(t, absent, "count") != 0 || !mustHashBoolValue(t, absent, "key_indexed") {
		t.Fatalf("a value no node holds gave %s", absent.Inspect())
	}
	if mustHashIntValue(t, never, "count") != 0 || mustHashBoolValue(t, never, "key_indexed") {
		t.Fatalf("a key never indexed gave %s", never.Inspect())
	}
	dbRefused(t, DbFind(handle, stringObj(""), stringObj("file")), "key is empty")
}

// Indexing a key again adds a value; it does not replace the old one. db_node
// shows both rather than choosing.
func TestDbNodeShowsEveryValueOfAKeyIndexedTwice(t *testing.T) {
	handle := dbOpenMemory(t)
	node := intObj(dbInt(t, DbAddNode(handle, intObj(3))))
	mustValue(t, DbIndexProp(handle, node, stringObj("status"), stringObj("open")))
	mustValue(t, DbIndexProp(handle, node, stringObj("status"), stringObj("closed")))
	mustValue(t, DbIndexProp(handle, node, stringObj("owner"), stringObj("ana")))
	mustValue(t, DbIndexProp(handle, node, stringObj("raw"), stringObj("\xff\x00")))

	read := mustHash(t, DbNode(handle, node))
	properties := mustHashValue(t, read, "properties").(*object.Hash)
	status := mustHashArrayValue(t, properties, "status")
	if len(status) != 2 || status[0].Inspect() != "closed" || status[1].Inspect() != "open" {
		t.Fatalf("status read back as %s", mustHashValue(t, properties, "status").Inspect())
	}
	if mustHashStringValue(t, properties, "owner") != "ana" {
		t.Fatalf("owner read back as %s", mustHashValue(t, properties, "owner").Inspect())
	}
	if raw, ok := mustHashValue(t, properties, "raw").(*object.Bytes); !ok || string(raw.Value) != "\xff\x00" {
		t.Fatalf("a value that is not UTF-8 read back as %s, want BYTES", mustHashValue(t, properties, "raw").Inspect())
	}
	if multi := mustHashArrayValue(t, read, "multi_valued"); len(multi) != 1 || multi[0].Inspect() != "status" {
		t.Fatalf("multi_valued is %s", mustHashValue(t, read, "multi_valued").Inspect())
	}
	if mustHashIntValue(t, read, "property_count") != 4 || mustHashIntValue(t, read, "blob_bytes") != 0 {
		t.Fatalf("db_node gave %s", read.Inspect())
	}
	if labels := dbIDs(t, mustHashArrayValue(t, read, "labels")); !reflect.DeepEqual(labels, []int64{3}) {
		t.Fatalf("labels read back as %v, want the type given to db_add_node", labels)
	}
	// Both routes agree: db_find finds it under either value.
	for _, value := range []string{"open", "closed"} {
		found := mustHash(t, DbFind(handle, stringObj("status"), stringObj(value)))
		if got := dbIDs(t, mustHashArrayValue(t, found, "nodes")); !reflect.DeepEqual(got, []int64{node.Value}) {
			t.Fatalf("db_find status=%s gave %v", value, got)
		}
	}
	dbRefused(t, DbNode(handle, intObj(9999)), "node 9999 does not exist")
}

// An edge with no relation -- db_add_edge's, or one db_add_relation wrote
// before the relation was stored -- reads as null and is counted.
func TestDbRelationsCountsTheUnlabelledAndListsASelfLoopOnce(t *testing.T) {
	handle := dbOpenMemory(t)
	a, b := dbNodeID(t, handle), dbNodeID(t, handle)
	mustValue(t, DbAddEdge(handle, a, b))
	mustHash(t, DbAddRelation(handle, b, a, stringObj("answered")))
	mustHash(t, DbAddRelation(handle, a, a, stringObj("forked")))

	both := mustHash(t, DbRelations(handle, a, stringObj(" BOTH ")))
	relations := mustHashArrayValue(t, both, "relations")
	if len(relations) != 3 || mustHashIntValue(t, both, "count") != 3 || mustHashIntValue(t, both, "unlabelled") != 1 ||
		mustHashStringValue(t, both, "direction") != "both" {
		t.Fatalf("db_relations both ways gave %s", both.Inspect())
	}
	names := []string{}
	for _, relation := range relations {
		value := mustHashValue(t, relation.(*object.Hash), "relation")
		if value.Type() == object.NULL_OBJ {
			names = append(names, "null")
			continue
		}
		names = append(names, value.Inspect())
	}
	if !reflect.DeepEqual(names, []string{"null", "answered", "forked"}) {
		t.Fatalf("the relations in the order added are %v", names)
	}

	in := mustHash(t, DbRelations(handle, a, stringObj("in")))
	if mustHashIntValue(t, in, "count") != 2 {
		t.Fatalf("db_relations in gave %s", in.Inspect())
	}
	dbRefused(t, DbRelations(handle, a, stringObj("outbound")), `"outbound" is not a direction`)
	dbRefused(t, DbRelations(handle, intObj(9999), stringObj("out")), "node 9999 does not exist")
}

// db_bfs used to read any word it did not know as "both", walk a negative
// depth as zero, and keep one of several parallel edges.
func TestDbBFSKeepsParallelEdgesAndRefusesWhatItCannotAnswer(t *testing.T) {
	handle := dbOpenMemory(t)
	proc, file, net := dbNodeID(t, handle), dbNodeID(t, handle), dbNodeID(t, handle)
	edges := []int64{}
	for _, relation := range []string{"wrote", "read", "deleted"} {
		edges = append(edges, mustHashIntValue(t, mustHash(t, DbAddRelation(handle, proc, file, stringObj(relation))), "edge_id"))
	}
	edges = append(edges, dbInt(t, DbAddEdge(handle, file, net)))

	reach := mustHash(t, DbBFS(handle, proc, intObj(2), stringObj("OUT")))
	if nodes := dbIDs(t, mustHashArrayValue(t, reach, "nodes")); !reflect.DeepEqual(nodes, []int64{proc.Value, file.Value, net.Value}) {
		t.Fatalf("db_bfs reached %v", nodes)
	}
	if got := dbIDs(t, mustHashArrayValue(t, reach, "edges")); !reflect.DeepEqual(got, edges) {
		t.Fatalf("db_bfs crossed %v, want every edge including the parallel ones: %v", got, edges)
	}
	origin := mustHash(t, DbBFS(handle, proc, intObj(0), stringObj("out")))
	if len(mustHashArrayValue(t, origin, "nodes")) != 1 || len(mustHashArrayValue(t, origin, "edges")) != 0 {
		t.Fatalf("a walk of depth 0 gave %s", origin.Inspect())
	}
	backwards := mustHash(t, DbBFS(handle, net, intObj(1), stringObj("in")))
	if nodes := dbIDs(t, mustHashArrayValue(t, backwards, "nodes")); !reflect.DeepEqual(nodes, []int64{net.Value, file.Value}) {
		t.Fatalf("a walk inbound reached %v", nodes)
	}

	dbRefused(t, DbBFS(handle, proc, intObj(2), stringObj("outbound")), `"outbound" is not a direction`)
	dbRefused(t, DbBFS(handle, proc, intObj(-1), stringObj("out")), "must not be negative")
	dbRefused(t, DbBFS(handle, proc, intObj(1<<40), stringObj("out")), "larger than this walk")
	dbRefused(t, DbBFS(handle, intObj(9999), intObj(1), stringObj("out")), "node 9999 does not exist")
}

// db_shortest_path's documentation always said "empty when none exists"; it
// returned an error.
func TestDbShortestPathReturnsAnEmptyPathForNodesNotConnected(t *testing.T) {
	handle := dbOpenMemory(t)
	a, b, c, alone := dbNodeID(t, handle), dbNodeID(t, handle), dbNodeID(t, handle), dbNodeID(t, handle)
	mustValue(t, DbAddEdge(handle, a, b))
	mustValue(t, DbAddEdge(handle, c, b))

	path := mustValue(t, DbShortestPath(handle, a, c)).(*object.Array)
	if got := dbIDs(t, path.Elements); !reflect.DeepEqual(got, []int64{a.Value, b.Value, c.Value}) {
		t.Fatalf("the path from a to c is %v; it runs against the edge c->b, which this search is documented to do", got)
	}
	none := mustValue(t, DbShortestPath(handle, a, alone)).(*object.Array)
	if len(none.Elements) != 0 {
		t.Fatalf("two nodes that are not connected gave the path %s", none.Inspect())
	}
	dbRefused(t, DbShortestPath(handle, a, intObj(9999)), "node 9999 (argument 3) does not exist")
}

var dbRootPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestDbCompactReportsTheRootsOfTheImageItWrote(t *testing.T) {
	handle := dbOpenDiskAt(t, filepath.Join(t.TempDir(), "store"))
	defer DbClose(handle)
	dbNodeID(t, handle)
	first := mustHash(t, DbCompact(handle))
	root := mustHashStringValue(t, first, "snapshot_root")
	if !dbRootPattern.MatchString(root) {
		t.Fatalf("snapshot_root after a compaction is %q", root)
	}
	dbNodeID(t, handle)
	second := mustHash(t, DbCompact(handle))
	if mustHashStringValue(t, second, "prev_root") != root || mustHashStringValue(t, second, "snapshot_root") == root {
		t.Fatalf("the second compaction's roots do not chain to the first: %s after %s", second.Inspect(), root)
	}

	memory := mustHash(t, DbCompact(dbOpenMemory(t)))
	if mustHashStringValue(t, memory, "snapshot_root") != "" || mustHashStringValue(t, memory, "prev_root") != "" {
		t.Fatalf("an in-memory compaction reported roots: %s", memory.Inspect())
	}
}

func TestDbOpenDiskReadOnlyChangesNothingAndSaysHowItRead(t *testing.T) {
	readOnly := makeHashObject(map[string]object.Object{"read_only": boolObj(true)})

	missing := filepath.Join(t.TempDir(), "missing")
	dbRefused(t, DbOpenDisk(stringObj(missing), readOnly), "does not exist")
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("a read-only open created the store it was refused: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "store")
	writer := dbOpenDiskAt(t, dir)
	node := dbNodeID(t, writer)
	// Refused while a writer holds it, rather than read around it.
	dbRefused(t, DbOpenDisk(stringObj(dir), readOnly), "db_open_disk")
	mustValue(t, DbClose(writer))

	reader := dbOpenDiskAt(t, dir, readOnly)
	stats := mustHash(t, DbStats(reader))
	if !mustHashBoolValue(t, stats, "read_only") || mustHashStringValue(t, stats, "lock_free") != "" ||
		mustHashIntValue(t, stats, "nodes") != 1 {
		t.Fatalf("a locked read-only store reported %s", stats.Inspect())
	}
	dbRefused(t, DbAddNode(reader), "read-only")
	dbRefused(t, DbIndexProp(reader, node, stringObj("k"), stringObj("v")), "read-only")
	mustValue(t, DbClose(reader))

	// A store with no lock file is read without one, and says so.
	if err := os.Remove(filepath.Join(dir, graphstore.LockFileName)); err != nil {
		t.Fatal(err)
	}
	lockFree := dbOpenDiskAt(t, dir, readOnly)
	stats = mustHash(t, DbStats(lockFree))
	mustValue(t, DbClose(lockFree))
	if !strings.Contains(mustHashStringValue(t, stats, "lock_free"), graphstore.LockFileName) {
		t.Fatalf("a lock-free read did not say why: %s", stats.Inspect())
	}
	if _, err := os.Stat(filepath.Join(dir, graphstore.LockFileName)); !os.IsNotExist(err) {
		t.Fatalf("a read-only open created %s: %v", graphstore.LockFileName, err)
	}

	writable := mustHash(t, DbStats(dbOpenMemory(t)))
	if mustHashBoolValue(t, writable, "read_only") {
		t.Fatal("an in-memory handle reported itself read-only")
	}
	dbRefused(t, DbOpenDisk(stringObj(dir), makeHashObject(map[string]object.Object{"read_only": stringObj("yes")})), "BOOLEAN")
}

func TestDbSchemaAndDbVerifyDescribeTheStore(t *testing.T) {
	handle := dbOpenMemory(t)
	artifact := intObj(mustHashIntValue(t, mustHash(t, DbAddArtifact(handle, stringObj("file"),
		makeHashObject(map[string]object.Object{"path": stringObj("/x")}))), "node_id"))
	typed := intObj(dbInt(t, DbAddNode(handle, intObj(9))))
	mustHash(t, DbAddRelation(handle, artifact, typed, stringObj("wrote")))
	mustHash(t, DbAddRelation(handle, typed, artifact, stringObj("wrote")))
	mustValue(t, DbAddEdge(handle, typed, artifact, intObj(4)))

	schema := mustHash(t, DbSchema(handle))
	if mustHashIntValue(t, schema, "nodes") != 2 || mustHashIntValue(t, schema, "edges") != 3 {
		t.Fatalf("db_schema counted %s", schema.Inspect())
	}
	nodeTypes := mustHashArrayValue(t, schema, "node_types")
	if len(nodeTypes) != 2 || mustHashIntValue(t, nodeTypes[0].(*object.Hash), "type") != 0 ||
		mustHashIntValue(t, nodeTypes[1].(*object.Hash), "type") != 9 ||
		mustHashIntValue(t, nodeTypes[1].(*object.Hash), "count") != 1 {
		t.Fatalf("node_types is %s", mustHashValue(t, schema, "node_types").Inspect())
	}
	nodeKeys := []string{}
	for _, key := range mustHashArrayValue(t, schema, "node_keys") {
		nodeKeys = append(nodeKeys, key.Inspect())
	}
	if !reflect.DeepEqual(nodeKeys, []string{"artifact_type", "attr_path"}) {
		t.Fatalf("node_keys is %v", nodeKeys)
	}
	edgeKeys := mustHashArrayValue(t, schema, "edge_keys")
	if len(edgeKeys) != 1 || edgeKeys[0].Inspect() != dbRelationKey {
		t.Fatalf("edge_keys is %s", mustHashValue(t, schema, "edge_keys").Inspect())
	}
	relations := mustHashArrayValue(t, schema, "relations")
	if len(relations) != 1 || mustHashIntValue(t, relations[0].(*object.Hash), "count") != 2 {
		t.Fatalf("relations is %s", mustHashValue(t, schema, "relations").Inspect())
	}
	edgeTypes := mustHashArrayValue(t, schema, "edge_types")
	if len(edgeTypes) != 2 || mustHashIntValue(t, edgeTypes[1].(*object.Hash), "type") != 4 {
		t.Fatalf("edge_types is %s", mustHashValue(t, schema, "edge_types").Inspect())
	}

	report := mustHash(t, DbVerify(handle))
	if !mustHashBoolValue(t, report, "checked") || !mustHashBoolValue(t, report, "consistent") ||
		mustHashStringValue(t, report, "problem") != "" || mustHashBoolValue(t, report, "values_checked") {
		t.Fatalf("db_verify on a sound store gave %s", report.Inspect())
	}
}

// The words a choice parameter declares are the builtin's own list, read the
// way the builtin reads them, so the editor's warning and the runtime's
// refusal cannot disagree about a word.
func TestEveryChoiceParameterIsTheBuiltinsOwnList(t *testing.T) {
	want := map[string][]string{
		BuiltinNameDbBfs + ".direction":       dbDirections,
		BuiltinNameDbRelations + ".direction": dbDirections,
		BuiltinNameLedgerPath + ".costModel":  ledgerCostModelList(),
		BuiltinNameCaseTransition + ".to":     caseStates,
		BuiltinNameCaseAssign + ".role":       caseAssignRoles(),
		BuiltinNameRoleDefine + ".role":       RecipientRoles(),
		BuiltinNameRoleAssign + ".role":       recipientAssignRoles(),
		BuiltinNameReviewDecide + ".decision": {"approved", "changes_requested", "rejected"},
	}
	seen := map[string]bool{}
	for _, def := range Builtins {
		params, ok := ParamSpecs(def.Name)
		if !ok {
			continue
		}
		for _, p := range params {
			if len(p.OneOf) == 0 {
				continue
			}
			id := def.Name + "." + p.Name
			seen[id] = true
			if !reflect.DeepEqual(p.OneOf, want[id]) {
				t.Errorf("%s declares %v; the builtin's own list is %v", id, p.OneOf, want[id])
			}
			if !reflect.DeepEqual(p.Kinds, []ParamKind{ParamString}) {
				t.Errorf("%s declares words but kinds %v; a word is a STRING", id, p.Kinds)
			}
			for _, word := range p.OneOf {
				if choiceFold(word) != word {
					t.Errorf("%s declares %q, which the builtin would read as %q", id, word, choiceFold(word))
				}
				if !p.AcceptsChoice(" " + strings.ToUpper(word) + " ") {
					t.Errorf("%s: AcceptsChoice does not fold %q the way the builtin does", id, word)
				}
			}
			if p.AcceptsChoice("sideways") {
				t.Errorf("%s accepts a word it does not declare", id)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("%s declares no words", id)
		}
	}

	// And the builtins take every declared word and refuse the rest.
	handle := dbOpenMemory(t)
	node := dbNodeID(t, handle)
	for _, word := range dbDirections {
		mustHash(t, DbBFS(handle, node, intObj(1), stringObj(word)))
		mustHash(t, DbRelations(handle, node, stringObj(word)))
	}
	for model := range ledgerCostModels {
		if !slices.Contains(ledgerCostModelList(), model) {
			t.Errorf("cost model %q is missing from the declared list", model)
		}
	}
}
