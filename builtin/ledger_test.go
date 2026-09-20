package builtin

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// --- helpers ---------------------------------------------------------------

// openTestLedger opens a ledger under a temp directory and closes it before
// the directory is removed.
//
// The close is registered after t.TempDir, and cleanups run last-registered
// first, so the store releases its lock on the directory before the framework
// tries to delete it. Reversed, every test in this file would leave a locked
// directory behind on Windows.
func openTestLedger(t *testing.T, actor string) (int64, string) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "ledger")
	payload, errObj := unwrapPair(t, LedgerOpen(stringObj(dir), stringObj(actor)))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("ledger_open payload is not HASH. got=%T", payload)
	}
	handle := mustHashIntValue(t, hash, "handle")
	t.Cleanup(func() { LedgerClose(intObj(handle)) })
	return handle, dir
}

func ledgerProps(values map[string]string) *object.Hash {
	out := make(map[string]object.Object, len(values))
	for key, value := range values {
		out[key] = stringObj(value)
	}
	return makeHashObject(out)
}

// mustLedgerHash calls a builtin and insists it succeeded with a hash payload.
func mustLedgerHash(t *testing.T, name string, result object.Object) *object.Hash {
	t.Helper()

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("%s: %s", name, errObj.Message)
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("%s payload is not HASH. got=%T", name, payload)
	}
	return hash
}

// assertLedgerDeclaredFields is assertDeclaredFields without the handle echo.
//
// The filesystem families all carry the handle they were asked about back in
// their payload, and that helper checks it. Nothing in this family does: a
// ledger handle is a number in a process-local map, not an identifier anyone
// outside the run could use, and echoing it into a document that gets handed
// to somebody else would be noise in a record meant to be read by a third
// party.
func assertLedgerDeclaredFields(t *testing.T, name string, payload object.Object) {
	t.Helper()

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("%s payload is not HASH. got=%T", name, payload)
	}

	got := map[string]bool{}
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			t.Fatalf("%s returned a non-STRING key %s", name, pair.Key.Inspect())
		}
		got[key.Value] = true
	}

	declared, ok := builtinDocs[name]
	if !ok {
		t.Fatalf("%s has no metadata entry", name)
	}
	for _, field := range declared.returns.fields {
		if !got[field] {
			t.Errorf("%s declares field %q but did not return it", name, field)
		}
		delete(got, field)
	}
	for field := range got {
		t.Errorf("%s returned undeclared field %q", name, field)
	}
}

// --- the posture -----------------------------------------------------------

// The whole point of the family is that these are not negotiable, so they are
// asserted by value rather than by "an options hash was honoured".
func TestALedgerOpensInAPostureAScriptCannotTurnOff(t *testing.T) {
	_, dir := openTestLedger(t, "G. Gogia")

	payload, errObj := unwrapPair(t, LedgerOpen(stringObj(filepath.Join(dir, "..", "second")), stringObj("G. Gogia")))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	hash := payload.(*object.Hash)
	defer LedgerClose(intObj(mustHashIntValue(t, hash, "handle")))

	for field, want := range map[string]bool{
		"signed_commits_required": true,
		"verified_on_open":        true,
		"redaction_ledger":        true,
		"audit_log":               true,
		// False on purpose. Graphene's own custody report asks for it and this
		// family declines: filling a grant ledger would dress a typed-in name
		// up as an authorisation model. See the file header.
		"role_grants": false,
	} {
		if got := mustHashBoolValue(t, hash, field); got != want {
			t.Errorf("ledger_open reported %s=%v, want %v", field, got, want)
		}
	}

	if got := mustHashStringValue(t, hash, "retained_segments"); got != "all" {
		t.Errorf("ledger_open reported retained_segments=%q, want \"all\"", got)
	}
}

// There is no way to spell "open this without signing", so there is no test
// for one. What there is instead: the posture is fixed at two arguments.
func TestLedgerOpenTakesNoOptionsHash(t *testing.T) {
	_, errObj := unwrapPair(t, LedgerOpen(stringObj("x"), stringObj("y"), makeHashObject(nil)))
	if errObj == nil {
		t.Fatal("ledger_open accepted a third argument; the posture is meant to be unreachable from a script")
	}
}

func TestTheActorIsRecordedAndNothingAboutItIsVerified(t *testing.T) {
	_, dir := openTestLedger(t, "G. Gogia")

	second := filepath.Join(dir, "..", "same-name")
	payload, errObj := unwrapPair(t, LedgerOpen(stringObj(second), stringObj("G. Gogia")))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	hash := payload.(*object.Hash)
	defer LedgerClose(intObj(mustHashIntValue(t, hash, "handle")))

	if got := mustHashStringValue(t, hash, "actor"); got != "G. Gogia" {
		t.Errorf("the asserted name came back as %q", got)
	}
	// The id travels beside the name, never instead of it, because it is the
	// name and nothing more.
	if mustHashStringValue(t, hash, "actor_id") == "" {
		t.Error("the actor id is empty")
	}
}

// store.TxContext.Unattributed() reads ActorID == 0 as "no actor was given",
// so an id of zero would be committed as unattributed while the caller
// believed otherwise. It is the one value the derivation must never produce.
func TestAnActorIdIsNeverZeroBecauseZeroMeansUnattributed(t *testing.T) {
	var ctx store.TxContext
	if !ctx.Unattributed() {
		t.Fatal("the assumption behind this test no longer holds: a zero TxContext is not unattributed")
	}

	for _, name := range []string{"", "a", "G. Gogia", "0", "\x00", "examiner@example.test"} {
		if id := ledgerIDFrom([]byte(name)); id == 0 {
			t.Errorf("ledgerIDFrom(%q) produced zero, which graphene records as no actor at all", name)
		}
	}
}

func TestALedgerWithNoActorIsRefusedRatherThanDefaulted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	for _, actor := range []string{"", "   "} {
		_, errObj := unwrapPair(t, LedgerOpen(stringObj(dir), stringObj(actor)))
		if errObj == nil {
			t.Fatalf("ledger_open(%q) was accepted; a ledger records who wrote it and there is no default", actor)
		}
	}
}

// --- the property blob, which is the trap this family exists to close -------

// Properties live in two different places and only one of them is what a
// redaction removes. Both have to be written, and this asserts both.
func TestPropertiesAreWrittenToBothTheBlobAndTheIndex(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	session, _ := ledgerGet(handle)

	hash := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(
		intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001", "case": "IR-2026-0944"})))

	nodeID := mustHashIntValue(t, hash, "id")
	if got := mustHashIntValue(t, hash, "property_count"); got != 2 {
		t.Errorf("property_count = %d, want 2", got)
	}
	if mustHashIntValue(t, hash, "property_bytes") == 0 {
		t.Error("the entity was written with an empty blob, so it can never be property-redacted")
	}
	if !mustHashBoolValue(t, hash, "redactable") {
		t.Error("redactable is false on an entity written with properties")
	}

	// The blob: what RedactNodeProperties reads.
	node, err := session.graph.GetNode(store.NodeID(nodeID))
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if len(node.Properties) == 0 {
		t.Error("the node carries no property blob")
	}

	// The index: what a query reads.
	hits, err := session.graph.NodesByProperties(map[string][]byte{"uid": []byte("rec-0001")})
	if err != nil {
		t.Fatalf("NodesByProperties: %v", err)
	}
	if len(hits) != 1 || int64(hits[0]) != nodeID {
		t.Errorf("the property index does not resolve the node: got %v", hits)
	}
}

// The finding, proved in both directions.
//
// An entity written the way db_add_artifact writes them -- index entries and
// no blob -- cannot be property-redacted at all. The call refuses, nothing is
// destroyed, and the values stay in the index where anyone can still query for
// them. An entity written by this family redacts, and the index goes with it.
func TestAnEntityWrittenTheWayDbWritesThemCannotBePropertyRedacted(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	session, _ := ledgerGet(handle)

	// The old way: a node with labels, and properties registered only as index
	// entries. This is exactly what dbAddIndexedNode does.
	tx := session.graph.Begin().As(store.TxContext{ActorID: session.actorID, KeyID: session.keyID})
	indexOnly := tx.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(DATA)}})
	tx.IndexNodeProperties(indexOnly, map[string][]byte{"secret": []byte("kept-in-the-index")})
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The new way, same properties.
	written := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(
		intObj(handle), ledgerProps(map[string]string{"secret": "kept-in-the-blob"})))
	blobbed := store.NodeID(mustHashIntValue(t, written, "id"))

	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}

	request := disk.RedactionRequest{ActorID: session.actorID, Reason: "outside the scope of the warrant"}

	// Half one: the refusal.
	if _, err := session.store.RedactNodeProperties(indexOnly, request); err == nil {
		t.Error("an index-only entity was property-redacted; the trap this family exists for has moved")
	}

	// And the values are still there to be found, which is the part that makes
	// the refusal dangerous rather than merely inconvenient.
	hits, err := session.graph.NodesByProperties(map[string][]byte{"secret": []byte("kept-in-the-index")})
	if err != nil {
		t.Fatalf("NodesByProperties: %v", err)
	}
	if len(hits) != 1 {
		t.Errorf("expected the un-redacted value to still be queryable, got %v", hits)
	}

	// Half two: an entity this family wrote redacts, and takes its index
	// entries with it.
	if _, err := session.store.RedactNodeProperties(blobbed, request); err != nil {
		t.Fatalf("redacting an entity written by ledger_add_node: %v", err)
	}
	hits, err = session.graph.NodesByProperties(map[string][]byte{"secret": []byte("kept-in-the-blob")})
	if err != nil {
		t.Fatalf("NodesByProperties after redaction: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("the redacted value is still queryable through the index: %v", hits)
	}
}

// Whether an entity can ever be property-redacted is fixed when it is written.
// Reporting it at write time is the only moment it can still be acted on.
func TestAnEntityWithNoPropertiesSaysSoAtWriteTimeRatherThanAtRedactionTime(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	session, _ := ledgerGet(handle)

	hash := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(handle), makeHashObject(nil)))
	if mustHashBoolValue(t, hash, "redactable") {
		t.Fatal("an entity with no properties reported itself redactable")
	}
	if got := mustHashIntValue(t, hash, "property_bytes"); got != 0 {
		t.Errorf("property_bytes = %d on an entity with no properties", got)
	}

	if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_compact: %s", errObj.Message)
	}
	// And the prediction holds.
	_, err := session.store.RedactNodeProperties(
		store.NodeID(mustHashIntValue(t, hash, "id")),
		disk.RedactionRequest{ActorID: session.actorID, Reason: "checking the claim"})
	if err == nil {
		t.Error("redactable said false but the redaction succeeded")
	}
}

// The version hash a redaction record names as the identity of what it
// destroyed is derived from these bytes, so two machines encoding the same
// properties have to produce the same ones.
func TestAPropertyBlobIsTheSameBytesEveryTime(t *testing.T) {
	props := map[string][]byte{
		"zulu": []byte("last"), "alpha": []byte("first"),
		"mike": []byte("middle"), "case": []byte("IR-2026-0944"),
	}

	first, err := ledgerPropertyBlob(props)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	for i := 0; i < 32; i++ {
		again, err := ledgerPropertyBlob(props)
		if err != nil {
			t.Fatalf("blob: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("the same properties encoded differently on attempt %d", i)
		}
	}
}

func TestAPropertyValueThatIsNeitherTextNorBytesIsRefused(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	_, errObj := unwrapPair(t, LedgerAddNode(intObj(handle),
		makeHashObject(map[string]object.Object{"size": intObj(4096)})))
	if errObj == nil {
		t.Fatal("an INTEGER property was accepted; the index matches exact bytes and the rendering would be Mutant's guess")
	}

	// BYTES is accepted, because the caller spelled the bytes.
	hash := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(handle),
		makeHashObject(map[string]object.Object{"raw": &object.Bytes{Value: []byte{0x00, 0xFF}}})))
	if !mustHashBoolValue(t, hash, "redactable") {
		t.Error("a BYTES property did not produce a blob")
	}
}

// --- the two handle spaces -------------------------------------------------

// The counters are independent, so the same number is a valid handle in both
// spaces at once. This forces that collision and asserts it stays harmless --
// which is the whole reason the maps are separate.
func TestALedgerHandleAndAGraphHandleAreDifferentThings(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0001"}))); errObj != nil {
		t.Fatalf("ledger_add_node: %s", errObj.Message)
	}

	// The same number, now also a graph handle.
	inMemory := graphene.NewInMemory()
	dbHandles.Store(handle, inMemory)
	t.Cleanup(func() { dbHandles.Delete(handle); inMemory.Close() })

	// db_add_node on that number writes into the graph...
	if _, errObj := unwrapPair(t, DbAddNode(intObj(handle))); errObj != nil {
		t.Fatalf("db_add_node: %s", errObj.Message)
	}
	graphStats := mustLedgerHash(t, "db_stats", DbStats(intObj(handle)))
	if got := mustHashIntValue(t, graphStats, "nodes"); got != 1 {
		t.Errorf("the graph holds %d nodes, want 1", got)
	}

	// ...and not into the ledger, which still holds only its own.
	ledgerState := mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle)))
	if got := mustHashIntValue(t, ledgerState, "nodes"); got != 1 {
		t.Errorf("the ledger holds %d nodes, want 1 -- a db_ write reached it", got)
	}
	if mustHashStringValue(t, ledgerState, "actor") != "G. Gogia" {
		t.Error("ledger_stats resolved the graph handle instead of the ledger")
	}
}

func TestEveryLedgerBuiltinRefusesAHandleThatIsNotOne(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	unknown := intObj(handle + 100000)

	calls := map[string]object.Object{
		BuiltinNameLedgerStats:   LedgerStats(unknown),
		BuiltinNameLedgerCompact: LedgerCompact(unknown),
		BuiltinNameLedgerAddNode: LedgerAddNode(unknown, makeHashObject(nil)),
		BuiltinNameLedgerAddEdge: LedgerAddEdge(unknown, intObj(1), intObj(2), makeHashObject(nil)),
		BuiltinNameLedgerClose:   LedgerClose(unknown),
	}
	for name, result := range calls {
		_, errObj := unwrapPair(t, result)
		if errObj == nil {
			t.Errorf("%s accepted an unknown handle", name)
			continue
		}
		if !strings.Contains(errObj.Message, name) {
			t.Errorf("%s refused without naming itself: %s", name, errObj.Message)
		}
	}
}

// --- the directory ---------------------------------------------------------

func TestALedgerDirectoryRefusesToOpenAsAnOrdinaryGraph(t *testing.T) {
	handle, dir := openTestLedger(t, "G. Gogia")
	if _, errObj := unwrapPair(t, LedgerClose(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_close: %s", errObj.Message)
	}

	_, errObj := unwrapPair(t, DbOpenDisk(stringObj(dir)))
	if errObj == nil {
		t.Fatal("db_open_disk opened a forensic ledger")
	}
	if !strings.Contains(errObj.Message, "ledger_open") {
		t.Errorf("the refusal does not say what to use instead: %s", errObj.Message)
	}
	if !ledgerIsMarked(dir) {
		t.Error("the ledger directory carries no marker")
	}
}

// Why that guard exists. An unsigned commit does not corrupt the store
// quietly; it makes the store refuse to open under its own posture, for good.
func TestAnUnsignedCommitLeavesALedgerNoStrictOpenWillAccept(t *testing.T) {
	handle, dir := openTestLedger(t, "G. Gogia")
	if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle),
		ledgerProps(map[string]string{"uid": "rec-0001"}))); errObj != nil {
		t.Fatalf("ledger_add_node: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, LedgerClose(intObj(handle))); errObj != nil {
		t.Fatalf("ledger_close: %s", errObj.Message)
	}

	// Straight through graphene, which is the bypass the marker cannot cover:
	// the guard is in db_open_disk, and this is what db_open_disk would have
	// done.
	plain, err := graphene.OpenWithOptions(dir, disk.Options{})
	if err != nil {
		t.Fatalf("opening the ledger unsigned: %v", err)
	}
	tx := plain.Begin()
	tx.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(DATA)}})
	if err := tx.Commit(); err != nil {
		t.Fatalf("unsigned commit: %v", err)
	}
	if err := plain.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, errObj := unwrapPair(t, LedgerOpen(stringObj(dir), stringObj("G. Gogia")))
	if errObj == nil {
		t.Fatal("the ledger reopened strict after an unsigned commit was written into it")
	}
	if !strings.Contains(errObj.Message, "signature") {
		t.Errorf("the refusal does not say why: %s", errObj.Message)
	}
}

// --- compaction ------------------------------------------------------------

// An entity written but never compacted is in no snapshot, so there is nothing
// for a proof to resolve against. This is the state ledger_stats has to be
// able to describe, and describe as a state rather than as an error.
func TestNothingIsProvableUntilTheLedgerIsCompacted(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")
	session, _ := ledgerGet(handle)

	written := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(
		intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	nodeID := store.NodeID(mustHashIntValue(t, written, "id"))

	before := mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle)))
	if mustHashBoolValue(t, before, "compacted") {
		t.Error("a ledger that has never been compacted reported compacted=true")
	}
	if got := mustHashStringValue(t, before, "snapshot_root"); got != "" {
		t.Errorf("snapshot_root = %q before any compaction", got)
	}
	if _, err := session.store.ProveNode(nodeID); err == nil {
		t.Error("an uncompacted entity produced an inclusion proof")
	}

	report := mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(handle)))
	root := mustHashStringValue(t, report, "snapshot_root")
	if root == "" {
		t.Fatal("ledger_compact produced no snapshot root")
	}
	if !mustHashBoolValue(t, report, "compacted") {
		t.Error("ledger_compact reported compacted=false")
	}

	proof, err := session.store.ProveNode(nodeID)
	if err != nil {
		t.Fatalf("ProveNode after compaction: %v", err)
	}
	if err := disk.VerifyNodeInclusion(proof.Roots.Snapshot, proof); err != nil {
		t.Fatalf("the proof does not resolve against its own snapshot: %v", err)
	}

	after := mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle)))
	if mustHashStringValue(t, after, "snapshot_root") != root {
		t.Error("ledger_stats and ledger_compact disagree about the snapshot root")
	}
}

// The default retention keeps nothing, and graphene says what that costs:
// compaction discards the log "along with every commit's actor, timestamp,
// signature". This asserts the posture actually keeps them, by comparing
// against a store opened the way the engine defaults.
func TestCompactionKeepsTheCommitHistoryTheDefaultPostureDiscards(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	for i := 0; i < 3; i++ {
		if _, errObj := unwrapPair(t, LedgerAddNode(intObj(handle),
			ledgerProps(map[string]string{"uid": "rec-0001"}))); errObj != nil {
			t.Fatalf("ledger_add_node: %s", errObj.Message)
		}
		if _, errObj := unwrapPair(t, LedgerCompact(intObj(handle))); errObj != nil {
			t.Fatalf("ledger_compact: %s", errObj.Message)
		}
	}

	stats := mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle)))
	kept := mustHashIntValue(t, stats, "retained_segments")
	if kept < 3 {
		t.Errorf("the ledger kept %d retired segments across 3 compactions", kept)
	}

	// The same three compactions under the engine default.
	plainDir := filepath.Join(t.TempDir(), "plain")
	plain, err := graphene.OpenWithOptions(plainDir, disk.Options{})
	if err != nil {
		t.Fatalf("plain open: %v", err)
	}
	defer plain.Close()
	for i := 0; i < 3; i++ {
		tx := plain.Begin()
		tx.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(DATA)}})
		if err := tx.Commit(); err != nil {
			t.Fatalf("plain commit: %v", err)
		}
		if err := plain.Compact(); err != nil {
			t.Fatalf("plain compact: %v", err)
		}
	}
	segments, err := disk.ListSegments(plainDir)
	if err != nil {
		t.Fatalf("ListSegments: %v", err)
	}
	if len(segments) != 0 {
		t.Fatalf("the default posture kept %d segments; this test's premise is wrong", len(segments))
	}
}

// --- registration ----------------------------------------------------------

func TestEveryLedgerBuiltinChecksItsArity(t *testing.T) {
	handle, _ := openTestLedger(t, "G. Gogia")

	cases := []struct {
		name string
		args []object.Object
	}{
		{BuiltinNameLedgerOpen, nil},
		{BuiltinNameLedgerOpen, []object.Object{stringObj("only-a-path")}},
		{BuiltinNameLedgerClose, nil},
		{BuiltinNameLedgerStats, nil},
		{BuiltinNameLedgerCompact, nil},
		{BuiltinNameLedgerAddNode, []object.Object{intObj(handle)}},
		{BuiltinNameLedgerAddEdge, []object.Object{intObj(handle), intObj(1)}},
	}
	for _, testCase := range cases {
		_, errObj := unwrapPair(t, callBuiltinByName(t, testCase.name, testCase.args...))
		if errObj == nil {
			t.Errorf("%s accepted %d arguments", testCase.name, len(testCase.args))
			continue
		}
		if !strings.Contains(errObj.Message, "wrong number of arguments") {
			t.Errorf("%s refused for the wrong reason: %s", testCase.name, errObj.Message)
		}
	}
}

func TestEveryLedgerBuiltinReturnsTheDeclaredFields(t *testing.T) {
	handle, dir := openTestLedger(t, "G. Gogia")

	opened, errObj := unwrapPair(t, LedgerOpen(stringObj(filepath.Join(dir, "..", "fields")), stringObj("G. Gogia")))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	defer LedgerClose(intObj(mustHashIntValue(t, opened.(*object.Hash), "handle")))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerOpen, opened)

	node := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(
		intObj(handle), ledgerProps(map[string]string{"uid": "rec-0001"})))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerAddNode, node)

	other := mustLedgerHash(t, "ledger_add_node", LedgerAddNode(
		intObj(handle), ledgerProps(map[string]string{"uid": "rec-0002"})))

	edge := mustLedgerHash(t, "ledger_add_edge", LedgerAddEdge(
		intObj(handle),
		intObj(mustHashIntValue(t, node, "id")),
		intObj(mustHashIntValue(t, other, "id")),
		ledgerProps(map[string]string{"relation": "DERIVED_FROM"})))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerAddEdge, edge)

	// Both before and after a compaction, because the root fields are rendered
	// down two different paths and only one of them is exercised by a fresh
	// ledger.
	assertLedgerDeclaredFields(t, BuiltinNameLedgerStats, mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle))))
	compacted := mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(handle)))
	assertLedgerDeclaredFields(t, BuiltinNameLedgerCompact, compacted)
	assertLedgerDeclaredFields(t, BuiltinNameLedgerStats, mustLedgerHash(t, "ledger_stats", LedgerStats(intObj(handle))))
}
