package builtin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mutant/object"
	"mutant/security"
)

// useTestAuditChain empties the process chain and pins its clock.
//
// The chain is process-wide, as the custody session is, so a test that recorded
// events and walked away would leave them in the next test's manifest. The
// clock advances a second per entry rather than standing still, because two
// entries at the same instant would hide an ordering bug behind a tie.
func useTestAuditChain(t *testing.T) {
	t.Helper()

	auditLog.reset()
	previous := auditNow
	tick := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	auditNow = func() time.Time {
		tick = tick.Add(time.Second)
		return tick
	}
	t.Cleanup(func() {
		auditNow = previous
		auditLog.reset()
	})
}

func auditHeadHash(t *testing.T) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, AuditHead())
	if errObj != nil {
		t.Fatalf("audit_head failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("audit_head returned %T, want HASH", value)
	}
	return hash
}

func writeAuditLog(t *testing.T, path string) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, AuditWrite(stringObj(path)))
	if errObj != nil {
		t.Fatalf("audit_write failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("audit_write returned %T, want HASH", value)
	}
	return hash
}

func verifyAuditLog(t *testing.T, args ...object.Object) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, AuditVerify(args...))
	if errObj != nil {
		t.Fatalf("audit_verify failed: %s", errObj.Message)
	}
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("audit_verify returned %T, want HASH", value)
	}
	return hash
}

// readAuditDocument reads a written log back the way audit_verify does.
func readAuditDocument(t *testing.T, path string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %s", path, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decoding %s: %s", path, err)
	}
	return document
}

func writeAuditDocument(t *testing.T, path string, document map[string]any) {
	t.Helper()

	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("re-marshalling the log: %s", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("writing %s: %s", path, err)
	}
}

func auditLogEntries(t *testing.T, document map[string]any) []any {
	t.Helper()
	entries, ok := document["log"].([]any)
	if !ok {
		t.Fatal("the document has no log")
	}
	return entries
}

func auditLogEntry(t *testing.T, document map[string]any, index int) map[string]any {
	t.Helper()
	entries := auditLogEntries(t, document)
	if index >= len(entries) {
		t.Fatalf("the log has %d entries; wanted entry %d", len(entries), index)
	}
	entry, ok := entries[index].(map[string]any)
	if !ok {
		t.Fatalf("log entry %d is not an object", index)
	}
	return entry
}

// TestTheAuditHookIsNoLongerAStub is the point of the whole file. Every Record*
// function in security/telemetry.go has always called auditEvent, and auditEvent
// has always discarded its arguments, so the counters were the only record that
// anything happened. This asserts that a security event recorded through the
// public API now lands in the chain with the stage the caller named.
func TestTheAuditHookIsNoLongerAStub(t *testing.T) {
	useTestAuditChain(t)

	if !security.AuditSinkInstalled() {
		t.Fatal("no audit sink is installed; security events are being counted and not logged")
	}

	security.RecordDebuggerDetected("vm-run")
	security.RecordIntegrityFailure("vm-decode")

	snapshot := auditLog.snapshot()
	if snapshot.Total != 2 {
		t.Fatalf("the chain recorded %d events, want 2", snapshot.Total)
	}
	if got := snapshot.Entries[0].Event; got != "debugger_detected" {
		t.Fatalf("entry 1 event = %q", got)
	}
	if got := snapshot.Entries[0].Stage; got != "vm-run" {
		t.Fatalf("entry 1 stage = %q", got)
	}
	if got := snapshot.Entries[1].Event; got != "integrity_failed" {
		t.Fatalf("entry 2 event = %q", got)
	}
}

func TestAnEmptyChainSaysSoRatherThanShowingADigest(t *testing.T) {
	useTestAuditChain(t)

	head := auditHeadHash(t)
	if got := mustHashStringValue(t, head, "head"); got != auditGenesis {
		t.Fatalf("head of an empty chain = %q, want the genesis value", got)
	}
	if got := mustHashIntValue(t, head, "entries"); got != 0 {
		t.Fatalf("entries = %d, want 0", got)
	}
	if !mustHashBoolValue(t, head, "chain_complete") {
		t.Fatal("an empty chain is complete; nothing has been dropped from it")
	}
	if !mustHashBoolValue(t, head, "recording") {
		t.Fatal("recording is false, so nothing would be logged")
	}
}

func TestEachEntryCarriesTheHashOfTheOneBeforeIt(t *testing.T) {
	useTestAuditChain(t)

	for _, stage := range []string{"first", "second", "third"} {
		auditLog.AuditEvent("probe", stage)
	}

	snapshot := auditLog.snapshot()
	if len(snapshot.Entries) != 3 {
		t.Fatalf("retained %d entries, want 3", len(snapshot.Entries))
	}
	if got := snapshot.Entries[0].Prev; got != auditGenesis {
		t.Fatalf("the first entry follows %q, want the genesis value", got)
	}
	for index := 1; index < len(snapshot.Entries); index++ {
		if got, want := snapshot.Entries[index].Prev, snapshot.Entries[index-1].Hash; got != want {
			t.Fatalf("entry %d follows %s, want %s", index+1, got, want)
		}
	}
	if got, want := snapshot.Head, snapshot.Entries[2].Hash; got != want {
		t.Fatalf("head = %s, want the last entry's hash %s", got, want)
	}
	if got := snapshot.Entries[2].Seq; got != 3 {
		t.Fatalf("the third entry is numbered %d", got)
	}
}

// TestALinkCannotBeForgedAcrossAFieldBoundary is why auditLink length-prefixes
// rather than joining with a separator. `stage` is free text from the caller --
// "runner:"+stage in one place -- so any separator that can appear in a stage is
// a separator two different event/stage pairs could be made to share.
func TestALinkCannotBeForgedAcrossAFieldBoundary(t *testing.T) {
	left := auditLink(auditGenesis, 1, 0, "probe:a", "b")
	right := auditLink(auditGenesis, 1, 0, "probe", "a:b")
	if left == right {
		t.Fatal("two different event/stage pairs hash the same; the fields are not separated")
	}

	// The same holds for the boundary between the sequence number and the
	// timestamp, which are both decimal integers side by side.
	if auditLink(auditGenesis, 1, 23, "e", "s") == auditLink(auditGenesis, 12, 3, "e", "s") {
		t.Fatal("entry 1 at t=23 hashes the same as entry 12 at t=3")
	}
}

// TestTheHeadCoversEventsTheChainNoLongerKeeps is the cap's contract. The
// retained entries are bounded because OpChkDbg runs inside loops; the head is
// not, because it is 32 bytes.
func TestTheHeadCoversEventsTheChainNoLongerKeeps(t *testing.T) {
	useTestAuditChain(t)

	const overflow = 100
	expected := auditGenesis
	tick := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	for index := 1; index <= auditRetained+overflow; index++ {
		auditLog.AuditEvent("probe", "loop")
		tick = tick.Add(time.Second)
		expected = auditLink(expected, int64(index), tick.UnixNano(), "probe", "loop")
	}

	snapshot := auditLog.snapshot()
	if got := snapshot.Total; got != auditRetained+overflow {
		t.Fatalf("the chain counted %d events, want %d", got, auditRetained+overflow)
	}
	if snapshot.Dropped == 0 {
		t.Fatal("nothing was dropped, so the cap did not engage")
	}
	if len(snapshot.Entries) > auditRetained {
		t.Fatalf("retained %d entries, above the cap of %d", len(snapshot.Entries), auditRetained)
	}
	if got, want := int64(len(snapshot.Entries)), snapshot.Total-snapshot.Dropped; got != want {
		t.Fatalf("retained %d entries and dropped %d of %d; the three do not add up", got, snapshot.Dropped, snapshot.Total)
	}
	if got, want := snapshot.firstRetainedSeq(), snapshot.Dropped+1; got != want {
		t.Fatalf("the readable run starts at entry %d, want %d", got, want)
	}
	if snapshot.complete() {
		t.Fatal("a chain that dropped entries reports itself complete")
	}

	// The assertion the cap exists to preserve: the head is what it would have
	// been had nothing been dropped.
	if snapshot.Head != expected {
		t.Fatalf("head = %s, want %s -- the head no longer covers the dropped events", snapshot.Head, expected)
	}
}

func TestWritingAndVerifyingALogRoundTrips(t *testing.T) {
	useTestAuditChain(t)
	for _, stage := range []string{"vm-run", "vm-decode", "runner:startup"} {
		auditLog.AuditEvent("integrity_failed", stage)
	}
	head := auditLog.snapshot().Head

	path := filepath.Join(t.TempDir(), "audit.json")
	written := writeAuditLog(t, path)
	if got := mustHashStringValue(t, written, "head"); got != head {
		t.Fatalf("audit_write reported head %s, want %s", got, head)
	}
	if got := mustHashIntValue(t, written, "entries"); got != 3 {
		t.Fatalf("audit_write reported %d entries", got)
	}
	if mustHashStringValue(t, written, "sha256") == "" {
		t.Fatal("audit_write did not report the digest of what it wrote")
	}

	// Unanchored: the log is checked against the head stored inside it, which
	// is a check against a value its own writer chose. It must say so.
	result := verifyAuditLog(t, stringObj(path))
	if !mustHashBoolValue(t, result, "links_intact") {
		t.Fatalf("links_intact = false: %s", mustHashStringValue(t, result, "detail"))
	}
	if !mustHashBoolValue(t, result, "head_matches") {
		t.Fatal("head_matches = false on a log nobody touched")
	}
	if got := mustHashIntValue(t, result, "links_checked"); got != 3 {
		t.Fatalf("links_checked = %d, want 3", got)
	}
	if mustHashBoolValue(t, result, "anchored") {
		t.Fatal("anchored = true with no head supplied")
	}
	if mustHashBoolValue(t, result, "anchor_matches") {
		t.Fatal("anchor_matches = true with nothing to match against")
	}

	// Anchored against the real head.
	anchored := verifyAuditLog(t, stringObj(path), stringObj(head))
	if !mustHashBoolValue(t, anchored, "anchored") || !mustHashBoolValue(t, anchored, "anchor_matches") {
		t.Fatal("verifying against the true head did not match")
	}

	// Anchored against somebody else's head.
	wrong := verifyAuditLog(t, stringObj(path), stringObj(auditGenesis))
	if !mustHashBoolValue(t, wrong, "anchored") {
		t.Fatal("anchored = false when a head was supplied")
	}
	if mustHashBoolValue(t, wrong, "anchor_matches") {
		t.Fatal("anchor_matches = true against a head this log does not have")
	}
	if !mustHashBoolValue(t, wrong, "links_intact") {
		t.Fatal("a wrong anchor broke the links, which are a different question")
	}
}

func TestAnEditedEntryBreaksTheLinkAfterIt(t *testing.T) {
	useTestAuditChain(t)
	for _, stage := range []string{"one", "two", "three", "four"} {
		auditLog.AuditEvent("probe", stage)
	}

	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	document := readAuditDocument(t, path)
	entry := auditLogEntry(t, document, 1)
	entry["stage"] = "something else"
	writeAuditDocument(t, path, document)

	result := verifyAuditLog(t, stringObj(path))
	if mustHashBoolValue(t, result, "links_intact") {
		t.Fatal("an edited entry verified")
	}
	if got := mustHashIntValue(t, result, "broken_at"); got != 2 {
		t.Fatalf("broken_at = %d, want the edited entry 2", got)
	}
	if got := mustHashIntValue(t, result, "links_checked"); got != 1 {
		t.Fatalf("links_checked = %d; only the entry before the edit is verifiable", got)
	}
	if !strings.Contains(mustHashStringValue(t, result, "detail"), "entry 2") {
		t.Fatalf("detail does not name the entry: %q", mustHashStringValue(t, result, "detail"))
	}
}

// TestTheDisplayedTimeIsCheckedAgainstTheSealedOne closes the gap a reader
// would otherwise have no way to see: `at` is what a person reads and
// `unix_nano` is what the hash covers, so an editor who changed only the
// rendered string would move an event in the reader's eyes without breaking a
// single link.
func TestTheDisplayedTimeIsCheckedAgainstTheSealedOne(t *testing.T) {
	useTestAuditChain(t)
	auditLog.AuditEvent("probe", "one")
	auditLog.AuditEvent("probe", "two")

	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	document := readAuditDocument(t, path)
	entry := auditLogEntry(t, document, 0)
	entry["at"] = "2001-01-01T00:00:00Z"
	writeAuditDocument(t, path, document)

	result := verifyAuditLog(t, stringObj(path))
	if mustHashBoolValue(t, result, "links_intact") {
		t.Fatal("a log whose displayed time was moved verified")
	}
	if got := mustHashIntValue(t, result, "broken_at"); got != 1 {
		t.Fatalf("broken_at = %d, want 1", got)
	}
	if !strings.Contains(mustHashStringValue(t, result, "detail"), "2001-01-01") {
		t.Fatalf("detail does not show the value that was read: %q", mustHashStringValue(t, result, "detail"))
	}
}

// TestARewrittenChainPassesItselfAndFailsItsAnchor is the argument for
// audit_verify's second parameter. Somebody who edits an entry and recomputes
// every hash after it, including the head, produces a document that is
// internally perfect. Only a head from outside the document catches it.
func TestARewrittenChainPassesItselfAndFailsItsAnchor(t *testing.T) {
	useTestAuditChain(t)
	for _, stage := range []string{"one", "two", "three"} {
		auditLog.AuditEvent("command_attempt", stage)
	}
	trueHead := auditLog.snapshot().Head

	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	document := readAuditDocument(t, path)
	auditLogEntry(t, document, 1)["stage"] = "a command nobody ran"
	prev := auditGenesis
	for _, raw := range auditLogEntries(t, document) {
		entry := raw.(map[string]any)
		entry["prev"] = prev
		hash := auditLink(prev, manifestInt(entry, "seq"), manifestInt(entry, "unix_nano"),
			stringField(entry, "event"), stringField(entry, "stage"))
		entry["hash"] = hash
		prev = hash
	}
	document["head"] = prev
	writeAuditDocument(t, path, document)

	self := verifyAuditLog(t, stringObj(path))
	if !mustHashBoolValue(t, self, "links_intact") || !mustHashBoolValue(t, self, "head_matches") {
		t.Fatal("the rewritten chain was expected to be internally consistent; the test proves nothing otherwise")
	}

	anchored := verifyAuditLog(t, stringObj(path), stringObj(trueHead))
	if !mustHashBoolValue(t, anchored, "anchored") {
		t.Fatal("anchored = false when a head was supplied")
	}
	if mustHashBoolValue(t, anchored, "anchor_matches") {
		t.Fatal("a rewritten chain matched the head of the run it claims to be from")
	}
}

// TestTheCaseManifestCarriesTheChainHead is the binding. Without it the head is
// a number a script can print; with it the head is inside a document that is
// hashed and, on a machine with a key, signed.
func TestTheCaseManifestCarriesTheChainHead(t *testing.T) {
	useTestAuditChain(t)
	openTestCase(t, "IR-2026-0900", "G. Gogia")

	security.RecordSandboxDetected("vm-run")
	head := auditLog.snapshot().Head

	audit := manifestSection(t, currentManifest(t), "audit")
	if got := mustHashStringValue(t, audit, "head"); got != head {
		t.Fatalf("the manifest carries head %s, want %s", got, head)
	}
	if got := mustHashIntValue(t, audit, "entries"); got != 1 {
		t.Fatalf("the manifest reports %d entries, want 1", got)
	}
	if !mustHashBoolValue(t, audit, "chain_complete") {
		t.Fatal("chain_complete = false on a one-entry chain")
	}
	if mustHashStringValue(t, audit, "does_not_cover") == "" {
		t.Fatal("the manifest's audit block does not state what the chain cannot show")
	}
}

func TestAuditWriteIsRecordedInTheCaseTimeline(t *testing.T) {
	useTestAuditChain(t)
	openTestCase(t, "IR-2026-0901", "G. Gogia")
	security.RecordCommandAttempt("exec")

	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	found := false
	for _, raw := range manifestArray(t, currentManifest(t), "timeline") {
		entry, ok := raw.(*object.Hash)
		if !ok {
			continue
		}
		if mustHashStringValue(t, entry, "event") == BuiltinNameAuditWrite {
			found = true
		}
	}
	if !found {
		t.Fatal("writing the audit log left no trace in the case timeline")
	}
}

func TestAuditVerifyRefusesALogFromAnotherVersion(t *testing.T) {
	useTestAuditChain(t)
	auditLog.AuditEvent("probe", "one")

	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	document := readAuditDocument(t, path)
	document["algorithm"] = "mutant-audit-99"
	writeAuditDocument(t, path, document)

	_, errObj := unwrapPairNoFatal(AuditVerify(stringObj(path)))
	if errObj == nil {
		t.Fatal("a log written under other rules was checked under these ones")
	}
	if !strings.Contains(errObj.Message, "mutant-audit-99") {
		t.Fatalf("the error does not name the version it found: %s", errObj.Message)
	}
}

func TestAuditBuiltinsRejectBadArguments(t *testing.T) {
	useTestAuditChain(t)
	path := filepath.Join(t.TempDir(), "audit.json")
	writeAuditLog(t, path)

	cases := []struct {
		name   string
		result object.Object
	}{
		{"audit_head with an argument", AuditHead(stringObj("x"))},
		{"audit_write with no path", AuditWrite()},
		{"audit_write with a non-string path", AuditWrite(intObj(7))},
		{"audit_write with an empty path", AuditWrite(stringObj("  "))},
		{"audit_verify with no path", AuditVerify()},
		{"audit_verify with a non-string head", AuditVerify(stringObj(path), intObj(7))},
		{"audit_verify with three arguments", AuditVerify(stringObj(path), stringObj(""), stringObj(""))},
		{"audit_verify on a file that is not a log", AuditVerify(stringObj(filepath.Join(t.TempDir(), "absent.json")))},
	}
	for _, testCase := range cases {
		if _, errObj := unwrapPairNoFatal(testCase.result); errObj == nil {
			t.Fatalf("%s was accepted", testCase.name)
		}
	}
}

// TestAuditBuiltinsReturnTheDeclaredFields cross-checks both ways: every field
// the documentation promises is returned, and every field returned is
// documented. Hover, completion and the LSP's type inference read the
// declaration, so a field that exists only in the implementation is a field the
// editor will call undefined.
func TestAuditBuiltinsReturnTheDeclaredFields(t *testing.T) {
	useTestAuditChain(t)
	auditLog.AuditEvent("probe", "one")

	path := filepath.Join(t.TempDir(), "audit.json")

	returned := map[string]*object.Hash{
		BuiltinNameAuditHead:   auditHeadHash(t),
		BuiltinNameAuditWrite:  writeAuditLog(t, path),
		BuiltinNameAuditVerify: verifyAuditLog(t, stringObj(path)),
	}

	for name, hash := range returned {
		doc, ok := builtinDocs[name]
		if !ok {
			t.Fatalf("%s has no metadata entry", name)
		}
		declared := map[string]bool{}
		for _, field := range doc.returns.fields {
			declared[field] = true
		}

		actual := map[string]bool{}
		for _, pair := range hash.Pairs {
			key, ok := pair.Key.(*object.String)
			if !ok {
				t.Fatalf("%s returned a non-string hash key", name)
			}
			actual[key.Value] = true
			if !declared[key.Value] {
				t.Errorf("%s returns %q, which its metadata does not declare", name, key.Value)
			}
		}
		for field := range declared {
			if !actual[field] {
				t.Errorf("%s declares %q, which it did not return", name, field)
			}
		}
	}
}

func TestAuditMetadataStatesWhatTheChainCannotShow(t *testing.T) {
	for _, name := range []string{BuiltinNameAuditHead, BuiltinNameAuditWrite, BuiltinNameAuditVerify} {
		doc, ok := builtinDocs[name]
		if !ok {
			t.Fatalf("%s has no metadata entry", name)
		}
		if doc.summary == "" {
			t.Fatalf("%s has no summary", name)
		}
		if got := CapabilityCategory(name); got != "chain of custody" {
			t.Fatalf("%s files under %q", name, got)
		}
	}

	// The limit belongs in the document, not only in the manual.
	if !strings.Contains(auditDoesNotCover, "deleted") {
		t.Fatal("the does_not_cover sentence no longer names wholesale deletion")
	}
}
