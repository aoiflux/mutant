package builtin

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// An emitter's failure mode is not the source table's. A wrong field name in
// schema_events.go produces no event; a wrong field name here produces a
// document that looks complete, indexes without complaint, and is silently
// filed under something it is not. Nothing downstream will ever report it.
//
// So these tests check the three things a document can get wrong that reading it
// would not reveal: that a field the artifact never recorded is absent rather
// than present and empty, that a class or category is only claimed when the
// evidence supports it, and that the verbatim source entry survives the trip.
//
// Where a parser runs without a disk image -- bodyfile, syslog, shimcache -- the
// document is built from that parser's real output through events_from, so the
// chain is tested rather than a hand-built envelope's agreement with itself.

// docAt walks a dotted path through an emitted document, which is what the
// nesting in ECS and OCSF costs a test. A missing step yields nil rather than a
// failure, because "this field is absent" is the assertion half of these tests
// make.
func docAt(t *testing.T, document *object.Hash, path string) object.Object {
	t.Helper()
	var node object.Object = document
	for _, step := range strings.Split(path, ".") {
		hash, ok := node.(*object.Hash)
		if !ok {
			t.Fatalf("%s: %q is a %s, not a HASH", path, step, node.Type())
		}
		value := hashValueByKey(hash, step)
		if value == nil {
			return nil
		}
		node = value
	}
	return node
}

func docStr(t *testing.T, document *object.Hash, path string) string {
	t.Helper()
	value := docAt(t, document, path)
	if value == nil {
		return ""
	}
	text, ok := value.(*object.String)
	if !ok {
		t.Fatalf("%s is %s, want STRING", path, value.Type())
	}
	return text.Value
}

func docInt(t *testing.T, document *object.Hash, path string) int64 {
	t.Helper()
	value := docAt(t, document, path)
	if value == nil {
		t.Fatalf("%s is absent, want an INTEGER", path)
	}
	number, ok := value.(*object.Integer)
	if !ok {
		t.Fatalf("%s is %s, want INTEGER", path, value.Type())
	}
	return number.Value
}

// docList reads a field ECS spells as an array even when it holds one value.
func docList(t *testing.T, document *object.Hash, path string) []string {
	t.Helper()
	value := docAt(t, document, path)
	if value == nil {
		return nil
	}
	array, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("%s is %s, want ARRAY", path, value.Type())
	}
	out := make([]string, 0, len(array.Elements))
	for _, element := range array.Elements {
		text, ok := element.(*object.String)
		if !ok {
			t.Fatalf("%s holds a %s, want STRING", path, element.Type())
		}
		out = append(out, text.Value)
	}
	return out
}

func emitted(t *testing.T, emit BuiltinFunction, args ...object.Object) *object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, emit(args...))
	if errObj != nil {
		t.Fatalf("emitter refused a valid event: %s", errObj.Inspect())
	}
	document, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("emitter returned %s, want HASH", payload.Type())
	}
	return document
}

// bodyfileEvents runs the real bodyfile parser and normalizes its row, so the
// documents below are built from a parser's output rather than from a hash
// written to match them.
func bodyfileEvents(t *testing.T) []*object.Hash {
	t.Helper()
	path := filepath.Join(t.TempDir(), "body.txt")
	line := "d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|12345-128-1|r/rrw-r--r--|0|0|2048|" +
		"1700000000|1700000100|1700000200|1700000300\n"
	if err := os.WriteFile(path, []byte(line), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, errObj := unwrapPair(t, BodyfileParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bodyfile_parse: %s", errObj.Inspect())
	}
	return eventsOf(t, entries, stringObj("bodyfile"))
}

// --- ECS ---

func TestEcsNestsTheDocumentAndLeavesOutWhatWasNeverRecorded(t *testing.T) {
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	document := emitted(t, EcsEvent, created)

	// The row's crtime, which is the last of its four columns.
	if got := docStr(t, document, "@timestamp"); got != "2023-11-14T22:18:20Z" {
		t.Errorf("@timestamp = %q", got)
	}
	if got := docStr(t, document, "ecs.version"); got != ecsDefaultVersion {
		t.Errorf("ecs.version = %q", got)
	}
	if got := docStr(t, document, "event.kind"); got != "event" {
		t.Errorf("event.kind = %q", got)
	}
	if got := docStr(t, document, "event.module"); got != "bodyfile" {
		t.Errorf("event.module = %q", got)
	}
	if got := docList(t, document, "event.category"); len(got) != 1 || got[0] != "file" {
		t.Errorf("event.category = %v, want [file]", got)
	}
	// The envelope split one row into four events, one per time. ECS has no
	// field saying which, so event.type carries the shape of it and
	// mutant.ts_desc carries the name -- without either, the four documents are
	// the same document four times.
	if got := docList(t, document, "event.type"); len(got) != 1 || got[0] != "creation" {
		t.Errorf("event.type = %v, want [creation]", got)
	}
	if got := docStr(t, document, "mutant.ts_desc"); got != "Creation Time" {
		t.Errorf("mutant.ts_desc = %q", got)
	}
	if got := docStr(t, document, "file.path"); got != "/etc/passwd" {
		t.Errorf("file.path = %q", got)
	}
	if got := docInt(t, document, "file.size"); got != 2048 {
		t.Errorf("file.size = %d", got)
	}
	if got := docStr(t, document, "file.hash.md5"); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("file.hash.md5 = %q", got)
	}
	if docAt(t, document, "mutant.extra") == nil {
		t.Error("the verbatim source entry should reach mutant.extra")
	}

	// A bodyfile row records no process, no network peer, no URL and no
	// registry key. An empty process object in the document would claim it did.
	for _, absent := range []string{"process", "source", "destination", "url", "registry", "host", "user"} {
		if docAt(t, document, absent) != nil {
			t.Errorf("%s is present in a document built from a bodyfile row, which records nothing of the sort", absent)
		}
	}
	// Neither does it carry a hash it never saw.
	for _, absent := range []string{"file.hash.sha1", "file.hash.sha256"} {
		if docAt(t, document, absent) != nil {
			t.Errorf("%s is present, but the row only carried an MD5", absent)
		}
	}
}

func TestEcsReadsTheTimestampsMeaningIntoTheSubcategory(t *testing.T) {
	events := bodyfileEvents(t)
	for _, want := range []struct{ desc, eventType string }{
		{"Creation Time", "creation"},
		{"Content Modification Time", "change"},
		{"Metadata Modification Time", "change"},
		{"Last Access Time", "access"},
	} {
		document := emitted(t, EcsEvent, eventByDesc(t, events, want.desc))
		if got := docList(t, document, "event.type"); len(got) != 1 || got[0] != want.eventType {
			t.Errorf("%s -> event.type %v, want [%s]", want.desc, got, want.eventType)
		}
	}
}

func TestEcsCarriesSeverityAsBothAWordAndANumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	// <11> is facility 1, severity 3 (error), which the envelope calls "high".
	line := "<11>Jan  2 03:04:05 host sshd[42]: Failed password for root\n"
	if err := os.WriteFile(path, []byte(line), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	artifact, errObj := unwrapPair(t, SyslogParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("syslog_parse: %s", errObj.Inspect())
	}
	events := eventsOf(t, artifact, stringObj("syslog"))
	if len(events) != 1 {
		t.Fatalf("expected 1 syslog event, got %d", len(events))
	}
	document := emitted(t, EcsEvent, events[0])

	if got := docStr(t, document, "log.level"); got != "high" {
		t.Errorf("log.level = %q, want the envelope's word", got)
	}
	// The number runs the syslog way, which is the direction ECS's own example
	// uses. The word is there too, so nothing has to know that.
	if got := docInt(t, document, "event.severity"); got != 3 {
		t.Errorf("event.severity = %d, want 3", got)
	}
	if got := docStr(t, document, "event.dataset"); got != "syslog" {
		t.Errorf("event.dataset = %q", got)
	}
	if got := docStr(t, document, "process.name"); got != "sshd" {
		t.Errorf("process.name = %q", got)
	}
	if got := docInt(t, document, "process.pid"); got != 42 {
		t.Errorf("process.pid = %d", got)
	}
	// ECS has no "log" category, and every value it does have would be a claim
	// about what this line recorded.
	if docAt(t, document, "event.category") != nil {
		t.Errorf("event.category = %v, but ECS has no category for a log line", docList(t, document, "event.category"))
	}
}

func TestEcsWritesAnEventCodeAsAKeyword(t *testing.T) {
	document := emitted(t, EcsEvent, makeHashObject(map[string]object.Object{
		"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
		"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Recorded Time"),
		"kind": stringObj("evtx"), "category": stringObj("log"),
		"code": intObj(4624), "provider": stringObj("Microsoft-Windows-Security-Auditing"),
		"dataset": stringObj("Security"),
	}))
	// An event id names a kind of event; it does not count anything. Indexed as
	// a number it invites range queries that mean nothing.
	if got := docStr(t, document, "event.code"); got != "4624" {
		t.Errorf("event.code = %q, want the string \"4624\"", got)
	}
	if got := docStr(t, document, "event.provider"); got != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("event.provider = %q", got)
	}
}

// --- OCSF ---

func TestOcsfTakesTheClassFromTheCategoryAndTheActivityFromTheTimestamp(t *testing.T) {
	events := bodyfileEvents(t)
	for _, want := range []struct {
		desc       string
		activityID int64
		name       string
	}{
		{"Creation Time", 1, "Create"},
		{"Content Modification Time", 3, "Update"},
		{"Last Access Time", 2, "Read"},
		{"Metadata Modification Time", 6, "Set Attributes"},
	} {
		event := emitted(t, OcsfEvent, eventByDesc(t, events, want.desc))
		if got := docInt(t, event, "class_uid"); got != 1001 {
			t.Errorf("%s -> class_uid %d, want 1001", want.desc, got)
		}
		if got := docInt(t, event, "category_uid"); got != 1 {
			t.Errorf("%s -> category_uid %d, want 1", want.desc, got)
		}
		if got := docInt(t, event, "activity_id"); got != want.activityID {
			t.Errorf("%s -> activity_id %d, want %d", want.desc, got, want.activityID)
		}
		if got := docStr(t, event, "activity_name"); got != want.name {
			t.Errorf("%s -> activity_name %q, want %q", want.desc, got, want.name)
		}
		if got := docInt(t, event, "type_uid"); got != 1001*100+want.activityID {
			t.Errorf("%s -> type_uid %d, which is not class_uid*100 + activity_id", want.desc, got)
		}
		if got := docInt(t, event, "time"); got != hInt(t, eventByDesc(t, events, want.desc), "ts_ms") {
			t.Errorf("%s -> time %d, want the envelope's milliseconds", want.desc, got)
		}
	}
}

func TestOcsfLeavesAnEventItCannotClassifyOnTheBaseEvent(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)
	path := filepath.Join(t.TempDir(), "appcompat.bin")
	if err := os.WriteFile(path, buildWin10Shimcache([]string{`C:\temp\payload.exe`}, filetime), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	artifact, errObj := unwrapPair(t, ShimcacheParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("shimcache_parse: %s", errObj.Inspect())
	}
	events := eventsOf(t, artifact, stringObj("shimcache"))
	event := emitted(t, OcsfEvent, events[0])

	// Shimcache records that a program was present. OCSF 1007 Process Activity
	// would state that it ran, and a detection written against 1007 would then
	// fire on it.
	if got := docInt(t, event, "class_uid"); got != 0 {
		t.Errorf("class_uid = %d, want the Base Event; presence is not process activity", got)
	}
	if got := docStr(t, event, "class_name"); got != "Base Event" {
		t.Errorf("class_name = %q", got)
	}
	// The reading is not lost by staying uncategorized: 99 Other keeps it in
	// activity_name, where a consumer can still read it.
	if got := docInt(t, event, "activity_id"); got != 99 {
		t.Errorf("activity_id = %d, want 99 Other", got)
	}
	if got := docStr(t, event, "activity_name"); got != "present" {
		t.Errorf("activity_name = %q, want the envelope's action", got)
	}
	if got := docStr(t, event, "unmapped.kind"); got != "shimcache" {
		t.Errorf("unmapped.kind = %q", got)
	}
	if got := docStr(t, event, "unmapped.timestamp_desc"); got != "Content Modification Time" {
		t.Errorf("unmapped.timestamp_desc = %q", got)
	}
	if docAt(t, event, "unmapped.extra") == nil {
		t.Error("the verbatim source entry should reach unmapped.extra")
	}
}

func TestOcsfSaysUnknownRatherThanGuessingASeverity(t *testing.T) {
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	event := emitted(t, OcsfEvent, created)

	// severity_id is required by OCSF. A bodyfile row reports no severity, and
	// 0 Unknown is OCSF's own way of saying so.
	if got := docInt(t, event, "severity_id"); got != 0 {
		t.Errorf("severity_id = %d, want 0", got)
	}
	if got := docStr(t, event, "severity"); got != "Unknown" {
		t.Errorf("severity = %q", got)
	}

	for word, id := range map[string]int64{
		"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "fatal": 6,
	} {
		withSeverity := emitted(t, OcsfEvent, makeHashObject(map[string]object.Object{
			"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
			"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Recorded Time"),
			"kind": stringObj("syslog"), "category": stringObj("log"),
			"severity": stringObj(word),
		}))
		if got := docInt(t, withSeverity, "severity_id"); got != id {
			t.Errorf("severity %q -> severity_id %d, want %d", word, got, id)
		}
	}
}

func TestOcsfFileObjectCarriesTheNameItIsRequiredToHave(t *testing.T) {
	event := emitted(t, OcsfEvent, makeHashObject(map[string]object.Object{
		"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
		"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Written Time"),
		"kind": stringObj("amcache"), "category": stringObj("execution"), "action": stringObj("present"),
		"path": stringObj(`C:\Windows\System32\evil.exe`),
		"hashes": makeHashObject(map[string]object.Object{
			"sha1": stringObj("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
		}),
	}))

	// The entry carried a path and no file name, so the name is the path's last
	// component rather than the file object being left out.
	if got := docStr(t, event, "file.name"); got != "evil.exe" {
		t.Errorf("file.name = %q", got)
	}
	if got := docStr(t, event, "file.path"); got != `C:\Windows\System32\evil.exe` {
		t.Errorf("file.path = %q", got)
	}
	// type_id is required too, and the artifact did not say which type it is.
	if got := docInt(t, event, "file.type_id"); got != 0 {
		t.Errorf("file.type_id = %d, want 0 Unknown", got)
	}
	fingerprints, ok := docAt(t, event, "file.hashes").(*object.Array)
	if !ok || len(fingerprints.Elements) != 1 {
		t.Fatalf("file.hashes = %v, want one fingerprint", docAt(t, event, "file.hashes"))
	}
	fingerprint := fingerprints.Elements[0].(*object.Hash)
	if got := hStr(t, fingerprint, "algorithm"); got != "SHA-1" {
		t.Errorf("algorithm = %q", got)
	}
	if got := hInt(t, fingerprint, "algorithm_id"); got != 2 {
		t.Errorf("algorithm_id = %d, want 2", got)
	}

	// An event with nothing to name a file after describes no file at all,
	// rather than one called "".
	noFile := emitted(t, OcsfEvent, makeHashObject(map[string]object.Object{
		"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
		"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Recorded Time"),
		"kind": stringObj("syslog"), "category": stringObj("log"),
	}))
	if docAt(t, noFile, "file") != nil {
		t.Error("a syslog line describes no file; the file object should be absent")
	}
}

// --- Timesketch / plaso ---

func TestTimesketchAlwaysFillsTheThreeFieldsItRequires(t *testing.T) {
	// A mapping that supplies no message template and names no timestamp, which
	// is the shape a Mutant-written parser reaches here with.
	events := eventsOf(t,
		&object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"when": intObj(1700000000)}),
		}},
		makeHashObject(map[string]object.Object{
			"kind":     stringObj("caselog"),
			"category": stringObj("configuration"),
			"times":    &object.Array{Elements: []object.Object{makeHashObject(map[string]object.Object{"field": stringObj("when")})}},
		}))
	record := emitted(t, TimesketchEvent, events[0])

	// Timesketch drops a record missing any of these rather than flagging it,
	// so an empty one is a row that silently never arrives.
	for _, required := range []string{"message", "datetime", "timestamp_desc"} {
		if docStr(t, record, required) == "" {
			t.Errorf("%s is empty; Timesketch would drop this record on ingest", required)
		}
	}
	if got := docStr(t, record, "message"); got != "caselog event" {
		t.Errorf("message = %q, want the kind named rather than an empty line", got)
	}
	// A kind with no plaso equivalent gets its own type. Borrowing one would put
	// these rows in front of an analyzer written for something else.
	if got := docStr(t, record, "data_type"); got != "mutant:caselog:event" {
		t.Errorf("data_type = %q", got)
	}
}

func TestTimesketchCountsMicrosecondsAndNamesThePlasoType(t *testing.T) {
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	record := emitted(t, TimesketchEvent, created)

	if got := docStr(t, record, "data_type"); got != "fs:mactime:line" {
		t.Errorf("data_type = %q", got)
	}
	if got, want := docInt(t, record, "timestamp"), hInt(t, created, "ts_ms")*1000; got != want {
		t.Errorf("timestamp = %d, want %d microseconds", got, want)
	}
	if got := docStr(t, record, "timestamp_desc"); got != "Creation Time" {
		t.Errorf("timestamp_desc = %q", got)
	}
	if got := docStr(t, record, "filename"); got != "/etc/passwd" {
		t.Errorf("filename = %q", got)
	}
	if got := docStr(t, record, "md5_hash"); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5_hash = %q", got)
	}
	if got := docInt(t, record, "file_size"); got != 2048 {
		t.Errorf("file_size = %d", got)
	}
}

func TestTimesketchTakesThePlasoTypeFromTheBrowserTheEntryCameOutOf(t *testing.T) {
	for _, want := range []struct{ kind, browser, dataType string }{
		{"browser_history", "chrome", "chrome:history:page_visited"},
		{"browser_history", "firefox", "firefox:places:page_visited"},
		{"browser_cookies", "chrome", "chrome:cookie:entry"},
		{"browser_downloads", "firefox", "firefox:downloads:download"},
		// The envelope's `dataset` exists so the emitters never reach into
		// `extra` for it. When it is not there, the type is not guessed.
		{"browser_history", "", "mutant:browser_history:event"},
		{"browser_history", "safari", "mutant:browser_history:event"},
	} {
		values := map[string]object.Object{
			"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
			"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Last Visited Time"),
			"kind": stringObj(want.kind), "category": stringObj("web"), "action": stringObj("visit"),
		}
		if want.browser != "" {
			values["dataset"] = stringObj(want.browser)
		}
		record := emitted(t, TimesketchEvent, makeHashObject(values))
		if got := docStr(t, record, "data_type"); got != want.dataType {
			t.Errorf("%s/%q -> data_type %q, want %q", want.kind, want.browser, got, want.dataType)
		}
	}
}

// --- options ---

func TestEmittersFillInWhatAnArtifactCannotRecord(t *testing.T) {
	// An $MFT knows every path on the volume and nothing about which host the
	// volume came out of. The examiner who mounted the image does.
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	opts := makeHashObject(map[string]object.Object{
		"host": stringObj("WS01"), "user": stringObj("jdoe"),
	})

	if got := docStr(t, emitted(t, EcsEvent, created, opts), "host.name"); got != "WS01" {
		t.Errorf("ecs host.name = %q", got)
	}
	if got := docStr(t, emitted(t, OcsfEvent, created, opts), "device.hostname"); got != "WS01" {
		t.Errorf("ocsf device.hostname = %q", got)
	}
	if got := docStr(t, emitted(t, TimesketchEvent, created, opts), "hostname"); got != "WS01" {
		t.Errorf("timesketch hostname = %q", got)
	}
	if got := docStr(t, emitted(t, EcsEvent, created, opts), "user.name"); got != "jdoe" {
		t.Errorf("ecs user.name = %q", got)
	}

	// What the artifact did record wins. The option fills a gap; it does not
	// overwrite evidence.
	recorded := makeHashObject(map[string]object.Object{
		"ts": intObj(1700000000), "ts_ms": intObj(1700000000000),
		"iso": stringObj("2023-11-14T22:13:20Z"), "ts_desc": stringObj("Recorded Time"),
		"kind": stringObj("evtx"), "category": stringObj("log"),
		"host": stringObj("DC01"),
	})
	if got := docStr(t, emitted(t, EcsEvent, recorded, opts), "host.name"); got != "DC01" {
		t.Errorf("host.name = %q, want the host the artifact recorded", got)
	}
}

func TestEmittersCanLeaveTheSourceEntryOut(t *testing.T) {
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	without := makeHashObject(map[string]object.Object{"extra": boolObj(false)})

	if docAt(t, emitted(t, EcsEvent, created, without), "mutant.extra") != nil {
		t.Error("ecs_event kept the source entry despite extra:false")
	}
	if docAt(t, emitted(t, OcsfEvent, created, without), "unmapped.extra") != nil {
		t.Error("ocsf_event kept the source entry despite extra:false")
	}
	if docAt(t, emitted(t, TimesketchEvent, created, without), "extra") != nil {
		t.Error("timesketch_event kept the source entry despite extra:false")
	}
	// Dropping the entry does not drop what was read out of it.
	if got := docStr(t, emitted(t, OcsfEvent, created, without), "unmapped.kind"); got != "bodyfile" {
		t.Errorf("unmapped.kind = %q", got)
	}
}

func TestEmittersCarryTagsIntoEachSchemasOwnField(t *testing.T) {
	created := eventByDesc(t, bodyfileEvents(t), "Creation Time")
	opts := makeHashObject(map[string]object.Object{
		"tags": &object.Array{Elements: []object.Object{stringObj("case-42"), stringObj("triage")}},
	})

	for _, want := range []struct {
		name  string
		emit  BuiltinFunction
		field string
	}{
		{"ecs_event", EcsEvent, "tags"},
		{"ocsf_event", OcsfEvent, "metadata.labels"},
		{"timesketch_event", TimesketchEvent, "tag"},
	} {
		got := docList(t, emitted(t, want.emit, created, opts), want.field)
		if len(got) != 2 || got[0] != "case-42" || got[1] != "triage" {
			t.Errorf("%s %s = %v", want.name, want.field, got)
		}
	}
}

// --- shape in, shape out ---

func TestEmittersRenderAWholeTimelineInOneCall(t *testing.T) {
	events := bodyfileEvents(t)
	timeline := make([]object.Object, 0, len(events))
	for _, event := range events {
		timeline = append(timeline, event)
	}

	for _, emit := range []BuiltinFunction{EcsEvent, OcsfEvent, TimesketchEvent} {
		payload, errObj := unwrapPair(t, emit(&object.Array{Elements: timeline}))
		if errObj != nil {
			t.Fatalf("emitting a timeline: %s", errObj.Inspect())
		}
		documents, ok := payload.(*object.Array)
		if !ok {
			t.Fatalf("an array of events should give an array of documents, got %s", payload.Type())
		}
		if len(documents.Elements) != len(events) {
			t.Errorf("got %d documents for %d events", len(documents.Elements), len(events))
		}
	}
}

func TestEmittersRefuseWhatDidNotComeFromEventsFrom(t *testing.T) {
	// A raw parser entry has no ts and no iso. Emitting it anyway would produce
	// a document with no timestamp and every mapped field missing, which looks
	// like a real document and indexes like one.
	rawEntry := makeHashObject(map[string]object.Object{
		"name": stringObj("/etc/passwd"), "mtime": intObj(1700000000),
	})

	for _, want := range []struct {
		name string
		emit BuiltinFunction
		args []object.Object
		says string
	}{
		{"no arguments", EcsEvent, nil, "wrong number of arguments"},
		{"three arguments", OcsfEvent, []object.Object{rawEntry, rawEntry, rawEntry}, "wrong number of arguments"},
		{"a string", TimesketchEvent, []object.Object{stringObj("mft")}, "must be HASH or ARRAY"},
		{"a raw parser entry", EcsEvent, []object.Object{rawEntry}, "events_from"},
		{"an array holding a string", OcsfEvent,
			[]object.Object{&object.Array{Elements: []object.Object{stringObj("x")}}}, "must be a HASH"},
		{"an unknown option", TimesketchEvent,
			[]object.Object{rawEntry, makeHashObject(map[string]object.Object{"hosts": stringObj("WS01")})},
			"unknown option"},
		{"an option of the wrong type", EcsEvent,
			[]object.Object{rawEntry, makeHashObject(map[string]object.Object{"host": intObj(1)})},
			"must be STRING"},
	} {
		_, errObj := unwrapPairNoFatal(want.emit(want.args...))
		if errObj == nil {
			t.Errorf("%s: accepted, want a refusal", want.name)
			continue
		}
		if !strings.Contains(errObj.Message, want.says) {
			t.Errorf("%s: error %q does not mention %q", want.name, errObj.Message, want.says)
		}
	}
}

// TestEverySourceKindEmitsThroughAllThreeSchemas drives the whole source table
// through the emitters, so adding a kind to schema_events.go cannot quietly
// produce a document one of the schemas would reject.
//
// The envelope is built from the source spec rather than from a parser, because
// the point here is the emitters' coverage of the table, not the table's
// agreement with the parsers -- that is schema_events_test.go's job.
func TestEverySourceKindEmitsThroughAllThreeSchemas(t *testing.T) {
	kinds := make([]string, 0, len(eventSources))
	for kind := range eventSources {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	for _, kind := range kinds {
		source := eventSources[kind]
		values := map[string]object.Object{
			"ts": intObj(1700000000), "ts_ms": intObj(1700000000123),
			"iso": stringObj("2023-11-14T22:13:20.123Z"), "ts_desc": stringObj(source.times[0].desc),
			"kind": stringObj(source.kind), "category": stringObj(source.category),
			"extra": makeHashObject(map[string]object.Object{"raw": stringObj("verbatim")}),
		}
		if source.action != "" {
			values["action"] = stringObj(source.action)
		}
		event := makeHashObject(values)

		document := emitted(t, EcsEvent, event)
		if docStr(t, document, "event.kind") != "event" {
			t.Errorf("%s: ecs event.kind is not set", kind)
		}
		if got := docList(t, document, "event.type"); len(got) != 1 || got[0] == "" {
			t.Errorf("%s: ecs event.type = %v", kind, got)
		}

		ocsf := emitted(t, OcsfEvent, event)
		classUID, activityID := docInt(t, ocsf, "class_uid"), docInt(t, ocsf, "activity_id")
		if got := docInt(t, ocsf, "type_uid"); got != classUID*100+activityID {
			t.Errorf("%s: ocsf type_uid %d is not class_uid*100 + activity_id", kind, got)
		}
		if got := docInt(t, ocsf, "severity_id"); got < 0 || got > 6 {
			t.Errorf("%s: ocsf severity_id %d is outside the vocabulary", kind, got)
		}
		if docStr(t, ocsf, "metadata.version") == "" || docStr(t, ocsf, "activity_name") == "" {
			t.Errorf("%s: ocsf event is missing a required field", kind)
		}

		record := emitted(t, TimesketchEvent, event)
		for _, required := range []string{"message", "datetime", "timestamp_desc", "data_type"} {
			if docStr(t, record, required) == "" {
				t.Errorf("%s: timesketch %s is empty", kind, required)
			}
		}
		if strings.Contains(docStr(t, record, "data_type"), " ") {
			t.Errorf("%s: data_type %q has a space in it", kind, docStr(t, record, "data_type"))
		}
	}
}
