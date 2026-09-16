package builtin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// The source table in schema_events.go is a set of claims about field names in
// eleven other files, and a wrong name is silent: the timestamp is not found,
// no event is built, and events_from returns an empty array rather than an
// error. So wherever a parser can be run without a real disk image -- bodyfile,
// mactime, syslog, shimcache, prefetch, lnk -- these tests feed the parser's own
// output in rather than a hand-built entry, and the claim is checked against the
// code that makes it. That is how the prefetch spec was caught reading ISO
// strings as unix integers.
//
// The artifacts that need a hive, an NTFS volume or a browser database are
// covered with hand-built entries, and say so.

func eventsOf(t *testing.T, artifact object.Object, kind object.Object) []*object.Hash {
	t.Helper()
	payload, errObj := unwrapPair(t, EventsFrom(artifact, kind))
	if errObj != nil {
		t.Fatalf("events_from error: %s", errObj.Inspect())
	}
	array, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("events_from returned %s, want ARRAY", payload.Type())
	}
	events := make([]*object.Hash, 0, len(array.Elements))
	for i, element := range array.Elements {
		event, ok := element.(*object.Hash)
		if !ok {
			t.Fatalf("event %d is %s, want HASH", i, element.Type())
		}
		events = append(events, event)
	}
	return events
}

func hHas(h *object.Hash, key string) bool {
	return hashValueByKey(h, key) != nil
}

// eventByDesc finds the one event carrying a given ts_desc.
func eventByDesc(t *testing.T, events []*object.Hash, desc string) *object.Hash {
	t.Helper()
	for _, event := range events {
		if hStr(t, event, "ts_desc") == desc {
			return event
		}
	}
	descriptions := make([]string, 0, len(events))
	for _, event := range events {
		descriptions = append(descriptions, hStr(t, event, "ts_desc"))
	}
	t.Fatalf("no event described %q; got %s", desc, strings.Join(descriptions, ", "))
	return nil
}

// --- the envelope's rules ---

func TestEventsFromExpandsARecordIntoOneEventPerRecordedTimestamp(t *testing.T) {
	// Hand-built: an $MFT needs a volume image or a record stream, and what is
	// under test here is the fan-out, not the NTFS parser.
	record := makeHashObject(map[string]object.Object{
		"path": stringObj(`\Windows\System32\evil.exe`), "name": stringObj("evil.exe"), "size": intObj(4096),
		"si_created": intObj(1700000000), "si_created_ns": intObj(123456789),
		"si_modified": intObj(1700000100), "si_modified_ns": intObj(0),
		"si_mft_modified": intObj(0), "si_accessed": intObj(0),
		"fn_created": intObj(1600000000), "fn_modified": intObj(0),
		"fn_mft_modified": intObj(0), "fn_accessed": intObj(0),
	})
	artifact := makeHashObject(map[string]object.Object{
		"entries": &object.Array{Elements: []object.Object{record}},
	})

	events := eventsOf(t, artifact, stringObj("mft"))

	// Five of the eight timestamps are zero, and zero means "not recorded" --
	// emitting them would bury the three real ones under 1970.
	if len(events) != 3 {
		t.Fatalf("expected 3 events for 3 recorded timestamps, got %d", len(events))
	}

	created := eventByDesc(t, events, "Creation Time")
	if hInt(t, created, "ts") != 1700000000 {
		t.Errorf("ts = %d", hInt(t, created, "ts"))
	}
	// NTFS records at 100 ns; losing the fraction loses the timestomping tell.
	if got := hStr(t, created, "iso"); got != "2023-11-14T22:13:20.123456789Z" {
		t.Errorf("iso = %q, want the sub-second fraction preserved", got)
	}
	if got := hInt(t, created, "ts_ms"); got != 1700000000123 {
		t.Errorf("ts_ms = %d, want the millisecond fraction folded in", got)
	}
	if hStr(t, created, "kind") != "mft" || hStr(t, created, "category") != "file" {
		t.Errorf("kind/category = %q/%q", hStr(t, created, "kind"), hStr(t, created, "category"))
	}
	if got := hStr(t, created, "message"); got != `\Windows\System32\evil.exe` {
		t.Errorf("message = %q", got)
	}

	// The $FILE_NAME set is named apart from $STANDARD_INFORMATION, because an
	// analyst comparing the two is the reason both are emitted.
	fnCreated := eventByDesc(t, events, "Creation Time ($FILE_NAME)")
	if hInt(t, fnCreated, "ts") != 1600000000 {
		t.Errorf("fn ts = %d", hInt(t, fnCreated, "ts"))
	}

	eventByDesc(t, events, "Content Modification Time")
}

func TestEventsFromLeavesOutWhatTheArtifactDidNotRecord(t *testing.T) {
	entry := makeHashObject(map[string]object.Object{
		"path": stringObj(""), "name": stringObj("orphan.exe"), "size": intObj(0),
		"si_created": intObj(1700000000),
	})
	artifact := makeHashObject(map[string]object.Object{
		"entries": &object.Array{Elements: []object.Object{entry}},
	})

	events := eventsOf(t, artifact, stringObj("mft"))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]

	// An empty string would read as "the artifact recorded an empty path", which
	// is a claim the parser never made.
	if hHas(event, "path") {
		t.Error("an unreconstructed path should be absent, not empty")
	}
	// A zero size is a real size: an empty file.
	if !hHas(event, "size") || hInt(t, event, "size") != 0 {
		t.Error("size 0 is a value, not an absence")
	}
	// The message falls back past the field that has nothing in it.
	if got := hStr(t, event, "message"); got != "orphan.exe" {
		t.Errorf("message = %q, want the fallback field", got)
	}
}

func TestEventsFromCarriesTheSourceEntryVerbatim(t *testing.T) {
	entry := makeHashObject(map[string]object.Object{
		"path":       stringObj(`C:\temp\payload.exe`),
		"si_created": intObj(1700000000),
		// A field the envelope has no name for. It still has to survive.
		"file_attributes": intObj(0x20),
	})
	artifact := makeHashObject(map[string]object.Object{
		"entries": &object.Array{Elements: []object.Object{entry}},
	})

	events := eventsOf(t, artifact, stringObj("mft"))
	extra := hashValueByKey(events[0], "extra")
	if extra != object.Object(entry) {
		t.Fatal("extra should be the source entry itself, so normalizing discards nothing")
	}
	if hInt(t, extra.(*object.Hash), "file_attributes") != 0x20 {
		t.Error("a field the envelope does not name must still reach the caller")
	}
}

func TestEventsFromTakesAParserResultPairDirectly(t *testing.T) {
	artifact := makeHashObject(map[string]object.Object{
		"entries": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{"si_created": intObj(1700000000)}),
		}},
	})

	// events_from(mft_parse(path), "mft") is how this reads at a call site.
	events := eventsOf(t, resultAndError(artifact, nil), stringObj("mft"))
	if len(events) != 1 {
		t.Fatalf("a (result, err) pair should be accepted; got %d events", len(events))
	}

	// And a parser that failed reports its own failure, not a shape complaint
	// about the nothing it returned.
	_, errObj := unwrapPairNoFatal(EventsFrom(resultAndError(nil, newError("open $MFT: no such file")), stringObj("mft")))
	if errObj == nil {
		t.Fatal("a failed parse should carry its error out of events_from")
	}
	if !strings.Contains(errObj.Message, "no such file") {
		t.Errorf("error = %q, want the parser's own message", errObj.Message)
	}
}

// --- against the real parsers ---

func TestEventsFromReadsABodyfileAndItsMactimeRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.txt")
	// atime=crtime=1700000000, mtime=ctime=1700000100.
	line := "d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|12345-128-1|r/rrw-r--r--|0|0|2048|" +
		"1700000000|1700000100|1700000100|1700000000\n"
	if err := os.WriteFile(path, []byte(line), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, errObj := unwrapPair(t, BodyfileParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("bodyfile_parse: %s", errObj.Inspect())
	}

	// bodyfile_parse returns a bare array, so the array is the entries.
	fromBodyfile := eventsOf(t, entries, stringObj("bodyfile"))
	if len(fromBodyfile) != 4 {
		t.Fatalf("expected 4 events for the four MAC times, got %d", len(fromBodyfile))
	}
	created := eventByDesc(t, fromBodyfile, "Creation Time")
	if hInt(t, created, "ts") != 1700000000 {
		t.Errorf("crtime event ts = %d", hInt(t, created, "ts"))
	}
	if hStr(t, created, "path") != "/etc/passwd" {
		t.Errorf("path = %q", hStr(t, created, "path"))
	}
	hashes, ok := hashValueByKey(created, "hashes").(*object.Hash)
	if !ok {
		t.Fatal("a bodyfile row's MD5 should reach the envelope's hashes")
	}
	if hStr(t, hashes, "md5") != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("hashes.md5 = %q", hStr(t, hashes, "md5"))
	}

	// mactime has already collapsed the four times into two rows, and each row
	// says which of them it stands for.
	rows := Mactime(entries).(*object.Array)
	fromMactime := eventsOf(t, rows, stringObj("mactime"))
	if len(fromMactime) != 2 {
		t.Fatalf("expected 2 events for 2 mactime rows, got %d", len(fromMactime))
	}
	if got := hStr(t, fromMactime[0], "ts_desc"); got != "Last Access Time; Creation Time" {
		t.Errorf("ts_desc = %q, want the MACB flags spelled out", got)
	}
	if got := hStr(t, fromMactime[1], "ts_desc"); got != "Content Modification Time; Metadata Modification Time" {
		t.Errorf("ts_desc = %q", got)
	}
	if got := hStr(t, fromMactime[1], "message"); got != "m.c. /etc/passwd" {
		t.Errorf("message = %q", got)
	}
}

func TestEventsFromReadsSyslogAndSpeaksSeverityInWords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	// <11> is facility 1, severity 3 (error).
	line := "<11>1 2023-11-14T22:13:20Z web01 sshd 4242 - - Failed password for root\n"
	if err := os.WriteFile(path, []byte(line), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	artifact, errObj := unwrapPair(t, SyslogParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("syslog_parse: %s", errObj.Inspect())
	}

	events := eventsOf(t, artifact, stringObj("syslog"))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]

	if hInt(t, event, "ts") != 1700000000 {
		t.Errorf("ts = %d", hInt(t, event, "ts"))
	}
	if hStr(t, event, "host") != "web01" || hStr(t, event, "process") != "sshd" {
		t.Errorf("host/process = %q/%q", hStr(t, event, "host"), hStr(t, event, "process"))
	}
	if hInt(t, event, "pid") != 4242 {
		t.Errorf("pid = %d", hInt(t, event, "pid"))
	}
	// The syslog scale counts down and every other scale counts up, which is why
	// the envelope carries a word.
	if got := hStr(t, event, "severity"); got != "high" {
		t.Errorf("severity = %q, want the word for syslog level 3", got)
	}
	if hStr(t, event, "dataset") != "syslog" {
		t.Errorf("dataset = %q", hStr(t, event, "dataset"))
	}
	if got := hStr(t, event, "message"); got != "sshd: Failed password for root" {
		t.Errorf("message = %q", got)
	}
}

func TestEventsFromReadsAShimcache(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)
	blob := buildWin10Shimcache([]string{`C:\Windows\System32\evil.exe`, `C:\temp\payload.exe`}, filetime)

	path := filepath.Join(t.TempDir(), "appcompat.bin")
	if err := os.WriteFile(path, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	artifact, errObj := unwrapPair(t, ShimcacheParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("shimcache_parse: %s", errObj.Inspect())
	}

	events := eventsOf(t, artifact, stringObj("shimcache"))
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if hInt(t, events[0], "ts") != wantUnix {
		t.Errorf("ts = %d", hInt(t, events[0], "ts"))
	}
	if hStr(t, events[0], "path") != `C:\Windows\System32\evil.exe` {
		t.Errorf("path = %q", hStr(t, events[0], "path"))
	}
	// Shimcache records that a program was present, which is evidence of
	// execution rather than proof of it -- hence "present", not "run".
	if hStr(t, events[0], "category") != "execution" || hStr(t, events[0], "action") != "present" {
		t.Errorf("category/action = %q/%q", hStr(t, events[0], "category"), hStr(t, events[0], "action"))
	}
}

func TestEventsFromReadsEveryRunTimeInAPrefetchFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CALC.EXE-DEADBEEF.pf")
	if err := os.WriteFile(path, buildSCCAv30(), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	artifact, errObj := unwrapPair(t, PrefetchParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("prefetch_parse: %s", errObj.Inspect())
	}

	// A .pf is one artifact holding several run times, so the artifact is the
	// entry and the timestamp field is a list.
	events := eventsOf(t, artifact, stringObj("prefetch"))
	if len(events) != 1 {
		t.Fatalf("expected 1 event per recorded run time, got %d", len(events))
	}
	event := events[0]

	// prefetch_parse renders run times as ISO strings. Reading them as unix
	// integers yields no events at all and no error -- which is the failure this
	// assertion exists to catch.
	if hInt(t, event, "ts") != 1600000000 {
		t.Errorf("ts = %d, want the run time parsed from its ISO form", hInt(t, event, "ts"))
	}
	if hStr(t, event, "ts_desc") != "Last Time Executed" {
		t.Errorf("ts_desc = %q", hStr(t, event, "ts_desc"))
	}
	if hStr(t, event, "process") != "CALC.EXE" {
		t.Errorf("process = %q", hStr(t, event, "process"))
	}
	if got := hStr(t, event, "message"); got != "CALC.EXE was executed (run count 7)" {
		t.Errorf("message = %q", got)
	}
}

func TestEventsFromReadsAShellLink(t *testing.T) {
	const wantUnix = int64(1700000000)
	filetime := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)

	header := make([]byte, 76)
	binary.LittleEndian.PutUint32(header[0:4], 0x0000004C)
	binary.LittleEndian.PutUint32(header[20:24], 0x08|0x10|0x20|0x80)
	binary.LittleEndian.PutUint32(header[24:28], 0x20)
	binary.LittleEndian.PutUint64(header[28:36], filetime) // CreationTime
	binary.LittleEndian.PutUint64(header[36:44], 0)        // AccessTime, unset
	binary.LittleEndian.PutUint64(header[44:52], filetime) // WriteTime
	binary.LittleEndian.PutUint32(header[52:56], 4096)
	binary.LittleEndian.PutUint32(header[60:64], 1)

	blob := header
	blob = append(blob, unicodeStringData(`..\payload.exe`)...)
	blob = append(blob, unicodeStringData(`C:\Users\victim`)...)
	blob = append(blob, unicodeStringData(`-q -x`)...)

	path := filepath.Join(t.TempDir(), "shortcut.lnk")
	if err := os.WriteFile(path, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	artifact, errObj := unwrapPair(t, LnkParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("lnk_parse: %s", errObj.Inspect())
	}

	// A .lnk is one record with three header FILETIMEs, one of them unset.
	events := eventsOf(t, artifact, stringObj("lnk"))
	if len(events) != 2 {
		t.Fatalf("expected 2 events for the 2 set FILETIMEs, got %d", len(events))
	}
	created := eventByDesc(t, events, "Creation Time")
	if hInt(t, created, "ts") != wantUnix {
		t.Errorf("ts = %d", hInt(t, created, "ts"))
	}
	if hStr(t, created, "cmdline") != "-q -x" {
		t.Errorf("cmdline = %q", hStr(t, created, "cmdline"))
	}
	if got := hStr(t, created, "message"); got != `shell link to ..\payload.exe -q -x` {
		t.Errorf("message = %q, want the fallback to relative_path", got)
	}
	eventByDesc(t, events, "Content Modification Time")
}

// --- Windows event log levels ---

func TestEventsFromTranslatesAWindowsEventLevel(t *testing.T) {
	// Hand-built: an .evtx needs a chunked BinXML file, and what is checked here
	// is the level-to-word mapping.
	record := makeHashObject(map[string]object.Object{
		"timestamp": intObj(1700000000), "event_id": intObj(4625), "level": intObj(2),
		"provider": stringObj("Microsoft-Windows-Security-Auditing"),
		"computer": stringObj("WS01"), "channel": stringObj("Security"),
	})
	artifact := makeHashObject(map[string]object.Object{
		"records": &object.Array{Elements: []object.Object{record}},
	})

	events := eventsOf(t, artifact, stringObj("evtx"))
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]

	if hStr(t, event, "severity") != "high" {
		t.Errorf("severity = %q, want the word for Level 2 (Error)", hStr(t, event, "severity"))
	}
	if hInt(t, event, "code") != 4625 {
		t.Errorf("code = %d", hInt(t, event, "code"))
	}
	if hStr(t, event, "dataset") != "Security" {
		t.Errorf("dataset = %q, want the channel", hStr(t, event, "dataset"))
	}
	if hStr(t, event, "host") != "WS01" {
		t.Errorf("host = %q", hStr(t, event, "host"))
	}

	// Level 0 is LogAlways, which asserts nothing about severity. Guessing
	// "informational" there would invent a fact.
	quiet := makeHashObject(map[string]object.Object{
		"timestamp": intObj(1700000000), "event_id": intObj(0), "level": intObj(0),
	})
	plain := eventsOf(t, makeHashObject(map[string]object.Object{
		"records": &object.Array{Elements: []object.Object{quiet}},
	}), stringObj("evtx"))
	if hHas(plain[0], "severity") {
		t.Error("Level 0 says nothing about severity, so the envelope should say nothing")
	}
	if hHas(plain[0], "code") {
		t.Error("event id 0 is not an event id")
	}
}

// --- the escape hatch ---

func TestEventsFromAcceptsAMappingForAnArtifactItDoesNotKnow(t *testing.T) {
	rows := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{
			"when": stringObj("2023-11-14T22:13:20Z"),
			"who":  stringObj("analyst"),
			"what": stringObj("sealed the evidence"),
		}),
	}}

	mapping := makeHashObject(map[string]object.Object{
		"kind":     stringObj("caselog"),
		"category": stringObj("configuration"),
		"action":   stringObj("seal"),
		"message":  stringObj("{who}: {what}"),
		"times": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{
				"field": stringObj("when"), "desc": stringObj("Recorded Time"), "format": stringObj("iso"),
			}),
		}},
		"fields": makeHashObject(map[string]object.Object{"user": stringObj("who")}),
	})

	events := eventsOf(t, rows, mapping)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]

	if hStr(t, event, "kind") != "caselog" || hStr(t, event, "action") != "seal" {
		t.Errorf("kind/action = %q/%q", hStr(t, event, "kind"), hStr(t, event, "action"))
	}
	if hInt(t, event, "ts") != 1700000000 {
		t.Errorf("ts = %d", hInt(t, event, "ts"))
	}
	if hStr(t, event, "user") != "analyst" {
		t.Errorf("user = %q", hStr(t, event, "user"))
	}
	if got := hStr(t, event, "message"); got != "analyst: sealed the evidence" {
		t.Errorf("message = %q", got)
	}
}

func TestEventsFromRefusesWhatItCannotMap(t *testing.T) {
	entries := &object.Array{Elements: []object.Object{}}

	for _, tc := range []struct {
		name     string
		artifact object.Object
		kind     object.Object
		want     string
	}{
		{
			name: "an unknown kind names the way to find the known ones",
			// A silent empty array would look like an artifact with no timestamps.
			artifact: entries, kind: stringObj("mft_v2"),
			want: "event_kinds()",
		},
		{
			name:     "a kind that is not a name or a mapping",
			artifact: entries, kind: intObj(3),
			want: "argument 2",
		},
		{
			name:     "an artifact that is neither a result nor entries",
			artifact: stringObj("C:/evidence/$MFT"), kind: stringObj("mft"),
			want: "argument 1",
		},
		{
			name:     "a result hash with no entries in it",
			artifact: makeHashObject(map[string]object.Object{"count": intObj(0)}),
			kind:     stringObj("mft"),
			want:     `carry "entries"`,
		},
		{
			name:     "an entry that is not a record",
			artifact: &object.Array{Elements: []object.Object{stringObj("row")}},
			kind:     stringObj("mft"),
			want:     "must be a HASH",
		},
		{
			name:     "a mapping with no timestamp to read",
			artifact: entries,
			kind:     makeHashObject(map[string]object.Object{"kind": stringObj("x")}),
			want:     "`times`",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(EventsFrom(tc.artifact, tc.kind))
			if errObj == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(errObj.Message, tc.want) {
				t.Errorf("error = %q, want it to mention %q", errObj.Message, tc.want)
			}
		})
	}

	if _, ok := EventsFrom(entries).(*object.MultiValue); !ok {
		t.Error("a wrong argument count should come back in the builtin's own (value, err) shape")
	}
	if _, ok := EventKinds(stringObj("x")).(*object.Error); !ok {
		t.Error("event_kinds takes no arguments")
	}
}

// --- introspection ---

func TestEventKindsDescribesEverySourceItCanConvert(t *testing.T) {
	listed, ok := EventKinds().(*object.Array)
	if !ok {
		t.Fatalf("event_kinds returned %s", EventKinds().Type())
	}
	if len(listed.Elements) != len(eventSources) {
		t.Fatalf("event_kinds listed %d kinds, the table has %d", len(listed.Elements), len(eventSources))
	}

	previous := ""
	for i, element := range listed.Elements {
		descriptor := element.(*object.Hash)
		kind := hStr(t, descriptor, "kind")

		source, known := eventSources[kind]
		if !known {
			t.Fatalf("event_kinds named %q, which is not in the table", kind)
		}
		if kind <= previous && i > 0 {
			t.Errorf("kinds should be ordered; %q followed %q", kind, previous)
		}
		previous = kind

		if hStr(t, descriptor, "category") != source.category {
			t.Errorf("%s: category = %q", kind, hStr(t, descriptor, "category"))
		}
		times := hashValueByKey(descriptor, "times").(*object.Array)
		if len(times.Elements) != len(source.times) {
			t.Errorf("%s: listed %d timestamps, maps %d", kind, len(times.Elements), len(source.times))
		}
		for _, listedTime := range times.Elements {
			spec := listedTime.(*object.Hash)
			if hStr(t, spec, "field") == "" || hStr(t, spec, "desc") == "" {
				t.Errorf("%s: a timestamp is listed without a field or a meaning", kind)
			}
			// Naming the format is what tells a caller whose mapping produced no
			// events whether the field was missing or read as the wrong type.
			if hStr(t, spec, "format") == "" {
				t.Errorf("%s: a timestamp is listed without the format it is read as", kind)
			}
		}
	}
}

// Every source spec claims a category and an action, and those two strings are
// what the ECS, OCSF and Timesketch emitters will switch on. A typo here becomes
// an artifact that silently lands in the wrong schema class, so the vocabulary
// is closed rather than free-form.
func TestEverySourceUsesTheClosedVocabulary(t *testing.T) {
	categories := map[string]bool{
		"file": true, "process": true, "execution": true, "registry": true,
		"network": true, "dns": true, "web": true, "email": true,
		"authentication": true, "configuration": true, "log": true,
		"module": true, "scheduled_job": true,
	}

	for name, source := range eventSources {
		if name != source.kind {
			t.Errorf("source %q is keyed as %q; the table key and the emitted kind must agree", source.kind, name)
		}
		if !categories[source.category] {
			t.Errorf("%s: category %q is outside the vocabulary the emitters switch on", name, source.category)
		}
		if len(source.times) == 0 {
			t.Errorf("%s: a source with no timestamp can produce no events", name)
		}
		seen := map[string]bool{}
		for _, spec := range source.times {
			if seen[spec.field] {
				t.Errorf("%s: timestamp %q is read twice, which would double every event", name, spec.field)
			}
			seen[spec.field] = true
			if spec.desc == "" {
				t.Errorf("%s: timestamp %q has no meaning attached", name, spec.field)
			}
		}
	}
}
