package builtin

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Velocidex/ordereddict"
	evtx "www.velocidex.com/golang/evtx"

	"mutant/object"
)

// These tests exercise the mutant-side conversion and summary extraction
// (evtxRecordToHash, evtxValueToObject, evtxDescend, evtxAs*) directly against a
// synthesized ordereddict event tree — the same shape the Velocidex library
// produces after BinXML template expansion. This keeps them hermetic and
// cross-platform; a real .evtx round-trip is covered by evtx_windows_test.go.

func evtxSampleEvent() *ordereddict.Dict {
	system := ordereddict.NewDict().
		Set("Provider", ordereddict.NewDict().
			Set("Name", "Microsoft-Windows-Security-Auditing").
			Set("Guid", "{54849625-5478-4994-a5ba-3e3b0328c30d}")).
		Set("EventID", int64(4624)).
		Set("Level", int64(0)).
		Set("Channel", "Security").
		Set("Computer", "DESKTOP-TEST").
		Set("EventRecordID", uint64(987654))
	data := ordereddict.NewDict().
		Set("TargetUserName", "alice").
		Set("LogonType", int64(2))
	return ordereddict.NewDict().
		Set("Event", ordereddict.NewDict().
			Set("System", system).
			Set("EventData", data))
}

func TestEvtxRecordToHash(t *testing.T) {
	const wantUnix = int64(1600000000)
	ft := uint64((wantUnix + filetimeEpochDeltaSec) * 10_000_000)

	rec := &evtx.EventRecord{
		Header: evtx.EventRecordHeader{RecordID: 42, FileTime: ft},
		Event:  evtxSampleEvent(),
	}
	h := evtxRecordToHash(rec).(*object.Hash)

	if got := hInt(t, h, "record_id"); got != 42 {
		t.Errorf("record_id = %d, want 42", got)
	}
	if got := hInt(t, h, "timestamp"); got != wantUnix {
		t.Errorf("timestamp = %d, want %d", got, wantUnix)
	}
	if got := hStr(t, h, "timestamp_iso"); got != unixToISO(wantUnix) {
		t.Errorf("timestamp_iso = %q, want %q", got, unixToISO(wantUnix))
	}
	if got := hInt(t, h, "event_id"); got != 4624 {
		t.Errorf("event_id = %d, want 4624", got)
	}
	if got := hInt(t, h, "event_record_id"); got != 987654 {
		t.Errorf("event_record_id = %d, want 987654", got)
	}
	if got := hStr(t, h, "channel"); got != "Security" {
		t.Errorf("channel = %q, want Security", got)
	}
	if got := hStr(t, h, "computer"); got != "DESKTOP-TEST" {
		t.Errorf("computer = %q, want DESKTOP-TEST", got)
	}
	if got := hStr(t, h, "provider"); got != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("provider = %q", got)
	}
	if got := hInt(t, h, "level"); got != 0 {
		t.Errorf("level = %d, want 0", got)
	}

	// Full event tree is preserved and navigable.
	event := hashValueByKey(h, "event")
	target := evtxDescend(event, "Event", "EventData", "TargetUserName")
	if s, ok := target.(*object.String); !ok || s.Value != "alice" {
		t.Errorf("event.Event.EventData.TargetUserName = %v, want alice", target)
	}
}

func TestEvtxEventIDAsDict(t *testing.T) {
	// Some providers render EventID with attributes as {Value, Qualifiers}.
	system := ordereddict.NewDict().
		Set("EventID", ordereddict.NewDict().Set("Value", int64(1102)).Set("Qualifiers", int64(0))).
		Set("Channel", "Security")
	event := ordereddict.NewDict().Set("Event", ordereddict.NewDict().Set("System", system))
	rec := &evtx.EventRecord{Header: evtx.EventRecordHeader{RecordID: 1}, Event: event}

	h := evtxRecordToHash(rec).(*object.Hash)
	if got := hInt(t, h, "event_id"); got != 1102 {
		t.Errorf("event_id (dict form) = %d, want 1102", got)
	}
}

func TestEvtxValueToObject(t *testing.T) {
	arr := []interface{}{int64(1), "two", true, nil}
	obj := evtxValueToObject(arr).(*object.Array)
	if len(obj.Elements) != 4 {
		t.Fatalf("array len = %d, want 4", len(obj.Elements))
	}
	if _, ok := obj.Elements[3].(*object.Null); !ok {
		t.Errorf("nil element should convert to Null, got %T", obj.Elements[3])
	}

	// Scalars.
	if v := evtxValueToObject(uint32(7)).(*object.Integer); v.Value != 7 {
		t.Errorf("uint32 -> %d", v.Value)
	}
	if v := evtxValueToObject(true).(*object.Boolean); !v.Value {
		t.Error("bool -> false")
	}
	when := time.Unix(1600000000, 0)
	if v := evtxValueToObject(when).(*object.String); v.Value != when.UTC().Format(time.RFC3339) {
		t.Errorf("time -> %q", v.Value)
	}
	if v := evtxValueToObject([]byte{0xde, 0xad}).(*object.String); v.Value != "dead" {
		t.Errorf("[]byte -> %q, want dead", v.Value)
	}
}

// TestEvtxParseFileFromEnv runs the full builtin against a real .evtx supplied
// via MUTANT_EVTX_TEST_FILE. Opt-in so it stays hermetic in CI.
func TestEvtxParseFileFromEnv(t *testing.T) {
	path := os.Getenv("MUTANT_EVTX_TEST_FILE")
	if path == "" {
		t.Skip("set MUTANT_EVTX_TEST_FILE to run against a real .evtx")
	}
	payload, errObj := unwrapPair(t, EvtxParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("evtx_parse: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	recs := hashValueByKey(h, "records").(*object.Array)
	t.Logf("chunks=%d records=%d", hInt(t, h, "chunk_count"), len(recs.Elements))
	if len(recs.Elements) == 0 {
		t.Fatal("no records parsed")
	}
	withEventID := 0
	for _, e := range recs.Elements {
		r := e.(*object.Hash)
		if _, ok := hashValueByKey(r, "event").(*object.Hash); !ok {
			t.Fatal("event is not a hash")
		}
		if hInt(t, r, "event_id") > 0 {
			withEventID++
		}
	}
	t.Logf("records with a positive event_id: %d/%d", withEventID, len(recs.Elements))
	if withEventID == 0 {
		t.Error("no records had an extractable event_id")
	}
}

func TestEvtxParseRejectsNonEvtx(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "notevtx.bin")
	if err := os.WriteFile(bad, []byte("this is not an event log"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, errObj := unwrapPair(t, EvtxParse(stringObj(bad))); errObj == nil {
		t.Error("expected error for a non-EVTX file")
	}
}
