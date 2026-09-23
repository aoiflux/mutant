package builtin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// classifiedRead returns plaintext read out of the disclosure fixture's record:
// bytes 90..130, which cross from `open` into `pii`.
func classifiedRead(t *testing.T) (*discloseFixture, *object.Bytes) {
	t.Helper()
	f := newDiscloseFixture(t)
	value := mustValue(t, RecordRead(f.record, intObj(90), intObj(40)))
	buffer, ok := value.(*object.Bytes)
	if !ok {
		t.Fatalf("record_read returned %T", value)
	}
	return f, buffer
}

// assertNoPlaintext fails if a message carries any of the plaintext, as text
// or as the hex Inspect would have rendered it.
func assertNoPlaintext(t *testing.T, where, message string, plaintext []byte) {
	t.Helper()
	for _, leak := range []string{string(plaintext[:12]), hex.EncodeToString(plaintext[:8])} {
		if strings.Contains(message, leak) {
			t.Fatalf("%s: the refusal contains the plaintext it refused to send (%q): %s", where, leak, message)
		}
	}
}

func TestReadPlaintextIsMarkedWithWhereItCameFrom(t *testing.T) {
	f, buffer := classifiedRead(t)
	c := buffer.Classified
	if c == nil {
		t.Fatal("plaintext read out of a classified record carries no mark")
	}
	if c.RecordUID == "" || strings.Join(c.Labels, ",") != "open,pii" || len(c.Tags) != 2 {
		t.Fatalf("the mark does not name the record and both classes the read crossed: %+v", c)
	}
	if !bytes.Equal(buffer.Value, f.plaintext[90:130]) {
		t.Fatal("the marked buffer is not the plaintext")
	}

	// A partial read under a grant is marked with what it actually opened --
	// the zero-filled holes are not plaintext of anything.
	partial := mustHash(t, RecordReadPartial(f.record, intObj(150), intObj(20)))
	marked := mustHashValue(t, partial, "bytes").(*object.Bytes)
	if marked.Classified == nil || len(marked.Classified.Tags) != 2 {
		t.Fatalf("a partial read that crossed pii into restricted is marked %+v", marked.Classified)
	}
}

// Every sink refuses a marked buffer, directly and inside a container, and no
// refusal carries a byte of it.
func TestEverySinkRefusesClassifiedPlaintext(t *testing.T) {
	f, buffer := classifiedRead(t)
	dir := t.TempDir()
	nested := &object.Array{Elements: []object.Object{stringObj("header"),
		makeHashObject(map[string]object.Object{"payload": buffer})}}
	report := makeHashObject(map[string]object.Object{
		"title":    stringObj("exhibit"),
		"sections": &object.Array{Elements: []object.Object{makeHashObject(map[string]object.Object{"body": buffer})}},
	})

	db := mustValue(t, DbOpen())
	defer DbClose(db)

	var printed bytes.Buffer
	restore := SetOutput(&printed)
	defer restore()

	sinks := map[string]func() object.Object{
		"putln":        func() object.Object { return Putln(stringObj("value:"), buffer) },
		"putln nested": func() object.Object { return Putln(nested) },
		"putf":         func() object.Object { return Putf(stringObj("%s\n"), buffer) },
		"fs_write":     func() object.Object { return FsWrite(stringObj(filepath.Join(dir, "a.bin")), buffer) },
		"fs_append":    func() object.Object { return FsAppend(stringObj(filepath.Join(dir, "b.bin")), buffer) },
		"http_post":    func() object.Object { return HttpPost(stringObj("http://127.0.0.1:1/"), buffer) },
		"http_request": func() object.Object {
			return HttpRequest(stringObj("POST"), stringObj("http://127.0.0.1:1/"), nested, makeHashObject(nil))
		},
		"report_write":  func() object.Object { return ReportWrite(report, stringObj(filepath.Join(dir, "r.md"))) },
		"report_render": func() object.Object { return ReportRender(report, stringObj("markdown")) },
		"case_note":     func() object.Object { return CaseNote(stringObj("read the pii"), nested) },
		"cache_put":     func() object.Object { return CachePut(stringObj("c"), stringObj("k"), nested) },
		"ledger_add_node": func() object.Object {
			return LedgerAddNode(intObj(f.ledger), makeHashObject(map[string]object.Object{"content": buffer}))
		},
		"ledger_add_edge": func() object.Object {
			return LedgerAddEdge(intObj(f.ledger), intObj(1), intObj(1), makeHashObject(map[string]object.Object{"content": buffer}))
		},
		"db_add_artifact": func() object.Object {
			return DbAddArtifact(db, stringObj("exhibit"), makeHashObject(map[string]object.Object{"body": buffer}))
		},
	}
	// Which argument each call above puts the plaintext in, counted from 1 as
	// the refusal counts it.
	positions := map[string]int{
		"putln": 2, "putln nested": 1, "putf": 2, "fs_write": 2, "fs_append": 2,
		"http_post": 2, "http_request": 3, "report_write": 1, "report_render": 1,
		"case_note": 2, "cache_put": 3, "ledger_add_node": 2, "ledger_add_edge": 4,
		"db_add_artifact": 3,
	}
	if len(positions) != len(sinks) {
		t.Fatalf("%d sinks and %d positions", len(sinks), len(positions))
	}
	for name, call := range sinks {
		result := call()
		var message string
		switch v := result.(type) {
		case *object.Error:
			message = v.Message
		default:
			_, errObj := unwrapPairNoFatal(result)
			if errObj == nil {
				t.Errorf("%s accepted classified plaintext", name)
				continue
			}
			message = errObj.Message
		}
		if !strings.Contains(message, buffer.Classified.RecordUID) || !strings.Contains(message, "record_release") {
			t.Errorf("%s refused without naming the record and the way out: %s", name, message)
		}
		if want := fmt.Sprintf("argument %d holds", positions[name]); !strings.Contains(message, want) {
			t.Errorf("%s refused naming the wrong argument, want %q: %s", name, want, message)
		}
		assertNoPlaintext(t, name, message, buffer.Value)
	}
	if printed.Len() != 0 {
		t.Fatalf("a refused print still printed %d bytes", printed.Len())
	}
	for _, file := range []string{"a.bin", "b.bin", "r.md"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err == nil {
			t.Errorf("a refused write left %s behind", file)
		}
	}
}

// A slice of classified plaintext is classified plaintext; a slice of an
// ordinary buffer is not.
func TestBytesSliceCarriesTheMark(t *testing.T) {
	_, buffer := classifiedRead(t)
	sliced := mustValue(t, BytesSlice(buffer, intObj(2), intObj(5))).(*object.Bytes)
	if sliced.Classified != buffer.Classified {
		t.Fatal("bytes_slice dropped the mark")
	}
	plain := mustValue(t, BytesSlice(&object.Bytes{Value: []byte("ordinary")}, intObj(0), intObj(3))).(*object.Bytes)
	if plain.Classified != nil {
		t.Fatal("bytes_slice marked a buffer nothing classified")
	}
}

// The mark changes nothing about what a buffer IS: Inspect is the identity
// function for equality, dedup, containment and hash ordering, and two buffers
// with the same bytes must stay one value to all of them.
func TestTheMarkDoesNotChangeIdentity(t *testing.T) {
	_, buffer := classifiedRead(t)
	twin := &object.Bytes{Value: append([]byte(nil), buffer.Value...)}
	if buffer.Inspect() != twin.Inspect() || buffer.HashKey() != twin.HashKey() {
		t.Fatal("a classified buffer inspects or hashes differently from an ordinary one with the same bytes")
	}
	unique := Unique(&object.Array{Elements: []object.Object{buffer, twin}})
	if n := len(unique.(*object.Array).Elements); n != 1 {
		t.Fatalf("unique kept %d of two identical buffers because one was classified", n)
	}
	if found := Contains(&object.Array{Elements: []object.Object{twin}}, buffer); found.(*object.Boolean) == nil || !found.(*object.Boolean).Value {
		t.Fatal("contains could not find a classified buffer's twin")
	}
}

// A release is the deliberate path: an unmarked copy, and a line in the case
// timeline that says who let what go and why.
func TestARecordReleaseIsRecordedAndUnmarked(t *testing.T) {
	_, buffer := classifiedRead(t)
	released := mustValue(t, RecordRelease(buffer, stringObj("exhibit 4 for the hearing"))).(*object.Bytes)
	if released.Classified != nil || !bytes.Equal(released.Value, buffer.Value) {
		t.Fatal("the release is not an unmarked copy of the same bytes")
	}
	if &released.Value[0] == &buffer.Value[0] {
		t.Fatal("the release shares storage with the classified buffer, so zeroing one would reach the other")
	}
	path := filepath.Join(t.TempDir(), "exhibit.bin")
	mustValue(t, FsWrite(stringObj(path), released))

	custodyStore.RLock()
	var event custodyEvent
	for _, e := range custodyStore.session.timeline {
		if e.Event == BuiltinNameRecordRelease {
			event = e
		}
	}
	custodyStore.RUnlock()
	data, _ := event.Data.(map[string]any)
	if data["reason"] != "exhibit 4 for the hearing" || data["bytes"] != int64(40) {
		t.Fatalf("the release is not in the timeline as it happened: %+v", event)
	}
	assertNoPlaintext(t, "the timeline", event.Detail, buffer.Value)

	// A class the case cannot name is recorded by its tag, not as a blank.
	tag := strings.Repeat("ab", 16)
	stranger := &object.Bytes{Value: []byte("xyz"), Classified: &object.Classification{
		RecordUID: "r", Tags: []string{tag, "cd"}, Labels: []string{"", "pii"}}}
	mustValue(t, RecordRelease(stranger, stringObj("a class from another case")))
	custodyStore.RLock()
	last := custodyStore.session.timeline[len(custodyStore.session.timeline)-1]
	custodyStore.RUnlock()
	if classes := last.Data.(map[string]any)["classes"]; classes != "unnamed:"+tag+", pii" {
		t.Fatalf("a release of an unnamed class recorded its classes as %q", classes)
	}

	for name, call := range map[string]object.Object{
		"an ordinary buffer": RecordRelease(&object.Bytes{Value: []byte("x")}, stringObj("why")),
		"no reason":          RecordRelease(buffer, stringObj("  ")),
	} {
		if _, errObj := unwrapPairNoFatal(call); errObj == nil {
			t.Errorf("a release of %s was accepted", name)
		}
	}
	mustHash(t, CaseClose())
	if _, errObj := unwrapPairNoFatal(RecordRelease(buffer, stringObj("why"))); errObj == nil ||
		!strings.Contains(errObj.Message, "no case is open") {
		t.Fatalf("a release with nowhere to record it was accepted: %v", errObj)
	}
}

// The check looks inside every kind of container, walks a container that
// holds itself once, and refuses a value too deep to look at rather than
// passing it.
func TestTheCheckFindsPlaintextInEveryContainer(t *testing.T) {
	_, buffer := classifiedRead(t)
	cyclic := &object.Array{}
	cyclic.Elements = []object.Object{cyclic, intObj(1)}
	containers := map[string]object.Object{
		"struct":      &object.Struct{TypeName: "Exhibit", Fields: map[string]object.Object{"body": buffer}},
		"enum":        &object.EnumValue{TypeName: "Maybe", Tag: "Some", Value: buffer},
		"multi value": &object.MultiValue{Values: []object.Object{intObj(1), buffer}},
		"cell":        &object.Cell{Value: buffer},
	}
	for name, value := range containers {
		if refuseClassified("probe", value) == nil {
			t.Errorf("classified plaintext inside a %s was not found", name)
		}
	}
	if refuseClassified("probe", cyclic) != nil {
		t.Fatal("an array holding itself was refused, or never finished")
	}
	deep := object.Object(intObj(0))
	for i := 0; i < classifiedWalkDepth+2; i++ {
		deep = &object.Array{Elements: []object.Object{deep}}
	}
	if errObj := refuseClassified("probe", deep); errObj == nil || !strings.Contains(errObj.Message, "too deep") {
		t.Fatalf("a value too deep to check was passed as clean: %v", errObj)
	}
}
