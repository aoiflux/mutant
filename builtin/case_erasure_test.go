package builtin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// erasureRun is a case attached to its ledger and active, owned by alice, with
// one record sealed and signed under the case key and a copy of it byte for
// byte.
type erasureRun struct {
	*lifecycleRun
	record, copy string
	uid, sha     string
}

func openErasureRun(t *testing.T) *erasureRun {
	t.Helper()
	useTestKeyStore(t)
	run := custodyRun(t)
	mustHash(t, ClassDefine(stringObj("open")))
	mustHash(t, ClassDefine(stringObj("pii")))
	source, dest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(
		mustHash(t, RecordClassifyRange(intObj(10), intObj(20), stringObj("pii")))),
		recordSealOpts(map[string]object.Object{"sign": boolObj(true)})))
	copied := filepath.Join(t.TempDir(), "copy.mrec")
	copyTestFile(t, dest, copied)
	verified := mustHash(t, RecordVerify(stringObj(dest)))
	if !mustHashBoolValue(t, verified, "signature_valid") {
		t.Fatalf("the sealed record does not verify: %s", verified.Inspect())
	}
	return &erasureRun{lifecycleRun: run, record: dest, copy: copied,
		uid: mustHashStringValue(t, verified, "record_uid"), sha: fileSHA(t, dest)}
}

func (r *erasureRun) handle() object.Object { return intObj(r.ledger) }

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func copyTestFile(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func previewOption() object.Object {
	return makeHashObject(map[string]object.Object{"preview": boolObj(true)})
}

func generationOption(n int64) object.Object {
	return makeHashObject(map[string]object.Object{"generation": intObj(n)})
}

func rotateCaseKeyOption() object.Object {
	return makeHashObject(map[string]object.Object{"mode": stringObj("case_key")})
}

// erasureRows reads erasure_list and its rows.
func erasureRows(t *testing.T, ledger object.Object, options ...object.Object) (*object.Hash, []*object.Hash) {
	t.Helper()
	list := mustHash(t, ErasureList(append([]object.Object{ledger}, options...)...))
	var rows []*object.Hash
	for _, row := range mustHashArrayValue(t, list, "erasures") {
		rows = append(rows, row.(*object.Hash))
	}
	return list, rows
}

func hashStrings(t *testing.T, hash *object.Hash, key string) []string {
	t.Helper()
	var out []string
	for _, element := range mustHashArrayValue(t, hash, key) {
		out = append(out, element.(*object.String).Value)
	}
	return out
}

func hashInts(t *testing.T, hash *object.Hash, key string) []int64 {
	t.Helper()
	var out []int64
	for _, element := range mustHashArrayValue(t, hash, key) {
		out = append(out, element.(*object.Integer).Value)
	}
	return out
}

// rewriteRecordHeader writes a copy of a record whose header is render's
// version of it, with the prefix's length made to agree.
func rewriteRecordHeader(t *testing.T, path string, render func([]byte) []byte) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	length := int(binary.BigEndian.Uint32(raw[len(security.RecordFileMagic):security.RecordFilePrefixSize]))
	header := render(raw[security.RecordFilePrefixSize : security.RecordFilePrefixSize+length])
	out := append(security.RecordFilePrefix(len(header)), header...)
	out = append(out, raw[security.RecordFilePrefixSize+length:]...)
	dest := filepath.Join(t.TempDir(), "rewritten.mrec")
	if err := os.WriteFile(dest, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dest
}

// A record's key is erased in one copy: the preview writes nothing, the
// erasure overwrites the key and says what it did not reach, the erased copy
// verifies as erased and opens no more, the other copy still opens, and the
// ledger records the erasure against the record as it was.
func TestARecordErasureDestroysTheKeyInOneCopyOnly(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()

	preview := mustHash(t, RecordErase(ledger, stringObj(r.record), stringObj("a deletion order"), previewOption()))
	if !mustHashBoolValue(t, preview, "preview") || mustHashBoolValue(t, preview, "erased") ||
		mustHashStringValue(t, preview, "uid") != "" || mustHashIntValue(t, preview, "seq") != 0 ||
		mustHashStringValue(t, preview, "file_sha256_before") != r.sha || fileSHA(t, r.record) != r.sha {
		t.Fatalf("a preview gave %s", preview.Inspect())
	}
	if list, _ := erasureRows(t, ledger); mustHashIntValue(t, list, "count") != 0 {
		t.Fatalf("a preview recorded %s", list.Inspect())
	}

	erased := mustHash(t, RecordErase(ledger, stringObj(r.record), stringObj("a deletion order")))
	after := fileSHA(t, r.record)
	if !mustHashBoolValue(t, erased, "erased") || mustHashBoolValue(t, erased, "preview") ||
		mustHashStringValue(t, erased, "kind") != "record" || mustHashStringValue(t, erased, "record_uid") != r.uid ||
		mustHashIntValue(t, erased, "seq") != 1 || mustHashIntValue(t, erased, "generation") != 1 ||
		mustHashStringValue(t, erased, "file_sha256_before") != r.sha ||
		mustHashStringValue(t, erased, "file_sha256_after") != after || after == r.sha ||
		mustHashStringValue(t, preview, "file_sha256_after") != after ||
		mustHashStringValue(t, erased, "header_sha256_before") == mustHashStringValue(t, erased, "header_sha256_after") ||
		mustHashStringValue(t, erased, "by") != "alice" || mustHashStringValue(t, erased, "by_role") != "case_owner" ||
		mustHashStringValue(t, erased, "reason") != "a deletion order" {
		t.Fatalf("record_erase gave %s", erased.Inspect())
	}
	if info, err := os.Stat(r.record); err != nil || info.Size() != mustHashIntValue(t, erased, "bytes") {
		t.Fatalf("the erased copy is %v bytes, and was %d: %v", info, mustHashIntValue(t, erased, "bytes"), err)
	}
	missed := strings.Join(hashStrings(t, erased, "does_not_erase"), "\n")
	for _, want := range []string{"any other copy of this record", "a disclosure package", "a grant already issued",
		"the storage under this file", "the evidence the record was sealed from", "what the ledger records"} {
		if !strings.Contains(missed, want) {
			t.Errorf("does_not_erase does not name %q: %s", want, missed)
		}
	}

	verified := mustHash(t, RecordVerify(stringObj(r.record)))
	if !mustHashBoolValue(t, verified, "erased") || !mustHashBoolValue(t, verified, "signed") ||
		mustHashBoolValue(t, verified, "signature_valid") ||
		!strings.Contains(mustHashStringValue(t, verified, "signature_note"), "the key in this copy was erased") {
		t.Fatalf("record_verify of the erased copy gave %s", verified.Inspect())
	}
	if intact := mustHash(t, RecordVerify(stringObj(r.copy))); mustHashBoolValue(t, intact, "erased") ||
		!mustHashBoolValue(t, intact, "signature_valid") {
		t.Fatalf("record_verify of the other copy gave %s", intact.Inspect())
	}
	mustRefuse(t, "opening the erased copy", RecordOpen(stringObj(r.record)),
		"was erased, so nothing opens this copy of record "+r.uid)
	opened := mustHash(t, RecordOpen(stringObj(r.copy)))
	RecordClose(mustHashValue(t, opened, "handle"))
	mustRefuse(t, "erasing it again", RecordErase(ledger, stringObj(r.record), stringObj("again")), "was erased already")

	// A copy erased and then changed anywhere else keeps the failure that says
	// so: the erased copy's own note is for a copy whose segments still fold.
	raw, err := os.ReadFile(r.record)
	if err != nil {
		t.Fatal(err)
	}
	length := int(binary.BigEndian.Uint32(raw[len(security.RecordFileMagic):security.RecordFilePrefixSize]))
	raw[security.RecordFilePrefixSize+length] ^= 0xFF
	changed := filepath.Join(t.TempDir(), "erased-and-changed.mrec")
	if err := os.WriteFile(changed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if both := mustHash(t, RecordVerify(stringObj(changed))); !mustHashBoolValue(t, both, "erased") ||
		!strings.Contains(mustHashStringValue(t, both, "signature_note"), "do not fold to the root") {
		t.Fatalf("record_verify of an erased copy that changed gave %s", both.Inspect())
	}

	session := r.session(t)
	event := schemaNode(t, session, disclosureNodeErasure, "erasure.uid", mustHashStringValue(t, erased, "uid"))
	assertCaseRecordEdges(t, session, event.id, openCaseUID(t), "alice")
	record := edgeTo(t, session, event.id, disclosureEdgeErases)
	if record.get("record.uid") != r.uid || record.get("record.sha256") != r.sha {
		t.Fatalf("the erasure ERASES %v", record.props)
	}
	// The erasure put the record in the ledger as a disclosure would: the
	// file it was, and the classes it carries.
	classified, err := session.store.EdgesOf(record.id, store.DirectionOutbound,
		[]store.EdgeType{disclosureEdgeClassifiedAs})
	if err != nil || len(classified) != 2 {
		t.Fatalf("the erased record is CLASSIFIED_AS %d classes: %v", len(classified), err)
	}
	if data := timelineData(t, BuiltinNameRecordErase); mustHashStringValue(t, data, "uid") != mustHashStringValue(t, erased, "uid") ||
		mustHashStringValue(t, data, "file_sha256_after") != after {
		t.Fatalf("the timeline records the erasure as %s", data.Inspect())
	}

	// The other copy is erased on its own, as the next event of the chain, and
	// two copies of one record erased are the same bytes.
	second := mustHash(t, RecordErase(ledger, stringObj(r.copy), stringObj("the copy too")))
	if mustHashIntValue(t, second, "seq") != 2 || fileSHA(t, r.copy) != after {
		t.Fatalf("erasing the other copy gave %s", second.Inspect())
	}
	list, rows := erasureRows(t, ledger)
	if mustHashIntValue(t, list, "count") != 2 || mustHashIntValue(t, list, "records") != 2 ||
		mustHashIntValue(t, list, "case_keys") != 0 || mustHashStringValue(t, list, "source") != "ledger" {
		t.Fatalf("erasure_list gave %s", list.Inspect())
	}
	first := rows[0]
	if mustHashStringValue(t, first, "by") != "alice" || mustHashStringValue(t, first, "by_role") != "case_owner" ||
		mustHashStringValue(t, first, "header_sha256_before") != mustHashStringValue(t, erased, "header_sha256_before") ||
		mustHashStringValue(t, first, "header_sha256_after") != mustHashStringValue(t, erased, "header_sha256_after") ||
		mustHashIntValue(t, first, "bytes") != mustHashIntValue(t, erased, "bytes") ||
		mustHashStringValue(t, first, "uid") != mustHashStringValue(t, erased, "uid") {
		t.Fatalf("the first erasure reads back as %s", first.Inspect())
	}
	if mustHashStringValue(t, first, "record_uid") != r.uid || mustHashStringValue(t, first, "file_sha256_after") != after ||
		mustHashStringValue(t, first, "file_sha256_before") != r.sha || mustHashStringValue(t, first, "reason") != "a deletion order" ||
		mustHashStringValue(t, first, "case_uid") != strings.ToLower(openCaseUID(t)) ||
		mustHashStringValue(t, first, "kind") != "record" || mustHashIntValue(t, first, "generation") != 1 ||
		len(hashInts(t, first, "generations")) != 0 || mustHashStringValue(t, first, "scope") != "" {
		t.Fatalf("the first erasure reads back as %s", first.Inspect())
	}
	if _, one := erasureRows(t, ledger, makeHashObject(map[string]object.Object{
		"case_uid": stringObj(" " + strings.ToUpper(openCaseUID(t)) + " ")})); len(one) != 2 {
		t.Fatalf("erasure_list of the case read %d erasures", len(one))
	}
	if _, none := erasureRows(t, ledger, makeHashObject(map[string]object.Object{
		"case_uid": stringObj(strings.Repeat("cd", 16))})); len(none) != 0 {
		t.Fatalf("erasure_list of another case read %d erasures", len(none))
	}
}

// A grant already issued still opens the segments it names in an erased copy:
// the erasure destroyed the record key in the header, and a grant carries its
// segments' own keys. does_not_erase says so, and this is what it says.
func TestAGrantStillOpensAnErasedCopy(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	mustHash(t, RoleDefine(stringObj("legal"), viewArray("counsel")))
	mustHash(t, RoleAssign(ledger, stringObj("Counsel"), stringObj("legal"), stringObj("counsel for the defence")))
	opened := mustHash(t, RecordOpen(stringObj(r.record)))
	record := mustHashValue(t, opened, "handle")
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	issued := mustHash(t, DiscloseToPassphrase(ledger, record, stringObj("counsel"), stringObj("Counsel")))
	RecordClose(record)
	mustLedgerHash(t, "ledger_compact", LedgerCompact(ledger))
	dir := filepath.Join(t.TempDir(), "package")
	mustHash(t, DiscloseBundle(ledger, stringObj(mustHashStringValue(t, issued, "disclosure_uid")), stringObj(dir)))

	// A handle opened under the grant holds the grant's material and no key
	// schedule, so it stops neither erasure.
	purposeStub(t, map[string]string{BuiltinNameRecordOpen: testGrantPassphrase})
	grant := makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})
	before := mustHashValue(t, mustHash(t, RecordOpen(stringObj(r.record), grant)), "handle")
	defer RecordClose(before)
	mustHash(t, RecordErase(ledger, stringObj(r.record), stringObj("the examiner's copy")))
	after := mustHashValue(t, mustHash(t, RecordOpen(stringObj(r.record), grant)), "handle")
	defer RecordClose(after)
	mustHash(t, CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("the case is over")))
	for _, handle := range []object.Object{before, after} {
		read, errObj := unwrapPairNoFatal(RecordRead(handle, intObj(0), intObj(200)))
		if errObj != nil {
			t.Fatalf("reading the erased copy under the grant: %s", errObj.Message)
		}
		for i, b := range recordBytes(t, read) {
			if b != byte('a'+i%26) {
				t.Fatalf("byte %d of the erased copy read under the grant is %q", i, b)
			}
		}
	}
}

// Everything that can refuse an erasure refuses it before the file is
// touched.
func TestARecordErasureIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()
	untouched := func(what string) {
		t.Helper()
		if fileSHA(t, r.record) != r.sha {
			t.Fatalf("%s wrote to the record", what)
		}
	}

	mustRefuse(t, "an empty reason", RecordErase(ledger, stringObj(r.record), stringObj(" ")), "must not be empty")
	mustRefuse(t, "a passphrase given as an option", RecordErase(ledger, stringObj(r.record), stringObj("x"),
		makeHashObject(map[string]object.Object{"passphrase": stringObj("x")})), "a passphrase is not an argument")
	opened := mustHash(t, RecordOpen(stringObj(r.copy)))
	handle := mustHashValue(t, opened, "handle")
	mustRefuse(t, "a record another handle holds", RecordErase(ledger, stringObj(r.record), stringObj("x")),
		"is open as handle")
	RecordClose(handle)
	hold := mustHash(t, RetentionHold(ledger, stringObj("litigation")))
	mustRefuse(t, "an erasure under a hold", RecordErase(ledger, stringObj(r.record), stringObj("x")),
		"is under a legal hold")
	mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, hold, "uid")), stringObj("settled")))
	untouched("the refusals so far")

	reindented := rewriteRecordHeader(t, r.record, func(header []byte) []byte {
		var out bytes.Buffer
		if err := json.Indent(&out, header, "", "  "); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	})
	mustRefuse(t, "a header record_seal would not write", RecordErase(ledger, stringObj(reindented), stringObj("x")),
		"is not in the form record_seal writes it")
	caseUID := strings.ToLower(openCaseUID(t))
	another := rewriteRecordHeader(t, r.record, func(header []byte) []byte {
		return bytes.Replace(header, []byte(`"case_uid":"`+caseUID), []byte(`"case_uid":"`+strings.Repeat("cd", 16)), 1)
	})
	mustRefuse(t, "another case's record", RecordErase(ledger, stringObj(another), stringObj("x")),
		"is a record of case "+strings.Repeat("cd", 16)+", and the open case is")
	unopenable := rewriteRecordHeader(t, r.record, func(header []byte) []byte {
		at := bytes.Index(header, []byte(`"record_key_wrapped":"`)) + len(`"record_key_wrapped":"`)
		out := bytes.Clone(header)
		if out[at] == '0' {
			out[at] = '1'
		} else {
			out[at] = '0'
		}
		return out
	})
	mustRefuse(t, "a key the case key does not unwrap", RecordErase(ledger, stringObj(unopenable), stringObj("x")),
		"the open case key unwraps no key in")

	readOnly := filepath.Join(t.TempDir(), "read-only.mrec")
	copyTestFile(t, r.record, readOnly)
	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o600) })
	mustRefuse(t, "a file that cannot be written", RecordErase(ledger, stringObj(readOnly), stringObj("x")),
		"cannot be written, so the key in it cannot be erased")

	// The first copy erased puts the record in the ledger, and a copy whose
	// segments changed afterwards is not the file the ledger knows.
	changed := filepath.Join(t.TempDir(), "changed.mrec")
	raw, err := os.ReadFile(r.copy)
	if err != nil {
		t.Fatal(err)
	}
	length := int(binary.BigEndian.Uint32(raw[len(security.RecordFileMagic):security.RecordFilePrefixSize]))
	raw[security.RecordFilePrefixSize+length] ^= 0xFF
	if err := os.WriteFile(changed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A handle open on another record holds another record's key, and stops
	// nothing here.
	otherSource, otherDest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(otherSource), stringObj(otherDest), recordArray(), recordSealOpts(nil)))
	otherHandle := mustHashValue(t, mustHash(t, RecordOpen(stringObj(otherDest))), "handle")
	mustHash(t, RecordErase(ledger, stringObj(r.copy), stringObj("the first copy")))
	RecordClose(otherHandle)
	mustRefuse(t, "a copy the ledger knows by another digest", RecordErase(ledger, stringObj(changed), stringObj("x")),
		"the ledger records record "+r.uid+" as a file with digest "+r.sha)

	r.lifecycleRun = r.next(t, "bob", "investigator")
	r.attach(t)
	mustRefuse(t, "an investigator's erasure", RecordErase(r.handle(), stringObj(r.record), stringObj("x")),
		"bob is acting as investigator, and an erasure is recorded by a case_owner or an administrator. A role "+
			"is asserted, not authenticated")
	untouched("every refusal")
}

// An erasure needs the key generation that wraps the record open, and none is
// made once the ledger records every generation of the case key erased -- not
// even through a copy of the key file the erasure did not reach.
func TestARecordErasureNeedsTheKeyThatWrapsIt(t *testing.T) {
	r := openErasureRun(t)
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	backup := filepath.Join(t.TempDir(), "backup.mkey")
	copyTestFile(t, r.keyPath, backup)
	r.lifecycleRun = r.next(t, "alice", "case_owner")
	r.attach(t)
	ledger := r.handle()
	mustRefuse(t, "a record wrapped under another generation", RecordErase(ledger, stringObj(r.record), stringObj("x")),
		"record "+r.uid+" is wrapped under generation 1 of the case key, and the open key is generation 2; open the "+
			"key at generation 1 to erase it")

	mustHash(t, CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("the case is over")))
	mustRefuse(t, "an erasure once the key is erased", RecordErase(ledger, stringObj(r.record), stringObj("x")),
		"every generation of case IR-LIFE's key was erased with case_key_erase")
	mustHash(t, CaseKeyOpen(stringObj(backup), generationOption(1)))
	mustRefuse(t, "an erasure through a copy of the key file", RecordErase(ledger, stringObj(r.record), stringObj("x")),
		"the ledger records every generation of case IR-LIFE's key erased at")
	mustRefuse(t, "the copy of the key file erased", CaseKeyErase(ledger, stringObj(backup), stringObj("x")),
		"after which nothing in the case is erased again")
	if fileSHA(t, r.record) != r.sha {
		t.Fatal("a refused erasure wrote to the record")
	}
}

// Every generation of the case key is erased: the file overwritten and gone,
// the key the case held zeroed, no record opening, every record still
// verifying, and the ledger naming what was erased.
func TestACaseKeyErasureDestroysEveryGeneration(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	raw, err := os.ReadFile(r.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := security.ParseCaseKeyFile(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Another case's key file -- by its id, by its uid under the same id, and
	// by an id edited in the file -- is refused before any passphrase is asked
	// for, even for the erasure of one generation, which needs one.
	calls := stubPassphrase(t, testCasePassphrase)
	other := filepath.Join(t.TempDir(), "other.mkey")
	mustHash(t, CaseKeyCreate(stringObj(other), makeHashObject(map[string]object.Object{
		"case_id": stringObj("IR-OTHER")})))
	sameID := filepath.Join(t.TempDir(), "same-id.mkey")
	mustHash(t, CaseKeyCreate(stringObj(sameID)))
	edited := filepath.Join(t.TempDir(), "edited.mkey")
	if err := os.WriteFile(edited, bytes.Replace(raw, []byte(`"case_id": "IR-LIFE"`), []byte(`"case_id": "IR-EDIT"`), 1),
		0o600); err != nil {
		t.Fatal(err)
	}
	asked := *calls
	caseUID := strings.ToLower(openCaseUID(t))
	for _, c := range []struct{ path, want string }{
		{other, "is the key file of case IR-OTHER (uid "},
		{sameID, "is the key file of case IR-LIFE (uid "},
		{edited, "is the key file of case IR-EDIT (uid " + caseUID + "), and the open case is IR-LIFE"},
	} {
		mustRefuse(t, "another case's key file", CaseKeyErase(ledger, stringObj(c.path), stringObj("x"),
			generationOption(1)), c.want)
	}
	if *calls != asked {
		t.Fatalf("another case's key file was asked %d passphrases", *calls-asked)
	}
	opened := mustHash(t, RecordOpen(stringObj(r.copy)))
	mustRefuse(t, "a record open under the key", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x")),
		"is open as handle")
	RecordClose(mustHashValue(t, opened, "handle"))
	hold := mustHash(t, RetentionHold(ledger, stringObj("litigation")))
	mustRefuse(t, "an erasure under a hold", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x")),
		"is under a legal hold")
	mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, hold, "uid")), stringObj("settled")))
	r.lifecycleRun = r.next(t, "bob", "investigator")
	r.attach(t)
	mustRefuse(t, "an investigator's erasure", CaseKeyErase(r.handle(), stringObj(r.keyPath), stringObj("x")),
		"bob is acting as investigator, and an erasure is recorded by a case_owner or an administrator")
	r.lifecycleRun = r.next(t, "alice", "case_owner")
	r.attach(t)
	ledger = r.handle()

	erased := mustHash(t, CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("the case is over")))
	if mustHashStringValue(t, erased, "kind") != "case_key" || mustHashStringValue(t, erased, "scope") != "all" ||
		!mustHashBoolValue(t, erased, "file_removed") || mustHashIntValue(t, erased, "current") != 0 ||
		!mustHashBoolValue(t, erased, "session_key_zeroed") || mustHashIntValue(t, erased, "seq") != 1 ||
		mustHashStringValue(t, erased, "path") != r.keyPath {
		t.Fatalf("case_key_erase gave %s", erased.Inspect())
	}
	if got := hashInts(t, erased, "generations"); !slices.Equal(got, []int64{1, 2}) {
		t.Fatalf("case_key_erase erased generations %v", got)
	}
	want := []string{file.Generations[0].Fingerprint, file.Generations[1].Fingerprint}
	if got := hashStrings(t, erased, "fingerprints"); !slices.Equal(got, want) {
		t.Fatalf("case_key_erase names the fingerprints %v, and the key file held %v", got, want)
	}
	missed := strings.Join(hashStrings(t, erased, "does_not_erase"), "\n")
	for _, want := range []string{"a copy of the key file kept anywhere else", "a grant already issued",
		"the storage under the key file", "record_verify still checks each"} {
		if !strings.Contains(missed, want) {
			t.Errorf("does_not_erase does not name %q: %s", want, missed)
		}
	}
	if _, err := os.Stat(r.keyPath); !os.IsNotExist(err) {
		t.Fatalf("the key file is still there: %v", err)
	}
	mustRefuse(t, "opening a record", RecordOpen(stringObj(r.copy)),
		"every generation of case IR-LIFE's key was erased with case_key_erase")
	if verified := mustHash(t, RecordVerify(stringObj(r.copy))); !mustHashBoolValue(t, verified, "signature_valid") ||
		mustHashBoolValue(t, verified, "erased") {
		t.Fatalf("a record under the erased key verifies as %s", verified.Inspect())
	}
	classification := manifestSection(t, mustHash(t, CaseManifest()), "classification")
	if !mustHashBoolValue(t, classification, "key_erased") || !mustHashBoolValue(t, classification, "keyed") {
		t.Fatalf("the manifest says %s", classification.Inspect())
	}
	if data := timelineData(t, BuiltinNameCaseKeyErase); mustHashStringValue(t, data, "generations") != "1,2" {
		t.Fatalf("the timeline records the erasure as %s", data.Inspect())
	}

	list, rows := erasureRows(t, ledger)
	if mustHashIntValue(t, list, "case_keys") != 1 || mustHashIntValue(t, list, "records") != 0 {
		t.Fatalf("erasure_list counts %s", list.Inspect())
	}
	if len(rows) != 1 || mustHashStringValue(t, rows[0], "key_file_mac") != file.FileMAC ||
		mustHashStringValue(t, rows[0], "key_file_mac_after") != "" || !mustHashBoolValue(t, rows[0], "file_removed") ||
		!slices.Equal(hashInts(t, rows[0], "generations"), []int64{1, 2}) ||
		!slices.Equal(hashStrings(t, rows[0], "fingerprints"), want) || mustHashStringValue(t, rows[0], "record_uid") != "" {
		t.Fatalf("erasure_list reads the key's erasure as %v", rows)
	}
	session := r.session(t)
	event := schemaNode(t, session, disclosureNodeErasure, "erasure.uid", mustHashStringValue(t, erased, "uid"))
	assertCaseRecordEdges(t, session, event.id, openCaseUID(t), "alice")
	if erases := edgeTo(t, session, event.id, disclosureEdgeErases); erases.get("case.uid") != strings.ToLower(openCaseUID(t)) {
		t.Fatalf("the key's erasure ERASES %v", erases.props)
	}
	mustRefuse(t, "a key file no longer there", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x")),
		"does not exist")
}

// One generation is erased in a file that stays: never the current one, once,
// with the file's MAC and signature holding afterwards, the generations after
// it still opening, and a later passphrase rotation carrying it over.
func TestOneGenerationOfTheCaseKeyIsErasedAndTheRestStillOpen(t *testing.T) {
	r := openErasureRun(t)
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	r.lifecycleRun = r.next(t, "alice", "case_owner")
	r.attach(t)
	ledger := r.handle()
	mustHash(t, ClassDefine(stringObj("open")))
	source, dest, _ := recordFixture(t)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), recordArray(), recordSealOpts(nil)))

	mustRefuse(t, "the current generation", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"),
		generationOption(2)), "generation 2 is the one "+r.keyPath+" seals under now")
	mustRefuse(t, "a generation the file does not have", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"),
		generationOption(3)), "has no generation 3")
	pending := r.keyPath + caseKeyErasingSuffix
	if err := os.WriteFile(pending, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "a file an interrupted erasure left a copy beside", CaseKeyErase(ledger, stringObj(r.keyPath),
		stringObj("x"), generationOption(1)), "was interrupted and left "+pending)
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}

	// A passphrase that does not open the file is forgotten, so that trying
	// again asks again.
	typo := installForgetting(t, "a typo")
	mustRefuse(t, "a wrong passphrase", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"), generationOption(1)),
		"the case key did not open")
	if len(typo.forgotten) != 1 || typo.forgotten[0] != BuiltinNameCaseKeyErase+" "+r.keyPath {
		t.Fatalf("a wrong passphrase told the source to forget %v", typo.forgotten)
	}
	stubPassphrase(t, testCasePassphrase)

	// A record wrapped under generation 2 is open while generation 1 is
	// erased: its handle holds nothing the erasure destroys.
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	before := mustHash(t, CaseKeyFingerprint(stringObj(r.keyPath)))
	erased := mustHash(t, CaseKeyErase(ledger, stringObj(r.keyPath),
		stringObj("records sealed before the rotation are to go"), generationOption(1)))
	RecordClose(mustHashValue(t, opened, "handle"))
	if mustHashStringValue(t, erased, "scope") != "generation" ||
		!slices.Equal(hashInts(t, erased, "generations"), []int64{1}) ||
		mustHashBoolValue(t, erased, "file_removed") || mustHashIntValue(t, erased, "current") != 2 ||
		mustHashBoolValue(t, erased, "session_key_zeroed") {
		t.Fatalf("case_key_erase of generation 1 gave %s", erased.Inspect())
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatalf("the copy the rewrite keeps is still there: %v", err)
	}
	if raw, err := os.ReadFile(r.keyPath); err != nil || !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatalf("the rewritten key file ends %q: %v", raw[max(0, len(raw)-8):], err)
	}
	if classification := manifestSection(t, mustHash(t, CaseManifest()), "classification"); mustHashBoolValue(t,
		classification, "key_erased") {
		t.Fatal("the manifest says every generation was erased")
	}
	described := mustHash(t, CaseKeyFingerprint(stringObj(r.keyPath)))
	generations := mustHashArrayValue(t, described, "generations")
	if !mustHashBoolValue(t, generations[0].(*object.Hash), "erased") ||
		mustHashBoolValue(t, generations[1].(*object.Hash), "erased") ||
		!mustHashBoolValue(t, described, "signature_valid") ||
		mustHashStringValue(t, described, "previous_file_mac") == mustHashStringValue(t, before, "previous_file_mac") {
		t.Fatalf("the key file after the erasure says %s", described.Inspect())
	}
	if fp := hashStrings(t, erased, "fingerprints"); len(fp) != 1 ||
		fp[0] != mustHashStringValue(t, generations[0].(*object.Hash), "fingerprint") {
		t.Fatalf("the erasure names the fingerprints %v", fp)
	}
	reopened := mustHash(t, RecordOpen(stringObj(dest)))
	RecordClose(mustHashValue(t, reopened, "handle"))
	mustRefuse(t, "erasing it again", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"), generationOption(1)),
		"generation 1 of "+r.keyPath+" was erased already")
	_, rows := erasureRows(t, ledger)
	if len(rows) != 1 || mustHashStringValue(t, rows[0], "scope") != "generation" ||
		mustHashBoolValue(t, rows[0], "file_removed") || !slices.Equal(hashInts(t, rows[0], "generations"), []int64{1}) ||
		mustHashStringValue(t, rows[0], "key_file_mac_after") == "" ||
		mustHashStringValue(t, rows[0], "key_file_mac_after") == mustHashStringValue(t, rows[0], "key_file_mac") {
		t.Fatalf("erasure_list reads the erasure as %v", rows)
	}

	LedgerClose(intObj(r.ledger))
	resetCustodyForTesting()
	openTestCase(t, "IR-LIFE", "alice")
	// Asked in turn: the refused open, the rotation's current passphrase and
	// its replacement, and the open after it. The refused open reached an
	// erased generation after the file's MAC held, so its passphrase was right
	// and is not forgotten.
	forgetting := installForgetting(t, testCasePassphrase, testCasePassphrase, "a different passphrase")
	mustRefuse(t, "opening the erased generation", CaseKeyOpen(stringObj(r.keyPath), generationOption(1)),
		"generation 1: this generation of the case key was erased")
	if len(forgetting.forgotten) != 0 {
		t.Fatalf("opening an erased generation told the source to forget %v", forgetting.forgotten)
	}
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), makeHashObject(map[string]object.Object{
		"mode": stringObj("passphrase")})))
	mustHash(t, CaseKeyOpen(stringObj(r.keyPath)))
	after := mustHashArrayValue(t, mustHash(t, CaseKeyFingerprint(stringObj(r.keyPath))), "generations")
	if !mustHashBoolValue(t, after[0].(*object.Hash), "erased") {
		t.Fatal("a passphrase rotation brought the erased generation back")
	}
}

// A retained case is disposed of only when the ledger shows everything a
// disposal needs, and a refusal names all of what is missing; the disposal
// names the erasure of the key it rests on, and a disposed case is final.
func TestACaseIsDisposedOfOnlyWhenNothingIsLeftToKeep(t *testing.T) {
	run := custodyRun(t)
	ledger := intObj(run.ledger)
	run.intake(t, "EXH-1", exhibitFile(t, "the drive"))
	run.intake(t, "EXH-2", exhibitFile(t, "the phone"))
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateInReview, caseStateConcluded)
	mustRefuse(t, "disposing of a concluded case", CaseTransition(ledger, stringObj("disposed"), stringObj("x")),
		"case IR-LIFE is concluded and case_transition does not move it to disposed")
	mustHash(t, RetentionSet(ledger, stringObj("2999-01-01"), stringObj("kept for good")))
	hold := mustHash(t, RetentionHold(ledger, stringObj("litigation")))

	run = run.next(t, "bob", "investigator")
	run.attach(t)
	mustRefuse(t, "an investigator's disposal", CaseTransition(intObj(run.ledger), stringObj("disposed"),
		stringObj("x")), "bob is acting as investigator, and the disposal of a case is recorded by a case_owner or "+
		"an administrator")
	run = run.next(t, "alice", "case_owner")
	run.attach(t)
	ledger = intObj(run.ledger)

	_, errObj := unwrapPairNoFatal(CaseTransition(ledger, stringObj("disposed"), stringObj("x")))
	if errObj == nil {
		t.Fatal("a case with everything left to keep was disposed of")
	}
	for _, want := range []string{
		"case IR-LIFE cannot be disposed of yet: a legal hold is in force -- the first placed at " +
			mustHashStringValue(t, hold, "at") + " by alice: \"litigation\"",
		"it is kept until 2999-01-01T00:00:00Z, which has not come",
		"2 exhibits are neither returned nor disposed of -- the first, \"EXH-1\", is held by alice",
		"its case key is not erased",
	} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("the refusal does not say %q: %s", want, errObj.Message)
		}
	}

	mustHash(t, RetentionRelease(ledger, stringObj(mustHashStringValue(t, hold, "uid")), stringObj("settled")))
	mustHash(t, RetentionSet(ledger, stringObj("2001-01-01"), stringObj("the period ran")))
	mustHash(t, EvidenceReturn(ledger, stringObj("EXH-1"), stringObj("its owner"), stringObj("no longer needed")))
	mustRefuse(t, "one exhibit left", CaseTransition(ledger, stringObj("disposed"), stringObj("x")),
		"case IR-LIFE cannot be disposed of yet: exhibit \"EXH-2\" is held by alice; its case key is not erased")
	mustHash(t, EvidenceDispose(ledger, stringObj("EXH-2"), stringObj("shredded")))
	mustRefuse(t, "the key left", CaseTransition(ledger, stringObj("disposed"), stringObj("x")),
		"case IR-LIFE cannot be disposed of yet: its case key is not erased: case_key_erase(ledger, key_path, reason) "+
			"erases every generation of it, and a case is disposed of after its key")

	key := mustHash(t, CaseKeyErase(ledger, stringObj(run.keyPath), stringObj("the period ran")))
	disposed := mustHash(t, CaseTransition(ledger, stringObj("disposed"), stringObj("nothing is left to keep")))
	if mustHashStringValue(t, disposed, "state") != caseStateDisposed ||
		mustHashStringValue(t, disposed, "from") != caseStateRetained {
		t.Fatalf("the disposal gave %s", disposed.Inspect())
	}
	events, state, err := caseLifecycleRead(run.session(t).graph, openCaseUID(t))
	if err != nil || state != caseStateDisposed ||
		caseChainHead(events).get("lifecycle.erasure_uid") != mustHashStringValue(t, key, "uid") {
		t.Fatalf("the lifecycle is %s after the disposal: %v", state, err)
	}
	if row := caseLifecycleRow(*caseChainHead(events)).(*object.Hash); mustHashStringValue(t, row,
		"erasure_uid") != mustHashStringValue(t, key, "uid") {
		t.Fatalf("the disposal reads back as %s", row.Inspect())
	}
	mustRefuse(t, "a move out of disposed", CaseTransition(ledger, stringObj("active"), stringObj("x")),
		"case_transition moves a case that is disposed nowhere")
	mustRefuse(t, "a hold on a disposed case", RetentionHold(ledger, stringObj("x")),
		"takes no retention period, or legal hold placed or lifted")
}

// A case the ledger holds as retained with no retention period is not
// disposed of, and a disposed case erases nothing, whatever key is open.
func TestADisposedCaseErasesNothing(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()
	forceLifecycle(t, r.session(t), openCaseUID(t), caseStateInReview, caseStateConcluded, caseStateRetained)
	mustRefuse(t, "a case kept for no period", CaseTransition(ledger, stringObj("disposed"), stringObj("x")),
		"case IR-LIFE cannot be disposed of yet: no retention period is recorded for it; its case key is not erased")
	forceLifecycle(t, r.session(t), openCaseUID(t), caseStateDisposed)
	const refused = "takes no erasure of a record's key or the case key"
	mustRefuse(t, "a record's erasure", RecordErase(ledger, stringObj(r.record), stringObj("x")), refused)
	mustRefuse(t, "the key's erasure", CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x")), refused)
	if fileSHA(t, r.record) != r.sha {
		t.Fatal("a refused erasure wrote to the record")
	}
	if _, err := os.Stat(r.keyPath); err != nil {
		t.Fatalf("a refused erasure took the key file: %v", err)
	}
}

// Each piece an erasure reads back is refused when it reads back wrong:
// the record's header changed between reading and writing, the record does
// not read back erased, and the key file does not read back as the rewrite
// left it.
func TestAnErasureReadsBackWhatItWrote(t *testing.T) {
	r := openErasureRun(t)
	op := BuiltinNameRecordErase
	identity, errObj := recordCaseIdentity(op)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	defer security.SecureZero(identity.caseKey)
	target, errObj := recordEraseLoad(op, r.copy, identity)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	if err := recordEraseCheck(op, target, identity); err == nil ||
		!strings.Contains(err.Error(), "its header is not the one the erasure wrote") {
		t.Fatalf("a record never erased read back as erased: %v", err)
	}
	raw, err := os.ReadFile(r.copy)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		file []byte
	}{
		{"a header that changed", bytes.Replace(raw, []byte(`"examiner":"alice"`), []byte(`"examiner":"alicf"`), 1)},
		{"a file that grew", append(bytes.Clone(raw), 0)},
	} {
		if err := os.WriteFile(r.copy, c.file, 0o600); err != nil {
			t.Fatal(err)
		}
		if file, _, errObj := recordEraseMeasure(op, target); errObj == nil ||
			!strings.Contains(errObj.Message, "changed while its erasure was being prepared") {
			if file != nil {
				_ = file.Close()
			}
			t.Fatalf("%s was measured for its erasure: %v", c.name, errObj)
		}
	}
	if err := os.WriteFile(r.copy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, _, errObj := recordEraseMeasure(op, target)
	if errObj != nil {
		t.Fatalf("the file as it was read: %s", errObj.Message)
	}
	_ = file.Close()
}

// The rewrite of a key file without one generation is read back before the
// erasure is recorded: the generation must read back erased, every other one
// as it was, and the file's MAC must hold.
func TestAKeyFileRewriteIsReadBackBeforeItIsRecorded(t *testing.T) {
	r := openErasureRun(t)
	op := BuiltinNameCaseKeyErase
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	file, errObj := readKeyFile(op, r.keyPath)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	rewrite, errObj := caseKeyErasePrepare(op, r.keyPath, file, 1)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	defer rewrite.zero()
	if err := rewrite.check(op, r.keyPath); err == nil || !strings.Contains(err.Error(), "generation 1 is not erased in it") {
		t.Fatalf("a key file never rewritten read back as rewritten: %v", err)
	}
	write := func(f *security.CaseKeyFile) {
		t.Helper()
		document, err := security.MarshalCaseKeyFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.keyPath, document, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	changed := *rewrite.file
	changed.Generations = slices.Clone(rewrite.file.Generations)
	changed.Generations[1].Created = "2001-01-01T00:00:00Z"
	write(&changed)
	if err := rewrite.check(op, r.keyPath); err == nil || !strings.Contains(err.Error(), "generation 2 changed in it") {
		t.Fatalf("a key file whose generation 2 changed read back as rewritten: %v", err)
	}
	forged := *rewrite.file
	forged.FileMAC = strings.Repeat("0", len(forged.FileMAC))
	write(&forged)
	if err := rewrite.check(op, r.keyPath); err == nil {
		t.Fatal("a key file whose MAC does not hold read back as rewritten")
	}
	if err := os.WriteFile(r.keyPath, rewrite.document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rewrite.check(op, r.keyPath); err != nil {
		t.Fatalf("the rewrite itself: %v", err)
	}
}

// A rewrite shorter than the key file it overwrites -- a copy whose line
// endings were turned into CRLF on its way, say -- is padded so that every old
// byte is overwritten, and the padding is cut off once that is on the disk: the
// file is left holding the new document and nothing after it.
func TestAKeyFileRewriteLeavesNoPadding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.key")
	document := []byte("{\n  \"current\": 2\n}\n")
	if err := os.WriteFile(path, bytes.ReplaceAll(document, []byte("\n"), []byte("\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := caseKeyFileRewrite(path, document); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, document) {
		t.Fatalf("the rewritten key file holds %q, not the document %q", got, document)
	}
}

// A key file rotated or rewritten while its erasure was being prepared is not
// erased: what the erasure records is of the file as it was read. The
// passphrase prompt is where that happens, and case_key_erase asks again once
// the locks are held: a file restored from an older copy, or removed, while
// the passphrase is typed is left as it was left, and nothing is recorded.
func TestAKeyFileThatChangedWhileItsErasureWasPreparedIsRefused(t *testing.T) {
	r := openErasureRun(t)
	op := BuiltinNameCaseKeyErase
	older, err := os.ReadFile(r.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	file, errObj := readKeyFile(op, r.keyPath)
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	if errObj := caseKeyEraseUnchanged(op, r.keyPath, file.FileMAC); errObj != nil {
		t.Fatalf("the key file as it was read: %s", errObj.Message)
	}
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	if errObj := caseKeyEraseUnchanged(op, r.keyPath, file.FileMAC); errObj == nil ||
		!strings.Contains(errObj.Message, "changed while its erasure was being prepared") {
		t.Fatalf("a key file rotated after it was read was taken as the same: %v", errObj)
	}

	r.lifecycleRun = r.next(t, "alice", "case_owner")
	r.attach(t)
	rotated, err := os.ReadFile(r.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, meanwhile := range []struct {
		what, refusal string
		act           func() error
		leaves        []byte // nil: no file is left
	}{
		{"an older copy restored over the key file", "changed while its erasure was being prepared",
			func() error { return os.WriteFile(r.keyPath, older, 0o600) }, older},
		{"the key file removed", r.keyPath + " does not exist", func() error { return os.Remove(r.keyPath) }, nil},
	} {
		if err := os.WriteFile(r.keyPath, rotated, 0o600); err != nil {
			t.Fatal(err)
		}
		asked := 0
		previous := security.SetPassphraseSource(passphraseFunc(func(security.PassphraseRequest) ([]byte, error) {
			asked++
			return []byte(testCasePassphrase), meanwhile.act()
		}))
		mustRefuse(t, meanwhile.what, CaseKeyErase(r.handle(), stringObj(r.keyPath), stringObj("x"),
			generationOption(1)), meanwhile.refusal)
		security.SetPassphraseSource(previous)
		raw, err := os.ReadFile(r.keyPath)
		if asked != 1 || (meanwhile.leaves == nil) != os.IsNotExist(err) || !bytes.Equal(raw, meanwhile.leaves) {
			t.Fatalf("%s: the passphrase was asked for %d times, and %d bytes are left in the key file (%v)",
				meanwhile.what, asked, len(raw), err)
		}
		if _, err := os.Stat(r.keyPath + caseKeyErasingSuffix); !os.IsNotExist(err) {
			t.Fatalf("%s: the refused erasure left a copy beside the key file: %v", meanwhile.what, err)
		}
	}
	if _, rows := erasureRows(t, r.handle()); len(rows) != 0 {
		t.Fatalf("the ledger records an erasure that was refused: %v", rows)
	}
}

// erasure_list reads every case's erasures, ordered by case, or one case's.
func TestTheErasureListReadsEveryCaseOrOne(t *testing.T) {
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	run.attach(t)
	session := run.session(t)
	cases := []string{strings.ToLower(openCaseUID(t)), strings.Repeat("cd", 16)}
	for _, caseUID := range cases {
		disclosureLedgerMu.Lock()
		w, err := caseBeginWrite(session, caseUID, "IR-"+caseUID[:4], custodyNow())
		if err == nil {
			_, err = w.erasureAppend(caseErasures{}, erasureKindRecord, w.caseN, map[string]string{
				"erasure.record_uid": strings.Repeat("ab", 16)})
		}
		if err == nil {
			err = w.tx.commit()
		}
		disclosureLedgerMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(cases)
	list, rows := erasureRows(t, intObj(run.ledger))
	if mustHashIntValue(t, list, "count") != 2 || len(rows) != 2 ||
		mustHashStringValue(t, rows[0], "case_uid") != cases[0] || mustHashStringValue(t, rows[1], "case_uid") != cases[1] {
		t.Fatalf("erasure_list of every case gave %s", list.Inspect())
	}
	_, one := erasureRows(t, intObj(run.ledger), makeHashObject(map[string]object.Object{"case_uid": stringObj(cases[1])}))
	if len(one) != 1 || mustHashStringValue(t, one[0], "case_uid") != cases[1] {
		t.Fatalf("erasure_list of one case gave %v", one)
	}
}

// The lifecycle reader refuses a move the lifecycle does not have, wherever
// it is in the chain.
func TestTheLifecycleReaderRefusesAMoveACaseDoesNotMake(t *testing.T) {
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	run.attach(t)
	forceLifecycle(t, run.session(t), openCaseUID(t), caseStateDisposed)
	mustRefuse(t, "a move after a forged one", CaseTransition(intObj(run.ledger), stringObj("active"), stringObj("x")),
		"moves the case from registered to disposed, which is not a move a case makes: from registered, "+
			"case_transition moves a case to active")
}

// An erasure chain this program did not write is refused by every reader
// rather than resolved.
func TestAnErasureChainThisProgramDidNotWriteIsRefused(t *testing.T) {
	uid := strings.Repeat("ab", 16)
	for _, tc := range []struct {
		name   string
		events []map[string]string
		want   string
	}{
		{"another case's", []map[string]string{{"erasure.kind": "record", "erasure.record_uid": uid,
			"erasure.case_uid": strings.Repeat("cd", 16)}}, "names case " + strings.Repeat("cd", 16)},
		{"an unknown kind", []map[string]string{{"erasure.kind": "exhibit"}},
			"records the erasure of a \"exhibit\", which this program does not erase"},
		{"a record that is not one", []map[string]string{{"erasure.kind": "record", "erasure.record_uid": "EXH-1"}},
			"erases record \"EXH-1\", which is not a record's uid"},
		{"a scope there is not", []map[string]string{{"erasure.kind": "case_key", "erasure.scope": "most",
			"erasure.generations": "1"}}, "erases \"most\" of the case key, which is neither every generation nor one"},
		{"one generation that is two", []map[string]string{{"erasure.kind": "case_key", "erasure.scope": "generation",
			"erasure.generations": "1,2"}}, "erases one generation of the case key and names generations \"1,2\""},
		{"no generation", []map[string]string{{"erasure.kind": "case_key", "erasure.scope": "all",
			"erasure.generations": ""}}, "erases every generation of the case key and names generations \"\""},
		{"a generation that is not one", []map[string]string{{"erasure.kind": "case_key", "erasure.scope": "all",
			"erasure.generations": "1,0"}}, "names generations \"1,0\""},
		{"an erasure after the key's", []map[string]string{
			{"erasure.kind": "case_key", "erasure.scope": "all", "erasure.generations": "1"},
			{"erasure.kind": "record", "erasure.record_uid": uid},
		}, "follows the erasure of every generation of the case key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := openLifecycleRun(t, "alice", "case_owner", "", "")
			run.attach(t)
			forgeCaseRecord(t, run.session(t), func(w *caseWriter) error {
				var erasures caseErasures
				for _, props := range tc.events {
					event, err := w.erasureAppend(erasures, props["erasure.kind"], w.caseN, props)
					if err != nil {
						return err
					}
					erasures.events = append(erasures.events, event)
				}
				return nil
			})
			mustRefuse(t, "erasure_list", ErasureList(intObj(run.ledger)), tc.want)
		})
	}
}

// An ErasureEvent is found by each key it is looked up by: a lookup on a key
// the index does not hold finds nothing and says nothing.
func TestTheErasureLabelIsFoundByEachOfItsLookupKeys(t *testing.T) {
	want := []string{"erasure.uid", "erasure.chain"}
	if keys := disclosureKeys[disclosureNodeErasure]; !slices.Equal(keys, want) {
		t.Fatalf("an ErasureEvent is indexed by %v", keys)
	}
	run := openLifecycleRun(t, "alice", "case_owner", "", "")
	run.attach(t)
	session := run.session(t)
	var event caseChainEvent
	forgeCaseRecord(t, session, func(w *caseWriter) error {
		var err error
		event, err = w.erasureAppend(caseErasures{}, erasureKindCaseKey, w.caseN, map[string]string{
			"erasure.scope": erasureScopeAll, "erasure.generations": "1"})
		return err
	})
	for _, key := range want {
		ids, err := session.graph.NodesByProperty(key, []byte(event.get(key)))
		if err != nil || !slices.Contains(ids, event.id) {
			t.Errorf("the ErasureEvent is not found by %s: %v (%v)", key, ids, err)
		}
	}
}

func TestEveryErasureBuiltinReturnsTheDeclaredFields(t *testing.T) {
	r := openErasureRun(t)
	ledger := r.handle()
	mustHash(t, CaseKeyRotate(stringObj(r.keyPath), rotateCaseKeyOption()))
	type call struct {
		name   string
		result object.Object
	}
	calls := []call{
		{BuiltinNameRecordErase, RecordErase(ledger, stringObj(r.record), stringObj("x"), previewOption())},
		{BuiltinNameRecordErase, RecordErase(ledger, stringObj(r.copy), stringObj("x"))},
		{BuiltinNameErasureList, ErasureList(ledger)},
	}
	// The session opened generation 1 before the rotation, so erasing
	// generation 1 zeroes the key it holds.
	one := CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"), generationOption(1))
	calls = append(calls, call{BuiltinNameCaseKeyErase, one},
		call{BuiltinNameCaseKeyErase, CaseKeyErase(ledger, stringObj(r.keyPath), stringObj("x"))},
		call{BuiltinNameRecordVerify, RecordVerify(stringObj(r.copy))})
	for _, c := range calls {
		payload, errObj := unwrapPairNoFatal(c.result)
		if errObj != nil {
			t.Fatalf("%s: %s", c.name, errObj.Message)
		}
		assertLedgerDeclaredFields(t, c.name, payload)
	}
	if payload, _ := unwrapPairNoFatal(one); !mustHashBoolValue(t, payload.(*object.Hash), "session_key_zeroed") {
		t.Fatalf("erasing the generation the case holds left its key: %s", payload.Inspect())
	}
}
