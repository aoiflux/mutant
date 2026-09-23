package builtin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/graphene/disk"

	"mutant/object"
	"mutant/security"
)

// diskUnmarshalProofForTest returns the leaf a node inclusion proof commits to.
func diskUnmarshalProofForTest(blob []byte) ([]byte, error) {
	decoded, err := disk.UnmarshalProof(blob)
	if err != nil {
		return nil, err
	}
	if decoded.Node == nil {
		return nil, errors.New("the proof is not a node inclusion proof")
	}
	return decoded.Node.LeafData, nil
}

// purposeStub answers by who is asking, so that the case key and a grant have
// different passphrases in a test the way they do in a real case -- and so
// that a builtin asking for the wrong one gets the wrong answer and fails.
func purposeStub(t *testing.T, answers map[string]string) {
	t.Helper()
	previous := security.SetPassphraseSource(passphraseFunc(func(req security.PassphraseRequest) ([]byte, error) {
		answer, ok := answers[req.Purpose]
		if !ok {
			t.Errorf("%s asked for a passphrase this test did not expect it to need (%s)", req.Purpose, req.Path)
			return nil, security.ErrEmptyPassphrase
		}
		return []byte(answer), nil
	}))
	t.Cleanup(func() { security.SetPassphraseSource(previous) })
}

const (
	testCasePassphrase  = "correct horse battery staple"
	testGrantPassphrase = "a different secret for counsel"
)

// discloseFixture is a keyed case with three classes, a signed 400-byte record
// sealed at 64-byte segments, two views and a ledger:
//
//	segment  0    1    2    3     4     5    6    7
//	bytes    0    64   100  160   224   250  300  364
//	class    open open pii  restr restr pii  open open
//
// counsel grants open and pii (segments 0-2 and 5-7), regulator grants
// restricted (3-4).
type discloseFixture struct {
	source     string
	recordPath string
	record     object.Object
	ledger     int64
	ledgerDir  string
	plaintext  []byte
}

func newDiscloseFixture(t *testing.T) *discloseFixture {
	t.Helper()
	recordTestCase(t)
	mustHash(t, ClassDefine(stringObj("pii")))
	source, dest, _ := recordFixture(t)
	plaintext := make([]byte, 400)
	for i := range plaintext {
		plaintext[i] = byte('A' + i%26)
	}
	if err := os.WriteFile(source, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	ranges := recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(60), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(160), intObj(90), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	)
	mustHash(t, RecordSeal(stringObj(source), stringObj(dest), ranges,
		recordSealOpts(map[string]object.Object{"sign": boolObj(true)})))
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	t.Cleanup(func() { RecordClose(handle) })
	mustHash(t, ViewDefine(stringObj("counsel"), viewArray("open", "pii")))
	mustHash(t, ViewDefine(stringObj("regulator"), viewArray("restricted")))
	ledger, ledgerDir := openTestLedger(t, "examiner")
	return &discloseFixture{source: source, recordPath: dest, record: handle, ledger: ledger, ledgerDir: ledgerDir,
		plaintext: plaintext}
}

// issue discloses under a view and returns the result.
func (f *discloseFixture) issue(t *testing.T, view, recipient string) *object.Hash {
	t.Helper()
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	return mustHash(t, DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj(view), stringObj(recipient)))
}

// bundle compacts the ledger and writes the package, returning its directory
// and the root to check it against.
func (f *discloseFixture) bundle(t *testing.T, uid string) (string, string) {
	t.Helper()
	mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(f.ledger)))
	dir := filepath.Join(t.TempDir(), "package")
	bundled := mustHash(t, DiscloseBundle(intObj(f.ledger), stringObj(uid), stringObj(dir)))
	if b, _ := mustHashValue(t, bundled, "snapshot_root_bundled").(*object.Boolean); b == nil || b.Value {
		t.Fatal("the bundle says its snapshot root travelled inside it")
	}
	return dir, keyFieldString(t, bundled, "snapshot_root")
}

func (f *discloseFixture) verify(t *testing.T, dir string, root object.Object) *object.Hash {
	t.Helper()
	purposeStub(t, map[string]string{BuiltinNameDiscloseVerify: testGrantPassphrase})
	return mustHash(t, DiscloseVerify(stringObj(dir), root))
}

func discloseBool(t *testing.T, h *object.Hash, key string) bool {
	t.Helper()
	b, ok := mustHashValue(t, h, key).(*object.Boolean)
	if !ok {
		t.Fatalf("%s is not a boolean", key)
	}
	return b.Value
}

// discloseChecks maps each check to whether it passed, and fails the test with
// the whole list if a named check is missing.
func discloseChecks(t *testing.T, h *object.Hash) map[string]string {
	t.Helper()
	out := map[string]string{}
	rows, _ := mustHashValue(t, h, "checks").(*object.Array)
	for _, row := range rows.Elements {
		check := row.(*object.Hash)
		name := keyFieldString(t, check, "check")
		passed := discloseBool(t, check, "passed")
		out[name] = map[bool]string{true: "pass", false: "FAIL: " + keyFieldString(t, check, "detail")}[passed]
	}
	return out
}

// The whole path: issued, recorded in the ledger, bundled, verified by the
// recipient against a root they hold, and read back under the grant alone.
func TestADisclosureIsIssuedRecordedBundledAndVerified(t *testing.T) {
	f := newDiscloseFixture(t)
	issued := f.issue(t, "counsel", "Counsel for the respondent")
	uid := keyFieldString(t, issued, "disclosure_uid")
	if got := mustHashIntValue(t, issued, "granted_segments"); got != 6 {
		t.Fatalf("counsel was granted %d segments, want 6 (open and pii)", got)
	}
	if got := mustHashIntValue(t, issued, "withheld_segments"); got != 2 {
		t.Fatalf("counsel had %d segments withheld, want 2 (restricted)", got)
	}
	if discloseBool(t, issued, "bytes_recoverable") {
		t.Fatal("a disclosure claims its bytes can be recovered")
	}

	dir, root := f.bundle(t, uid)
	for _, name := range []string{discloseManifestName, discloseRecordName, discloseGrantName, discloseProofName,
		discloseReportName, discloseChecksumsName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("the package has no %s: %v", name, err)
		}
	}
	original, _ := os.ReadFile(f.recordPath)
	copied, _ := os.ReadFile(filepath.Join(dir, discloseRecordName))
	if string(original) != string(copied) {
		t.Fatal("the record in the package is not byte-identical to the one under custody")
	}
	if manifest, _ := os.ReadFile(filepath.Join(dir, discloseManifestName)); strings.Contains(string(manifest), root) {
		t.Fatal("the snapshot root the recipient checks against is inside the package")
	}

	verified := f.verify(t, dir, stringObj(root))
	checks := discloseChecks(t, verified)
	for name, outcome := range checks {
		if outcome != "pass" {
			t.Errorf("%s: %s", name, outcome)
		}
	}
	if len(checks) != 10 {
		t.Errorf("ran %d checks, want 10: %v", len(checks), checks)
	}
	if !discloseBool(t, verified, "verified") {
		t.Fatalf("a package that passes every check is not verified: %v", checks)
	}
	t.Logf("verified with %d checks: %v", len(checks), checks)

	// The recipient's side of the read: no case, no case key, the grant alone.
	mustHash(t, CaseClose())
	purposeStub(t, map[string]string{BuiltinNameRecordOpen: testGrantPassphrase})
	opened := mustHash(t, RecordOpen(stringObj(filepath.Join(dir, discloseRecordName)),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
	if got := keyFieldString(t, opened, "opened_with"); got != "grant" {
		t.Fatalf("opened_with = %q", got)
	}
	if got := keyFieldString(t, opened, "disclosure_uid"); got != uid {
		t.Fatalf("the opened record names disclosure %q, want %q", got, uid)
	}
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)

	released := recordBytes(t, mustValue(t, RecordRead(handle, intObj(100), intObj(60))))
	if string(released) != string(f.plaintext[100:160]) {
		t.Fatal("a granted span read back as the wrong bytes")
	}
	_, errObj := unwrapPairNoFatal(RecordRead(handle, intObj(150), intObj(20)))
	if errObj == nil || !strings.Contains(errObj.Message, "segment 3") {
		t.Fatalf("a read into a withheld segment was not refused by name: %v", errObj)
	}
	partial := mustHash(t, RecordReadPartial(handle, intObj(0), intObj(400)))
	if got := mustHashIntValue(t, partial, "withheld"); got != 90 {
		t.Fatalf("the partial read withheld %d bytes, want the 90 restricted ones", got)
	}
	holes, _ := mustHashValue(t, partial, "holes").(*object.Array)
	for _, hole := range holes.Elements {
		reason := keyFieldString(t, hole.(*object.Hash), "reason")
		if !strings.Contains(reason, "grant that does not include this segment") {
			t.Fatalf("a hole under a grant reads %q", reason)
		}
	}
}

// Two recipients, two views: each opens exactly their own segments.
func TestTwoRecipientsEachOpenExactlyTheirSegments(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	regulator := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")
	counselDir, _ := f.bundle(t, counsel)
	regulatorDir, _ := f.bundle(t, regulator)

	want := map[string][]bool{
		counselDir:   {true, true, true, false, false, true, true, true},
		regulatorDir: {false, false, false, true, true, false, false, false},
	}
	purposeStub(t, map[string]string{BuiltinNameRecordOpen: testGrantPassphrase})
	for dir, opens := range want {
		opened := mustHash(t, RecordOpen(stringObj(filepath.Join(dir, discloseRecordName)),
			makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
		handle := mustHashValue(t, opened, "handle")
		offsets := []int64{0, 64, 100, 160, 224, 250, 300, 364}
		lengths := []int64{64, 36, 60, 64, 26, 50, 64, 36}
		for i, open := range opens {
			_, errObj := unwrapPairNoFatal(RecordRead(handle, intObj(offsets[i]), intObj(lengths[i])))
			if (errObj == nil) != open {
				t.Errorf("%s: segment %d opened=%t, want %t", filepath.Base(filepath.Dir(dir)), i, errObj == nil, open)
			}
		}
		RecordClose(handle)
	}
}

// A root of null is a finding, never a pass, and the rest is still checked.
func TestAVerificationWithNoRootIsNeverAPass(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir, _ := f.bundle(t, uid)
	verified := f.verify(t, dir, &object.Null{})
	if discloseBool(t, verified, "verified") {
		t.Fatal("a verification with no root reported verified")
	}
	if discloseBool(t, verified, "root_supplied") {
		t.Fatal("root_supplied is true for a null root")
	}
	checks := discloseChecks(t, verified)
	if !strings.HasPrefix(checks["ledger_inclusion"], "FAIL: no snapshot root was supplied") {
		t.Fatalf("ledger_inclusion: %s", checks["ledger_inclusion"])
	}
	for name, outcome := range checks {
		if name != "ledger_inclusion" && outcome != "pass" {
			t.Errorf("with no root, %s should still have been checked and passed: %s", name, outcome)
		}
	}
}

// Every edit to a package is caught by the check that covers the thing edited.
func TestAPackageThatWasEditedFailsTheCheckThatCoversIt(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	regulator := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")
	dir, root := f.bundle(t, counsel)
	otherDir, _ := f.bundle(t, regulator)

	fresh := func(t *testing.T) string {
		t.Helper()
		copyDir := filepath.Join(t.TempDir(), "copy")
		if err := os.MkdirAll(copyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(copyDir, entry.Name()), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return copyDir
	}
	edit := func(t *testing.T, path string, change func([]byte) []byte) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, change(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name  string
		setup func(t *testing.T, copyDir string) string
		fails string
	}{
		{"a report edited after the fact", func(t *testing.T, d string) string {
			edit(t, filepath.Join(d, discloseReportName), func(b []byte) []byte { return append(b, " (amended)"...) })
			return root
		}, "files"},
		{"a manifest field changed", func(t *testing.T, d string) string {
			edit(t, filepath.Join(d, discloseManifestName), func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"recipient": "Counsel"`, `"recipient": "Someone else"`, 1))
			})
			return root
		}, "manifest_seal"},
		{"the other disclosure's grant swapped in", func(t *testing.T, d string) string {
			data, _ := os.ReadFile(filepath.Join(otherDir, discloseGrantName))
			if err := os.WriteFile(filepath.Join(d, discloseGrantName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			return root
		}, "grant_names_record"},
		// The same swap, read by the check that asks the question a reviewer
		// actually cares about: does this grant open more, or other, than the
		// view names? It must say no on its own, not only because an earlier
		// check happened to trip first.
		{"a grant for another view swapped in", func(t *testing.T, d string) string {
			data, _ := os.ReadFile(filepath.Join(otherDir, discloseGrantName))
			if err := os.WriteFile(filepath.Join(d, discloseGrantName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			return root
		}, "complete_as_authorised"},
		{"a byte of the record flipped", func(t *testing.T, d string) string {
			edit(t, filepath.Join(d, discloseRecordName), func(b []byte) []byte {
				b[len(b)/2] ^= 0x01
				return b
			})
			return root
		}, "record_signature"},
		{"a root from another snapshot", func(t *testing.T, d string) string {
			return strings.Repeat("ab", 32)
		}, "ledger_inclusion"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			copyDir := fresh(t)
			useRoot := c.setup(t, copyDir)
			verified := f.verify(t, copyDir, stringObj(useRoot))
			if discloseBool(t, verified, "verified") {
				t.Fatal("an edited package verified")
			}
			checks := discloseChecks(t, verified)
			if !strings.HasPrefix(checks[c.fails], "FAIL") {
				t.Fatalf("%s was not caught by %s: %v", c.name, c.fails, checks)
			}
		})
	}
}

// A recipient cannot re-disclose: a grant opens segments and cannot issue them.
func TestAGrantOpenedRecordCannotDisclose(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir, _ := f.bundle(t, uid)
	purposeStub(t, map[string]string{BuiltinNameRecordOpen: testGrantPassphrase})
	opened := mustHash(t, RecordOpen(stringObj(filepath.Join(dir, discloseRecordName)),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)
	_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), handle, stringObj("counsel"), stringObj("x")))
	if errObj == nil || !strings.Contains(errObj.Message, "opened under a grant") {
		t.Fatalf("a grant-opened record issued a disclosure: %v", errObj)
	}
}

// A bundle needs the disclosure to be in a compacted snapshot, and a directory
// of its own.
func TestABundleNeedsACompactedLedgerAndAnEmptyDirectory(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir := filepath.Join(t.TempDir(), "package")
	_, errObj := unwrapPairNoFatal(DiscloseBundle(intObj(f.ledger), stringObj(uid), stringObj(dir)))
	if errObj == nil || !strings.Contains(errObj.Message, "ledger_compact") {
		t.Fatalf("a bundle was written with no proof to carry: %v", errObj)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused bundle left %d files behind", len(entries))
	}
	mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(f.ledger)))
	occupied := t.TempDir()
	if err := os.WriteFile(filepath.Join(occupied, "something"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errObj = unwrapPairNoFatal(DiscloseBundle(intObj(f.ledger), stringObj(uid), stringObj(occupied)))
	if errObj == nil || !strings.Contains(errObj.Message, "is not empty") {
		t.Fatalf("a package was written into an occupied directory: %v", errObj)
	}
	unknown := strings.Repeat("0", 32)
	_, errObj = unwrapPairNoFatal(DiscloseBundle(intObj(f.ledger), stringObj(unknown), stringObj(dir)))
	if errObj == nil || !strings.Contains(errObj.Message, "not issued in this case in this run") {
		t.Fatalf("an unknown disclosure was bundled: %v", errObj)
	}
}

// The leaf check pins graphene's property-hash encoding: the manifest's copy of
// the Disclosure node, hashed as graphene hashes a v3 leaf, matches the proof
// from the real ledger -- and does not match once any property differs.
func TestTheLedgerProofCommitsToTheManifestsRecord(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir, _ := f.bundle(t, uid)
	raw, err := os.ReadFile(filepath.Join(dir, discloseManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, discloseProofName))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := diskUnmarshalProofForTest(blob)
	if err != nil {
		t.Fatal(err)
	}
	ledger := manifestMap(manifest, "ledger")
	if detail := disclosureLeafNames(decoded, ledger); detail != "" {
		t.Fatalf("the proof from a real ledger does not match the manifest's record: %s -- graphene's leaf "+
			"encoding or its property-hash tag has changed", detail)
	}
	record := ledger["record"].(map[string]any)
	record["disclosure.recipient"] = "Someone else"
	if detail := disclosureLeafNames(decoded, ledger); !strings.Contains(detail, "properties are not the ones") {
		t.Fatalf("a changed property still matched the proof: %q", detail)
	}
}

// A disclosure is in the case manifest beside the view it was issued under.
func TestADisclosureIsInTheCaseManifest(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	custodyStore.RLock()
	manifest := custodyStore.session.manifest()
	custodyStore.RUnlock()
	classification := manifestMap(manifest, "classification")
	rows, _ := classification["disclosures"].([]any)
	if len(rows) != 1 {
		t.Fatalf("the manifest lists %d disclosures, want 1", len(rows))
	}
	row := rows[0].(map[string]any)
	if row["uid"] != uid || row["recipient"] != "Counsel" || row["view"] != "counsel" {
		t.Fatalf("the manifest row does not describe the disclosure: %v", row)
	}
	if recoverable, _ := row["bytes_recoverable"].(bool); recoverable {
		t.Fatal("the manifest says a disclosure's bytes are recoverable")
	}
}

// A node a script writes into the same ledger cannot pass for a disclosure:
// it carries a label a script cannot spell, and every read filters on it.
func TestAScriptCannotForgeADisclosureInTheLedger(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	forged := ledgerProps(map[string]string{"disclosure.uid": uid, "disclosure.recipient": "Mallory"})
	mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(f.ledger), forged, intObj(5)))
	if _, errObj := unwrapPairNoFatal(LedgerAddNode(intObj(f.ledger), forged, intObj(disclosureTypeBase+6))); errObj == nil {
		t.Fatal("a script wrote a node with the Disclosure label")
	}
	session, _ := ledgerGet(f.ledger)
	node, found, err := disclosureFind(session.graph, disclosureNodeDisclosure, "disclosure.uid", uid)
	if err != nil || !found {
		t.Fatalf("the real disclosure is no longer found once a forgery shares its uid: %v", err)
	}
	if node.get("disclosure.recipient") != "Counsel" {
		t.Fatalf("the lookup returned the forgery: %v", node.props)
	}
	// And the bundle, which reads the ledger back, still binds the real one.
	dir, root := f.bundle(t, uid)
	if !discloseBool(t, f.verify(t, dir, stringObj(root)), "verified") {
		t.Fatal("a forged node in the ledger broke the real disclosure's package")
	}
}

// A disclosure the ledger could not record was not issued, and nothing in the
// run says it was.
func TestADisclosureTheLedgerCouldNotRecordWasNotIssued(t *testing.T) {
	f := newDiscloseFixture(t)
	session, _ := ledgerGet(f.ledger)
	if err := session.graph.Close(); err != nil {
		t.Fatal(err)
	}
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), stringObj("Counsel")))
	if errObj == nil || !strings.Contains(errObj.Message, "was not issued") {
		t.Fatalf("a disclosure went through with no ledger to record it: %v", errObj)
	}
	custodyStore.RLock()
	count := len(custodyStore.session.disclosures)
	custodyStore.RUnlock()
	if count != 0 {
		t.Fatalf("the case holds %d disclosures after one that was not recorded", count)
	}
	// The handle's store is closed; drop it so cleanup does not close it twice.
	ledgerHandles.Delete(f.ledger)
}

// A record that changed between the grant and the bundle is not the record that
// was disclosed, and the bundle says so rather than packaging it.
func TestABundleRefusesARecordThatChangedSinceTheGrant(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(f.ledger)))
	data, err := os.ReadFile(f.recordPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-3] ^= 0x01
	if err := os.WriteFile(f.recordPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "package")
	_, errObj := unwrapPairNoFatal(DiscloseBundle(intObj(f.ledger), stringObj(uid), stringObj(dir)))
	if errObj == nil || !strings.Contains(errObj.Message, "is not the record that was disclosed") {
		t.Fatalf("a record edited after its grant was packaged: %v", errObj)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused bundle left %d files behind", len(entries))
	}
}

// A grant for one record is refused against another before anybody is asked
// for a passphrase: a passphrase typed for the wrong file is typed for nothing.
func TestAGrantForAnotherRecordIsRefusedBeforeAnyPassphrase(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir, _ := f.bundle(t, uid)

	// A second record in the same case: same classes, same shape, another uid.
	source := filepath.Join(t.TempDir(), "other.bin")
	if err := os.WriteFile(source, f.plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.mrec")
	purposeStub(t, map[string]string{})
	mustHash(t, RecordSeal(stringObj(source), stringObj(other), recordArray(), recordSealOpts(nil)))

	asked := false
	previous := security.SetPassphraseSource(passphraseFunc(func(security.PassphraseRequest) ([]byte, error) {
		asked = true
		return []byte(testGrantPassphrase), nil
	}))
	t.Cleanup(func() { security.SetPassphraseSource(previous) })
	_, errObj := unwrapPairNoFatal(RecordOpen(stringObj(other),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
	if errObj == nil || !strings.Contains(errObj.Message, "this grant is for record") {
		t.Fatalf("a grant opened a record it was not issued for: %v", errObj)
	}
	if asked {
		t.Fatal("the examiner was asked for a passphrase for a grant that could never open this record")
	}
}

// A wrong grant passphrase is forgotten, so that the recipient is asked again.
func TestAWrongGrantPassphraseIsForgotten(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	dir, _ := f.bundle(t, uid)
	source := installForgetting(t, "not the grant passphrase")
	_, errObj := unwrapPairNoFatal(RecordOpen(stringObj(filepath.Join(dir, discloseRecordName)),
		makeHashObject(map[string]object.Object{"grant": stringObj(filepath.Join(dir, discloseGrantName))})))
	if errObj == nil {
		t.Fatal("the wrong passphrase opened the grant")
	}
	if len(source.forgotten) != 1 || !strings.HasSuffix(source.forgotten[0], discloseGrantName) {
		t.Fatalf("a failed grant open told the source to forget %v", source.forgotten)
	}
}

// A withdrawal is recorded once, stops further grants of the record to that
// recipient and the packaging of the withdrawn disclosure, and says in a field
// that it reaches nobody's copy.
func TestAWithdrawalIsRecordedOnceAndStopsFurtherGrants(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	withdrawn := mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("classification under review")))
	if discloseBool(t, withdrawn, "bytes_recoverable") {
		t.Fatal("a withdrawal claims the bytes can be recovered")
	}
	if !discloseBool(t, withdrawn, "recorded") {
		t.Fatal("a withdrawal does not say it was recorded")
	}

	_, errObj := unwrapPairNoFatal(DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("again")))
	if errObj == nil || !strings.Contains(errObj.Message, "already withdrawn") ||
		!strings.Contains(errObj.Message, "classification under review") {
		t.Fatalf("a second withdrawal was not refused by naming the first: %v", errObj)
	}

	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	_, errObj = unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), stringObj("Counsel")))
	if errObj == nil || !strings.Contains(errObj.Message, "was withdrawn") {
		t.Fatalf("the record was disclosed again to a recipient whose disclosure was withdrawn: %v", errObj)
	}
	// Another recipient is not affected.
	f.issue(t, "regulator", "The regulator")

	mustLedgerHash(t, "ledger_compact", LedgerCompact(intObj(f.ledger)))
	_, errObj = unwrapPairNoFatal(DiscloseBundle(intObj(f.ledger), stringObj(uid), stringObj(filepath.Join(t.TempDir(), "p"))))
	if errObj == nil || !strings.Contains(errObj.Message, "is not packaged") {
		t.Fatalf("a withdrawn disclosure was packaged: %v", errObj)
	}

	custodyStore.RLock()
	row := custodyStore.session.disclosureRows()[0].(map[string]any)
	custodyStore.RUnlock()
	if row["withdrawn_at"] == "" {
		t.Fatal("the case manifest does not show the withdrawal")
	}
}

// A withdrawal needs the ledger and not the case: it may come long after the
// case that issued the disclosure was closed.
func TestAWithdrawalNeedsNoOpenCase(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	mustHash(t, CaseClose())
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("recalled by the court")))
	_, errObj := unwrapPairNoFatal(DiscloseWithdraw(intObj(f.ledger), stringObj(strings.Repeat("1", 32)), stringObj("x")))
	if errObj == nil || !strings.Contains(errObj.Message, "records no disclosure") {
		t.Fatalf("a disclosure that does not exist was withdrawn: %v", errObj)
	}
	_, errObj = unwrapPairNoFatal(DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("   ")))
	if errObj == nil || !strings.Contains(errObj.Message, "must state a reason") {
		t.Fatalf("a withdrawal with no reason was accepted: %v", errObj)
	}
}

// The history lists every disclosure with its withdrawal, and counts -- rather
// than lists or hides -- nodes that carry a disclosure uid without being one.
func TestTheHistoryListsEveryDisclosureAndCountsForgeries(t *testing.T) {
	f := newDiscloseFixture(t)
	first := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	second := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(first), stringObj("superseded")))
	mustLedgerHash(t, "ledger_add_node", LedgerAddNode(intObj(f.ledger),
		ledgerProps(map[string]string{"disclosure.uid": strings.Repeat("f", 32)}), intObj(3)))

	history := mustHash(t, DiscloseHistory(intObj(f.ledger)))
	for key, want := range map[string]int64{"count": 2, "withdrawn": 1, "recipients": 2, "records": 1, "foreign": 1} {
		if got := mustHashIntValue(t, history, key); got != want {
			t.Errorf("%s = %d, want %d", key, got, want)
		}
	}
	rows, _ := mustHashValue(t, history, "disclosures").(*object.Array)
	if len(rows.Elements) != 2 {
		t.Fatalf("%d rows", len(rows.Elements))
	}
	a, b := rows.Elements[0].(*object.Hash), rows.Elements[1].(*object.Hash)
	if keyFieldString(t, a, "disclosure_uid") != first || keyFieldString(t, b, "disclosure_uid") != second {
		t.Fatal("the history is not in the order the disclosures were issued")
	}
	if !discloseBool(t, a, "withdrawn") || keyFieldString(t, a, "withdrawal_reason") != "superseded" {
		t.Fatal("the withdrawn disclosure is not shown withdrawn, with its reason")
	}
	if discloseBool(t, b, "withdrawn") {
		t.Fatal("a disclosure nobody withdrew is shown withdrawn")
	}
	if keyFieldString(t, a, "granted_runs") != "0-2,5-7" || keyFieldString(t, b, "granted_runs") != "3-4" {
		t.Fatalf("granted runs: %q and %q", keyFieldString(t, a, "granted_runs"), keyFieldString(t, b, "granted_runs"))
	}
}

// Every recipient given a segment is listed, withdrawn or not, because a
// withdrawn recipient still holds what they were given.
func TestForSegmentListsEveryHolderWithdrawnOrNot(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := f.issue(t, "counsel", "Counsel")
	recordUID := keyFieldString(t, counsel, "record_uid")
	counselUID := keyFieldString(t, counsel, "disclosure_uid")
	f.issue(t, "regulator", "The regulator")
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(counselUID), stringObj("superseded")))

	pii := mustHash(t, DiscloseForSegment(intObj(f.ledger), stringObj(recordUID), intObj(2)))
	if mustHashIntValue(t, pii, "offset") != 100 || mustHashIntValue(t, pii, "length") != 60 ||
		keyFieldString(t, pii, "label") != "pii" {
		t.Fatalf("segment 2 is not described as pii at 100+60: %v", pii.Inspect())
	}
	holders, _ := mustHashValue(t, pii, "held_by").(*object.Array)
	if len(holders.Elements) != 1 {
		t.Fatalf("segment 2 has %d holders, want 1", len(holders.Elements))
	}
	holder := holders.Elements[0].(*object.Hash)
	if keyFieldString(t, holder, "recipient") != "Counsel" || !discloseBool(t, holder, "withdrawn") {
		t.Fatal("the withdrawn recipient of segment 2 is not listed as still holding it")
	}

	restricted := mustHash(t, DiscloseForSegment(intObj(f.ledger), stringObj(recordUID), intObj(3)))
	holders, _ = mustHashValue(t, restricted, "held_by").(*object.Array)
	if len(holders.Elements) != 1 || keyFieldString(t, holders.Elements[0].(*object.Hash), "recipient") != "The regulator" {
		t.Fatalf("segment 3 is not held by the regulator alone: %v", restricted.Inspect())
	}

	unknown := mustHash(t, DiscloseForSegment(intObj(f.ledger), stringObj(strings.Repeat("ab", 16)), intObj(0)))
	if discloseBool(t, unknown, "record_known") || mustHashIntValue(t, unknown, "count") != 0 {
		t.Fatal("a record this ledger never saw is reported as known or held")
	}
	_, errObj := unwrapPairNoFatal(DiscloseForSegment(intObj(f.ledger), stringObj(recordUID), intObj(8)))
	if errObj == nil || !strings.Contains(errObj.Message, "has 8 segments") {
		t.Fatalf("a segment past the end was answered: %v", errObj)
	}
}

// reseal seals the fixture's evidence again under different ranges and opens
// the new record.
func (f *discloseFixture) reseal(t *testing.T, ranges object.Object) (object.Object, string) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "reclassified.mrec")
	purposeStub(t, map[string]string{})
	mustHash(t, RecordSeal(stringObj(f.source), stringObj(dest), ranges,
		recordSealOpts(map[string]object.Object{"sign": boolObj(true)})))
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	t.Cleanup(func() { RecordClose(handle) })
	return handle, keyFieldString(t, opened, "record_uid")
}

// The first pii span is reclassified as restricted. Counsel, whose view grants
// pii and not restricted, holds those 60 bytes and would not be given them
// now; the regulator, whose disclosure never included them, is not affected.
func TestAReclassificationFindsWhoHoldsWhatChanged(t *testing.T) {
	f := newDiscloseFixture(t)
	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	f.issue(t, "regulator", "The regulator")
	newRecord, newUID := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
		mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
	))

	result := mustHash(t, DiscloseReclassified(intObj(f.ledger), newRecord, f.record))
	if !discloseBool(t, result, "recorded") || discloseBool(t, result, "already_recorded") {
		t.Fatal("the first reclassification of a pair was not recorded")
	}
	changed, _ := mustHashValue(t, result, "changed").(*object.Array)
	if len(changed.Elements) != 1 {
		t.Fatalf("%d changed ranges, want 1: %s", len(changed.Elements), result.Inspect())
	}
	c := changed.Elements[0].(*object.Hash)
	if mustHashIntValue(t, c, "offset") != 100 || mustHashIntValue(t, c, "length") != 60 ||
		keyFieldString(t, c, "from_label") != "pii" || keyFieldString(t, c, "to_label") != "restricted" {
		t.Fatalf("the change is not pii->restricted at 100+60: %s", c.Inspect())
	}
	affected, _ := mustHashValue(t, result, "affected").(*object.Array)
	if len(affected.Elements) != 1 {
		t.Fatalf("%d disclosures affected, want only counsel's: %s", len(affected.Elements), result.Inspect())
	}
	a := affected.Elements[0].(*object.Hash)
	if keyFieldString(t, a, "disclosure_uid") != counsel || mustHashIntValue(t, a, "now_withheld_bytes") != 60 {
		t.Fatalf("counsel's disclosure is not reported holding 60 bytes it would now be refused: %s", a.Inspect())
	}
	held, _ := mustHashValue(t, a, "changed_held").(*object.Array)
	if len(held.Elements) != 1 || discloseBool(t, held.Elements[0].(*object.Hash), "view_grants_new") {
		t.Fatalf("the held range should be one row whose view does not grant the new class: %s", a.Inspect())
	}
	if strings.Contains(result.Inspect(), "raised") || strings.Contains(result.Inspect(), "lowered") {
		t.Fatal("the report says which way a class moved, which nothing in this tool can know")
	}

	again := mustHash(t, DiscloseReclassified(intObj(f.ledger), newRecord, f.record))
	if discloseBool(t, again, "recorded") || !discloseBool(t, again, "already_recorded") {
		t.Fatal("asking again recorded the reclassification a second time")
	}
	if mustHashIntValue(t, again, "ledger_node") != mustHashIntValue(t, result, "ledger_node") {
		t.Fatal("asking again pointed at a different record of the reclassification")
	}

	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), stringObj("Someone new")))
	if errObj == nil || !strings.Contains(errObj.Message, "was reclassified by record "+newUID) {
		t.Fatalf("a superseded record was disclosed: %v", errObj)
	}
	mustHash(t, DiscloseToPassphrase(intObj(f.ledger), newRecord, stringObj("counsel"), stringObj("Someone new")))
}

// A reclassification is the same evidence and nothing else.
func TestAReclassificationRefusesWhatIsNotTheSameEvidence(t *testing.T) {
	f := newDiscloseFixture(t)
	_, errObj := unwrapPairNoFatal(DiscloseReclassified(intObj(f.ledger), f.record, f.record))
	if errObj == nil || !strings.Contains(errObj.Message, "cannot reclassify itself") {
		t.Fatalf("a record reclassified itself: %v", errObj)
	}

	// Same length, different bytes: the lengths agree and the digests do not.
	other := filepath.Join(t.TempDir(), "other.bin")
	changed := append([]byte(nil), f.plaintext...)
	changed[7] ^= 0x20
	if err := os.WriteFile(other, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "other.mrec")
	purposeStub(t, map[string]string{})
	mustHash(t, RecordSeal(stringObj(other), stringObj(dest), recordArray(), recordSealOpts(nil)))
	opened := mustHash(t, RecordOpen(stringObj(dest)))
	handle := mustHashValue(t, opened, "handle")
	defer RecordClose(handle)
	_, errObj = unwrapPairNoFatal(DiscloseReclassified(intObj(f.ledger), handle, f.record))
	if errObj == nil || !strings.Contains(errObj.Message, "do not decrypt to the same plaintext") {
		t.Fatalf("records of different evidence were recorded as a reclassification: %v", errObj)
	}
}

func TestReclassChangesAreExactByteRanges(t *testing.T) {
	span := func(off, n uint64, class string) security.RecordSpan {
		return security.RecordSpan{Offset: off, Length: n, Class: class}
	}
	cases := []struct {
		name          string
		before, after []security.RecordSpan
		want          string
	}{
		{"nothing changed", []security.RecordSpan{span(0, 10, "a"), span(10, 5, "b")},
			[]security.RecordSpan{span(0, 10, "a"), span(10, 5, "b")}, ""},
		{"a boundary moved", []security.RecordSpan{span(0, 10, "a"), span(10, 10, "b")},
			[]security.RecordSpan{span(0, 13, "a"), span(13, 7, "b")}, "10+3:b>a"},
		{"a middle run changed, split across spans", []security.RecordSpan{span(0, 4, "a"), span(4, 4, "b"), span(8, 4, "b")},
			[]security.RecordSpan{span(0, 4, "a"), span(4, 8, "c")}, "4+8:b>c"},
		{"two directions side by side", []security.RecordSpan{span(0, 5, "a"), span(5, 5, "b")},
			[]security.RecordSpan{span(0, 5, "b"), span(5, 5, "a")}, "0+5:a>b;5+5:b>a"},
		{"tags compared without regard to case", []security.RecordSpan{span(0, 5, "AB")},
			[]security.RecordSpan{span(0, 5, "ab")}, ""},
	}
	for _, c := range cases {
		if got := reclassText(reclassChanges(c.before, c.after)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
