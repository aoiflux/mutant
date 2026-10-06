package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// M26-REC-008. A disclosure package is untrusted input on the recipient's side,
// and disclose_verify indexed the packaged record with segment numbers taken out
// of the package's grant file. GrantFile.shell bounds those by the grant's own
// segment count and never by the record travelling beside it, so a grant issued
// for a longer record of the same case indexed past the end: "index out of range
// [10] with length 8", which aborted the whole verification instead of reporting
// a failed check. It also leaked the record handle, because the Close sat at the
// end of DiscloseVerify's body rather than in a defer, so the caller's next
// os.Rename of the package failed with "being used by another process".
//
// Both halves are asserted here, and so is the arrangement that makes the test
// meaningful at all: EVERY granted index must be out of range for the packaged
// record. A grant with even one in-range index fails on that segment's AAD
// first, and the test would then pass against the unfixed code while proving
// nothing -- which is the failure mode this suite has been bitten by before.
func TestVerifyRefusesAGrantForALongerRecordAndKeepsNoHandle(t *testing.T) {
	f := newDiscloseFixture(t)

	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")

	// A second record of the same evidence, classified so that `restricted`
	// lands entirely past the eighth segment. At the fixture's 64-byte segments
	// the four short pii spans and the open gaps between them fill indices 0-7,
	// and the 200-byte restricted tail becomes four more segments, 8-11. The
	// regulator view grants restricted alone, so every index in its grant is out
	// of range for the eight-segment record that counsel's package carries.
	longer, _ := f.reseal(t, recordArray(
		mustHash(t, RecordClassifyRange(intObj(25), intObj(25), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(75), intObj(25), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(125), intObj(25), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(175), intObj(25), stringObj("pii"))),
		mustHash(t, RecordClassifyRange(intObj(200), intObj(200), stringObj("restricted"))),
	))
	regulator := keyFieldString(t, f.issueFrom(t, longer, "regulator", "The regulator"), "disclosure_uid")

	counselDir, root := f.bundle(t, counsel)
	longerDir, _ := f.bundle(t, regulator)

	// The baseline, so checks_run below is compared with this tree's own number
	// rather than a constant that would go stale the moment a check is added.
	clean := f.verify(t, counselDir, stringObj(root))
	if !discloseBool(t, clean, "verified") {
		t.Fatalf("the unmodified package did not verify: %v", discloseChecks(t, clean))
	}
	wantChecks := mustHashIntValue(t, clean, "checks_run")

	forged := copyPackage(t, counselDir)
	grantBytes, err := os.ReadFile(filepath.Join(longerDir, discloseGrantName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(forged, discloseGrantName), grantBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// The precondition, measured rather than assumed. If this ever stops
	// holding, the test below is worthless and says so here instead of passing.
	packaged, errObj := recordLoad("test", filepath.Join(forged, discloseRecordName))
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	total := uint64(len(packaged.segments))
	packaged.file.Close()
	grantFile, errObj := disclosureReadGrantFile("test", filepath.Join(forged, discloseGrantName))
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	indices, err := grantFile.Indices()
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) == 0 {
		t.Fatal("the swapped grant opens no segment, so it cannot reach the indexing this test is about")
	}
	for _, index := range indices {
		if index < total {
			t.Fatalf("granted segment %d is in range for a record of %d segments, so this package would "+
				"fail on that segment's AAD before reaching the index out of range; the segment "+
				"arrangement this test depends on no longer holds", index, total)
		}
	}

	// Counted, not stubbed: the refusal is placed before the passphrase request,
	// because nothing needs the key to establish that this grant was not issued
	// for this record, and asking for a secret to check something already known
	// to be wrong is not a question worth putting to the examiner.
	_, prompts := countDisclosureWork(t)

	// If the fix is absent, the call below panics here and the test does not
	// report -- which is the point. There is deliberately no recover(): a panic
	// must fail this test loudly, not be caught and graded.
	verified := mustHash(t, DiscloseVerify(stringObj(forged), stringObj(root)))

	if discloseBool(t, verified, "verified") {
		t.Error("a package carrying a grant for a different, longer record verified")
	}
	if discloseBool(t, verified, "grant_opened") {
		t.Error("grant_opened is true although no granted segment was decrypted")
	}
	checks := discloseChecks(t, verified)
	if !strings.HasPrefix(checks["grant_opens"], "FAIL") {
		t.Errorf("grant_opens did not fail on a grant for a longer record: %v", checks)
	}
	if detail := checks["grant_opens"]; !strings.Contains(detail, "not issued for the record in this package") {
		t.Errorf("grant_opens failed for the wrong reason, so the index bound may not be what caught "+
			"it: %q", detail)
	}
	if got := mustHashIntValue(t, verified, "checks_run"); got != wantChecks {
		t.Errorf("checks_run is %d on the forged package and %d on the clean one; the refusal must be a "+
			"failed check, not a check that stopped running", got, wantChecks)
	}
	if *prompts != 0 {
		t.Errorf("the examiner was asked for a passphrase %d time(s) for a package already known not to "+
			"match its grant", *prompts)
	}

	// The handle half. On Windows a rename of an open file fails, which is how
	// the leak was first noticed, so this is the assertion that pins the defer.
	from := filepath.Join(forged, discloseRecordName)
	if err := os.Rename(from, from+".moved"); err != nil {
		t.Errorf("the packaged record could not be renamed after verification, so its handle is still "+
			"open: %v", err)
	}
}
