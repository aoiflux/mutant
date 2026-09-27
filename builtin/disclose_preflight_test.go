package builtin

import (
	"strings"
	"testing"

	"mutant/object"
	"mutant/security"
)

// countDisclosureWork counts the grants issued and the passphrases asked for
// while the test runs. Every passphrase request is answered, so a refusal that
// comes after the prompt is still seen as one.
func countDisclosureWork(t *testing.T) (issued, prompts *int) {
	t.Helper()
	issued, prompts = new(int), new(int)
	previousIssue := disclosureIssueGrant
	disclosureIssueGrant = func(keys *security.RecordKeys, descriptors []security.SegmentAAD) (*security.RecordGrant, error) {
		*issued++
		return previousIssue(keys, descriptors)
	}
	previousSource := security.SetPassphraseSource(passphraseFunc(func(security.PassphraseRequest) ([]byte, error) {
		*prompts++
		return []byte(testGrantPassphrase), nil
	}))
	t.Cleanup(func() {
		disclosureIssueGrant = previousIssue
		security.SetPassphraseSource(previousSource)
	})
	return issued, prompts
}

// M26-REC-001. DISCLOSURE_POLICY says a withdrawal is checked before any new
// key is issued. The withdrawal and supersession refusals ran inside the ledger
// write, after the grant's key material had been derived and after the
// examiner had chosen and confirmed a passphrase for a grant that was then
// refused. Both are now refused before either happens.
func TestARefusedDisclosureIssuesNoKeyAndAsksForNoPassphrase(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, f *discloseFixture) (record object.Object, recipient, want string)
	}{
		{"withdrawn recipient", func(t *testing.T, f *discloseFixture) (object.Object, string, string) {
			uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
			mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("classification under review")))
			return f.record, "Counsel", "was withdrawn"
		}},
		{"superseded record", func(t *testing.T, f *discloseFixture) (object.Object, string, string) {
			newRecord, newUID := f.reseal(t, recordArray(
				mustHash(t, RecordClassifyRange(intObj(100), intObj(150), stringObj("restricted"))),
				mustHash(t, RecordClassifyRange(intObj(250), intObj(50), stringObj("pii"))),
			))
			mustHash(t, DiscloseReclassified(intObj(f.ledger), newRecord, f.record))
			return f.record, "Someone new", "was reclassified by record " + newUID
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newDiscloseFixture(t)
			record, recipient, want := c.setup(t, f)

			issued, prompts := countDisclosureWork(t)
			_, errObj := unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), record, stringObj("counsel"), stringObj(recipient)))
			if errObj == nil || !strings.Contains(errObj.Message, want) {
				t.Fatalf("the disclosure was not refused with %q: %v", want, errObj)
			}
			if *issued != 0 {
				t.Errorf("a refused disclosure derived a grant's key material %d time(s) first", *issued)
			}
			if *prompts != 0 {
				t.Errorf("a refused disclosure asked for a passphrase %d time(s) first", *prompts)
			}
		})
	}

	// The counters see a disclosure that goes ahead, so a zero above is a
	// refusal and not a counter that was never reached.
	f := newDiscloseFixture(t)
	f.assign(t, "Counsel")
	issued, prompts := countDisclosureWork(t)
	mustHash(t, DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), stringObj("Counsel")))
	if *issued != 1 || *prompts == 0 {
		t.Fatalf("an issued disclosure counted %d grant(s) and %d prompt(s)", *issued, *prompts)
	}
}
