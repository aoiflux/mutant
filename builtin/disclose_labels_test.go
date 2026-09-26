package builtin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mutant/object"
)

// The disclosure family's label names are written beside the ledger on the
// first disclosure write of a session and not rewritten by the writes after it
// (M26-CUS-003). graphene replaces the whole table, fsync and rename, on every
// declaration, so a write that declared again would leave a new file behind:
// the table's modification time is what tells the two apart.
func TestTheLabelTableIsWrittenOncePerLedgerSession(t *testing.T) {
	f := newDiscloseFixture(t)
	labels := filepath.Join(f.ledgerDir, "graphene.labels")

	counsel := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	written, err := os.ReadFile(labels)
	if err != nil {
		t.Fatalf("the first disclosure wrote no label table: %v", err)
	}
	for _, name := range []string{"Disclosure", "Withdrawal", "ReclassEvent", "GRANTS", "WITHDREW"} {
		if !bytes.Contains(written, []byte(name)) {
			t.Fatalf("the label table does not name %s:\n%s", name, written)
		}
	}
	past := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(labels, past, past); err != nil {
		t.Fatal(err)
	}

	regulator := keyFieldString(t, f.issue(t, "regulator", "The regulator"), "disclosure_uid")
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(counsel), stringObj("classification under review")))
	info, err := os.Stat(labels)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("a disclosure and a withdrawal in the session that already declared the names rewrote "+
			"the label table (modified %s)", info.ModTime())
	}
	if again, _ := os.ReadFile(labels); !bytes.Equal(again, written) {
		t.Fatalf("the label table changed within the session:\n%s\nwas:\n%s", again, written)
	}

	// A new session declares again, once: the table is its own file, and
	// this session does not know what happened to it while the ledger was
	// closed.
	LedgerClose(intObj(f.ledger))
	payload, errObj := unwrapPair(t, LedgerOpen(stringObj(f.ledgerDir), stringObj("examiner")))
	if errObj != nil {
		t.Fatalf("ledger_open: %s", errObj.Message)
	}
	reopened := mustHashIntValue(t, payload.(*object.Hash), "handle")
	t.Cleanup(func() { LedgerClose(intObj(reopened)) })
	mustHash(t, DiscloseWithdraw(intObj(reopened), stringObj(regulator), stringObj("classification under review")))
	info, err = os.Stat(labels)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(past) {
		t.Fatal("the first disclosure write of a new session did not declare the names")
	}
}
