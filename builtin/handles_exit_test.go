package builtin

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// forgetChild is set only when TestAForgottenLedgerIsClosedAtTheEnd runs this
// test binary again as a program that forgets to close its stores. A flag and
// not an environment variable, for the reason recordCrashChild gives.
var forgetChild = flag.String("handles.forgetchild", "", "internal: open stores in this directory and end without closing them")

// TestForgetChild is the child: a program that opens a ledger and a disk
// graph, writes to both, and reaches its end without ledger_close or db_close.
// It then does what every program end does, and prints what that said.
func TestForgetChild(t *testing.T) {
	if *forgetChild == "" {
		t.Skip("the child half of TestAForgottenLedgerIsClosedAtTheEnd")
	}
	opened, errObj := unwrapPair(t, LedgerOpen(stringObj(filepath.Join(*forgetChild, "ledger")), stringObj("examiner")))
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	ledger := mustHashIntValue(t, opened.(*object.Hash), "handle")
	mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(ledger), ledgerProps(map[string]string{"uid": "img-1"})))

	db, errObj := unwrapPair(t, DbOpenDisk(stringObj(filepath.Join(*forgetChild, "graph"))))
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	unwrapPair(t, DbAddNode(db))
	memory, _ := unwrapPair(t, DbOpen())
	unwrapPair(t, DbAddNode(memory))

	for _, note := range CloseForgottenHandles() {
		fmt.Println("NOTE:", note)
	}
}

// M26-CUS-004. A program that forgot ledger_close or db_close left the store
// open until the process exited, and graphene recorded the next open as a
// restart after an unclean shutdown -- in a custody ledger, a permanent audit
// entry for a crash that never happened. The end of every program now closes
// what it left open and says which stores those were.
func TestAForgottenLedgerIsClosedAtTheEnd(t *testing.T) {
	if *forgetChild != "" {
		t.Skip("running as the child")
	}
	dir := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestForgetChild$", "-test.count=1", "-test.v",
		"-handles.forgetchild="+dir)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("the child failed: %v\n%s", err, output)
	}

	ledgerDir := filepath.Join(dir, "ledger")
	reopened := mustLedgerHash(t, BuiltinNameLedgerOpen, LedgerOpen(stringObj(ledgerDir), stringObj("examiner")))
	handle := mustHashIntValue(t, reopened, "handle")
	t.Cleanup(func() { LedgerClose(intObj(handle)) })
	stats := mustLedgerHash(t, BuiltinNameLedgerStats, LedgerStats(intObj(handle)))
	if entries := mustHashIntValue(t, stats, "audit_entries"); entries != 0 {
		t.Errorf("the reopened ledger holds %d audit entries: the forgotten handle was recorded as an unclean shutdown", entries)
	}

	notes := string(output)
	for _, want := range []string{ledgerDir, "ledger_close", filepath.Join(dir, "graph"), "db_close"} {
		if !strings.Contains(notes, want) {
			t.Errorf("what the program's end said does not name %q:\n%s", want, notes)
		}
	}
	if count := strings.Count(notes, "NOTE:"); count != 2 {
		t.Errorf("%d notes, want 2: one per forgotten store on disk, none for the in-memory graph:\n%s", count, notes)
	}
}
