//go:build !releaseassetsgen

package releaseassets

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// errHalfRead stands for a read that fails for a reason other than the file not
// being there: a truncated embed, an unreadable one. It is deliberately not
// fs.ErrNotExist, because the whole point of the split below is that those two
// faults get different advice.
var errHalfRead = errors.New("read stopped halfway")

type brokenRuntimeFS struct{}

func (brokenRuntimeFS) Open(name string) (fs.File, error) {
	return nil, errHalfRead
}

// Get's failure messages are the only thing a reader has to act on, so each
// branch has to name the remedy that fits it.
//
// The branch that matters most is the one a plain `go build` or `go install`
// produces. .gitignore keeps releaseassets/data/ out of the repository and
// un-ignores only placeholder.bin, so a binary built that way carries a
// manifest naming seven files its embedded filesystem does not hold. That used
// to be reported as the asset being "invalid", which named no way out and sent
// the reader looking for a corrupt file that was never there -- while the one
// message that did name a remedy sat on a branch they could not reach, because
// the manifest is committed and complete (M26-DOC1-003).
func TestMissingRuntimeAssetNamesItsRemedy(t *testing.T) {
	original := runtimeAssetFS
	t.Cleanup(func() { runtimeAssetFS = original })
	runtimeAssetFS = missingRuntimeFS{}

	_, err := Get("windows", "amd64")
	if err == nil {
		t.Fatal("Get succeeded against an asset filesystem that holds nothing; there is no message to check")
	}
	msg := err.Error()

	// Both remedies, because the reader is on one of two platforms and only one
	// of the two commands is theirs to run.
	for _, want := range []string{"mutant gen assets", "scripts/build.sh", "scripts/build.ps1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message for an asset that was never embedded does not mention %q, so it tells the reader what is wrong and not what to do about it.\ngot: %s", want, msg)
		}
	}

	// Naming the cause is what stops the reader hunting for a corrupt file.
	if !strings.Contains(msg, "go install") {
		t.Errorf("the message does not say that a plain go build or go install is what produces this, which is the one fact that identifies the reader's own mistake.\ngot: %s", msg)
	}
	if strings.Contains(msg, "is invalid") {
		t.Errorf("an asset that was never embedded is still being called invalid. Nothing is invalid: the file is absent, and the two need different advice.\ngot: %s", msg)
	}
}

// The other half of the split. A read that fails any other way is a real
// corruption, and saying so is correct -- if this ever starts advising a
// rebuild, a genuinely broken embed is being blamed on the build command.
func TestCorruptRuntimeAssetIsStillReportedAsCorrupt(t *testing.T) {
	original := runtimeAssetFS
	t.Cleanup(func() { runtimeAssetFS = original })
	runtimeAssetFS = brokenRuntimeFS{}

	_, err := Get("windows", "amd64")
	if err == nil {
		t.Fatal("Get succeeded against an asset filesystem that fails every read")
	}
	if !errors.Is(err, errHalfRead) {
		t.Errorf("the underlying read error was not wrapped, so the cause is lost: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "is invalid") {
		t.Errorf("a read that failed for a reason other than absence is no longer reported as invalid.\ngot: %s", msg)
	}
	if strings.Contains(msg, "scripts/build.sh") {
		t.Errorf("a corrupt asset is being blamed on the build command, which will send someone to rebuild a tree that is not the problem.\ngot: %s", msg)
	}
}

// A target the manifest does not name at all is a third case, and it is the one
// branch that needs no filesystem to reach -- which is why it is checked
// without swapping anything. It has always named a remedy; this holds it to the
// spelling the CLI actually accepts. `mutant gen --release-assets` still works
// but main.go documents it as the legacy form of `mutant gen assets`.
func TestUnknownTargetNamesTheCurrentSpelling(t *testing.T) {
	_, err := Get("plan9", "mips")
	if err == nil {
		t.Fatal("Get succeeded for plan9/mips, which the manifest does not name")
	}
	msg := err.Error()
	if !strings.Contains(msg, "mutant gen assets") {
		t.Errorf("the message for an unknown target does not name `mutant gen assets`.\ngot: %s", msg)
	}
	if strings.Contains(msg, "--release-assets") {
		t.Errorf("the message still names the legacy flag form rather than the subcommand.\ngot: %s", msg)
	}
}
