package builtin

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// recordCrashChild is set only when TestAKilledSealLeavesNoPartialRecord runs
// this test binary again as the process to kill. It is a flag and not an
// environment variable because this tree takes no configuration from the
// environment, its tests included.
var recordCrashChild = flag.String("record.crashchild", "", "internal: seal a record into this directory and exit mid-seal")

// recordCrashExit is the child's exit status when it stopped where it was told.
const recordCrashExit = 3

// TestRecordCrashChild is the child: it seals a record of several segments and
// ends the process after the first one is written, as a kill or a power cut
// would -- no deferred call runs and nothing is cleaned up.
func TestRecordCrashChild(t *testing.T) {
	if *recordCrashChild == "" {
		t.Skip("the child half of TestAKilledSealLeavesNoPartialRecord")
	}
	// recordTestCase's own temporary directory would outlive an os.Exit, so the
	// case key goes where the parent will clean up.
	openTestCase(t, "IR-REC", "examiner")
	stubPassphrase(t, "correct horse battery staple")
	key := filepath.Join(*recordCrashChild, "case.mkey")
	mustHash(t, CaseKeyCreate(stringObj(key)))
	mustHash(t, CaseKeyOpen(stringObj(key)))
	mustHash(t, ClassDefine(stringObj("open")))
	source := filepath.Join(*recordCrashChild, "evidence.bin")
	if err := os.WriteFile(source, make([]byte, 400), 0o600); err != nil {
		t.Fatal(err)
	}
	recordSealInterrupt = func() { os.Exit(recordCrashExit) }
	RecordSeal(stringObj(source), stringObj(filepath.Join(*recordCrashChild, "evidence.mrec")),
		recordArray(), recordSealOpts(nil))
	t.Fatal("the seal finished without reaching the interrupt")
}

// M26-REC-004. record_seal wrote the record under its final name and removed it
// only when it saw an error, so a process killed mid-seal left a partial .mrec
// with a valid header where a complete one was expected. The seal now writes a
// temporary file beside it and renames that over the name, which it holds
// reserved and empty until then: what a crash leaves under the name is either
// nothing or an empty file the reader refuses, never part of a record.
func TestAKilledSealLeavesNoPartialRecord(t *testing.T) {
	if *recordCrashChild != "" {
		t.Skip("running as the child")
	}
	dir := t.TempDir()
	// The child derives a case key, which is a 256 MiB Argon2id run, and this
	// process may be holding the freed heap of every derivation the tests
	// before it made. On a 2 GiB host the two together met the OOM killer, so
	// that heap goes back to the system before the child starts.
	debug.FreeOSMemory()
	child := exec.Command(os.Args[0], "-test.run=^TestRecordCrashChild$", "-test.count=1",
		"-record.crashchild="+dir)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != recordCrashExit {
		t.Fatalf("the child did not stop mid-seal (%v):\n%s", err, output)
	}

	dest := filepath.Join(dir, "evidence.mrec")
	info, err := os.Stat(dest)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		t.Fatal(err)
	case info.Size() != 0:
		t.Fatalf("a killed seal left %d bytes of a record under its final name", info.Size())
	}
	session, errObj := recordLoad("record_open", dest)
	if errObj == nil {
		session.file.Close()
		t.Fatal("the empty file a killed seal leaves was opened as a record")
	}
	if !strings.Contains(errObj.Message, "interrupted") {
		t.Errorf("the refusal of the empty file does not say a seal was interrupted: %s", errObj.Message)
	}
}
