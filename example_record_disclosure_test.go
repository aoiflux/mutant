package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/runner"
	"mutant/security"
)

// examples/forensics/record_disclosure.mut, run the way an examiner runs it:
// compiled and executed through the command line, with every passphrase typed
// at a terminal -- here a scripted one.
//
// It is the one test that takes the record and disclosure families through the
// real VM rather than calling builtins directly, and that difference is not
// academic: it is how the Classified mark was found to be dropped whenever a
// buffer was bound to a variable, because every variable is stored encrypted
// and the round trip rebuilt the buffer from its bytes alone. Every builtin
// test passed, and in a real program every sink passed the plaintext through.
func TestTheRecordDisclosureExampleRunsEndToEnd(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	security.SetLocalKeyStoreDirForTesting(filepath.Join(work, "keys"))
	t.Cleanup(func() { security.SetLocalKeyStoreDirForTesting("") })

	copyInto := func(from, to string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, from))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(work, to)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, to), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyInto(filepath.Join("examples", "data", "phish.eml"), filepath.Join("examples", "data", "phish.eml"))
	copyInto(filepath.Join("examples", "forensics", "record_disclosure.mut"), "record_disclosure.mut")
	t.Chdir(work)

	// The case key's passphrase, chosen and confirmed; each grant's, chosen and
	// confirmed; and the counsel grant's once more, typed by the recipient.
	source, prompts, asked := scriptedSource(t,
		"case key passphrase", "case key passphrase",
		"counsel grant passphrase", "counsel grant passphrase",
		"desk grant passphrase", "desk grant passphrase",
		"counsel grant passphrase")
	// run() installs the terminal source on every call; this one replaces it
	// just before the program starts.
	realRun := runtimeDeps.runCode
	runtimeDeps.runCode = func(path string, options runner.Options) int {
		security.SetPassphraseSource(source)
		return realRun(path, options)
	}
	t.Cleanup(func() { runtimeDeps.runCode = realRun })

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "record_disclosure.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the example did not compile (exit %d):\n%s", code, stderr)
	}
	var out bytes.Buffer
	restore := builtin.SetOutput(&out)
	stderr = captureStderr(t, func() { code = run([]string{"mutant", "record_disclosure.mu", "--dev"}) })
	restore()
	printed := out.String()
	if code != 0 || strings.Contains(printed, "[error]") {
		t.Fatalf("the example failed (exit %d)\nstdout:\n%s\nstderr:\n%s\nprompts:\n%s",
			code, printed, stderr, prompts.String())
	}

	for _, want := range []string{
		// The mark survived being held in a variable, and the refusal names the
		// argument, the record and the class.
		`fs_write: argument 2 holds 19 bytes of plaintext read from record`,
		`classified "pii"`,
		"released 19 bytes",
		// Each view withholds exactly the other's class.
		"bytes 1275 + 178  class: restricted",
		"bytes 551 + 19  class: pii",
		// The recipient's side.
		"checks passed: 10 of 10",
		"verified with no root: false",
		"finding: ledger_inclusion:",
		"counsel reads the record with 178 of 1471 bytes withheld",
		// The ledger's answer to who holds what.
		"view: counsel  segments: 0-2,4  bytes recoverable: false",
		"view: malware-desk  segments: 0,2-4  bytes recoverable: false",
		"signed: true",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("the example's output does not contain %q:\n%s", want, printed)
		}
	}
	// Nothing the example prints -- refusals included -- carries the address or
	// the malware it classified.
	for _, plaintext := range []string{"finance@example.org", "TVqQ"} {
		if strings.Contains(printed, plaintext) {
			t.Errorf("the output contains classified plaintext %q", plaintext)
		}
	}
	if *asked != 7 {
		t.Errorf("the terminal was asked %d times, want 7:\n%s", *asked, prompts.String())
	}
}
