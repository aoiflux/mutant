package main

// A program that ends on plaintext read out of a classified record, run the way
// an examiner runs it.
//
// This is the wiring half of the render guard. builtin's own tests hold
// WithheldEcho to its wording and vm's hold the renderers to theirs; what
// neither can show is that the three places which echo a finished program's
// value actually call it. Here the value goes through the real compile, the
// real VM and the real `mutant prog.mu` path, and what is asserted is what
// reached the terminal.
//
// It is also the only test in which the mark has to survive everything at once:
// the read, the binding to a name (every variable is stored encrypted, and that
// round trip is where the mark was dropped once before), and the echo.
//
// Each program binds the read to a name, closes the record, and ends on the
// variable. Binding it is deliberate: that is the EncryptObject/DecryptObject
// round trip the mark was dropped by once before. Closing it is what lets
// t.TempDir remove its own directory, since an open file cannot be unlinked on
// Windows -- and `os.MkdirTemp("", ...)` is not an alternative, because it
// reads TMP and policy's environment guard refuses that outside its allowlist.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/repl"
	"mutant/runner"
	"mutant/security"
)

// The exhibit: forty bytes, of which bytes 10..30 are classified `pii`. The
// plaintext is distinctive so that a leak of any part of it is unmistakable.
const (
	echoExhibit    = "0123456789VICTIM-EMAIL-ADDRESS0123456789"
	echoClassified = "VICTIM-EMAIL-ADDRESS"
)

// echoProgram seals the exhibit and ends on a read of its classified range, so
// the program's last value is a marked buffer and nothing else happens after.
const echoProgram = `let _, err = case_open("IR-2026-0413", "render guard test", {"hash": "sha256"});
if (err) { putln("[error] case_open:", err); };
let key, err = case_key_create("case.key");
if (err) { putln("[error] case_key_create:", err); };
let _, err = case_key_open("case.key");
if (err) { putln("[error] case_key_open:", err); };
let _, err = class_define("open");
if (err) { putln("[error] class_define open:", err); };
let _, err = class_define("pii");
if (err) { putln("[error] class_define pii:", err); };
let pii, err = record_classify_range(10, 20, "pii");
if (err) { putln("[error] record_classify_range:", err); };
let sealed, err = record_seal("exhibit.bin", "exhibit.mrec", [pii], {"default": "open"});
if (err) { putln("[error] record_seal:", err); };
let opened, err = record_open("exhibit.mrec");
if (err) { putln("[error] record_open:", err); };
let record = opened["handle"];
putln("sealed and opened");

// Bound to a name, so the buffer has been through EncryptObject and
// DecryptObject -- the round trip where the mark was dropped once before --
// and the record is closed before the program ends on it.
let data, err = record_read(record, 10, 20);
if (err) { putln("[error] record_read:", err); };
let _, err = record_close(record);
if (err) { putln("[error] record_close:", err); };
data;
`

// closeTheCase gives the case back when the test is done.
//
// One process holds one case: case_open refuses while another is open and so
// does case_key_open. Two of the programs here end on the value under test and
// so never reach a case_close of their own, which would leave the case open for
// whatever ran next -- and did, until this was added.
func closeTheCase(t *testing.T) {
	t.Cleanup(func() { builtin.CaseClose() })
}

// echoLeaks reports whether text carries the classified plaintext, as text or
// as the hex a buffer's Inspect renders it in.
func echoLeaks(text string) bool {
	const hexDigits = "0123456789abcdef"
	var hex strings.Builder
	for _, b := range []byte(echoClassified) {
		hex.WriteByte(hexDigits[b>>4])
		hex.WriteByte(hexDigits[b&0x0f])
	}
	// Eight bytes of hex is sixteen characters, which is past any cap and short
	// enough to survive a truncation.
	return strings.Contains(text, echoClassified) ||
		strings.Contains(text, hex.String()[:16])
}

func TestAProgramEndingOnClassifiedPlaintextIsNotEchoed(t *testing.T) {
	work := t.TempDir()
	security.SetLocalKeyStoreDirForTesting(filepath.Join(work, "keys"))
	t.Cleanup(func() { security.SetLocalKeyStoreDirForTesting("") })
	closeTheCase(t)

	if err := os.WriteFile(filepath.Join(work, "exhibit.bin"), []byte(echoExhibit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "echo.mut"), []byte(echoProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	// case_key_create chooses a passphrase and confirms it; case_key_open
	// straight after reuses the answer rather than asking again.
	source, prompts, _ := scriptedSource(t, "case key passphrase", "case key passphrase")
	realRun := runtimeDeps.runCode
	runtimeDeps.runCode = func(path string, options runner.Options) int {
		security.SetPassphraseSource(source)
		return realRun(path, options)
	}
	t.Cleanup(func() { runtimeDeps.runCode = realRun })

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "echo.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the program did not compile (exit %d):\n%s", code, stderr)
	}

	// The echo goes to os.Stdout directly rather than through builtin's output
	// sink, so capturing the sink would not see it.
	var printed string
	stderr = captureStderr(t, func() {
		printed = captureStdout(t, func() { code = run([]string{"mutant", "echo.mu", "--dev"}) })
	})
	if code != 0 || strings.Contains(printed, "[error]") {
		t.Fatalf("the program failed (exit %d)\nstdout:\n%s\nstderr:\n%s\nprompts:\n%s",
			code, printed, stderr, prompts.String())
	}
	if !strings.Contains(printed, "sealed and opened") {
		t.Fatalf("the program did not get as far as sealing:\nstdout:\n%s\nstderr:\n%s", printed, stderr)
	}

	// The whole of it: not the plaintext, not its hex, and a notice that says
	// which record was withheld and how to release it deliberately.
	if strings.Contains(printed, echoClassified) {
		t.Errorf("the echo printed the classified plaintext:\n%s", printed)
	}
	if strings.Contains(printed, "564943544" /* "VICT" as hex, lower case */) {
		t.Errorf("the echo printed the classified plaintext as hex:\n%s", printed)
	}
	if !strings.Contains(printed, "not echoed") || !strings.Contains(printed, "record_release") {
		t.Errorf("the echo did not say that it withheld a value and how to release it:\n%s", printed)
	}
	if !strings.Contains(printed, "20 bytes of plaintext read from record") {
		t.Errorf("the notice does not say what it stood in for:\n%s", printed)
	}
}

// The same program, ending on something unmarked, is echoed as it always was.
// A guard that withheld everything would pass the test above.
func TestAProgramEndingOnAnUnmarkedValueIsStillEchoed(t *testing.T) {
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "plain.mut"),
		[]byte("putln(\"running\");\n2 + 40;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "plain.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the program did not compile (exit %d):\n%s", code, stderr)
	}

	var printed string
	captureStderr(t, func() {
		printed = captureStdout(t, func() { code = run([]string{"mutant", "plain.mu", "--dev"}) })
	})
	if code != 0 {
		t.Fatalf("the program failed (exit %d):\n%s", code, printed)
	}
	if !strings.Contains(printed, "42") {
		t.Fatalf("an unmarked value was not echoed:\n%s", printed)
	}
}

// A classified buffer passed to a function that fails.
//
// M26-VM-011 names two ways the rendering gets out: the traceback printed to
// stderr, and err.Stack, which stampError fills from the same rendered
// arguments and which a program can read as an array of plain STRINGs that no
// sink refuses. Both come from frameArguments, so one guarded renderer settles
// both -- and this is the test that says so, because it reads the error object
// from inside the program as well as reading what was printed.
const echoTracebackProgram = `let _, err = case_open("IR-2026-0414", "render guard test", {"hash": "sha256"});
if (err) { putln("[error] case_open:", err); };
let key, err = case_key_create("case.key");
if (err) { putln("[error] case_key_create:", err); };
let _, err = case_key_open("case.key");
if (err) { putln("[error] case_key_open:", err); };
let _, err = class_define("open");
if (err) { putln("[error] class_define open:", err); };
let _, err = class_define("pii");
if (err) { putln("[error] class_define pii:", err); };
let pii, err = record_classify_range(10, 20, "pii");
if (err) { putln("[error] record_classify_range:", err); };
let sealed, err = record_seal("exhibit.bin", "exhibit.mrec", [pii], {"default": "open"});
if (err) { putln("[error] record_seal:", err); };
let opened, err = record_open("exhibit.mrec");
if (err) { putln("[error] record_open:", err); };
let data, err = record_read(opened["handle"], 10, 20);
if (err) { putln("[error] record_read:", err); };
let _, err = record_close(opened["handle"]);
if (err) { putln("[error] record_close:", err); };
putln("read the exhibit");

// First the soft failure: a builtin error carries a stack, and a program reads
// e.stack as an array of plain STRINGs that no sink refuses. The row's own
// verification wrote that array to a file and the file held the plaintext.
let reads_a_missing_file = fn(buffer) {
	let v, e = fs_read("Z:/no/such/directory/evidence.bin");
	return e;
};
let soft = reads_a_missing_file(data);
putln("stack:", soft.stack);

// Then the fatal one. The buffer is this function's parameter, so it is what
// the traceback renders.
let fails = fn(buffer) {
	return len(buffer) / 0;
};
fails(data);
`

func TestATracebackDoesNotRenderClassifiedPlaintext(t *testing.T) {
	work := t.TempDir()
	security.SetLocalKeyStoreDirForTesting(filepath.Join(work, "keys"))
	t.Cleanup(func() { security.SetLocalKeyStoreDirForTesting("") })
	closeTheCase(t)

	if err := os.WriteFile(filepath.Join(work, "exhibit.bin"), []byte(echoExhibit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "tb.mut"), []byte(echoTracebackProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	source, prompts, _ := scriptedSource(t, "case key passphrase", "case key passphrase")
	realRun := runtimeDeps.runCode
	runtimeDeps.runCode = func(path string, options runner.Options) int {
		security.SetPassphraseSource(source)
		return realRun(path, options)
	}
	t.Cleanup(func() { runtimeDeps.runCode = realRun })

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "tb.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the program did not compile (exit %d):\n%s", code, stderr)
	}

	// The program is meant to fail: the traceback is the output under test.
	var printed string
	stderr = captureStderr(t, func() {
		printed = captureStdout(t, func() { code = run([]string{"mutant", "tb.mu", "--dev"}) })
	})
	if strings.Contains(printed, "[error]") {
		t.Fatalf("the program failed before the division:\nstdout:\n%s\nstderr:\n%s\nprompts:\n%s",
			printed, stderr, prompts.String())
	}
	if !strings.Contains(printed, "read the exhibit") {
		t.Fatalf("the program did not get as far as reading:\nstdout:\n%s\nstderr:\n%s", printed, stderr)
	}
	// A runtime error's report is not guaranteed to land on one stream, and
	// which one it is is not what this test is about: what matters is that
	// nothing anywhere carries the plaintext.
	both := printed + "\n" + stderr
	if !strings.Contains(both, "division by zero") {
		t.Fatalf("the program was expected to fail with a division by zero:\nstdout:\n%s\nstderr:\n%s",
			printed, stderr)
	}
	if !strings.Contains(both, "at fails(") {
		t.Fatalf("the traceback does not name the frame the buffer was passed to:\nstdout:\n%s\nstderr:\n%s",
			printed, stderr)
	}
	if echoLeaks(both) {
		t.Errorf("the traceback rendered the classified plaintext:\nstdout:\n%s\nstderr:\n%s",
			printed, stderr)
	}
	if !strings.Contains(both, "20 bytes of plaintext read from record") {
		t.Errorf("the traceback does not say what it withheld:\nstdout:\n%s\nstderr:\n%s",
			printed, stderr)
	}

	// The e.stack leg: the program printed the array itself, which is plain
	// strings and which no sink refuses, so what those strings hold is the
	// whole of the protection.
	if !strings.Contains(printed, "stack:") {
		t.Fatalf("the program did not print e.stack:\nstdout:\n%s", printed)
	}
	stack := printed[strings.Index(printed, "stack:"):]
	if echoLeaks(stack) {
		t.Errorf("e.stack carries the classified plaintext, and no sink refuses a string:\n%s", stack)
	}
	if !strings.Contains(stack, "20 bytes of plaintext read from record") {
		t.Errorf("e.stack does not say what it withheld:\n%s", stack)
	}
}

// The REPL echoes every line's value, which makes it the shortest route from a
// classified record to a terminal: one `record_read(h, 10, 20)` typed at the
// prompt printed the buffer whole. M26-REC-006's fix proposal asks for this
// test by name.
func TestTheReplDoesNotEchoClassifiedPlaintext(t *testing.T) {
	work := t.TempDir()
	security.SetLocalKeyStoreDirForTesting(filepath.Join(work, "keys"))
	t.Cleanup(func() { security.SetLocalKeyStoreDirForTesting("") })
	closeTheCase(t)

	if err := os.WriteFile(filepath.Join(work, "exhibit.bin"), []byte(echoExhibit), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	source, _, _ := scriptedSource(t, "case key passphrase", "case key passphrase")
	previous := security.SetPassphraseSource(source)
	t.Cleanup(func() { security.SetPassphraseSource(previous) })

	// The same sequence as the program above, typed a line at a time, ending on
	// the read so that the REPL's own echo is what is under test.
	lines := strings.Join([]string{
		`case_open("IR-2026-0415", "render guard test", {"hash": "sha256"});`,
		`case_key_create("case.key");`,
		`case_key_open("case.key");`,
		`class_define("open");`,
		`class_define("pii");`,
		`let pii, err = record_classify_range(10, 20, "pii");`,
		`record_seal("exhibit.bin", "exhibit.mrec", [pii], {"default": "open"});`,
		`let opened, err = record_open("exhibit.mrec");`,
		`let data, err = record_read(opened["handle"], 10, 20);`,
		`record_close(opened["handle"]);`,
		`data;`,
		// No `exit`: the REPL's exit command calls os.Exit, which would end
		// the test binary. End of input is how Start returns.
	}, "\n") + "\n"

	var out bytes.Buffer
	repl.Start(strings.NewReader(lines), &out, "test", false, "")
	echoed := out.String()

	if !strings.Contains(echoed, "20 bytes of plaintext read from record") {
		t.Fatalf("the REPL did not withhold the buffer it read:\n%s", echoed)
	}
	if echoLeaks(echoed) {
		t.Errorf("the REPL echoed the classified plaintext:\n%s", echoed)
	}
	if !strings.Contains(echoed, "record_release") {
		t.Errorf("the REPL did not say how to release the value deliberately:\n%s", echoed)
	}
}
