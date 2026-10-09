package security

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The four rows of the exec-bounds kit: M26-TMP-006 (the timeout did not bound
// the call), M26-TMP-007 (the output was buffered whole), M26-TMP-008 (cmd.exe
// mangled the caller's quotes) and M26-TMP-009 (an empty command ran the shell
// and reported success).
//
// What runs where is deliberate. The string-building halves of 006 and 008 are
// pure functions and are checked on every host; the end-to-end halves need the
// platform whose behaviour they are about and are skipped elsewhere rather than
// faked.

// probeFeedBytes is how much output the memory property is measured over. The
// row asks for a hundred megabytes; this feeds it from one reused buffer, so
// nothing on the feeding side allocates and the growth measured is the
// writer's own.
const probeFeedBytes = 100 << 20

// probeFeedChunk is the slice handed to Write each time round. It is reused.
const probeFeedChunk = 64 << 10

// probeAllocCeiling is the allocation the capped writer is allowed over the
// whole feed. It keeps 8 KiB and counts the rest, so the true figure is the one
// kept buffer plus the one string built at the end; a megabyte of headroom
// leaves room for the test's own bookkeeping without leaving room for a
// regression. At HEAD the same feed cost 500 MiB.
const probeAllocCeiling = 1 << 20

// TestOutputIsCappedAsItArrivesAndNotAfterwards is M26-TMP-007. The cap used to
// be applied to a string built from a bytes.Buffer that had collected the whole
// output, so it bounded the answer and not the memory. Measured at HEAD, a
// command printing 64 MiB cost 320 MiB of allocation and a 257 MiB live heap to
// keep 8207 bytes of it.
func TestOutputIsCappedAsItArrivesAndNotAfterwards(t *testing.T) {
	w := newCappedWriter(resolveCommandExecMaxOutput())
	chunk := make([]byte, probeFeedChunk)
	for i := range chunk {
		chunk[i] = 'x'
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for fed := 0; fed < probeFeedBytes; fed += len(chunk) {
		n, err := w.Write(chunk)
		if err != nil {
			t.Fatalf("Write returned %v; the copying goroutine would stop and the command would block on a full pipe", err)
		}
		if n != len(chunk) {
			t.Fatalf("Write reported %d of %d bytes; io.Copy treats a short write as an error", n, len(chunk))
		}
	}

	text := w.text()
	runtime.ReadMemStats(&after)

	grew := after.TotalAlloc - before.TotalAlloc
	if grew > probeAllocCeiling {
		t.Fatalf("feeding %d bytes allocated %d; want at most %d", probeFeedBytes, grew, probeAllocCeiling)
	}
	if len(w.kept) != resolveCommandExecMaxOutput() {
		t.Fatalf("kept %d bytes, want the cap of %d", len(w.kept), resolveCommandExecMaxOutput())
	}
	if w.discarded != int64(probeFeedBytes-resolveCommandExecMaxOutput()) {
		t.Fatalf("counted %d discarded bytes, want %d", w.discarded, probeFeedBytes-resolveCommandExecMaxOutput())
	}
	if !strings.HasSuffix(text, truncatedOutputSuffix) {
		t.Fatalf("a cut stream is not marked as one: %q", text[max(0, len(text)-40):])
	}
	t.Logf("%d bytes in, %d bytes kept, %d bytes allocated", probeFeedBytes, len(w.kept), grew)
}

// TestOutputThatFitsIsNotMarkedOrAltered is the other half: the writer must be
// invisible when nothing was discarded, including for output that is not valid
// UTF-8. A complete answer is not the writer's to change.
func TestOutputThatFitsIsNotMarkedOrAltered(t *testing.T) {
	// 0xE4 alone is not a rune. It is also the whole of this command's output,
	// so it is an answer and not a cut.
	for _, body := range []string{"", "hi\n", string([]byte{0xE4}), string([]byte{0xE4, 0xB8})} {
		w := newCappedWriter(resolveCommandExecMaxOutput())
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if got := w.text(); got != body {
			t.Fatalf("output that fits came back as %q, want %q", got, body)
		}
	}
}

// TestACutStreamIsNotCutThroughARune is the rest of M26-TMP-007. The cap counts
// bytes and a rune is up to four of them, so the cut landed wherever it landed:
// truncateOutput("aaaaaaa" + four copies of a three-byte rune, 8) answered
// "aaaaaaa\xe4\n...[truncated]" at HEAD, which is not valid UTF-8 and which
// Mutant cannot print.
func TestACutStreamIsNotCutThroughARune(t *testing.T) {
	// One three-byte rune, built from its bytes so that nothing in the chain
	// between here and the file can have re-encoded it.
	wide := string([]byte{0xE4, 0xB8, 0xAD})

	for lead := 0; lead < 6; lead++ {
		body := strings.Repeat("a", lead) + strings.Repeat(wide, 8)
		w := newCappedWriter(8)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		got := w.text()
		if !utf8.ValidString(got) {
			t.Fatalf("lead=%d: the cut produced invalid UTF-8: %q", lead, got)
		}
		kept := strings.TrimSuffix(got, truncatedOutputSuffix)
		if kept == got {
			t.Fatalf("lead=%d: a cut stream is not marked as one: %q", lead, got)
		}
		// Nothing whole may be dropped: at most three bytes of a broken
		// sequence come off the end of what the cap kept.
		if len(kept) < 8-(utf8.UTFMax-1) || len(kept) > 8 {
			t.Fatalf("lead=%d: kept %d bytes of a cap of 8", lead, len(kept))
		}
		if !strings.HasPrefix(body, kept) {
			t.Fatalf("lead=%d: what was kept is not a prefix of the output: %q", lead, kept)
		}
	}
}

// TestAnEmptyCommandIsRefusedBeforeAnythingStarts is M26-TMP-009. An empty or
// blank command used to be handed to the shell, which started, read nothing and
// exited 0 -- measured at HEAD on all three of powershell, cmd and sh, each
// answering exit 0 with no error, which the builtin reports as ok true. The
// error string this package had written for the case was used nowhere.
func TestAnEmptyCommandIsRefusedBeforeAnythingStarts(t *testing.T) {
	for _, shell := range []string{"", "cmd", "sh", "bash", "powershell", "pwsh", "zsh"} {
		for _, command := range []string{"", " ", "\t\n ", "   "} {
			start := time.Now()
			result := ExecuteCommand(shell, command, "test:command_exec_bounds")
			elapsed := time.Since(start)

			if result.ErrorMessage != errorCommandEmpty {
				t.Errorf("shell=%q command=%q said %q, want %q",
					shell, command, result.ErrorMessage, errorCommandEmpty)
			}
			if result.ExitCode != -1 {
				t.Errorf("shell=%q command=%q exited %d, want -1: a refusal that reports 0 reads as a success",
					shell, command, result.ExitCode)
			}
			if result.TimedOut || result.Stdout != "" || result.Stderr != "" {
				t.Errorf("shell=%q command=%q: %+v", shell, command, result)
			}
			// No process started, so this cannot take as long as starting one.
			// A shell is tens of milliseconds at best; this is microseconds.
			if elapsed > 100*time.Millisecond {
				t.Errorf("shell=%q command=%q took %v, which is long enough to have started something",
					shell, command, elapsed)
			}
		}
	}
}

// TestACommandThatNeverRanDoesNotReportAProgramsExitCode covers the rest of the
// refusals, which M26-TMP-009 did not name but which had the same defect: a
// non-empty ErrorMessage next to ExitCode 0. A script reading exit_code alone
// -- which is what an exit code is for -- saw a success.
func TestACommandThatNeverRanDoesNotReportAProgramsExitCode(t *testing.T) {
	cases := []struct {
		what   string
		result CommandResult
	}{
		{"a shell name that is a path", ExecuteCommand("/bin/sh", "echo hi", "test:command_exec_bounds")},
		{"a shell name with an argument", ExecuteCommand("sh -c", "echo hi", "test:command_exec_bounds")},
		{"an empty argv", ExecuteArgv(nil, "test:command_exec_bounds")},
		{"an argv naming no program", ExecuteArgv([]string{"  "}, "test:command_exec_bounds")},
	}

	for _, tc := range cases {
		if tc.result.ErrorMessage == "" {
			t.Errorf("%s was not refused: %+v", tc.what, tc.result)
			continue
		}
		if tc.result.ExitCode != -1 {
			t.Errorf("%s exited %d, want -1", tc.what, tc.result.ExitCode)
		}
	}
}

// TestOnlyCmdGetsARawCommandLine is the portable half of M26-TMP-008: which
// shell has its command line written out, and what it says. Setting
// SysProcAttr.CmdLine turns off Go's argument escaping altogether, so the one
// shell it is done for, and the exact string, are worth pinning on every host
// rather than only where it takes effect.
func TestOnlyCmdGetsARawCommandLine(t *testing.T) {
	const command = `echo "a b"`

	for _, shell := range []string{"cmd", "batch"} {
		want := `cmd.exe /S /C "` + command + `"`
		if got := rawCommandLineFor(shell, command); got != want {
			t.Errorf("rawCommandLineFor(%q) = %q, want %q", shell, got, want)
		}
	}

	// Everything else keeps os/exec's escaping of the argv, which is correct
	// for a program that parses its command line the way the C runtime does
	// and is all there is off Windows.
	for _, shell := range []string{"powershell", "pwsh", "bash", "sh", "zsh", "fish", "dash"} {
		if got := rawCommandLineFor(shell, command); got != "" {
			t.Errorf("rawCommandLineFor(%q) = %q, want no raw command line", shell, got)
		}
	}

	// The /S has to be in the argv as well, so that the two spellings of the
	// same invocation agree -- the argv is what is used on the WSL interop
	// path, where the command line cannot be set.
	name, args, err := buildShellCommand("cmd", command)
	if err != nil {
		t.Fatal(err)
	}
	if name != cmdExecutable || len(args) != 3 || args[0] != cmdFlagQuoteStrip || args[1] != cmdFlagExec || args[2] != command {
		t.Fatalf("buildShellCommand(cmd) = %q %q", name, args)
	}
}

// TestCmdGetsTheQuotesTheCallerWrote is M26-TMP-008 end to end.
//
// Measured at HEAD: exec_string(`echo "a b"`, "cmd") printed `\"a b\"`,
// because os/exec escaped the argument the way the C runtime parses one and
// cmd.exe has no backslash escape at all. The quoting rule now is that the
// command reaches cmd.exe as written, which is what these cases state.
func TestCmdGetsTheQuotesTheCallerWrote(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe's command line is a Windows thing; on WSL the interop layer builds it")
	}

	cases := []struct{ command, want string }{
		{`echo "a b"`, `"a b"`},
		{`echo a b`, `a b`},
		{`echo "a"`, `"a"`},
		{`echo ""`, `""`},
		{`echo "a ""b"" c"`, `"a ""b"" c"`},
		{`echo a"b`, `a"b`},
		{`echo c:\`, `c:\`},
		{`echo \"x\"`, `\"x\"`},
	}

	for _, tc := range cases {
		result := ExecuteCommand("cmd", tc.command, "test:command_exec_bounds")
		if result.ErrorMessage != "" {
			t.Errorf("%s: %s", tc.command, result.ErrorMessage)
			continue
		}
		if got := strings.TrimRight(result.Stdout, "\r\n"); got != tc.want {
			t.Errorf("exec_string(%q, \"cmd\") printed %q, want %q", tc.command, got, tc.want)
		}
	}
}

// TestATimeoutBoundsTheCallAndNotJustOneProcess is M26-TMP-006, and the row
// this kit is for.
//
// Measured at HEAD on Windows: exec_string("ping -n 10 127.0.0.1", "cmd")
// returned after 9.1436496s against a 3-second timeout, with timed_out true and
// 725 bytes of the orphan's output in stdout. cmd.exe was killed on time;
// ping.exe inherited the output pipe, kept writing to it, and Wait does not
// return until that pipe reaches EOF.
//
// The bound asserted here is the timeout plus the wait delay plus slack for a
// shared host, which is what the fix promises. It is not a claim about the
// process tree -- TestATimedOutCommandLeavesNothingRunning is that.
func TestATimeoutBoundsTheCallAndNotJustOneProcess(t *testing.T) {
	shell, command := slowCommandThatLeavesAChildBehind(t)

	start := time.Now()
	result := ExecuteCommand(shell, command, "test:command_exec_bounds")
	elapsed := time.Since(start)

	if !result.TimedOut {
		t.Fatalf("%s %q did not time out: %+v", shell, command, result)
	}
	if result.ErrorMessage != errorCommandTimedOut {
		t.Errorf("a timeout said %q, want %q", result.ErrorMessage, errorCommandTimedOut)
	}
	if result.ExitCode != -1 {
		t.Errorf("a timeout exited %d, want -1", result.ExitCode)
	}

	bound := resolveCommandExecTimeout() + resolveCommandWaitDelay() + 2*time.Second
	if elapsed > bound {
		t.Fatalf("the call took %v against a %v timeout; want at most %v",
			elapsed, resolveCommandExecTimeout(), bound)
	}
	t.Logf("%s %q: %v (timeout %v, wait delay %v)",
		shell, command, elapsed, resolveCommandExecTimeout(), resolveCommandWaitDelay())
}

// TestATimedOutCommandLeavesNothingRunning is the other half of M26-TMP-006:
// not only is the call bounded, the processes are gone.
//
// It is checked by a side effect rather than by looking for a process, because
// this host is shared and a name is not an identity. The command starts a
// detached descendant whose whole job is to wait and then create a file, and
// then hangs until the deadline. If the kill reached the descendant the file
// never appears.
//
// What it proves differs by platform, and the README says so: on Windows the
// job object names the set exactly, so this holds on every path; on Unix the
// group kill happens at the deadline, which is the path this test takes.
func TestATimedOutCommandLeavesNothingRunning(t *testing.T) {
	marker, command, shell := orphanProbe(t)

	start := time.Now()
	result := ExecuteCommand(shell, command, "test:command_exec_bounds")
	if !result.TimedOut {
		t.Fatalf("the probe did not time out, so it proves nothing: %+v", result)
	}
	t.Logf("the call returned after %v", time.Since(start))

	// Longer than the descendant's own wait, counted from the call returning.
	time.Sleep(4 * time.Second)

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("%s was created after the call returned: something the command started outlived it", marker)
	}
}

// slowCommandThatLeavesAChildBehind is a command that outlasts the deadline and
// whose output pipe is held by a process that is not the shell -- which is the
// shape M26-TMP-006 is about. A shell that merely sleeps would be killed by the
// old code too.
func slowCommandThatLeavesAChildBehind(t *testing.T) (shell, command string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// ping is the one sleep every Windows has, and its output is not
		// redirected, so it is holding our stdout pipe.
		return shellCmd, "ping -n 30 127.0.0.1"
	}
	if _, err := exec.LookPath(shExec); err != nil {
		t.Skip("no sh on PATH")
	}
	// The backgrounded sleep inherits the pipe and is not the process the
	// deadline kills.
	return shellSh, "sleep 30 & sleep 30"
}

// orphanProbe returns a marker path that must never be created, a command that
// tries to create it from a descendant after the call has given up, and the
// shell to run it in.
func orphanProbe(t *testing.T) (marker, command, shell string) {
	t.Helper()
	dir := t.TempDir()

	if runtime.GOOS == "windows" {
		marker = dir + `\late.txt`
		// start /b detaches the inner cmd.exe from this one without opening a
		// window. It stays in the job, because nothing asks to break out of
		// one. The trailing ping is what holds this call open to the deadline,
		// and its output is not redirected, so it holds the output pipe too.
		//
		// The marker path is not quoted because t.TempDir gives a path under
		// the temporary directory with no spaces in it, and the one quote that
		// matters to /S is the last one on the line, which must be the
		// wrapper's own.
		command = `start /b cmd /c "ping -n 4 127.0.0.1 >nul & echo late > ` +
			marker + `" & ping -n 30 127.0.0.1`
		return marker, command, shellCmd
	}

	if _, err := exec.LookPath(shExec); err != nil {
		t.Skip("no sh on PATH")
	}
	marker = dir + "/late.txt"
	command = "(sleep 3; echo late > '" + marker + "') & sleep 30"
	return marker, command, shellSh
}
