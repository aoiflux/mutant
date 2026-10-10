package security

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// M26-NET-018. A command builder collects lines; cmd_run joined them with "\n"
// and handed the result to whichever shell was named. cmd.exe reads its command
// from a command line, and a command line ends at the first newline, so every
// line after the first was dropped -- and the result still said ok with
// exit_code 0, which is the half that makes it a defect rather than a
// limitation.
//
// The tests below are in two halves on purpose. The first half checks the
// string this package now builds, which is where the decision lives and which
// runs on every platform. The second half runs real shells, because a
// separator that looks right and that the shell reads differently is exactly
// the failure this row was.

// TestTheLinesAreJoinedWithWhatTheShellReads pins the separator per shell. The
// OS is an argument so that both answers are checkable from one host: the Unix
// default never having been run anywhere is how M26-TMP-005 survived.
func TestTheLinesAreJoinedWithWhatTheShellReads(t *testing.T) {
	lines := []string{"echo FIRST", "echo SECOND"}

	cases := []struct {
		goos  string
		shell string
		want  string
	}{
		// cmd.exe and its other name, on which a newline ends the command.
		{"windows", "cmd", "echo FIRST&echo SECOND"},
		{"windows", "batch", "echo FIRST&echo SECOND"},
		{"linux", "cmd", "echo FIRST&echo SECOND"},
		// Spelling is normalised before the shell is matched, so these are the
		// same shell and must get the same separator. CmdBuilder stores the
		// caller's spelling untouched, which is how a mixed-case name reaches
		// here at all.
		{"windows", "CMD", "echo FIRST&echo SECOND"},
		{"windows", "  Cmd  ", "echo FIRST&echo SECOND"},
		// Every other shell reads a newline as the end of a statement.
		{"windows", "powershell", "echo FIRST\necho SECOND"},
		{"windows", "pwsh", "echo FIRST\necho SECOND"},
		{"linux", "sh", "echo FIRST\necho SECOND"},
		{"linux", "bash", "echo FIRST\necho SECOND"},
		{"linux", "zsh", "echo FIRST\necho SECOND"},
		// An empty name means the host's default, which is why the OS is read
		// at all: powershell on Windows, sh elsewhere, and neither is cmd.
		{"windows", "", "echo FIRST\necho SECOND"},
		{"linux", "", "echo FIRST\necho SECOND"},
		{"darwin", "", "echo FIRST\necho SECOND"},
	}

	for _, tc := range cases {
		if got := joinShellLinesFor(tc.goos, tc.shell, lines); got != tc.want {
			t.Errorf("joinShellLinesFor(%q, %q) = %q, want %q", tc.goos, tc.shell, got, tc.want)
		}
	}

	// The exported form answers for this host, and this host is the one the
	// suite runs on.
	if got := JoinShellLines("cmd", lines); got != "echo FIRST&echo SECOND" {
		t.Errorf("JoinShellLines(cmd) = %q", got)
	}
}

// TestTheJoinAddsNothingToALinesOwnText is why the separator carries no spaces.
// cmd's echo prints everything up to the separator, so " & " put a space on the
// end of every line's output but the last -- measured, `echo FIRST & echo
// SECOND` printed "FIRST \r\nSECOND\r\n". A line's own trailing space is a
// different thing and is kept, because the caller wrote that one.
func TestTheJoinAddsNothingToALinesOwnText(t *testing.T) {
	cases := []struct {
		lines []string
		want  string
	}{
		{[]string{"echo A"}, "echo A"},
		{[]string{"echo A", "echo B"}, "echo A&echo B"},
		{[]string{"echo A", "echo B", "echo C"}, "echo A&echo B&echo C"},
		// The caller's own spacing, kept exactly.
		{[]string{"echo A ", "echo B"}, "echo A &echo B"},
		{[]string{"echo A", " echo B"}, "echo A& echo B"},
		// A single line is handed over as it stands, whatever is in it.
		{[]string{`echo "a b"`}, `echo "a b"`},
		{[]string{`echo a^&b`, "echo B"}, `echo a^&b&echo B`},
	}

	for _, tc := range cases {
		if got := joinShellLinesFor("windows", "cmd", tc.lines); got != tc.want {
			t.Errorf("joinShellLinesFor(cmd, %q) = %q, want %q", tc.lines, got, tc.want)
		}
	}
}

// TestABlankLineIsLeftOutOfACmdCommand covers the one thing the cmd join drops.
// A blank line does nothing in any other shell; in this one "&" with nothing
// beside it is a syntax error that costs the whole command, not just the blank
// line -- `&echo B` answers "& was unexpected at this time." and runs neither
// line. Leaving it out drops nothing that would have happened.
func TestABlankLineIsLeftOutOfACmdCommand(t *testing.T) {
	cases := []struct {
		lines []string
		want  string
	}{
		{[]string{"", "echo B"}, "echo B"},
		{[]string{"echo A", "", "echo B"}, "echo A&echo B"},
		{[]string{"echo A", ""}, "echo A"},
		{[]string{"echo A", "   ", "echo B"}, "echo A&echo B"},
		{[]string{"echo A", "\t", "echo B"}, "echo A&echo B"},
		// Every line blank leaves nothing, which ExecuteCommand refuses as an
		// empty command -- the answer a "\n"-joined blank script already got.
		{[]string{""}, ""},
		{[]string{"", "  "}, ""},
	}

	for _, tc := range cases {
		if got := joinShellLinesFor("windows", "cmd", tc.lines); got != tc.want {
			t.Errorf("joinShellLinesFor(cmd, %q) = %q, want %q", tc.lines, got, tc.want)
		}
	}

	// A shell that reads newlines keeps the blank line, because there it is a
	// statement separator doing its job and nothing is wrong with it.
	if got := joinShellLinesFor("linux", "sh", []string{"echo A", "", "echo B"}); got != "echo A\n\necho B" {
		t.Errorf("a blank line was dropped for sh: %q", got)
	}
}

// TestEveryLineReallyRunsUnderCmd is the row's own case, end to end through a
// real cmd.exe. The expectation is written out here rather than derived from
// the join, because a join and an assertion that agree with each other and not
// with the shell is what the "\n" version was.
func TestEveryLineReallyRunsUnderCmd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe is a Windows shell; the join itself is checked above on every platform")
	}

	for _, shell := range []string{"cmd", "batch"} {
		result := ExecuteCommand(shell, JoinShellLines(shell, []string{"echo FIRST", "echo SECOND"}), "test:command_exec_lines")
		if result.ErrorMessage != "" {
			t.Errorf("%s: %s", shell, result.ErrorMessage)
			continue
		}
		if result.ExitCode != 0 {
			t.Errorf("%s exited %d, stderr %q", shell, result.ExitCode, result.Stderr)
			continue
		}
		// Both lines, in order, and neither carrying a space the caller did
		// not write.
		if result.Stdout != "FIRST\r\nSECOND\r\n" {
			t.Errorf("%s printed %q, want \"FIRST\\r\\nSECOND\\r\\n\"", shell, result.Stdout)
		}
	}

	// Three lines, to show the separator is not a special case of two.
	result := ExecuteCommand("cmd", JoinShellLines("cmd", []string{"echo ONE", "echo TWO", "echo THREE"}), "test:command_exec_lines")
	if result.Stdout != "ONE\r\nTWO\r\nTHREE\r\n" {
		t.Errorf("three lines printed %q", result.Stdout)
	}

	// A quoted argument has to survive the join as well as the /S quote pair
	// rawCommandLineFor wraps the whole command in (M26-TMP-008).
	result = ExecuteCommand("cmd", JoinShellLines("cmd", []string{`echo "a b"`, "echo SECOND"}), "test:command_exec_lines")
	if result.Stdout != "\"a b\"\r\nSECOND\r\n" {
		t.Errorf("a quoted argument before the separator printed %q", result.Stdout)
	}

	// And a caller who wants a literal ampersand escapes it cmd's way, which
	// the join leaves alone.
	result = ExecuteCommand("cmd", JoinShellLines("cmd", []string{`echo a^&b`, "echo SECOND"}), "test:command_exec_lines")
	if result.Stdout != "a&b\r\nSECOND\r\n" {
		t.Errorf("an escaped ampersand printed %q", result.Stdout)
	}
}

// TestEveryLineRunsUnderTheShellsThatAlreadyWorked is the parity half: the
// shells a newline already worked for must still behave exactly as they did,
// since their join did not change.
func TestEveryLineRunsUnderTheShellsThatAlreadyWorked(t *testing.T) {
	type want struct {
		shell  string
		stdout string
	}
	cases := []want{}
	if runtime.GOOS == "windows" {
		cases = append(cases, want{"powershell", "FIRST\r\nSECOND\r\n"})
	}
	for _, posix := range []string{"sh", "bash"} {
		if _, err := exec.LookPath(posix); err != nil {
			t.Logf("no %s on PATH; skipping that one", posix)
			continue
		}
		cases = append(cases, want{posix, "FIRST\nSECOND\n"})
	}
	if len(cases) == 0 {
		t.Skip("no shell on this host reads a newline")
	}

	for _, tc := range cases {
		result := ExecuteCommand(tc.shell, JoinShellLines(tc.shell, []string{"echo FIRST", "echo SECOND"}), "test:command_exec_lines")
		if result.ErrorMessage != "" {
			t.Errorf("%s: %s", tc.shell, result.ErrorMessage)
			continue
		}
		if result.Stdout != tc.stdout {
			t.Errorf("%s printed %q, want %q", tc.shell, result.Stdout, tc.stdout)
		}
	}
}

// TestAnAllBlankBuilderIsRefusedRatherThanRun pins the end of the blank-line
// rule. Dropping the blank lines must not turn a builder with nothing to run
// into a shell that starts, reads nothing and exits 0 -- which is the defect
// M26-TMP-009 already closed for exec_string("").
func TestAnAllBlankBuilderIsRefusedRatherThanRun(t *testing.T) {
	for _, shell := range []string{"cmd", "powershell", "sh"} {
		command := JoinShellLines(shell, []string{"", "   "})
		result := ExecuteCommand(shell, command, "test:command_exec_lines")
		if result.ErrorMessage != errorCommandEmpty {
			t.Errorf("%s: blank lines gave %+v, want the empty-command refusal", shell, result)
		}
		if result.ExitCode != -1 {
			t.Errorf("%s: blank lines exited %d, want -1", shell, result.ExitCode)
		}
	}
}

// TestAFailedLineDoesNotStopTheRestUnderCmd states the exit-code rule, which is
// the shell's and not this package's, and states it the same way for cmd as the
// shells that already worked state it for themselves. "&&" would have stopped
// at the first failure and would therefore have made the same builder mean two
// different things depending on the shell named.
func TestAFailedLineDoesNotStopTheRestUnderCmd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe is a Windows shell")
	}

	// The failing line is measured on its own first. A test for "the next line
	// still runs" that uses a line which happens to succeed passes while
	// proving nothing, and a missing program is the one failure cmd reports the
	// same way every time -- a missing path given to `dir` is not.
	const missing = "mutant-no-such-program-exists"
	alone := ExecuteCommand("cmd", missing, "test:command_exec_lines")
	if alone.ExitCode == 0 {
		t.Fatalf("the line meant to fail exited 0, so this test would prove nothing: %+v", alone)
	}

	// It is followed by the rest, and the exit code is the last line's -- so an
	// earlier failure does not show up in the result at all.
	result := ExecuteCommand("cmd", JoinShellLines("cmd", []string{missing, "echo SECOND"}), "test:command_exec_lines")
	if !strings.Contains(result.Stdout, "SECOND") {
		t.Errorf("a line after a failing one did not run: stdout %q stderr %q", result.Stdout, result.Stderr)
	}
	if result.ExitCode != 0 {
		t.Errorf("the exit code was %d, want the last line's 0", result.ExitCode)
	}

	// Which is what sh does with the same two statements, and the reason for
	// the choice. Measured here rather than asserted in prose.
	if _, err := exec.LookPath("sh"); err == nil {
		shAlone := ExecuteCommand("sh", missing, "test:command_exec_lines")
		if shAlone.ExitCode == 0 {
			t.Fatalf("sh ran %s successfully, so this comparison proves nothing: %+v", missing, shAlone)
		}
		shResult := ExecuteCommand("sh", JoinShellLines("sh", []string{missing, "echo SECOND"}), "test:command_exec_lines")
		if !strings.Contains(shResult.Stdout, "SECOND") {
			t.Errorf("sh did not run the line after a failing one: %q", shResult.Stdout)
		}
		if shResult.ExitCode != 0 {
			t.Errorf("sh reported %d for a failing first line, so cmd should not report it either", shResult.ExitCode)
		}
	}

	// An explicit exit does end the run, in both shells, because that is what
	// the caller wrote. `exit /b` inside cmd /C ends the whole command.
	result = ExecuteCommand("cmd", JoinShellLines("cmd", []string{"exit /b 7", "echo SECOND"}), "test:command_exec_lines")
	if result.ExitCode != 7 {
		t.Errorf("exit /b 7 gave exit code %d, want 7", result.ExitCode)
	}
	if strings.Contains(result.Stdout, "SECOND") {
		t.Errorf("a line after an explicit exit ran: %q", result.Stdout)
	}
}
