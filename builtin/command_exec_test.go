package builtin

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"mutant/object"
)

func TestCommandBuilderRoundTrip(t *testing.T) {
	builderPair := CmdBuilder(&object.String{Value: "powershell"})
	builder, errObj := unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_builder: %s", errObj.Inspect())
	}

	builderPair = CmdAdd(builder, &object.String{Value: "$x='a'"})
	builder, errObj = unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_add: %s", errObj.Inspect())
	}

	builderPair = CmdAdd(builder, &object.String{Value: "Write-Output $x"})
	builder, errObj = unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_add: %s", errObj.Inspect())
	}

	hash, ok := builder.(*object.Hash)
	if !ok {
		t.Fatalf("builder is not Hash. got=%T", builder)
	}

	linesObj := hashValueByKey(hash, "lines")
	lines, ok := linesObj.(*object.Array)
	if !ok {
		t.Fatalf("lines is not Array. got=%T", linesObj)
	}
	if len(lines.Elements) != 2 {
		t.Fatalf("wrong line count. got=%d, want=2", len(lines.Elements))
	}
}

func TestCmdRunEmptyBuilderErrors(t *testing.T) {
	builderPair := CmdBuilder()
	builder, errObj := unwrapPair(t, builderPair)
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_builder: %s", errObj.Inspect())
	}

	result := CmdRun(builder)
	_, errObj = unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected error in pair slot, got nil")
	}
}

// TestCmdRunRunsEveryLineItWasGiven is M26-NET-018 at the builtin, which is
// where a script meets it. cmd_run joined the builder's lines with "\n" and
// cmd.exe stops reading its command line at the first newline, so a two-step
// collection ran step one, dropped step two and came back ok with exit_code 0.
//
// The separator now comes from security.JoinShellLines, which is the package
// that knows what a shell name means. What is checked here is the wiring: that
// cmd_run asks for it, with the shell the builder is carrying.
func TestCmdRunRunsEveryLineItWasGiven(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe is a Windows shell; the join is checked per platform in the security package")
	}

	// "CMD" and not "cmd": cmd_builder stores the caller's spelling untouched,
	// so the builtin must not be the thing that decides which shell this is.
	result, errObj := unwrapPair(t, CmdRun(mustBuild(t, "CMD", "echo FIRST", "echo SECOND")))
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_run: %s", errObj.Inspect())
	}

	stdout := hashStr(t, result, "stdout")
	for _, want := range []string{"FIRST", "SECOND"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("cmd_run stdout %q does not contain %q", stdout, want)
		}
	}
	if got := hashInt(t, result, "exit_code"); got != 0 {
		t.Errorf("exit_code = %d, want 0, stderr %q", got, hashStr(t, result, "stderr"))
	}
	if got := hashStr(t, result, "error"); got != "" {
		t.Errorf("error = %q, want empty", got)
	}
	if !hashBool(t, result, "ok") {
		t.Error("ok is false for a command that ran and succeeded")
	}
}

// TestCmdRunStillRunsEveryLineForTheShellsThatWorked is the parity half. These
// shells were never broken, and the change must not have touched them.
func TestCmdRunStillRunsEveryLineForTheShellsThatWorked(t *testing.T) {
	shells := []string{}
	if runtime.GOOS == "windows" {
		shells = append(shells, "powershell")
	}
	for _, posix := range []string{"sh", "bash"} {
		if _, err := exec.LookPath(posix); err == nil {
			shells = append(shells, posix)
		}
	}
	if len(shells) == 0 {
		t.Skip("no newline-reading shell on this host")
	}

	for _, shell := range shells {
		result, errObj := unwrapPair(t, CmdRun(mustBuild(t, shell, "echo FIRST", "echo SECOND")))
		if errObj != nil {
			t.Errorf("%s: unexpected error from cmd_run: %s", shell, errObj.Inspect())
			continue
		}
		stdout := hashStr(t, result, "stdout")
		for _, want := range []string{"FIRST", "SECOND"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%s: stdout %q does not contain %q", shell, stdout, want)
			}
		}
	}
}

// TestCmdRunWithNothingButBlankLinesIsRefused closes the gap the blank-line
// rule could have opened. A blank line is left out of a cmd command, because
// "&" with nothing beside it is a syntax error that costs the whole command --
// but a builder holding only blank lines must not then become a shell that
// starts, reads nothing and reports success, which is the defect
// exec_string("") used to have.
func TestCmdRunWithNothingButBlankLinesIsRefused(t *testing.T) {
	for _, shell := range []string{"cmd", "powershell", "sh"} {
		result, errObj := unwrapPair(t, CmdRun(mustBuild(t, shell, "", "   ")))
		if errObj != nil {
			t.Errorf("%s: cmd_run raised instead of answering: %s", shell, errObj.Inspect())
			continue
		}
		if hashStr(t, result, "error") == "" {
			t.Errorf("%s: a builder of blank lines reported no error", shell)
		}
		if got := hashInt(t, result, "exit_code"); got == 0 {
			t.Errorf("%s: a builder of blank lines exited 0", shell)
		}
		if hashBool(t, result, "ok") {
			t.Errorf("%s: a builder of blank lines came back ok", shell)
		}
	}
}

// mustBuild is cmd_builder followed by one cmd_add per line, which is how a
// script writes it. The builder is immutable, so each call returns the next one
// and dropping a return value loses the line -- worth going through the
// builtins rather than assembling the hash by hand, since that chain is the
// shape under test.
func mustBuild(t *testing.T, shell string, lines ...string) object.Object {
	t.Helper()

	builder, errObj := unwrapPair(t, CmdBuilder(&object.String{Value: shell}))
	if errObj != nil {
		t.Fatalf("unexpected error from cmd_builder: %s", errObj.Inspect())
	}
	for _, line := range lines {
		builder, errObj = unwrapPair(t, CmdAdd(builder, &object.String{Value: line}))
		if errObj != nil {
			t.Fatalf("unexpected error from cmd_add(%q): %s", line, errObj.Inspect())
		}
	}
	return builder
}
