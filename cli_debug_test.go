package main

import (
	"strings"
	"testing"
)

// `mutant debug prog.mut` names a subcommand and a file in one command line,
// which is the shape the file-run path also matches -- so without `debug` in
// the subcommand list, asking to debug a program compiled it instead, and did
// it while prompting for a password.
//
// The assertion is that the file-run path declines the invocation. What the
// debug command then does with it is the adapter's business; this is about
// which of the two claims the command line.
func TestDebugIsASubcommandRatherThanAFileToRun(t *testing.T) {
	cases := [][]string{
		{"mutant", DEBUGCMD},
		{"mutant", DEBUGCMD, "prog.mut"},
		{"mutant", DEBUGCMD, "--port", "9000", "prog.mut"},
		{"mutant", DEBUGCMD, "--module-path", "lib", "prog.mut"},
	}

	for _, args := range cases {
		if handled, exitCode := handleFileInvocation(args); handled {
			t.Errorf("%q was taken as a file to run (exit %d)", strings.Join(args, " "), exitCode)
		}
	}
}

// The REPL is what a bare `mutant` starts, and a subcommand must not reach it.
func TestDebugDoesNotStartTheRepl(t *testing.T) {
	if shouldStartReplFromFlags([]string{DEBUGCMD}) {
		t.Error("mutant debug would have started the REPL")
	}
	if shouldStartReplFromFlags([]string{DEBUGCMD, "--port", "9000"}) {
		t.Error("mutant debug --port would have started the REPL")
	}
}

// A standalone binary carries its program inside itself and runs it when
// invoked with no recognised command. `debug` is a command, so it must not
// trigger that path.
func TestDebugIsNotAnEmbeddedPayloadRun(t *testing.T) {
	if shouldAttemptEmbeddedRun([]string{"mutant", DEBUGCMD}) {
		t.Error("mutant debug would have tried to run an embedded payload")
	}
}

// Debugging runs from source. Saying so at the command line beats failing later
// with a message about missing debug info, which is what a stripped .mu would
// have produced.
func TestDebuggingACompiledArtifactIsRefused(t *testing.T) {
	if code := handleDebugCommand([]string{"mutant", DEBUGCMD, "prog.mu"}); code != 2 {
		t.Errorf("debugging a .mu exited %d, want 2", code)
	}
}

func TestDebugTakesAtMostOneProgram(t *testing.T) {
	if code := handleDebugCommand([]string{"mutant", DEBUGCMD, "a.mut", "b.mut"}); code != 2 {
		t.Errorf("two programs exited %d, want 2", code)
	}
}
