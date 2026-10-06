package security

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheDefaultShellIsTheOneTheHostHas is the first half of M26-TMP-005. The
// default was the constant "powershell" on every platform, so exec_string with
// no shell argument -- which is how the example and the docs use it -- could
// not run anything at all on Linux or macOS: it reported
// `exec: "powershell.exe": executable file not found in $PATH`.
//
// The answer is taken per OS through an argument rather than read from
// runtime.GOOS inside the function, so that the Unix answer is checkable from
// a Windows host. Nobody had ever checked it, which is how this survived.
func TestTheDefaultShellIsTheOneTheHostHas(t *testing.T) {
	cases := []struct {
		goos string
		want string
	}{
		{"windows", "powershell"},
		{"linux", "sh"},
		{"darwin", "sh"},
		{"freebsd", "sh"},
		{"openbsd", "sh"},
	}

	for _, tc := range cases {
		if got := defaultShellFor(tc.goos); got != tc.want {
			t.Errorf("defaultShellFor(%q) = %q, want %q", tc.goos, got, tc.want)
		}
		if got := normalizeShell(tc.goos, ""); got != tc.want {
			t.Errorf("normalizeShell(%q, \"\") = %q, want %q", tc.goos, got, tc.want)
		}
		// An explicit name is never overridden by the host's default.
		if got := normalizeShell(tc.goos, "BASH"); got != "bash" {
			t.Errorf("normalizeShell(%q, \"BASH\") = %q, want bash", tc.goos, got)
		}
	}
}

// TestEveryShellNameIsGivenTheCommandAndNotAFilePath is the second half of
// M26-TMP-005, and the bug that made the whole row. bash was handed the
// command with no -c:
//
//	case shellBash: return bashExec, []string{command}, nil
//
// so `exec_string("echo hi", "bash")` ran `bash "echo hi"`, which bash reads as
// the path of a script -- exit 127, `bash: echo hi: No such file or directory`,
// on Windows and in WSL alike. And "pwsh" ran powershell.exe, a different shell
// that does not exist off Windows.
//
// These six are the names with an invocation of their own, where -c would be
// wrong or where the executable is not the name. Every other name is given the
// command with -c, which TestAnUnknownShellNameIsGivenTheCommandWithDashC
// covers; a seventh cannot be added here without deciding what makes it read a
// command.
func TestEveryShellNameIsGivenTheCommandAndNotAFilePath(t *testing.T) {
	const command = "echo hi"

	cases := []struct {
		shell    string
		wantExec string
		wantFlag string
	}{
		{"powershell", "powershell.exe", "-Command"},
		{"pwsh", "pwsh", "-Command"},
		{"cmd", "cmd.exe", "/C"},
		{"batch", "cmd.exe", "/C"},
		{"bash", "bash", "-c"},
		{"sh", "sh", "-c"},
	}

	for _, tc := range cases {
		name, args, err := buildShellCommand(tc.shell, command)
		if err != nil {
			t.Errorf("%s: %v", tc.shell, err)
			continue
		}
		if name != tc.wantExec {
			t.Errorf("%s runs %q, want %q", tc.shell, name, tc.wantExec)
		}
		if len(args) == 0 {
			t.Errorf("%s was given no arguments at all", tc.shell)
			continue
		}
		// The command must be the last argument, and the argument before it
		// must be the flag that says "this is a command". Without that flag the
		// command text is a file path to every POSIX shell.
		if args[len(args)-1] != command {
			t.Errorf("%s: the command is not the last argument: %q", tc.shell, args)
		}
		if len(args) < 2 || args[len(args)-2] != tc.wantFlag {
			t.Errorf("%s: want %q immediately before the command, got %q",
				tc.shell, tc.wantFlag, args)
		}
	}
}

// TestAnUnknownShellNameIsGivenTheCommandWithDashC is the owner's decision of
// 2026-10-06: any shell the host has should be usable by name. -c is the one
// convention they share -- every POSIX shell, and fish, csh, tcsh, nu and xonsh
// with them -- so a name this package has never heard of needs no entry here
// and no knowledge of it. A shell whose flag is not -c is reached through
// ExecuteArgv, where the caller writes the invocation out.
func TestAnUnknownShellNameIsGivenTheCommandWithDashC(t *testing.T) {
	const command = "echo hi"

	for _, shell := range []string{"zsh", "dash", "fish", "ksh", "ksh93", "mksh", "tcsh", "nu", "xonsh", "elvish"} {
		name, args, err := buildShellCommand(shell, command)
		if err != nil {
			t.Errorf("%s: %v", shell, err)
			continue
		}
		if name != shell {
			t.Errorf("%s runs %q, want the name itself", shell, name)
		}
		want := []string{"-c", command}
		if len(args) != len(want) || args[0] != want[0] || args[1] != want[1] {
			t.Errorf("%s was given %q, want %q", shell, args, want)
		}
	}
}

// TestAValueThatIsNotAShellNameIsRefused is the half of the old closed set
// worth keeping. The argument names a shell: a path would be resolved against
// the working directory, and a command line would be looked up as one long file
// name and come back as not found, which reads as "that shell is not
// installed" when the argument was never a shell name at all.
func TestAValueThatIsNotAShellNameIsRefused(t *testing.T) {
	for _, shell := range []string{
		"", "/bin/sh", "../sh", `c:\windows\system32\cmd.exe`,
		"sh -c", "sh;rm -rf /", "$SHELL", "sh|cat", "sh&", "my shell",
	} {
		if _, _, err := buildShellCommand(shell, "echo hi"); err == nil {
			t.Errorf("buildShellCommand(%q) should be refused", shell)
		}
	}
}

// TestExecuteArgvRefusesNothingToRun covers the two inputs that name no
// program. They are caught in the builtin too, where they are a caller mistake
// and come back as an error object; this is the floor underneath that.
func TestExecuteArgvRefusesNothingToRun(t *testing.T) {
	for _, argv := range [][]string{nil, {}, {""}, {"   "}} {
		result := ExecuteArgv(argv, "test:command_exec_argv")
		if result.ErrorMessage != errorArgvEmpty {
			t.Errorf("ExecuteArgv(%q) said %q, want %q", argv, result.ErrorMessage, errorArgvEmpty)
		}
	}
}

// TestExecuteArgvRunsTheProgramItIsGiven is the end-to-end half, and the reason
// the builtin exists: the caller writes the invocation and nothing here
// interprets it.
func TestExecuteArgvRunsTheProgramItIsGiven(t *testing.T) {
	shell := ""
	for _, candidate := range []string{"bash", "sh"} {
		if _, err := exec.LookPath(candidate); err == nil {
			shell = candidate
			break
		}
	}
	if shell == "" {
		t.Skip("no bash or sh on PATH")
	}

	result := ExecuteArgv([]string{shell, "-c", "echo hi"}, "test:command_exec_argv")
	if result.ErrorMessage != "" {
		t.Fatalf("%s -c 'echo hi': %s", shell, result.ErrorMessage)
	}
	if result.ExitCode != 0 {
		t.Fatalf("%s -c 'echo hi' exited %d, stderr %q", shell, result.ExitCode, result.Stderr)
	}
	if got := strings.TrimSpace(result.Stdout); got != "hi" {
		t.Fatalf("%s -c 'echo hi' printed %q, want \"hi\"", shell, got)
	}
}

// TestExecuteArgvPassesAnArgumentWholeIsWhyItExists: an element reaches the
// program as one argument whatever is in it. The same text inside a command
// string would be three words and a redirection.
func TestExecuteArgvPassesAnArgumentWholeIsWhyItExists(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}

	const nasty = "a b; echo pwned > /dev/null"
	result := ExecuteArgv([]string{"sh", "-c", `printf '%s' "$1"`, "sh", nasty}, "test:command_exec_argv")
	if result.ErrorMessage != "" {
		t.Fatalf("sh: %s", result.ErrorMessage)
	}
	if result.Stdout != nasty {
		t.Fatalf("the argument arrived as %q, want %q", result.Stdout, nasty)
	}
}

// TestExecuteArgvSaysSoWhenThereIsNoSuchProgram is the owner's rule of
// 2026-10-06: a builtin that cannot do its job fails loudly rather than
// answering as though it had. A missing program is reported, with an exit code
// that is not a program's.
func TestExecuteArgvSaysSoWhenThereIsNoSuchProgram(t *testing.T) {
	result := ExecuteArgv([]string{"mutant-no-such-program-exists"}, "test:command_exec_argv")
	if result.ErrorMessage == "" {
		t.Fatalf("a missing program was reported as success: %+v", result)
	}
	if result.ExitCode != -1 {
		t.Fatalf("a missing program exited %d, want -1", result.ExitCode)
	}
	if !strings.Contains(result.ErrorMessage, "mutant-no-such-program-exists") {
		t.Fatalf("the error does not name the program: %q", result.ErrorMessage)
	}
}

// TestBashActuallyRunsTheCommand is the end-to-end half: the mapping above is
// only right if the shell really runs the command. This runs where bash is on
// PATH, which on a Windows development host means the one Git ships.
func TestBashActuallyRunsTheCommand(t *testing.T) {
	for _, shell := range []string{"bash", "sh"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Logf("no %s on PATH; skipping that one", shell)
			continue
		}
		result := ExecuteCommand(shell, "echo hi", "test:command_exec_shell")
		if result.ErrorMessage != "" {
			t.Errorf("%s -c 'echo hi': %s", shell, result.ErrorMessage)
			continue
		}
		if result.ExitCode != 0 {
			t.Errorf("%s -c 'echo hi' exited %d, stderr %q",
				shell, result.ExitCode, result.Stderr)
			continue
		}
		if got := strings.TrimSpace(result.Stdout); got != "hi" {
			t.Errorf("%s -c 'echo hi' printed %q, want \"hi\"", shell, got)
		}
	}
}
