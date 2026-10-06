package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	// defaultCommandExecTimeout is how long exec_string and cmd_run let a
	// command run before the shell is killed and the result says timed_out:
	// long enough for a shell to start and answer a short query of the host,
	// short enough that a hung command does not hang the script.
	//
	//mutant:limit milliseconds
	defaultCommandExecTimeout = 3000
	// defaultCommandMaxOutput is how much of each of a command's output
	// streams exec_string and cmd_run hand back; what is past it is cut and
	// marked as truncated. A result is for reading an answer, not for
	// capturing a transcript.
	//
	//mutant:limit bytes
	defaultCommandMaxOutput = 8192

	errorCommandEmpty     = "command is empty"
	errorCommandTimedOut  = "command timed out"
	errorArgvEmpty        = "argv is empty"
	truncatedOutputSuffix = "\n...[truncated]"

	shellPowerShell = "powershell"
	shellPwsh       = "pwsh"
	shellCmd        = "cmd"
	shellBatch      = "batch"
	shellBash       = "bash"
	shellSh         = "sh"

	powershellExecutable = "powershell.exe"
	pwshExecutable       = "pwsh"
	cmdExecutable        = "cmd.exe"
	cmdFlagExec          = "/C"
	bashExec             = "bash"
	shExec               = "sh"
	// POSIX shells read the command from an argument, not from a file. Without
	// it `bash echo hi` is a request to run a script called "echo hi".
	posixFlagCommand = "-c"

	pwshFlagNoLogo         = "-NoLogo"
	pwshFlagNoProfile      = "-NoProfile"
	pwshFlagNonInteractive = "-NonInteractive"
	pwshFlagCommand        = "-Command"
)

type CommandResult struct {
	ExitCode     int
	Stdout       string
	Stderr       string
	TimedOut     bool
	ErrorMessage string
}

func ExecuteCommand(shell, command, stage string) CommandResult {
	RecordCommandAttempt(stage)

	trimmedCommand := strings.TrimSpace(command)
	normalizedShell := normalizeShell(runtime.GOOS, shell)
	execName, execArgs, err := buildShellCommand(normalizedShell, trimmedCommand)
	if err != nil {
		return CommandResult{
			ErrorMessage: err.Error(),
		}
	}

	return runProgram(execName, execArgs, stage)
}

// ExecuteArgv runs a program with exactly the arguments given and no shell in
// between: argv[0] is the program and the rest reach it as they stand.
//
// It is the answer to a shell this package does not know the flags for. A
// caller who needs zsh -lc, or a shell whose flag is not -c at all, writes the
// invocation out and nothing here interprets it -- which is also why it is the
// safer of the two: no interpreter parses the elements, so a value in one is an
// argument however it is spelled, where the same value inside a command string
// would be syntax.
//
// It is not a way around the command controls. It records the same attempt,
// answers with the same result, and is bound by the same timeout and the same
// output cap as ExecuteCommand.
func ExecuteArgv(argv []string, stage string) CommandResult {
	RecordCommandAttempt(stage)

	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return CommandResult{
			ErrorMessage: errorArgvEmpty,
		}
	}

	return runProgram(argv[0], argv[1:], stage)
}

// runProgram is what both forms end at: the timeout, the two capped streams and
// the one reading of an exit code, in one place so that the two cannot drift.
func runProgram(execName string, execArgs []string, stage string) CommandResult {
	timeout := resolveCommandExecTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, execName, execArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := CommandResult{
		ExitCode: 0,
		Stdout:   truncateOutput(stdout.String(), resolveCommandExecMaxOutput()),
		Stderr:   truncateOutput(stderr.String(), resolveCommandExecMaxOutput()),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ErrorMessage = errorCommandTimedOut
		result.ExitCode = -1
		RecordCommandFailed(stage)
		return result
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.ErrorMessage = runErr.Error()
		RecordCommandFailed(stage)
		return result
	}

	RecordCommandSucceeded(stage)

	return result
}

// DefaultShellName is the shell exec_string and cmd_run use when the caller
// names none. It is a function and not a constant because the answer depends on
// the host: there is no powershell.exe on a Linux or macOS machine, so a
// Windows default made the no-argument form of both builtins -- which is how
// the example and the docs use them -- unable to run anything at all there.
func DefaultShellName() string {
	return defaultShellFor(runtime.GOOS)
}

// defaultShellFor takes the OS as an argument rather than reading runtime.GOOS
// so that every platform's answer is testable from one host. Nobody had ever
// run the Unix answer, which is how M26-TMP-005 survived.
func defaultShellFor(goos string) string {
	if goos == "windows" {
		return shellPowerShell
	}
	// sh and not bash: POSIX requires it, and a minimal container may have
	// nothing else.
	return shellSh
}

func normalizeShell(goos, shell string) string {
	normalized := strings.ToLower(strings.TrimSpace(shell))
	if normalized == "" {
		return defaultShellFor(goos)
	}
	return normalized
}

// buildShellCommand maps a shell NAME -- one of a fixed set, not an executable
// path -- to the program to run and the arguments that make it read the command
// from the command line.
//
// Three of these were wrong (M26-TMP-005). bash was handed the command with no
// -c, so it read "echo hi" as the path of a script and answered
// `bash: echo hi: No such file or directory` on every platform, Windows
// included. "pwsh" ran powershell.exe, which is a different shell with
// different semantics and does not exist off Windows; it now runs the
// cross-platform binary the name refers to. And there was no name for a POSIX
// shell at all.
//
// The Windows-only names are left mapped where they were rather than refused
// off Windows, because powershell.exe and cmd.exe are reachable from WSL
// through interop and a script that uses them there works today. What they do
// on a host without them is report that the executable was not found, which is
// the honest answer.
//
// Any other bare name is run with -c, which is the one convention every POSIX
// shell shares and which fish, csh, tcsh, nu and xonsh share with them, so
// zsh, dash, ksh, mksh and whatever else the host has all work by name without
// this having to know anything about them. A shell whose flag is not -c is
// reached through ExecuteArgv instead, where the caller gives the invocation
// and this takes no responsibility for it.
func buildShellCommand(shell, command string) (string, []string, error) {
	switch shell {
	case shellPowerShell:
		return powershellExecutable, []string{pwshFlagNoLogo, pwshFlagNoProfile, pwshFlagNonInteractive, pwshFlagCommand, command}, nil
	case shellPwsh:
		return pwshExecutable, []string{pwshFlagNoLogo, pwshFlagNoProfile, pwshFlagNonInteractive, pwshFlagCommand, command}, nil
	case shellCmd, shellBatch:
		return cmdExecutable, []string{cmdFlagExec, command}, nil
	case shellBash:
		return bashExec, []string{posixFlagCommand, command}, nil
	case shellSh:
		return shExec, []string{posixFlagCommand, command}, nil
	default:
		if !isBareProgramName(shell) {
			return "", nil, fmt.Errorf("shell %q is not a shell name", shell)
		}
		return shell, []string{posixFlagCommand, command}, nil
	}
}

// isBareProgramName reports whether shell is a program name and nothing else:
// no directory, no argument, no punctuation a shell would read as syntax. It
// expects the lower-cased, trimmed form normalizeShell returns.
//
// The argument names a shell, and refusing the rest is what keeps that true. A
// value holding a separator would be resolved against the working directory,
// and a value holding a space would be looked up as one long file name and come
// back as not found, which reads as "that shell is not installed" when what
// happened is that the argument was never a shell name. Saying so is the
// difference between an answer and a plausible one.
func isBareProgramName(shell string) bool {
	if shell == "" {
		return false
	}
	for i := 0; i < len(shell); i++ {
		c := shell[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == '+':
		default:
			return false
		}
	}
	return true
}

func resolveCommandExecTimeout() time.Duration {
	return time.Duration(defaultCommandExecTimeout) * time.Millisecond
}

func resolveCommandExecMaxOutput() int {
	return defaultCommandMaxOutput
}

func truncateOutput(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + truncatedOutputSuffix
}
