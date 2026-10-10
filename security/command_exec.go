package security

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
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
	// defaultCommandWaitDelay is how much longer than the timeout above one
	// call may last. The clock starts when the deadline passes or when the
	// command's own process exits, whichever comes first, and what it bounds is
	// the wait for everything else the command started: a grandchild holding the
	// output pipe open used to keep the call alive for as long as it liked,
	// whatever the timeout said -- `cmd /C ping -n 10 127.0.0.1` took 9.14
	// seconds against a 3-second timeout and then reported that it had timed out
	// (M26-TMP-006). Half a second is long enough for a killed process tree to
	// die and let go of its handles on a loaded host, and short enough that the
	// worst case of exec_string stays under four seconds.
	//
	//mutant:limit milliseconds
	defaultCommandWaitDelay = 500

	errorCommandEmpty    = "command is empty"
	errorCommandTimedOut = "command timed out"
	errorArgvEmpty       = "argv is empty"
	// errorCommandAbandoned is the answer to a command that exited on its own
	// while something it had started still held its output pipe open. The exit
	// code is the command's own and is reported as such; what is not known is
	// whether the output is all of it, so the result does not come back ok.
	errorCommandAbandoned = "command exited but something it started still holds its output"
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
	// cmd.exe decides whether to keep or strip the quotes around a /C argument
	// by five conditions at once; /S replaces all five with one rule, which is
	// the only way to state what becomes of a caller's quotes. See
	// rawCommandLineFor.
	cmdFlagQuoteStrip = "/S"
	// cmdLineSeparator is what goes between the lines of a command builder for
	// cmd.exe, where a newline cannot: see JoinShellLines. It carries no
	// spaces, so that the join contributes nothing to any line's own text.
	cmdLineSeparator = "&"
	bashExec         = "bash"
	shExec           = "sh"
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
	// An empty command is refused before any process starts. It used to be
	// handed to the shell, which started, read nothing, exited 0 and left
	// exec_string("") answering ok with an empty stdout -- while the error this
	// package had already written for the case was used nowhere at all
	// (M26-TMP-009).
	if trimmedCommand == "" {
		return refusedCommand(errorCommandEmpty, stage)
	}

	normalizedShell := normalizeShell(runtime.GOOS, shell)
	execName, execArgs, err := buildShellCommand(normalizedShell, trimmedCommand)
	if err != nil {
		return refusedCommand(err.Error(), stage)
	}

	return runProgram(execName, execArgs, rawCommandLineFor(normalizedShell, trimmedCommand), stage)
}

// refusedCommand is the result of a command that never started: an exit code
// that is not a program's, and the attempt counted as the failure it is.
//
// A refusal used to come back as an ErrorMessage next to ExitCode 0, which is
// what a command that ran and succeeded looks like to anything reading the
// exit code on its own. RecordCommandFailed was not called either, so an
// attempt was counted that was never resolved one way or the other.
func refusedCommand(message, stage string) CommandResult {
	RecordCommandFailed(stage)
	return CommandResult{
		ExitCode:     -1,
		ErrorMessage: message,
	}
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
		return refusedCommand(errorArgvEmpty, stage)
	}

	// No raw command line, by construction: a caller who wants to decide where
	// the words break writes them out as argv, which is what this form is for.
	return runProgram(argv[0], argv[1:], "", stage)
}

// runProgram is what both forms end at: the timeout, the two capped streams and
// the one reading of an exit code, in one place so that the two cannot drift.
//
// rawCommandLine is the Windows command line to hand the program as written
// instead of letting os/exec escape execArgs into one, or "" to let it escape
// them. It is how cmd.exe is reached without its quotes being mangled
// (M26-TMP-008), and it is ignored everywhere else, because off Windows a
// process is started from an argv and there is no command line to set.
func runProgram(execName string, execArgs []string, rawCommandLine, stage string) CommandResult {
	timeout := resolveCommandExecTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, execName, execArgs...)
	// The timeout above bounds the command's own process and nothing else. What
	// bounds the CALL is this: without it Wait reads the output pipes until EOF,
	// and EOF does not arrive until every process holding the write end has let
	// go of it, so one `ping` the shell left behind kept a 3-second timeout open
	// for 9.14 measured seconds (M26-TMP-006).
	cmd.WaitDelay = resolveCommandWaitDelay()
	setRawCommandLine(cmd, rawCommandLine)

	// Capped writers rather than buffers: the output used to be kept whole and
	// cut afterwards, so a command printing 64 MiB cost 320 MiB of allocation
	// and a 257 MiB live heap to keep 8 KiB of it (M26-TMP-007).
	stdout := newCappedWriter(resolveCommandExecMaxOutput())
	stderr := newCappedWriter(resolveCommandExecMaxOutput())
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// The tree is arranged before the process starts, because what it decides is
	// which processes the kill on timeout reaches: a job object on Windows, a
	// process group on Unix.
	tree, treeErr := newProcessTree(cmd)
	if treeErr != nil {
		return refusedCommand(treeErr.Error(), stage)
	}
	defer tree.release()

	runErr := cmd.Start()
	if runErr == nil {
		tree.adopt(cmd)
		runErr = cmd.Wait()
	}

	result := CommandResult{
		ExitCode: 0,
		Stdout:   stdout.text(),
		Stderr:   stderr.text(),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ErrorMessage = errorCommandTimedOut
		result.ExitCode = -1
		RecordCommandFailed(stage)
		return result
	}

	// Compared with == and not errors.Is on purpose: Wait returns this sentinel
	// itself and unwrapped, and a builtin on the purity allowlist may not reach
	// errors.Is.
	if runErr == exec.ErrWaitDelay {
		// The command exited on its own, and exited well -- a bad status comes
		// back as an ExitError instead -- but something it had started was still
		// holding the output pipe when the wait gave up on it. The exit code is
		// the command's and is kept. What is not reported is ok, because this
		// does not know how much of the output there was going to be.
		result.ErrorMessage = errorCommandAbandoned
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
		// /S is in the argv as well as in the raw command line, so that the two
		// spellings of this invocation say the same thing. The argv is what is
		// used where a command line cannot be set, which is every platform but
		// Windows -- cmd.exe reached from WSL through interop above all.
		return cmdExecutable, []string{cmdFlagQuoteStrip, cmdFlagExec, command}, nil
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

// JoinShellLines turns the lines a command builder collected into the one
// command string the named shell runs, which is not the same string for every
// shell.
//
// cmd.exe reads its command from the command line, and a command line ends at
// the first newline. Joined with "\n", a builder made with cmd_builder("cmd")
// therefore ran its first line, silently dropped every later one, and came
// back ok with exit_code 0 (M26-NET-018, measured: the lines `echo FIRST` and
// `echo SECOND` gave stdout "FIRST\r\n"). The same builder under powershell
// printed both.
//
// "&" and not "&&": "&&" runs the next line only if the one before it
// succeeded, and a newline in powershell, sh and bash does not work that way.
// Measured, `sh -c "false\necho SECOND"` prints SECOND and exits 0. A builder
// is a list of lines to run, and the shells that already worked run all of
// them, so this one does too; the exit code is the last line's, in every
// shell, and an earlier line that failed does not stop the rest and does not
// show up in the result. That is the shell's rule rather than a choice made
// here, and it is why a step whose failure must stop the run is tested by the
// script that asked for it.
//
// The separator carries no spaces, which is not cosmetic. cmd's echo prints
// everything up to the separator, trailing space included: measured,
// `echo FIRST & echo SECOND` printed "FIRST \r\nSECOND\r\n", putting a space
// on the end of every line's output but the last. With a bare "&" the join
// contributes nothing to any line's own text, and a line's own trailing space
// still survives, because the caller wrote that one.
//
// A blank line is left out of the cmd command instead of joined. A blank line
// does nothing in every other shell, and in this one "&" with nothing beside
// it is a syntax error that costs the whole command: measured, `&echo B`
// answers `& was unexpected at this time.` and runs neither line. Leaving it
// out drops nothing that would have happened. When every line is blank the
// result is the empty string, which ExecuteCommand refuses -- the same answer
// a "\n"-joined blank script already got.
//
// What this does not give cmd is state across lines. cmd expands %VAR% when it
// parses the command line, before any of it has run, so a line reading a
// variable an earlier line set gets the unexpanded name: measured,
// `set X=1&echo %X%` prints `%X%`. That is cmd's own answer to the same
// command typed by hand, and the alternative -- /V:ON and !VAR! -- would make
// "!" a metacharacter in every command that does not want one. A run that
// needs state across steps belongs in a script the caller controls, reached
// with exec_argv.
func JoinShellLines(shell string, lines []string) string {
	return joinShellLinesFor(runtime.GOOS, shell, lines)
}

// joinShellLinesFor takes the OS as an argument rather than reading
// runtime.GOOS, for the reason defaultShellFor does: the answer for a shell
// name that is only reachable on another platform is then checkable from this
// one. An empty shell name means the host's default, which is why the OS is
// needed at all.
func joinShellLinesFor(goos, shell string, lines []string) string {
	switch normalizeShell(goos, shell) {
	case shellCmd, shellBatch:
		kept := make([]string, 0, len(lines))
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, cmdLineSeparator)
	default:
		return strings.Join(lines, "\n")
	}
}

func resolveCommandExecTimeout() time.Duration {
	return time.Duration(defaultCommandExecTimeout) * time.Millisecond
}

func resolveCommandExecMaxOutput() int {
	return defaultCommandMaxOutput
}

func resolveCommandWaitDelay() time.Duration {
	return time.Duration(defaultCommandWaitDelay) * time.Millisecond
}

// rawCommandLineFor returns the Windows command line to give the shell as
// written, or "" when letting os/exec escape the arguments into one is right.
//
// cmd.exe is the one shell here that needs it, and it needs it because it does
// not read its command line the way the C runtime does. os/exec escapes each
// argument the C runtime's way, so `echo "a b"` reached cmd.exe as
// `echo \"a b\"`; cmd.exe has no backslash escape, so it printed the
// backslashes (M26-TMP-008, measured: stdout was `\"a b\"`).
//
// /S reduces cmd.exe's five conditions for keeping or stripping quotes to one:
// strip the first character if it is a quote, drop the last quote on the line,
// run what is left. So the pair added here is exactly the pair cmd.exe takes
// away, and the command arrives as the caller wrote it -- an embedded double
// quote included, which is the point.
//
// This widens nothing. exec_string hands an arbitrary command string to a
// shell by definition; that string reached the shell before this change too,
// escaped into something cmd.exe then misread. What changes is that the
// quoting rule is now one a caller can state.
func rawCommandLineFor(shell, command string) string {
	switch shell {
	case shellCmd, shellBatch:
		return cmdExecutable + " " + cmdFlagQuoteStrip + " " + cmdFlagExec + ` "` + command + `"`
	default:
		return ""
	}
}

// cappedWriter keeps the first limit bytes written to it and counts the rest.
//
// The output used to be collected whole in a bytes.Buffer and cut afterwards,
// so the cap bounded the ANSWER and not the memory: 64 MiB of stdout cost
// 320 MiB of allocation and a 257 MiB live heap to keep 8 KiB (M26-TMP-007).
//
// Every Write reports the whole slice written and never returns an error, and
// that is the one thing it must do. os/exec copies a stream that is not an
// *os.File through a pipe in a goroutine; a short write or an error there ends
// the copy, the pipe fills, and the command blocks forever on a write nobody
// is reading. Draining what is discarded is the job.
//
// One stream, one writer: stdout and stderr each get their own and each is
// written by its own copying goroutine, so there is nothing here to lock.
type cappedWriter struct {
	limit     int
	kept      []byte
	discarded int64
}

func newCappedWriter(limit int) *cappedWriter {
	if limit < 0 {
		limit = 0
	}
	return &cappedWriter{limit: limit, kept: make([]byte, 0, limit)}
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := w.limit - len(w.kept)
	if room > len(p) {
		room = len(p)
	}
	if room > 0 {
		w.kept = append(w.kept, p[:room]...)
	} else {
		room = 0
	}
	w.discarded += int64(len(p) - room)
	return len(p), nil
}

// text is the stream as the result reports it: what was kept, and a mark when
// something was not.
func (w *cappedWriter) text() string {
	if w.discarded == 0 {
		return string(w.kept)
	}
	return string(trimPartialRune(w.kept)) + truncatedOutputSuffix
}

// trimPartialRune drops an incomplete UTF-8 sequence from the end of b.
//
// A cap counts bytes and a rune is up to four of them, so the cut landed
// wherever it landed: 8192 bytes of a command's output ending mid-character
// came back as a string Mutant could not print -- measured, `"aaaaaaa\xe4"`
// for a cut at 8 (M26-TMP-007).
//
// It trims only what the cut broke. b is already known to be a prefix of
// something longer, so a sequence that is incomplete at the end of b is
// incomplete because of the cut. Output that was not truncated is returned
// untouched, including output that was never valid UTF-8 to begin with: a
// complete answer is not this function's to alter. For the same reason the
// result is not promised to be valid UTF-8 for a command that emits binary --
// the promise is that cutting does not make it invalid.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && i < len(b); i++ {
		tail := b[len(b)-i-1:]
		if r, size := utf8.DecodeRune(tail); r != utf8.RuneError || size > 1 {
			// tail begins a whole rune, so nothing at the end is partial.
			return b
		}
		if utf8.RuneStart(tail[0]) {
			// tail begins a sequence that is not whole in what was kept.
			return b[:len(b)-i-1]
		}
	}
	return b
}
