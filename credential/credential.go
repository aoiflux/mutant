// Package credential resolves the password for one Mutant invocation without
// requiring it on the command line.
//
// The problem it exists to solve: `--password <value>` puts the credential in
// argv, where it is visible in `ps`, in Task Manager, in process-creation EDR
// telemetry, and in shell history -- on every OS, to every local user, for the
// lifetime of the process. For a tool whose whole purpose is examining hosts
// that may already be compromised, that is the wrong default.
//
// An environment variable is not an available alternative. Mutant takes no
// configuration from the environment (docs/CONFIGURATION_POLICY.md), and a
// credential would be the worst possible thing to make an exception for: it is
// inherited by every child process and never appears in the command line an
// analyst records in their case notes.
//
// That leaves four sources, in the order a caller should prefer them:
//
//	interactive prompt   no password anywhere but the terminal (default)
//	--password-file      a file whose permissions the OS enforces
//	--password-stdin     a pipe, for CI and scripted pipelines
//	--password           argv; deprecated, warns on use
package credential

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// Source names where a password came from. It is reported in errors so a
// failure says which input to fix.
type Source string

const (
	SourcePrompt   Source = "interactive prompt"
	SourceFile     Source = "--password-file"
	SourceStdin    Source = "--password-stdin"
	SourceInline   Source = "--password"
	SourceInsecure Source = "--password-insecure"
)

// Request is the credential half of a parsed command line. Exactly one of the
// four explicit sources may be set; all unset means "prompt".
type Request struct {
	Inline   string // --password / --pwd  (deprecated: argv-visible)
	Insecure string // --password-insecure (explicit, unapologetic opt-in)
	FilePath string // --password-file <path>
	Stdin    bool   // --password-stdin

	// Confirm asks for the password twice and requires the two to match. Set it
	// on paths that *encrypt* -- a typo there is unrecoverable, because nothing
	// else in the system knows what the password was meant to be. Read paths
	// leave it false: a wrong password there simply fails to decrypt.
	Confirm bool
}

// explicit reports which sources the command line actually named. More than one
// is a usage error rather than a precedence question -- see Resolve.
func (r Request) explicit() []Source {
	var set []Source
	if r.Inline != "" {
		set = append(set, SourceInline)
	}
	if r.Insecure != "" {
		set = append(set, SourceInsecure)
	}
	if r.FilePath != "" {
		set = append(set, SourceFile)
	}
	if r.Stdin {
		set = append(set, SourceStdin)
	}
	return set
}

// Any reports whether the command line named a password source at all. Callers
// use it to decide whether a fallback (such as --dev's built-in key) applies
// before any prompting happens.
func (r Request) Any() bool {
	return len(r.explicit()) > 0
}

// Resolver reads a password. The function fields exist so tests can drive the
// interactive path without a terminal; a zero Resolver uses the real ones.
type Resolver struct {
	Stderr io.Writer
	Stdin  io.Reader

	// ReadSecret reads one line with terminal echo disabled.
	ReadSecret func() ([]byte, error)
	// IsTerminal reports whether an interactive prompt is possible.
	IsTerminal func() bool
	// GOOS overrides the platform for the file-permission check.
	GOOS string
}

func (r *Resolver) stderr() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return os.Stderr
}

func (r *Resolver) stdin() io.Reader {
	if r.Stdin != nil {
		return r.Stdin
	}
	return os.Stdin
}

func (r *Resolver) goos() string {
	if r.GOOS != "" {
		return r.GOOS
	}
	return runtime.GOOS
}

func (r *Resolver) isTerminal() bool {
	if r.IsTerminal != nil {
		return r.IsTerminal()
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func (r *Resolver) readSecret() ([]byte, error) {
	if r.ReadSecret != nil {
		return r.ReadSecret()
	}
	return term.ReadPassword(int(os.Stdin.Fd()))
}

// Resolve returns the password as a mutable byte slice. The caller owns it and
// should Zero it once the key has been derived.
//
// A []byte rather than a string is deliberate: Go strings are immutable, so a
// password that has been converted to one cannot be erased and stays in the
// heap until the garbage collector happens to reuse the page. Returning bytes
// keeps the window in which that is true as short as the caller cares to make
// it. See the note on Zero about how far this actually goes today.
func (r *Resolver) Resolve(req Request) ([]byte, Source, error) {
	named := req.explicit()
	if len(named) > 1 {
		return nil, "", fmt.Errorf("more than one password source given (%s). "+
			"Pick one -- there is no precedence order, because guessing which "+
			"credential you meant is exactly the kind of silent choice this flag "+
			"set exists to avoid", joinSources(named))
	}

	switch {
	case req.Inline != "":
		fmt.Fprintln(r.stderr(),
			"[deprecated] --password puts the credential in argv, where it is visible to "+
				"every local user via the process table and is recorded in shell history. "+
				"Use --password-file, --password-stdin, or omit it and be prompted. "+
				"This flag will require --password-insecure in the next minor release.")
		return withSource([]byte(req.Inline), SourceInline)

	case req.Insecure != "":
		return withSource([]byte(req.Insecure), SourceInsecure)

	case req.FilePath != "":
		secret, err := r.readFile(req.FilePath)
		if err != nil {
			return nil, SourceFile, err
		}
		return withSource(secret, SourceFile)

	case req.Stdin:
		secret, err := readAllLine(r.stdin())
		if err != nil {
			return nil, SourceStdin, fmt.Errorf("reading password from stdin: %w", err)
		}
		return withSource(secret, SourceStdin)
	}

	return r.prompt(req.Confirm)
}

// prompt reads the password from the terminal with echo disabled.
func (r *Resolver) prompt(confirm bool) ([]byte, Source, error) {
	if !r.isTerminal() {
		return nil, SourcePrompt, errors.New("no password given and stdin is not a terminal, " +
			"so there is nothing to prompt. Use --password-file <path> or --password-stdin " +
			"for non-interactive runs, or --dev to use the built-in development key " +
			"(local development only)")
	}

	first, err := r.ask("Password: ")
	if err != nil {
		return nil, SourcePrompt, err
	}
	if len(first) == 0 {
		return nil, SourcePrompt, errors.New("password cannot be empty")
	}

	if !confirm {
		return first, SourcePrompt, nil
	}

	second, err := r.ask("Confirm password: ")
	if err != nil {
		Zero(first)
		return nil, SourcePrompt, err
	}
	defer Zero(second)

	// Not constant-time on purpose: both values are the user's own input, in
	// their own terminal, and there is no secret here to leak to an attacker who
	// would have to already be the one typing.
	if string(first) != string(second) {
		Zero(first)
		return nil, SourcePrompt, errors.New("passwords do not match")
	}

	return first, SourcePrompt, nil
}

func (r *Resolver) ask(label string) ([]byte, error) {
	// The prompt goes to stderr, never stdout: stdout is the program's own
	// output and may be piped into something that would be corrupted by it.
	fmt.Fprint(r.stderr(), label)
	secret, err := r.readSecret()
	fmt.Fprintln(r.stderr())
	if err != nil {
		return nil, fmt.Errorf("reading password from terminal: %w", err)
	}
	return secret, nil
}

// readFile loads a password file, refusing one whose permissions let anybody
// else on the host read it.
func (r *Resolver) readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--password-file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("--password-file: %s is a directory", path)
	}

	if err := r.checkPermissions(path, info); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--password-file: %w", err)
	}

	return trimOneNewline(data), nil
}

// checkPermissions refuses a group- or world-accessible password file.
//
// This is a POSIX mode-bit check and it is skipped on Windows, where the bits
// os.FileInfo reports are synthesised from the read-only attribute rather than
// read from the ACL that actually governs access. Enforcing 0600 there would be
// theatre: it would pass for a file granted to Everyone and fail for nothing.
// Windows users should rely on the file's ACL and on it living in a per-user
// directory. Stated here rather than silently skipped, because a permission
// check that does not check anything is worse than an absent one.
func (r *Resolver) checkPermissions(path string, info os.FileInfo) error {
	if r.goos() == "windows" {
		return nil
	}

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("--password-file: %s is readable by other users (mode %04o). "+
			"Restrict it with `chmod 600 %s`", path, mode, path)
	}

	return nil
}

// Zero overwrites a password buffer.
//
// Scope, stated plainly: this erases the buffer it is handed. It does not erase
// copies the value has already been turned into elsewhere -- in particular, the
// moment a password becomes a Go string it becomes immutable and unreachable to
// this function, and Mutant's encryption pipeline takes strings today. Zeroing
// at the acquisition boundary shortens the window rather than closing it;
// closing it needs the pipeline threaded with []byte end to end.
func Zero(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

func withSource(secret []byte, src Source) ([]byte, Source, error) {
	if len(secret) == 0 {
		return nil, src, fmt.Errorf("%s supplied an empty password", src)
	}
	return secret, src, nil
}

// trimOneNewline removes a single trailing line terminator, and only one.
// Trimming all trailing whitespace would silently change a password that
// legitimately ends in a space -- the file would work here and fail everywhere
// else, which is the worst way for a credential to be wrong.
func trimOneNewline(data []byte) []byte {
	data = bytes.TrimSuffix(data, []byte("\n"))
	return bytes.TrimSuffix(data, []byte("\r"))
}

func readAllLine(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return trimOneNewline(data), nil
}

func joinSources(sources []Source) string {
	parts := make([]string, len(sources))
	for i, s := range sources {
		parts[i] = string(s)
	}
	return strings.Join(parts, ", ")
}
