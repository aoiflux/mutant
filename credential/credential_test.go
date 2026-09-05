package credential

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newTestResolver returns a Resolver wired to in-memory IO with no terminal, so
// a test that forgets to opt into prompting gets a deterministic error rather
// than blocking on a real tty.
func newTestResolver() (*Resolver, *bytes.Buffer) {
	var stderr bytes.Buffer
	return &Resolver{
		Stderr:     &stderr,
		Stdin:      strings.NewReader(""),
		IsTerminal: func() bool { return false },
		ReadSecret: func() ([]byte, error) { return nil, errors.New("no terminal in tests") },
	}, &stderr
}

func TestResolveReadsEachExplicitSource(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(passwordFile, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatalf("writing password file: %v", err)
	}

	tests := []struct {
		name    string
		request Request
		stdin   string
		want    string
		source  Source
	}{
		{
			name:    "inline flag still works while deprecated",
			request: Request{Inline: "from-argv"},
			want:    "from-argv",
			source:  SourceInline,
		},
		{
			name:    "explicit insecure opt-in",
			request: Request{Insecure: "from-argv-on-purpose"},
			want:    "from-argv-on-purpose",
			source:  SourceInsecure,
		},
		{
			name:    "password file, trailing newline stripped",
			request: Request{FilePath: passwordFile},
			want:    "from-a-file",
			source:  SourceFile,
		},
		{
			name:    "stdin, for pipelines",
			request: Request{Stdin: true},
			stdin:   "from-a-pipe\n",
			want:    "from-a-pipe",
			source:  SourceStdin,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := newTestResolver()
			resolver.Stdin = strings.NewReader(test.stdin)

			secret, source, err := resolver.Resolve(test.request)
			if err != nil {
				t.Fatalf("Resolve() error = %v, want nil", err)
			}
			if string(secret) != test.want {
				t.Errorf("password = %q, want %q", secret, test.want)
			}
			if source != test.source {
				t.Errorf("source = %q, want %q", source, test.source)
			}
		})
	}
}

// The deprecation warning is the whole mechanism of task 4: the flag keeps
// working for one minor release, but nobody gets to keep using it unaware.
func TestInlinePasswordWarnsAboutArgvExposure(t *testing.T) {
	resolver, stderr := newTestResolver()

	if _, _, err := resolver.Resolve(Request{Inline: "hunter2"}); err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	warning := stderr.String()
	if !strings.Contains(warning, "[deprecated]") {
		t.Errorf("stderr = %q, want a [deprecated] marker", warning)
	}
	for _, expected := range []string{"argv", "--password-file", "--password-stdin"} {
		if !strings.Contains(warning, expected) {
			t.Errorf("stderr = %q, want it to mention %q", warning, expected)
		}
	}
	if strings.Contains(warning, "hunter2") {
		t.Errorf("stderr echoed the password back: %q", warning)
	}
}

// --password-insecure is the explicit opt-in, so it must NOT nag. A warning
// nobody can act on is noise, and the user already said they meant it.
func TestInsecureOptInDoesNotWarn(t *testing.T) {
	resolver, stderr := newTestResolver()

	if _, _, err := resolver.Resolve(Request{Insecure: "hunter2"}); err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want silence for an explicit opt-in", stderr.String())
	}
}

func TestMultiplePasswordSourcesAreRejected(t *testing.T) {
	resolver, _ := newTestResolver()

	_, _, err := resolver.Resolve(Request{Inline: "a", FilePath: "b"})
	if err == nil {
		t.Fatal("Resolve() error = nil, want a conflict error")
	}
	for _, expected := range []string{"--password", "--password-file"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("error = %q, want it to name %q", err, expected)
		}
	}
}

func TestEmptyPasswordIsRejectedFromEverySource(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0o600); err != nil {
		t.Fatalf("writing empty password file: %v", err)
	}

	tests := []struct {
		name    string
		request Request
	}{
		{"empty file", Request{FilePath: emptyFile}},
		{"empty stdin", Request{Stdin: true}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := newTestResolver()
			if _, _, err := resolver.Resolve(test.request); err == nil {
				t.Fatal("Resolve() error = nil, want an empty-password error")
			}
		})
	}
}

// A password that legitimately ends in a space must survive the file round
// trip. Trimming all trailing whitespace would make the file work here and fail
// against an artifact encrypted with the real value.
func TestPasswordFileTrimsExactlyOneLineTerminator(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{"unix newline", "secret\n", "secret"},
		{"windows newline", "secret\r\n", "secret"},
		{"no newline", "secret", "secret"},
		{"trailing space is part of the password", "secret \n", "secret "},
		{"only one newline is removed", "secret\n\n", "secret\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("writing password file: %v", err)
			}

			resolver, _ := newTestResolver()
			secret, _, err := resolver.Resolve(Request{FilePath: path})
			if err != nil {
				t.Fatalf("Resolve() error = %v, want nil", err)
			}
			if string(secret) != test.want {
				t.Errorf("password = %q, want %q", secret, test.want)
			}
		})
	}
}

func TestPasswordFileRefusesWorldReadablePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are synthesised on Windows; see checkPermissions")
	}

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatalf("writing password file: %v", err)
	}

	resolver, _ := newTestResolver()
	_, _, err := resolver.Resolve(Request{FilePath: path})
	if err == nil {
		t.Fatal("Resolve() error = nil, want a permissions error for a 0644 password file")
	}
	if !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("error = %q, want it to explain the permissions problem", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error = %q, want it to name the fix", err)
	}
}

// The permission check is deliberately skipped on Windows. Pinning that as a
// test keeps it a decision rather than something that quietly breaks if the
// mode-bit logic is later made unconditional.
func TestPasswordFilePermissionCheckIsSkippedOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o666); err != nil {
		t.Fatalf("writing password file: %v", err)
	}

	resolver, _ := newTestResolver()
	resolver.GOOS = "windows"

	secret, _, err := resolver.Resolve(Request{FilePath: path})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil on windows", err)
	}
	if string(secret) != "secret" {
		t.Errorf("password = %q, want %q", secret, "secret")
	}
}

func TestPromptReadsFromTheTerminalWithoutEchoing(t *testing.T) {
	resolver, stderr := newTestResolver()
	resolver.IsTerminal = func() bool { return true }
	resolver.ReadSecret = func() ([]byte, error) { return []byte("typed-secret"), nil }

	secret, source, err := resolver.Resolve(Request{})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if string(secret) != "typed-secret" {
		t.Errorf("password = %q, want %q", secret, "typed-secret")
	}
	if source != SourcePrompt {
		t.Errorf("source = %q, want %q", source, SourcePrompt)
	}
	if !strings.Contains(stderr.String(), "Password:") {
		t.Errorf("stderr = %q, want a password prompt", stderr.String())
	}
	if strings.Contains(stderr.String(), "typed-secret") {
		t.Errorf("prompt echoed the password: %q", stderr.String())
	}
}

// Encrypting paths confirm, because a typo there produces an artifact nobody
// can open -- there is no other copy of the password to check against.
func TestConfirmPromptRequiresBothEntriesToMatch(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantErr bool
	}{
		{"matching entries", []string{"same", "same"}, false},
		{"mismatched entries", []string{"typed", "mistyped"}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := newTestResolver()
			resolver.IsTerminal = func() bool { return true }

			remaining := append([]string(nil), test.entries...)
			resolver.ReadSecret = func() ([]byte, error) {
				next := remaining[0]
				remaining = remaining[1:]
				return []byte(next), nil
			}

			_, _, err := resolver.Resolve(Request{Confirm: true})
			if test.wantErr {
				if err == nil {
					t.Fatal("Resolve() error = nil, want a mismatch error")
				}
				if !strings.Contains(err.Error(), "do not match") {
					t.Errorf("error = %q, want it to say the passwords do not match", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v, want nil", err)
			}
			if len(remaining) != 0 {
				t.Errorf("%d prompt(s) unread, want both consumed", len(remaining))
			}
		})
	}
}

// Without a terminal there is nothing to prompt, so the error has to name every
// way out -- otherwise a CI run just fails with no path forward.
func TestNoTerminalAndNoFlagNamesTheNonInteractiveOptions(t *testing.T) {
	resolver, _ := newTestResolver()

	_, _, err := resolver.Resolve(Request{})
	if err == nil {
		t.Fatal("Resolve() error = nil, want an error when stdin is not a terminal")
	}
	for _, expected := range []string{"--password-file", "--password-stdin", "--dev"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("error = %q, want it to offer %q", err, expected)
		}
	}
}

func TestZeroOverwritesTheBuffer(t *testing.T) {
	secret := []byte("super-secret")
	Zero(secret)

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("secret[%d] = %d, want 0 (buffer not zeroed)", i, b)
		}
	}
}

// Zero must act on the caller's own backing array, not a copy -- otherwise
// every call site that trusts it to erase a password erases nothing.
func TestZeroActsOnTheCallersBackingArray(t *testing.T) {
	backing := []byte("super-secret")
	alias := backing[:]

	Zero(alias)

	if !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Errorf("backing array = %q, want all zeroes", backing)
	}
}

func TestRequestAnyReportsWhetherASourceWasNamed(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		want    bool
	}{
		{"nothing named", Request{}, false},
		{"confirm alone is not a source", Request{Confirm: true}, false},
		{"inline", Request{Inline: "x"}, true},
		{"insecure", Request{Insecure: "x"}, true},
		{"file", Request{FilePath: "x"}, true},
		{"stdin", Request{Stdin: true}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.request.Any(); got != test.want {
				t.Errorf("Any() = %v, want %v", got, test.want)
			}
		})
	}
}
