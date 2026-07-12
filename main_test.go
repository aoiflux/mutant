package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mutant/global"
)

func TestShouldAttemptEmbeddedRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "bare executable attempts embedded run",
			args: []string{"mutant.exe"},
			want: true,
		},
		{
			name: "gen command does not attempt embedded run",
			args: []string{"mutant.exe", GENCMD},
			want: false,
		},
		{
			name: "help flag does not attempt embedded run",
			args: []string{"mutant.exe", "--help"},
			want: false,
		},
		{
			name: "source file does not attempt embedded run",
			args: []string{"mutant.exe", "hello" + global.MutantSourceCodeFileExtention},
			want: false,
		},
		{
			name: "unknown payload flag still attempts embedded run",
			args: []string{"mutant.exe", "--payload-mode"},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldAttemptEmbeddedRun(test.args); got != test.want {
				t.Fatalf("shouldAttemptEmbeddedRun(%v) = %t, want %t", test.args, got, test.want)
			}
		})
	}
}

func TestExtractSecurityModeArg(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "defaults to secure",
			args: []string{"mutant", "file.mu"},
			want: true,
		},
		{
			name: "compat disables secure mode",
			args: []string{"mutant", "file.mu", "--compat"},
			want: false,
		},
		{
			name: "dev disables secure mode",
			args: []string{"mutant", "file.mu", "--dev"},
			want: false,
		},
		{
			name: "last explicit mode wins",
			args: []string{"mutant", "file.mu", "--compat", "--secure"},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := extractSecurityModeArg(test.args); got != test.want {
				t.Fatalf("extractSecurityModeArg(%v) = %t, want %t", test.args, got, test.want)
			}
		})
	}
}

func TestHasReleaseAssetsArg(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "assets subcommand",
			args: []string{"mutant", GENCMD, "assets"},
			want: true,
		},
		{
			name: "legacy release assets flag",
			args: []string{"mutant", GENCMD, "--release-assets"},
			want: true,
		},
		{
			name: "normal gen command",
			args: []string{"mutant", GENCMD, "hello.mut"},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasReleaseAssetsArg(test.args); got != test.want {
				t.Fatalf("hasReleaseAssetsArg(%v) = %t, want %t", test.args, got, test.want)
			}
		})
	}
}

func TestPrepareGenRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantSrc      string
		wantPassword string
		wantMutation int
		wantSeed     int64
	}{
		{
			name:         "parses positional source and options",
			args:         []string{"mutant", GENCMD, "hello.mut", "--password", "secret", "--mutation", "5", "--seed", "42"},
			wantSrc:      "hello.mut",
			wantPassword: "secret",
			wantMutation: 5,
			wantSeed:     42,
		},
		{
			name:         "parses explicit src flag and pwd alias",
			args:         []string{"mutant", GENCMD, "--src", "hello.mut", "--pwd=abc"},
			wantSrc:      "hello.mut",
			wantPassword: "abc",
			wantMutation: defaultPolymorphicLevel,
			wantSeed:     0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src, password, mutation, seed, err := prepareGenRun(test.args)
			if err != nil {
				t.Fatalf("prepareGenRun(%v) returned error: %v", test.args, err)
			}

			wantSrc, err := filepath.Abs(test.wantSrc)
			if err != nil {
				t.Fatalf("filepath.Abs(%q): %v", test.wantSrc, err)
			}

			if src != wantSrc {
				t.Fatalf("src = %q, want %q", src, wantSrc)
			}
			if password != test.wantPassword {
				t.Fatalf("password = %q, want %q", password, test.wantPassword)
			}
			if mutation != test.wantMutation {
				t.Fatalf("mutation = %d, want %d", mutation, test.wantMutation)
			}
			if seed != test.wantSeed {
				t.Fatalf("seed = %d, want %d", seed, test.wantSeed)
			}
		})
	}
}

func TestPrepareRelease(t *testing.T) {
	src, goos, goarch, password, mutation, seed, err := prepareRelease([]string{
		"mutant",
		RELEASECMD,
		"hello.mut",
		"--os", "windows",
		"--arch", "amd64",
		"--password", "secret",
		"--mutation", "7",
		"--seed", "99",
	})
	if err != nil {
		t.Fatalf("prepareRelease returned error: %v", err)
	}

	wantSrc, err := filepath.Abs("hello.mut")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if src != wantSrc {
		t.Fatalf("src = %q, want %q", src, wantSrc)
	}
	if goos != "windows" {
		t.Fatalf("goos = %q, want %q", goos, "windows")
	}
	if goarch != "amd64" {
		t.Fatalf("goarch = %q, want %q", goarch, "amd64")
	}
	if password != "secret" {
		t.Fatalf("password = %q, want %q", password, "secret")
	}
	if mutation != 7 {
		t.Fatalf("mutation = %d, want %d", mutation, 7)
	}
	if seed != 99 {
		t.Fatalf("seed = %d, want %d", seed, 99)
	}
}

func TestPrepareReleaseAssetsGeneration(t *testing.T) {
	out, err := prepareReleaseAssetsGeneration([]string{
		"mutant",
		GENCMD,
		"assets",
		"--out",
		"build/releaseassets",
	})
	if err != nil {
		t.Fatalf("prepareReleaseAssetsGeneration returned error: %v", err)
	}

	wantOut, err := filepath.Abs("build/releaseassets")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if out != wantOut {
		t.Fatalf("out = %q, want %q", out, wantOut)
	}
}

func TestPrintGeneralHelp(t *testing.T) {
	output := captureStdout(t, printGeneralHelp)

	assertContains(t, output, "Usage:")
	assertContains(t, output, "mutant gen assets [options]")
	assertContains(t, output, "Runtime options:")
	assertContains(t, output, "mutant help release")
}

func TestPrintHelpTopic(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		wants []string
	}{
		{
			name:  "gen assets help topic",
			args:  []string{GENCMD, "assets"},
			wants: []string{"mutant gen assets", "--release-assets"},
		},
		{
			name:  "run help topic",
			args:  []string{RUNCMD},
			wants: []string{"mutant run", "Legacy alias for \"mutant gen\""},
		},
		{
			name:  "unknown help topic falls back to general help",
			args:  []string{"weird"},
			wants: []string{"unknown help topic: weird", "Commands:"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				printHelpTopic(test.args)
			})

			for _, want := range test.wants {
				assertContains(t, output, want)
			}
		})
	}
}

func TestHandleBuiltinCommand(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		want  bool
		wants []string
	}{
		{
			name:  "help flag handled",
			args:  []string{"mutant", "--help"},
			want:  true,
			wants: []string{"Usage:", "Commands:"},
		},
		{
			name:  "version flag handled",
			args:  []string{"mutant", "--version"},
			want:  true,
			wants: []string{VERSION},
		},
		{
			name: "non builtin command not handled",
			args: []string{"mutant", GENCMD},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				if got := handleBuiltinCommand(test.args); got != test.want {
					t.Fatalf("handleBuiltinCommand(%v) = %t, want %t", test.args, got, test.want)
				}
			})

			for _, want := range test.wants {
				assertContains(t, output, want)
			}
		})
	}
}

func TestRunDispatchesGenCommand(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	var called bool
	var gotSrc, gotPassword string
	var gotMutation int
	var gotSeed int64
	var gotRelease bool

	runtimeDeps.compileCode = func(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64) {
		called = true
		gotSrc = src
		gotPassword = password
		gotMutation = mutationLevel
		gotSeed = mutationSeed
		gotRelease = release
	}

	exitCode := run([]string{"mutant", GENCMD, "hello.mut", "--password", "secret", "--mutation", "5", "--seed", "42"})
	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}
	if !called {
		t.Fatalf("expected compileCode to be called")
	}

	wantSrc, err := filepath.Abs("hello.mut")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if gotSrc != wantSrc {
		t.Fatalf("src = %q, want %q", gotSrc, wantSrc)
	}
	if gotPassword != "secret" {
		t.Fatalf("password = %q, want %q", gotPassword, "secret")
	}
	if gotMutation != 5 {
		t.Fatalf("mutation = %d, want %d", gotMutation, 5)
	}
	if gotSeed != 42 {
		t.Fatalf("seed = %d, want %d", gotSeed, 42)
	}
	if gotRelease {
		t.Fatalf("release = %t, want false", gotRelease)
	}
}

func TestRunDispatchesAssetsCommand(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	var gotOut string
	runtimeDeps.generateReleaseAssets = func(out string) {
		gotOut = out
	}

	exitCode := run([]string{"mutant", GENCMD, "assets", "--out", "build/releaseassets"})
	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}

	wantOut, err := filepath.Abs("build/releaseassets")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if gotOut != wantOut {
		t.Fatalf("out = %q, want %q", gotOut, wantOut)
	}
}

func TestRunDispatchesReleaseCommand(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	var called bool
	var gotSrc, gotOS, gotArch string
	var gotPassword string
	var gotRelease bool

	runtimeDeps.compileCode = func(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64) {
		called = true
		gotSrc = src
		gotOS = goos
		gotArch = goarch
		gotPassword = password
		gotRelease = release
	}

	exitCode := run([]string{"mutant", RELEASECMD, "hello.mut", "--os", "windows", "--arch", "amd64", "--password", "secret"})
	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}
	if !called {
		t.Fatalf("expected compileCode to be called")
	}

	wantSrc, err := filepath.Abs("hello.mut")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if gotSrc != wantSrc {
		t.Fatalf("src = %q, want %q", gotSrc, wantSrc)
	}
	if gotOS != "windows" {
		t.Fatalf("goos = %q, want %q", gotOS, "windows")
	}
	if gotArch != "amd64" {
		t.Fatalf("goarch = %q, want %q", gotArch, "amd64")
	}
	if gotPassword != "secret" {
		t.Fatalf("password = %q, want %q", gotPassword, "secret")
	}
	if !gotRelease {
		t.Fatalf("release = %t, want true", gotRelease)
	}
}

func TestRunDispatchesBytecodeInvocation(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	var gotSrc, gotPassword string
	var gotSecure, gotSignerAuth bool

	runtimeDeps.runCode = func(src, password string, secureMode bool, enforceSignerAuth bool) {
		gotSrc = src
		gotPassword = password
		gotSecure = secureMode
		gotSignerAuth = enforceSignerAuth
	}

	exitCode := run([]string{"mutant", "hello.mu", "--password", "secret", "--compat", "--signer-auth"})
	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}

	if gotSrc != "hello.mu" {
		t.Fatalf("src = %q, want %q", gotSrc, "hello.mu")
	}
	if gotPassword != "secret" {
		t.Fatalf("password = %q, want %q", gotPassword, "secret")
	}
	if gotSecure {
		t.Fatalf("secureMode = %t, want false", gotSecure)
	}
	if !gotSignerAuth {
		t.Fatalf("enforceSignerAuth = %t, want true", gotSignerAuth)
	}
}

func TestRunReturnsErrorForUnknownCommand(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	output := captureStdout(t, func() {
		if exitCode := run([]string{"mutant", "unknown-command"}); exitCode != 1 {
			t.Fatalf("run returned exit code %d, want 1", exitCode)
		}
	})

	assertContains(t, output, "unknown command or file: unknown-command")
	assertContains(t, output, "Commands:")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	return string(output)
}

func assertContains(t *testing.T, output, want string) {
	t.Helper()
	if !strings.Contains(output, want) {
		t.Fatalf("output did not contain %q\noutput:\n%s", want, output)
	}
}

func withRuntimeDeps(deps cliRuntime) func() {
	original := runtimeDeps
	runtimeDeps = deps
	return func() {
		runtimeDeps = original
	}
}

func stubRuntimeDeps() cliRuntime {
	return cliRuntime{
		runRepl:               func(string, bool, string) {},
		compileCode:           func(string, string, string, bool, string, int, int64) {},
		generateReleaseAssets: func(string) {},
		runCode:               func(string, string, bool, bool) {},
		hasStandalonePayload:  func(string) (bool, error) { return false, nil },
		executablePath:        func() (string, error) { return "", nil },
		getPwd:                func() string { return "stub-password" },
	}
}

func TestStubRuntimeDepsShape(t *testing.T) {
	if reflect.ValueOf(stubRuntimeDeps()).Type() != reflect.TypeOf(cliRuntime{}) {
		t.Fatalf("stubRuntimeDeps returned unexpected type")
	}
}
