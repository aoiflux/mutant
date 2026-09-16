package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mutant/credential"
	"mutant/global"
	"mutant/runner"
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
			src, request, mutation, seed, _, err := prepareGenRun(test.args)
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
			// prepareGenRun now returns the *request* rather than a resolved
			// password: an argv password is one source among four, and resolving it
			// is credential.Resolver's job.
			if request.Inline != test.wantPassword {
				t.Fatalf("request.Inline = %q, want %q", request.Inline, test.wantPassword)
			}
			if !request.Confirm {
				t.Errorf("request.Confirm = false, want true -- gen encrypts, so a typo is unrecoverable")
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
	src, goos, goarch, request, mutation, seed, _, err := prepareRelease([]string{
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
	if request.Inline != "secret" {
		t.Fatalf("request.Inline = %q, want %q", request.Inline, "secret")
	}
	if !request.Confirm {
		t.Errorf("request.Confirm = false, want true -- release encrypts, so a typo is unrecoverable")
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

	runtimeDeps.compileCode = func(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64, modulePaths []string) int {
		called = true
		gotSrc = src
		gotPassword = password
		gotMutation = mutationLevel
		gotSeed = mutationSeed
		gotRelease = release
		return 0
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
	runtimeDeps.generateReleaseAssets = func(out string) int {
		gotOut = out
		return 0
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

	runtimeDeps.compileCode = func(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64, modulePaths []string) int {
		called = true
		gotSrc = src
		gotOS = goos
		gotArch = goarch
		gotPassword = password
		gotRelease = release
		return 0
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

	var gotSrc string
	var gotOpts runner.Options

	runtimeDeps.runCode = func(src string, opts runner.Options) int {
		gotSrc = src
		gotOpts = opts
		return 0
	}

	exitCode := run([]string{"mutant", "hello.mu", "--password", "secret", "--compat", "--signer-auth"})
	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}

	if gotSrc != "hello.mu" {
		t.Fatalf("src = %q, want %q", gotSrc, "hello.mu")
	}
	if gotOpts.Password != "secret" {
		t.Fatalf("password = %q, want %q", gotOpts.Password, "secret")
	}
	if gotOpts.SecureMode {
		t.Fatalf("secureMode = %t, want false", gotOpts.SecureMode)
	}
	if !gotOpts.EnforceSignerAuth {
		t.Fatalf("enforceSignerAuth = %t, want true", gotOpts.EnforceSignerAuth)
	}
	if gotOpts.Timing {
		t.Fatalf("timing = %t, want false", gotOpts.Timing)
	}
}

// Timing used to be switched on by an environment variable, which meant a run
// could not be reproduced from the command line an analyst wrote down. It is a
// flag now, and nothing in the toolchain reads the environment for configuration.
func TestTimingIsCarriedFromTheCommandLine(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	var gotOpts runner.Options
	runtimeDeps.runCode = func(_ string, opts runner.Options) int {
		gotOpts = opts
		return 0
	}

	if exitCode := run([]string{"mutant", "hello.mu", "--timing", "--password", "secret"}); exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}

	if !gotOpts.Timing {
		t.Fatalf("timing = %t, want true", gotOpts.Timing)
	}
}

// The trusted verification key arrives as a path on the command line, never as
// key material in the environment. See docs/CONFIGURATION_POLICY.md.
func TestTrustedKeyPathIsCarriedFromTheCommandLine(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"separated", []string{"mutant", "hello.mu", "--password", "secret", "--trusted-key", "keys/pub.hex"}, "keys/pub.hex"},
		{"joined", []string{"mutant", "hello.mu", "--password", "secret", "--trusted-key=keys/pub.hex"}, "keys/pub.hex"},
		{"absent", []string{"mutant", "hello.mu", "--password", "secret"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

			var gotOpts runner.Options
			runtimeDeps.runCode = func(_ string, opts runner.Options) int {
				gotOpts = opts
				return 0
			}

			if exitCode := run(tc.args); exitCode != 0 {
				t.Fatalf("run returned exit code %d, want 0", exitCode)
			}
			if gotOpts.TrustedKeyPath != tc.want {
				t.Fatalf("trustedKeyPath = %q, want %q", gotOpts.TrustedKeyPath, tc.want)
			}
		})
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

// The dev-mode contract is "no password required". It used to hold only on the
// run side: executeProgramFile branched on the file extension before resolving
// the password, so the .mut compile path ran with an empty key and the AES layer
// rejects one. No Mutant program could be compiled without a password by any
// means, which made the dev key unreachable through the CLI. (M-1)
func TestDevModeCompilesAndRunsWithoutAPassword(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"compile a .mut", "hello" + global.MutantSourceCodeFileExtention},
		{"run a .mu", "hello" + global.MutantByteCodeCompiledFileExtension},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

			gotPassword := ""
			runtimeDeps.compileCode = func(_, _, _ string, _ bool, password string, _ int, _ int64, _ []string) int {
				gotPassword = password
				return 0
			}
			runtimeDeps.runCode = func(_ string, opts runner.Options) int {
				gotPassword = opts.Password
				return 0
			}

			exitCode := 0
			captureStderr(t, func() {
				exitCode = run([]string{"mutant", tc.file, "--dev"})
			})

			if exitCode != 0 {
				t.Fatalf("run returned exit code %d, want 0", exitCode)
			}
			if gotPassword != "stub-password" {
				t.Fatalf("password = %q, want the development key", gotPassword)
			}
		})
	}
}

// The fallback used to be positional -- `len(args) == 2` -- so a plain
// `mutant prog.mu` silently decrypted with the built-in development key, which
// is a compile-time constant published in every binary. Because the test counted
// argv rather than reading intent, adding a supposedly no-op --secure changed
// which key was used. Neither invocation may reach getPwd(), and both must
// behave the same way. (M-2)
func TestDefaultModeNeverUsesTheDevelopmentKey(t *testing.T) {
	invocations := [][]string{
		{"mutant", "hello" + global.MutantByteCodeCompiledFileExtension},
		{"mutant", "hello" + global.MutantByteCodeCompiledFileExtension, "--secure"},
	}

	for _, args := range invocations {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

			devKeyUsed, programRan := false, false
			runtimeDeps.getPwd = func() string {
				devKeyUsed = true
				return "stub-password"
			}
			runtimeDeps.runCode = func(string, runner.Options) int {
				programRan = true
				return 0
			}

			// Stubbed rather than relying on `go test` handing the binary a
			// non-terminal stdin: this test is about the dev key never being
			// reached, and it should not also be a test of the ambient tty.
			t.Cleanup(withPasswordResolver(func(req credential.Request) ([]byte, credential.Source, error) {
				return (&credential.Resolver{IsTerminal: func() bool { return false }}).Resolve(req)
			}))

			exitCode := 0
			output := captureStderr(t, func() {
				exitCode = run(args)
			})

			if exitCode != 1 {
				t.Fatalf("run returned exit code %d, want 1: a missing password is an error, never a silent downgrade", exitCode)
			}
			if devKeyUsed {
				t.Fatal("getPwd() was reached outside dev mode")
			}
			if programRan {
				t.Fatal("the program ran with no password supplied")
			}
			// Each option is asserted in full. Checking for "--password" alone
			// would pass on the substring inside "--password-file" and stop
			// proving anything the moment that flag was added.
			for _, wayOut := range []string{"--password-file", "--password-stdin", "--dev"} {
				assertContains(t, output, wayOut)
			}
		})
	}
}

// GetPwd() is identical in every Mutant binary ever built, so anything encrypted
// under it is readable by anyone holding a copy of the binary. Reaching for it
// silently is the problem; saying so is the fix. (M-3)
func TestDevModeAnnouncesTheDevelopmentKey(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	output := captureStderr(t, func() {
		if exitCode := run([]string{"mutant", "hello" + global.MutantByteCodeCompiledFileExtension, "--dev"}); exitCode != 0 {
			t.Fatalf("run returned exit code %d, want 0", exitCode)
		}
	})

	assertContains(t, output, "built-in development key")
	assertContains(t, output, "not for release artifacts")
}

// A release artifact built under the development key would have no
// confidentiality at all, so --dev is refused rather than warned about. (M-3)
func TestReleaseCommandsRefuseDevMode(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"release", []string{"mutant", RELEASECMD, "--src", "hello" + global.MutantSourceCodeFileExtention, "--dev"}},
		{"gen assets", []string{"mutant", GENCMD, "assets", "--out", "assets.go", "--dev"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

			built := false
			runtimeDeps.compileCode = func(string, string, string, bool, string, int, int64, []string) int {
				built = true
				return 0
			}
			runtimeDeps.generateReleaseAssets = func(string) int {
				built = true
				return 0
			}

			exitCode := 0
			output := captureStdout(t, func() {
				exitCode = run(tc.args)
			})

			if exitCode == 0 {
				t.Fatalf("run returned exit code 0, want non-zero: --dev must not produce a release artifact")
			}
			if built {
				t.Fatal("a release artifact was produced under the development key")
			}
			assertContains(t, output, "--dev cannot be used when producing a release artifact")
		})
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	return captureFile(t, &os.Stderr, fn)
}

// captureFile redirects one of the process's standard streams for the duration
// of fn and returns what was written to it.
//
// The reader drains concurrently with fn rather than after it. A pipe holds only
// a few kilobytes -- 4 KiB on Windows -- so a helper that writes everything
// before reading anything deadlocks the moment the output it captures outgrows
// that buffer, which `mutant --help` did the first time a few lines were added
// to it. The failure is a hung test, not a failed assertion, so it does not
// point at what caused it.
func captureFile(t *testing.T, stream **os.File, fn func()) string {
	t.Helper()

	original := *stream
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	*stream = writer
	defer func() {
		*stream = original
	}()

	captured := make(chan string, 1)
	go func() {
		output, readErr := io.ReadAll(reader)
		if readErr != nil {
			captured <- ""
			return
		}
		captured <- string(output)
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	return <-captured
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	return captureFile(t, &os.Stdout, fn)
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
		compileCode:           func(string, string, string, bool, string, int, int64, []string) int { return 0 },
		generateReleaseAssets: func(string) int { return 0 },
		runCode:               func(string, runner.Options) int { return 0 },
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

// ---------------------------------------------------------------------------
// S-2 -- credential handling: the password must not have to travel in argv.
// ---------------------------------------------------------------------------

// withPasswordResolver swaps the credential resolver for one test. Every test
// that exercises a password path uses it, so no test depends on whether the
// process running `go test` happens to have a terminal on stdin.
func withPasswordResolver(fn func(credential.Request) ([]byte, credential.Source, error)) func() {
	original := resolvePassword
	resolvePassword = fn
	return func() {
		resolvePassword = original
	}
}

func TestExtractPasswordRequestParsesEverySource(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want credential.Request
	}{
		{
			name: "no password source named",
			args: []string{"mutant", "hello.mu"},
			want: credential.Request{},
		},
		{
			name: "separated inline flag",
			args: []string{"mutant", "hello.mu", "--password", "secret"},
			want: credential.Request{Inline: "secret"},
		},
		{
			name: "joined inline flag",
			args: []string{"mutant", "hello.mu", "--password=secret"},
			want: credential.Request{Inline: "secret"},
		},
		{
			name: "single-dash pwd alias",
			args: []string{"mutant", "hello.mu", "-pwd", "secret"},
			want: credential.Request{Inline: "secret"},
		},
		{
			name: "joined pwd alias",
			args: []string{"mutant", "hello.mu", "-pwd=secret"},
			want: credential.Request{Inline: "secret"},
		},
		{
			name: "password file",
			args: []string{"mutant", "hello.mu", "--password-file", "/keys/pw"},
			want: credential.Request{FilePath: "/keys/pw"},
		},
		{
			name: "password file, joined",
			args: []string{"mutant", "hello.mu", "--password-file=/keys/pw"},
			want: credential.Request{FilePath: "/keys/pw"},
		},
		{
			name: "stdin",
			args: []string{"mutant", "hello.mu", "--password-stdin"},
			want: credential.Request{Stdin: true},
		},
		{
			name: "explicit insecure opt-in",
			args: []string{"mutant", "hello.mu", "--password-insecure", "secret"},
			want: credential.Request{Insecure: "secret"},
		},
		{
			// --password-insecure must not be mistaken for --password carrying the
			// value "-insecure": the prefix match has to lose to the longer flag.
			name: "insecure opt-in is not parsed as inline",
			args: []string{"mutant", "hello.mu", "--password-insecure=secret"},
			want: credential.Request{Insecure: "secret"},
		},
		{
			// Conflicts are collected here and rejected by the resolver, so the
			// error can name every source the user actually typed.
			name: "conflicting sources are both recorded",
			args: []string{"mutant", "hello.mu", "--password", "a", "--password-stdin"},
			want: credential.Request{Inline: "a", Stdin: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractPasswordRequest(test.args, false)
			if got != test.want {
				t.Errorf("extractPasswordRequest() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// The done_when for S-2: the buffer the resolver handed back must be zeroed
// once the password has been converted for the encryption pipeline.
func TestPasswordBufferIsZeroedAfterResolution(t *testing.T) {
	secret := []byte("super-secret")
	t.Cleanup(withPasswordResolver(func(credential.Request) ([]byte, credential.Source, error) {
		return secret, credential.SourceFile, nil
	}))

	password, err := resolveProgramPassword(credential.Request{FilePath: "/keys/pw"}, false)
	if err != nil {
		t.Fatalf("resolveProgramPassword() error = %v, want nil", err)
	}

	if password != "super-secret" {
		t.Fatalf("password = %q, want %q", password, "super-secret")
	}

	for i, b := range secret {
		if b != 0 {
			t.Fatalf("resolver buffer byte %d = %d, want 0: the password was left in memory", i, b)
		}
	}
}

// The built-in development key applies only when nothing else was named. An
// explicit source that fails must surface its own error rather than being
// papered over by the development key -- otherwise a mistyped --password-file
// silently produces a dev-key artifact. (M-1/M-3 boundary, retested under S-2)
func TestDevModeDoesNotOverrideAnExplicitPasswordSource(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	devKeyUsed := false
	runtimeDeps.getPwd = func() string {
		devKeyUsed = true
		return "stub-password"
	}
	t.Cleanup(withPasswordResolver(func(credential.Request) ([]byte, credential.Source, error) {
		return nil, credential.SourceFile, errors.New("--password-file: no such file")
	}))

	_, err := resolveProgramPassword(credential.Request{FilePath: "/missing"}, true)
	if err == nil {
		t.Fatal("resolveProgramPassword() error = nil, want the password-file error")
	}
	if devKeyUsed {
		t.Error("getPwd() was reached even though --password-file was named")
	}
}

func TestPasswordFileIsReadEndToEnd(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(passwordFile, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatalf("writing password file: %v", err)
	}

	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	got := ""
	runtimeDeps.runCode = func(_ string, opts runner.Options) int {
		got = opts.Password
		return 0
	}

	exitCode := run([]string{
		"mutant",
		"hello" + global.MutantByteCodeCompiledFileExtension,
		"--password-file", passwordFile,
	})

	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0", exitCode)
	}
	if got != "from-a-file" {
		t.Fatalf("password reaching the runner = %q, want %q", got, "from-a-file")
	}
}

// The inline flag keeps working for one minor release, but it announces itself
// every time. Silent deprecation is how a leak survives a version bump.
func TestInlinePasswordStillRunsButWarns(t *testing.T) {
	t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

	got := ""
	runtimeDeps.runCode = func(_ string, opts runner.Options) int {
		got = opts.Password
		return 0
	}

	exitCode := 0
	output := captureStderr(t, func() {
		exitCode = run([]string{
			"mutant",
			"hello" + global.MutantByteCodeCompiledFileExtension,
			"--password", "secret",
		})
	})

	if exitCode != 0 {
		t.Fatalf("run returned exit code %d, want 0: --password must keep working this release", exitCode)
	}
	if got != "secret" {
		t.Fatalf("password reaching the runner = %q, want %q", got, "secret")
	}
	assertContains(t, output, "[deprecated]")
	assertContains(t, output, "--password-file")
	if strings.Contains(output, "secret") {
		t.Errorf("the deprecation warning echoed the password back:\n%s", output)
	}
}

// Compiling encrypts, so a mistyped password is unrecoverable -- there is no
// second copy anywhere to check it against. Running only decrypts, where a
// wrong password merely fails. The confirm prompt has to follow that split.
func TestOnlyEncryptingPathsConfirmThePassword(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		wantConfirm bool
	}{
		{
			name:        "compiling a .mut confirms",
			file:        "hello" + global.MutantSourceCodeFileExtention,
			wantConfirm: true,
		},
		{
			name:        "running a .mu does not confirm",
			file:        "hello" + global.MutantByteCodeCompiledFileExtension,
			wantConfirm: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(withRuntimeDeps(stubRuntimeDeps()))

			gotConfirm := false
			t.Cleanup(withPasswordResolver(func(req credential.Request) ([]byte, credential.Source, error) {
				gotConfirm = req.Confirm
				return []byte("secret"), credential.SourcePrompt, nil
			}))

			if exitCode := run([]string{"mutant", test.file, "--password", "secret"}); exitCode != 0 {
				t.Fatalf("run returned exit code %d, want 0", exitCode)
			}
			if gotConfirm != test.wantConfirm {
				t.Errorf("Request.Confirm = %v, want %v", gotConfirm, test.wantConfirm)
			}
		})
	}
}

func TestContradictoryModeFlagsAreRejected(t *testing.T) {
	// Both orders, both spellings, and with the file argument in the position it
	// really occupies: the old resolution was positional in one case (--dev won
	// over --secure regardless of order) and last-flag-wins in the others, so a
	// test that only checked one order would have passed against the old code.
	contradictions := []struct {
		name string
		args []string
		want []string
	}{
		{"secure then compat", []string{"mutant", "p.mu", "--secure", "--compat"}, []string{"--secure", "--compat"}},
		{"compat then secure", []string{"mutant", "p.mu", "--compat", "--secure"}, []string{"--secure", "--compat"}},
		{"secure then dev", []string{"mutant", "p.mu", "--secure", "--dev"}, []string{"--secure", "--dev"}},
		{"dev then secure", []string{"mutant", "p.mu", "--dev", "--secure"}, []string{"--secure", "--dev"}},
		{"single dash spellings", []string{"mutant", "p.mu", "-dev", "-secure"}, []string{"--secure", "--dev"}},
		{"mixed spellings", []string{"mutant", "p.mu", "--compat", "-secure"}, []string{"--secure", "--compat"}},
		{"signer auth both ways", []string{"mutant", "p.mu", "--signer-auth", "--no-signer-auth"}, []string{"--signer-auth", "--no-signer-auth"}},
		{"contradiction on a gen command", []string{"mutant", "gen", "--src", "p.mut", "--dev", "--secure"}, []string{"--secure", "--dev"}},
	}

	for _, tc := range contradictions {
		t.Run(tc.name, func(t *testing.T) {
			var exitCode int
			output := captureStderr(t, func() {
				exitCode = run(tc.args)
			})

			if exitCode == 0 {
				t.Fatalf("expected a non-zero exit for %v, got 0", tc.args)
			}
			for _, flag := range tc.want {
				if !strings.Contains(output, flag) {
					t.Fatalf("expected the error to name %s, got: %s", flag, output)
				}
			}
		})
	}
}

func TestNonContradictoryFlagCombinationsAreLeftAlone(t *testing.T) {
	// --dev implies --compat, so naming both is redundant rather than
	// contradictory, and repeating a flag is how a wrapper script that appends
	// one to an already-complete command line behaves.
	harmless := [][]string{
		{"mutant", "p.mu", "--dev", "--compat"},
		{"mutant", "p.mu", "--compat", "--compat"},
		{"mutant", "p.mu", "--secure", "--secure"},
		{"mutant", "p.mu", "--secure", "--signer-auth"},
		{"mutant", "p.mu", "--dev", "--timing"},
	}

	for _, args := range harmless {
		if err := validateModeFlags(args); err != nil {
			t.Fatalf("expected %v to be accepted, got: %v", args, err)
		}
	}
}
