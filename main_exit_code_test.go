package main

import "testing"

// A failed compile or a failed run has to leave a non-zero exit code. Both used
// to print the error and then report success, so nothing calling mutant -- a
// shell script, a CI step, a build pipeline -- could tell a broken program from
// a working one. The worst case was a released standalone binary that refused a
// wrong password and still exited 0.

func TestFailedCompileExitsNonZero(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"gen", []string{"mutant", GENCMD, "hello.mut", "--password", "secret"}},
		{"run of a source file", []string{"mutant", "hello.mut", "--password", "secret"}},
		{"release", []string{"mutant", RELEASECMD, "hello.mut", "--os", "windows", "--arch", "amd64", "--password", "secret"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := stubRuntimeDeps()
			deps.compileCode = func(string, string, string, bool, string, int, int64) int { return 1 }
			defer withRuntimeDeps(deps)()

			if got := run(tc.args); got != 1 {
				t.Fatalf("a failed compile exited %d, want 1", got)
			}
		})
	}
}

func TestFailedRunExitsNonZero(t *testing.T) {
	deps := stubRuntimeDeps()
	deps.runCode = func(string, string, bool, bool) int { return 1 }
	defer withRuntimeDeps(deps)()

	if got := run([]string{"mutant", "hello.mu", "--password", "secret"}); got != 1 {
		t.Fatalf("a failed run exited %d, want 1", got)
	}
}

// The standalone release path is the one that matters most: the payload is
// embedded in the executable, so this is what a user ships.
func TestFailedEmbeddedPayloadRunExitsNonZero(t *testing.T) {
	deps := stubRuntimeDeps()
	deps.hasStandalonePayload = func(string) (bool, error) { return true, nil }
	deps.executablePath = func() (string, error) { return "mutant-release.exe", nil }
	deps.runCode = func(string, string, bool, bool) int { return 1 }
	defer withRuntimeDeps(deps)()

	if got := run([]string{"mutant-release.exe", "--password", "secret"}); got != 1 {
		t.Fatalf("a failed standalone run exited %d, want 1", got)
	}
}

func TestFailedReleaseAssetGenerationExitsNonZero(t *testing.T) {
	deps := stubRuntimeDeps()
	deps.generateReleaseAssets = func(string) int { return 1 }
	defer withRuntimeDeps(deps)()

	if got := run([]string{"mutant", GENCMD, "assets", "--out", "build/releaseassets"}); got != 1 {
		t.Fatalf("failed asset generation exited %d, want 1", got)
	}
}

// Success must still be 0 -- the fix must not turn every invocation red.
func TestSuccessfulCommandsExitZero(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"gen", []string{"mutant", GENCMD, "hello.mut", "--password", "secret"}},
		{"run", []string{"mutant", "hello.mu", "--password", "secret"}},
		{"release", []string{"mutant", RELEASECMD, "hello.mut", "--os", "linux", "--arch", "amd64", "--password", "secret"}},
		{"assets", []string{"mutant", GENCMD, "assets", "--out", "build/releaseassets"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer withRuntimeDeps(stubRuntimeDeps())()

			if got := run(tc.args); got != 0 {
				t.Fatalf("a successful %s exited %d, want 0", tc.name, got)
			}
		})
	}
}
