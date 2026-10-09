package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go.mod names the Go version a release is meant to be built with, and the two
// release gates refuse any other. Not pedantry about patch numbers: go1.27.0
// turns the jsonv2 experiment on by default, so encoding/json compiles from its
// v2_*.go sources and the v1 files are not built at all, while every gate of
// the 2.6.0 review ran on the v1 engine.
//
// The BUILD scripts deliberately do not check. Owner decision 2026-10-09: the
// refusal made compiling difficult, so it came out of scripts/build.ps1 and
// scripts/build.sh along with every comment that described it. The pin is
// therefore enforced in exactly two places, and this file is what keeps those
// two from quietly becoming none.
//
// M26-RUN-019 is why it is worth a test at all. Commit a923a5c had already
// deleted the five checking lines from build.ps1 while leaving three separate
// pieces of prose saying the version "is checked below rather than trusted" --
// a script describing a refusal it no longer performed, on the one release path
// that is a Windows default run. Three sibling scripts still had the check and
// nothing compared them, because nothing was watching.

// toolchainPinWindow is how many lines after the comparison its refusal may
// appear. Both gates spell it one to two lines later; the window is wider than
// needed so that adding an error message does not fail the test.
const toolchainPinWindow = 6

// toolchainPinGates is every script that gates a release. The two shells
// interpolate the same way, so the expected text differs only in the variable
// each language names.
var toolchainPinGates = []struct {
	rel      string
	compare  string   // the comparison against what the toolchain reports
	refusals []string // any one of these, inside the window, ends the run
}{
	{"scripts/release_gate.ps1", `"go$goModVersion"`, []string{"throw "}},
	{"scripts/release_gate.sh", `"go$GO_MOD_VERSION"`, []string{"return 1", "exit 1"}},
}

// toolchainUnpinnedBuilders are the scripts the owner decided should build with
// whatever toolchain they are handed. They are named here so that the claim is
// recorded rather than merely absent, and so the test below can hold them to
// the other half of that decision: a script that does not check must not say it
// does.
var toolchainUnpinnedBuilders = []string{"scripts/build.ps1", "scripts/build.sh"}

// TestEveryReleaseGateRefusesAnUnpinnedToolchain: each gate reads the pinned
// version out of go.mod, asks the toolchain it was given what version it
// actually is, compares the two, and stops on a mismatch. All four steps are
// checked, because three of them without the fourth is what a923a5c shipped in
// build.ps1 -- it kept the parameter, the comments and the build, and lost only
// the refusal.
func TestEveryReleaseGateRefusesAnUnpinnedToolchain(t *testing.T) {
	for _, s := range toolchainPinGates {
		t.Run(filepath.Base(s.rel), func(t *testing.T) {
			lines := toolchainPinLines(t, s.rel)

			if !toolchainPinAny(lines, "go.mod") {
				t.Errorf("%s never reads go.mod, so it has no pinned version to compare against", s.rel)
			}
			if !toolchainPinAny(lines, "env GOVERSION") {
				t.Errorf("%s never asks the toolchain for its GOVERSION, so it cannot know what it is gating", s.rel)
			}

			at := -1
			for n, line := range lines {
				if strings.Contains(line, s.compare) && !toolchainPinIsComment(line) {
					at = n
					break
				}
			}
			if at < 0 {
				t.Fatalf("%s does not compare the toolchain against the pin; expected a line holding %s outside a comment. "+
					"The build scripts no longer check, so this gate is one of only two places that does: "+
					"without it a release could be gated on one Go and shipped from another, which is how v2.5.0 "+
					"came to be built with a newer Go than its own tag pinned.", s.rel, s.compare)
			}

			end := min(at+toolchainPinWindow, len(lines))
			for _, want := range s.refusals {
				if toolchainPinAny(lines[at:end], want) {
					return
				}
			}
			t.Errorf("%s:%d compares the toolchain against the pin but does not stop on a mismatch within %d lines; expected one of %q. "+
				"A check that reports and continues is not a refusal.", s.rel, at+1, toolchainPinWindow, s.refusals)
		})
	}
}

// TestTheUnpinnedBuildScriptsDoNotClaimToCheck is the other half of the owner's
// 2026-10-09 decision. Removing a refusal and leaving the prose that describes
// it is strictly worse than either keeping or removing both: it is what made
// M26-RUN-019 a finding rather than a changelog line, because the file then
// tells its next reader that the toolchain is verified when it is not.
func TestTheUnpinnedBuildScriptsDoNotClaimToCheck(t *testing.T) {
	// Phrases that assert a check is performed. A script may still MENTION
	// go.mod or name a version to pass -- that is advice, not a claim.
	claims := []string{
		"checked below rather",
		"it is checked below",
		"this script refuses",
		"env GOVERSION",
	}
	for _, rel := range toolchainUnpinnedBuilders {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			lines := toolchainPinLines(t, rel)
			for _, claim := range claims {
				for n, line := range lines {
					if !strings.Contains(line, claim) {
						continue
					}
					t.Errorf("%s:%d still says the toolchain version is checked (%q) but the check was removed by owner "+
						"decision 2026-10-09: %s", rel, n+1, claim, strings.TrimSpace(line))
				}
			}
		})
	}
}

// TestEveryScriptThatCrossCompilesIsAccountedFor: the two tables above are the
// whole set, not a sample. Any script under scripts/ that names GOOS is
// producing or gating artifacts for a platform other than the one it runs on,
// which is what a release path means here, so it is either a gate that must
// check or a builder the owner decided need not. A new one is neither until
// somebody says which, and that is a decision rather than a default.
func TestEveryScriptThatCrossCompilesIsAccountedFor(t *testing.T) {
	known := make(map[string]bool, len(toolchainPinGates)+len(toolchainUnpinnedBuilders))
	for _, s := range toolchainPinGates {
		known[filepath.Base(s.rel)] = true
	}
	for _, rel := range toolchainUnpinnedBuilders {
		known[filepath.Base(rel)] = true
	}

	dir := filepath.Join(repositoryRoot, "scripts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".sh") && !strings.HasSuffix(name, ".ps1")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "GOOS") {
			continue
		}
		found++
		if !known[name] {
			t.Errorf("scripts/%s selects a GOOS, so it builds or gates release artifacts, but neither toolchainPinGates "+
				"nor toolchainUnpinnedBuilders names it; add it to whichever it is", name)
		}
	}
	if want := len(known); found != want {
		t.Errorf("found %d scripts naming GOOS but the tables name %d; an entry for a script that no longer exists "+
			"passes vacuously, so the two have to agree", found, want)
	}
}

// toolchainPinLines reads a script with CRLF folded away, so no assertion
// depends on which ending a given script happens to carry. scripts/ is mixed
// and deliberately so.
func toolchainPinLines(t *testing.T, rel string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// toolchainPinIsComment reports whether a line is commented out. Both PowerShell
// and sh use #, which is the only reason one helper serves both.
func toolchainPinIsComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func toolchainPinAny(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) && !toolchainPinIsComment(line) {
			return true
		}
	}
	return false
}
