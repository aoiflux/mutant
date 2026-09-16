package generator

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/security"
)

// testSigningKey mints a throwaway key so the test does not touch, or depend on,
// the host's bootstrapped keypair.
func testSigningKey(t *testing.T) []byte {
	t.Helper()

	pair, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return pair.PrivateKey
}

// exampleProgram gives the test the path of a program with enough statements
// for its position tables to be worth measuring.
func exampleProgram(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "examples", "binary", "static_bin_analysis.mut")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example program unavailable: %s", err)
	}
	return path
}

// compile honours stripDebug, which is what Generate passes `release` into.
//
// The assertion is on size because the artifact this returns is gob-encoded,
// compressed and then encrypted, so a test at this layer cannot read fields back
// out of it. What removal actually does is pinned in the compiler
// (TestStripDebugInfoRemovesEveryPosition), and that a non-stripped artifact
// still carries positions after the full round trip is pinned in the runner
// (TestGeneratedProgramCarriesPositionsThroughTheContainer). This covers the
// piece neither of those does: that the flag is wired through at all.
func TestCompileStripsDebugInfoWhenAsked(t *testing.T) {
	source := exampleProgram(t)
	const password = "correct horse battery"

	full, err, _, _ := compile(source, nil, false, password, 0, 7, testSigningKey(t))
	if err != nil {
		t.Fatalf("compile with positions: %v", err)
	}

	stripped, err, _, _ := compile(source, nil, true, password, 0, 7, testSigningKey(t))
	if err != nil {
		t.Fatalf("compile without positions: %v", err)
	}

	if len(stripped) >= len(full) {
		t.Errorf("stripping debug info did not shrink the artifact: %d bytes with, %d without",
			len(full), len(stripped))
	}

	t.Logf("artifact %d bytes with positions, %d without (%d saved)",
		len(full), len(stripped), len(full)-len(stripped))
}
