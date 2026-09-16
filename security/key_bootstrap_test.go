package security

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The trusted verification key used to be supplied through an environment
// variable. Key material in the environment is invisible in the invocation an
// analyst records and leaks into every child process, so the replacement is a
// --trusted-key path. See docs/CONFIGURATION_POLICY.md.
func TestResolveTrustedPublicKeyHexFromPathReadsTheNamedFile(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "trusted.hex")
	// Trailing whitespace is what a file written by `echo` actually contains.
	if err := os.WriteFile(path, []byte(hex.EncodeToString(publicKey)+"\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, generated, dir, err := ResolveTrustedPublicKeyHexFromPath(path)
	if err != nil {
		t.Fatalf("ResolveTrustedPublicKeyHexFromPath returned %v, want nil", err)
	}
	if want := hex.EncodeToString(publicKey); got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if generated {
		t.Fatal("generated = true, want false: naming a key file must not touch the local keystore")
	}
	if dir != filepath.Dir(path) {
		t.Fatalf("dir = %q, want %q", dir, filepath.Dir(path))
	}
}

// A malformed or missing key file has to fail loudly. Falling back to the local
// keystore would silently verify against a key the operator did not ask for.
func TestResolveTrustedPublicKeyHexFromPathRejectsBadKeyFiles(t *testing.T) {
	dir := t.TempDir()

	shortKey := filepath.Join(dir, "short.hex")
	if err := os.WriteFile(shortKey, []byte("aabbcc"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	notHex := filepath.Join(dir, "nothex.hex")
	if err := os.WriteFile(notHex, []byte("this is not hex"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"missing file", filepath.Join(dir, "absent.hex"), "read trusted public key"},
		{"wrong size", shortKey, "invalid trusted public key size"},
		{"not hex", notHex, "invalid trusted public key encoding"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, _, _, err := ResolveTrustedPublicKeyHexFromPath(tc.path)
			if err == nil {
				t.Fatalf("ResolveTrustedPublicKeyHexFromPath(%q) returned key %q and no error", tc.path, key)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
			if key != "" {
				t.Fatalf("key = %q on failure, want empty", key)
			}
		})
	}
}

// An empty path is the default: fall back to the local keystore, exactly as
// ResolveTrustedPublicKeyHex has always done.
func TestResolveTrustedPublicKeyHexFromPathFallsBackToTheKeystore(t *testing.T) {
	dir := t.TempDir()
	SetLocalKeyStoreDirForTesting(dir)
	t.Cleanup(func() { SetLocalKeyStoreDirForTesting("") })

	key, generated, gotDir, err := ResolveTrustedPublicKeyHexFromPath("")
	if err != nil {
		t.Fatalf("ResolveTrustedPublicKeyHexFromPath returned %v, want nil", err)
	}
	if !generated {
		t.Fatal("generated = false, want true: the keystore dir was empty")
	}
	if gotDir != dir {
		t.Fatalf("dir = %q, want %q", gotDir, dir)
	}
	if len(key) != hex.EncodedLen(ed25519.PublicKeySize) {
		t.Fatalf("key length = %d, want %d", len(key), hex.EncodedLen(ed25519.PublicKeySize))
	}
}
