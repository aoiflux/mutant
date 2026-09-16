package builtin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

// The read-only invariant has two halves. policy/evidence_guard_test.go checks
// the source: no evidence-reading code asks the operating system to change
// anything. This file checks the behaviour: evidence opened from a file the
// operating system will not let anyone write still reads correctly, and comes
// back byte-identical afterwards.
//
// The second half is what an examiner can be shown. It is also the check that
// survives a refactor the AST guard cannot see through -- a third-party library
// writing through a handle Mutant gave it would fail here.

// evidenceFingerprint is size plus digest: enough to prove nothing moved.
func evidenceFingerprint(t *testing.T, path string) (int64, string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return int64(len(data)), hex.EncodeToString(sum[:])
}

// writeReadOnly writes a file and takes write permission away from it, so a
// write attempt fails at the operating system rather than at a code review.
func writeReadOnly(t *testing.T, name string, payload []byte) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatalf("making %s read-only: %v", name, err)
	}
	// Restore write permission so t.TempDir's cleanup can remove it on Windows,
	// where the read-only attribute blocks deletion.
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	return path
}

func buildTestZip(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entry, err := writer.Create("notes.txt")
	if err != nil {
		t.Fatalf("creating the zip entry: %v", err)
	}
	if _, err := entry.Write([]byte("evidence")); err != nil {
		t.Fatalf("writing the zip entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing the zip: %v", err)
	}
	return buf.Bytes()
}

func buildTestTar(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	body := []byte("evidence")
	if err := writer.WriteHeader(&tar.Header{Name: "notes.txt", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatalf("writing the tar header: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("writing the tar body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing the tar: %v", err)
	}
	return buf.Bytes()
}

func TestEvidenceOpensFromAReadOnlyFile(t *testing.T) {
	rawPayload := make([]byte, 4096)
	for i := range rawPayload {
		rawPayload[i] = byte(i % 251)
	}

	cases := []struct {
		name    string
		file    string
		payload []byte
		// exercise opens the evidence, reads from it, and closes it. A failure
		// here means an evidence family needs write access to its own source.
		exercise func(t *testing.T, path string)
	}{
		{
			name:    "a raw disk image",
			file:    "disk.dd",
			payload: rawPayload,
			exercise: func(t *testing.T, path string) {
				opened, errObj := unwrapPair(t, RAWOpen(stringObj(path)))
				if errObj != nil {
					t.Fatalf("raw_open on a read-only image: %s", errObj.Message)
				}
				handle := mustHashStringValue(t, opened.(*object.Hash), "handle")
				defer RAWClose(stringObj(handle))

				if _, errObj := unwrapPair(t, RAWReadAt(stringObj(handle), intObj(0), intObj(32))); errObj != nil {
					t.Fatalf("raw_read_at on a read-only image: %s", errObj.Message)
				}
			},
		},
		{
			name:    "a zip archive",
			file:    "container.zip",
			payload: buildTestZip(t),
			exercise: func(t *testing.T, path string) {
				opened, errObj := unwrapPair(t, ZipOpen(stringObj(path)))
				if errObj != nil {
					t.Fatalf("zip_open on a read-only archive: %s", errObj.Message)
				}
				handle := mustHashStringValue(t, opened.(*object.Hash), "handle")
				defer ZipClose(stringObj(handle))

				if _, errObj := unwrapPair(t, ZipRead(stringObj(handle), stringObj("notes.txt"))); errObj != nil {
					t.Fatalf("zip_read on a read-only archive: %s", errObj.Message)
				}
			},
		},
		{
			name:    "a tar archive",
			file:    "container.tar",
			payload: buildTestTar(t),
			exercise: func(t *testing.T, path string) {
				opened, errObj := unwrapPair(t, TarOpen(stringObj(path)))
				if errObj != nil {
					t.Fatalf("tar_open on a read-only archive: %s", errObj.Message)
				}
				handle := mustHashStringValue(t, opened.(*object.Hash), "handle")
				defer TarClose(stringObj(handle))

				if _, errObj := unwrapPair(t, TarRead(stringObj(handle), stringObj("notes.txt"))); errObj != nil {
					t.Fatalf("tar_read on a read-only archive: %s", errObj.Message)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeReadOnly(t, tc.file, tc.payload)
			sizeBefore, digestBefore := evidenceFingerprint(t, path)

			tc.exercise(t, path)

			sizeAfter, digestAfter := evidenceFingerprint(t, path)
			if sizeAfter != sizeBefore {
				t.Fatalf("the source changed size: %d -> %d", sizeBefore, sizeAfter)
			}
			if digestAfter != digestBefore {
				t.Fatalf("the source's digest changed:\n  before %s\n  after  %s", digestBefore, digestAfter)
			}
		})
	}
}

// The manifest asserts this, so something has to check that the assertion is
// still the one the policy backs.
func TestManifestAssertsTheReadOnlyInvariant(t *testing.T) {
	openTestCase(t, "IR-1", "examiner")

	integrity := manifestSection(t, currentManifest(t), "integrity")
	readOnly, ok := mustHashValue(t, integrity, "evidence_read_only").(*object.Boolean)
	if !ok || !readOnly.Value {
		t.Fatal("the manifest does not assert that evidence is read-only")
	}
	if got := mustHashStringValue(t, integrity, "read_only_policy"); got != "docs/EVIDENCE_HANDLING_POLICY.md" {
		t.Fatalf("read_only_policy = %q; the manifest must name the document the claim rests on", got)
	}
}
