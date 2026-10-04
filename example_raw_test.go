package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
)

// TestTheRawExampleRunsOnAnImage runs examples/filesystem/raw_example.mut as
// shipped, against a file where the example looks for its image. Any file is a
// raw image, so this one needs no fixture.
//
// The sweep marks the example needs-input and never runs it, so it failed on the
// first real image for as long as it had (M26-EX-020): it built its lines with
// `+` and stopped on file_size, an integer. It also printed sector_size, which
// raw_metadata has called assumed_sector_size since 0b59b54 because a raw image
// records none, and it gave the bytes it read to putf as the format, so the
// sector here holds a `%` followed by verbs, and has to come back as it was
// written.
func TestTheRawExampleRunsOnAnImage(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(filepath.Join(root, "examples", "filesystem", "raw_example.mut"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "raw_example.mut"), example, 0o644); err != nil {
		t.Fatal(err)
	}

	const sector = "100% sector zero %d %s"
	image := make([]byte, 4096)
	copy(image, sector)
	if err := os.WriteFile(filepath.Join(work, "disk.raw"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	var code int
	stderr := captureStderr(t, func() { code = run([]string{"mutant", "raw_example.mut", "--dev"}) })
	if code != 0 {
		t.Fatalf("the example did not compile (exit %d):\n%s", code, stderr)
	}
	var out bytes.Buffer
	restore := builtin.SetOutput(&out)
	stderr = captureStderr(t, func() { code = run([]string{"mutant", "raw_example.mu", "--dev"}) })
	restore()
	printed := out.String()
	if code != 0 {
		t.Fatalf("the example failed (exit %d)\nstdout:\n%s\nstderr:\n%s", code, printed, stderr)
	}

	for _, want := range []string{
		"RAW opened (handle=raw-handle-",
		")\nRAW metadata:\n",
		"  file_size=4096\n",
		"  assumed_sector_size=512\n",
		"First 512 bytes (string rendering):\n" + sector,
		"Handle closed: true\n",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("the example's output lacks %q\nstdout:\n%s", want, printed)
		}
	}
}
