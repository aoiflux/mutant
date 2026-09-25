package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// M26-RUN-001. The runner read its input with os.ReadFile and inflated the
// bytecode with io.ReadAll over a zstd decoder, neither bounded: a file of any
// size was read whole, and a payload of a few kilobytes could inflate to
// whatever its frame declared before gob looked at a byte. Both reads are now
// bounded by a named limit, and refused past it. The tests pass small limits;
// the production path passes maxArtifactFile and maxBytecode.
func TestAnArtifactPastItsLimitIsRefusedBeforeItIsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.dd")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readArtifact(path, 1024); err == nil {
		t.Fatalf("a 4096-byte file was read under a 1024-byte limit (%d bytes)", len(data))
	} else if !strings.Contains(err.Error(), "4096") {
		t.Errorf("the refusal does not say how large the file is: %v", err)
	}
	if data, err := readArtifact(path, 4096); err != nil || len(data) != 4096 {
		t.Fatalf("a file at its limit was refused: %d bytes, %v", len(data), err)
	}
}

func TestBytecodePastItsLimitIsRefusedWhileInflating(t *testing.T) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	const inflated = 2 << 20
	compressed := encoder.EncodeAll(make([]byte, inflated), nil)
	encoder.Close()
	if len(compressed) > 4096 {
		t.Fatalf("the fixture is %d bytes compressed; the point is that it is small", len(compressed))
	}

	if data, err := maybeDecompressEncodedByteCode(compressed, 1<<20); err == nil {
		t.Fatalf("%d compressed bytes inflated to %d under a 1 MiB limit", len(compressed), len(data))
	}
	data, err := maybeDecompressEncodedByteCode(compressed, inflated)
	if err != nil || !bytes.Equal(data, make([]byte, inflated)) {
		t.Fatalf("bytecode at its limit was refused or changed: %d bytes, %v", len(data), err)
	}
}
