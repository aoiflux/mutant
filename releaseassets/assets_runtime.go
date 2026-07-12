//go:build !releaseassetsgen
// +build !releaseassetsgen

package releaseassets

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type missingRuntimeFS struct{}

func (missingRuntimeFS) Open(name string) (fs.File, error) {
	return nil, fs.ErrNotExist
}

func Get(goos, goarch string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s", strings.ToLower(goos), normalizeArch(strings.ToLower(goarch)))
	relPath, ok := RuntimeAssetFiles[key]
	if !ok || strings.TrimSpace(relPath) == "" {
		return nil, fmt.Errorf("unable to generate release mode builds: embedded runtime asset missing for %s (run 'mutant gen --release-assets' and rebuild mutant)", key)
	}

	binaryData, err := fs.ReadFile(runtimeAssetFS, relPath)
	if err != nil {
		return nil, fmt.Errorf("unable to generate release mode builds: embedded runtime asset for %s is invalid: %w", key, err)
	}

	decompressedBinaryData, err := decompressReleaseRuntimeBinary(binaryData)
	if err != nil {
		return nil, fmt.Errorf("unable to generate release mode builds: embedded runtime asset for %s failed to decompress: %w", key, err)
	}

	return decompressedBinaryData, nil
}

func decompressReleaseRuntimeBinary(binaryData []byte) ([]byte, error) {
	if len(binaryData) < 4 || binaryData[0] != 0x28 || binaryData[1] != 0xb5 || binaryData[2] != 0x2f || binaryData[3] != 0xfd {
		return binaryData, nil
	}

	decoder, err := zstd.NewReader(bytes.NewReader(binaryData))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	decompressedBinaryData, err := io.ReadAll(decoder)
	if err != nil {
		return nil, err
	}

	return decompressedBinaryData, nil
}
