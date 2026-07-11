//go:build !releaseassetsgen
// +build !releaseassetsgen

package releaseassets

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"strings"
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
	if len(binaryData) < 2 || binaryData[0] != 0x1f || binaryData[1] != 0x8b {
		return binaryData, nil
	}

	gz, err := gzip.NewReader(bytes.NewReader(binaryData))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	decompressedBinaryData, err := io.ReadAll(gz)
	if err != nil {
		return nil, err
	}

	return decompressedBinaryData, nil
}
