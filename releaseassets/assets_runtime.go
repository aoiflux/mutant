//go:build !releaseassetsgen
// +build !releaseassetsgen

package releaseassets

import (
	"bytes"
	"errors"
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
		return nil, fmt.Errorf("unable to generate release mode builds: embedded runtime asset missing for %s (run 'mutant gen assets' and rebuild mutant)", key)
	}

	binaryData, err := fs.ReadFile(runtimeAssetFS, relPath)
	if err != nil {
		// Two faults land here and they do not share a remedy. A binary built
		// with plain `go build` or `go install` embeds no runtime assets at
		// all, because only placeholder.bin is tracked: the manifest names a
		// file the embedded filesystem does not hold, and the answer is to
		// build the way a release is built. Telling that person their asset
		// is "invalid" sends them hunting for a corrupt file that was never
		// there. A read that fails any other way is a real corruption.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("unable to generate release mode builds: this build embeds no runtime asset for %s, which is what a plain 'go build' or 'go install' produces: build with "+
				"scripts/build.sh --host-only (scripts/build.ps1 -HostOnly on Windows), or run 'mutant gen assets' and rebuild mutant", key)
		}

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
