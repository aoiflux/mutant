package generator

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type releaseTarget struct {
	goos   string
	goarch string
}

var releaseTargets = []releaseTarget{
	{goos: "darwin", goarch: "amd64"},
	{goos: "linux", goarch: "amd64"},
	{goos: "linux", goarch: "386"},
	{goos: "linux", goarch: "arm64"},
	{goos: "linux", goarch: "arm"},
	{goos: "windows", goarch: "amd64"},
	{goos: "windows", goarch: "386"},
}

func GenerateReleaseAssets(outputPath string) error {
	assetsDir := resolveAssetsDir(outputPath)
	dataDir := filepath.Join(assetsDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}

	placeholderPath := filepath.Join(dataDir, "placeholder.bin")
	if err := os.WriteFile(placeholderPath, []byte{}, 0644); err != nil {
		return err
	}

	entries := make(map[string]string, len(releaseTargets))
	for _, target := range releaseTargets {
		binaryData, err := buildReleaseRuntimeBinary(target.goos, target.goarch)
		if err != nil {
			return err
		}

		compressedBinaryData, err := compressReleaseRuntimeBinary(binaryData)
		if err != nil {
			return err
		}

		key := fmt.Sprintf("%s/%s", target.goos, target.goarch)
		fileName := fmt.Sprintf("%s_%s.bin", target.goos, target.goarch)
		relPath := filepath.ToSlash(filepath.Join("data", fileName))
		absPath := filepath.Join(dataDir, fileName)

		if err := os.WriteFile(absPath, compressedBinaryData, 0644); err != nil {
			return err
		}
		entries[key] = relPath
	}

	indexSource := renderReleaseAssetsIndex(entries)
	indexPath := filepath.Join(assetsDir, "generated_assets.go")
	if err := os.WriteFile(indexPath, indexSource, 0644); err != nil {
		return err
	}

	embedSource := renderReleaseAssetsEmbedBinding()
	embedPath := filepath.Join(assetsDir, "generated_embed.go")
	if err := os.WriteFile(embedPath, embedSource, 0644); err != nil {
		return err
	}

	return nil
}

func resolveAssetsDir(outputPath string) string {
	if outputPath == "" {
		return filepath.Clean("releaseassets")
	}

	cleanPath := filepath.Clean(outputPath)
	ext := strings.ToLower(filepath.Ext(cleanPath))
	if ext == ".go" {
		return filepath.Dir(cleanPath)
	}

	return cleanPath
}

func buildReleaseRuntimeBinary(goos, goarch string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "mutant-release-asset-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	outName := "mutant-runtime"
	if goos == "windows" {
		outName += ".exe"
	}
	outPath := filepath.Join(tmpDir, outName)

	cmd := exec.Command("go", "build", "-tags", "releaseassetsgen", "-o", outPath, ".")
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return nil, fmt.Errorf("failed to generate release runtime asset for %s/%s: %s", goos, goarch, string(output))
		}
		return nil, fmt.Errorf("failed to generate release runtime asset for %s/%s: %w", goos, goarch, err)
	}

	binaryData, err := os.ReadFile(outPath)
	if err != nil {
		return nil, err
	}

	return binaryData, nil
}

func compressReleaseRuntimeBinary(binaryData []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	if _, err := gz.Write(binaryData); err != nil {
		_ = gz.Close()
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func renderReleaseAssetsIndex(entries map[string]string) []byte {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("//go:build !releaseassetsgen\n")
	buf.WriteString("// +build !releaseassetsgen\n\n")
	buf.WriteString("package releaseassets\n\n")
	buf.WriteString("// RuntimeAssetFiles is generated via `mutant gen --release-assets`.\n")
	buf.WriteString("var RuntimeAssetFiles = map[string]string{\n")
	for _, key := range keys {
		buf.WriteString(fmt.Sprintf("\t%q: %q,\n", key, entries[key]))
	}
	buf.WriteString("}\n")

	return buf.Bytes()
}

func renderReleaseAssetsEmbedBinding() []byte {
	var buf bytes.Buffer
	buf.WriteString("//go:build !releaseassetsgen\n")
	buf.WriteString("// +build !releaseassetsgen\n\n")
	buf.WriteString("package releaseassets\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"embed\"\n")
	buf.WriteString("\t\"io/fs\"\n")
	buf.WriteString(")\n\n")
	buf.WriteString("//go:embed data/*.bin\n")
	buf.WriteString("var embeddedRuntimeFS embed.FS\n\n")
	buf.WriteString("var runtimeAssetFS fs.FS = embeddedRuntimeFS\n")

	return buf.Bytes()
}
