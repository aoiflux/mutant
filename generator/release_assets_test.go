package generator

import (
	"bytes"
	"go/format"
	"testing"
)

// The index is committed as generated, so it has to come out gofmt-clean: the
// release gate runs gofmt over every tracked file, and a regenerated index that
// needed formatting would fail it the next time assets were rebuilt.
func TestReleaseAssetsIndexIsGofmtClean(t *testing.T) {
	src, err := renderReleaseAssetsIndex(map[string]string{
		"darwin/amd64":  "data/darwin_amd64.bin",
		"linux/386":     "data/linux_386.bin",
		"windows/arm64": "data/windows_arm64.bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := format.Source(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, formatted) {
		t.Errorf("the rendered index is not gofmt-clean:\n%s", src)
	}
	if !bytes.Contains(src, []byte(`"linux/386":     "data/linux_386.bin",`)) {
		t.Errorf("values are not column-aligned:\n%s", src)
	}
}
