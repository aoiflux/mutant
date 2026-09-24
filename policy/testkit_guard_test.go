package policy

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testkitImport is the package that holds test-only helpers.
const testkitImport = "mutant/testkit"

// TestTestkitIsImportedOnlyByTests: a helper written for tests -- a goroutine
// snapshot, a settle loop -- has no business in a binary an examiner runs.
func TestTestkitIsImportedOnlyByTests(t *testing.T) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "testkit/") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned++
		for _, imp := range file.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == testkitImport {
				t.Errorf("%s imports %s, which only tests may import", rel, testkitImport)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("scanned no files; the walk is looking in the wrong place")
	}
}
