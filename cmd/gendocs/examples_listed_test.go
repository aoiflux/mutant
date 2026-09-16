package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A directory under examples/ that has a README is making a promise: this is
// what is in here. Twenty-one programs had been added since anyone updated one,
// including workshop step 6 -- a whole numbered lesson in the sequence a reader
// is told to read in order, which nothing in the workshop pointed at.
//
// This is the prose-count defect one level down. A count drifts silently; so
// does a list, and a list is worse, because a program nobody is told about is a
// program nobody runs. Same failure, same answer.
//
// A directory with no README is left alone. Whether one is worth writing is a
// judgement about that directory, and a test that forced the question would be
// answered with an empty file.
func TestEveryExampleIsListedInItsReadme(t *testing.T) {
	root := filepath.FromSlash("../../examples")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading examples/: %v", err)
	}

	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		directory := filepath.Join(root, entry.Name())
		readme, err := os.ReadFile(filepath.Join(directory, "README.md"))
		if err != nil {
			continue
		}
		text := string(readme)

		programs, err := filepath.Glob(filepath.Join(directory, "*.mut"))
		if err != nil {
			t.Fatalf("listing %s: %v", directory, err)
		}
		sort.Strings(programs)

		var unlisted []string
		for _, program := range programs {
			name := filepath.Base(program)
			if !strings.Contains(text, name) {
				unlisted = append(unlisted, name)
			}
		}
		checked++

		if len(unlisted) > 0 {
			t.Errorf("examples/%s/README.md does not mention %d of its programs: %s",
				entry.Name(), len(unlisted), strings.Join(unlisted, ", "))
		}
	}

	if checked == 0 {
		t.Fatal("walked examples/ and found no directory with a README to check")
	}
}
