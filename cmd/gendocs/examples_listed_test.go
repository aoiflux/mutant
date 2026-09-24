package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
// A directory with no README is not forced to grow one -- a test that forced the
// question would be answered with an empty file -- but it is not invisible
// either: the nearest README above it has to name the directory, so every
// program is reachable from some README a reader starts at.

const examplesRoot = "../../examples"

// exampleProgram is one .mut under examples/, with the README responsible for
// it.
type exampleProgram struct {
	rel    string // relative to examples/, forward slashes
	readme string // relative to examples/, the nearest README.md at or above it
}

func examplePrograms(t *testing.T) []exampleProgram {
	t.Helper()
	var programs []exampleProgram
	err := filepath.WalkDir(examplesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".mut") {
			return nil
		}
		rel, err := filepath.Rel(examplesRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		programs = append(programs, exampleProgram{rel: rel, readme: nearestReadme(rel)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking examples/: %v", err)
	}
	sort.Slice(programs, func(i, j int) bool { return programs[i].rel < programs[j].rel })
	return programs
}

// nearestReadme walks up from a program's directory to examples/ itself.
func nearestReadme(rel string) string {
	for dir := filepath.ToSlash(filepath.Dir(rel)); ; dir = filepath.ToSlash(filepath.Dir(dir)) {
		candidate := "README.md"
		if dir != "." {
			candidate = dir + "/README.md"
		}
		if _, err := os.Stat(filepath.Join(examplesRoot, filepath.FromSlash(candidate))); err == nil {
			return candidate
		}
		if dir == "." {
			return ""
		}
	}
}

// mentions reports whether text names token as a whole word: `ioc_extract.mut`
// is not mentioned by `my_ioc_extract.mut`, and `lib` is not mentioned by
// `library`.
func mentions(text, token string) bool {
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(token) + `($|[^A-Za-z0-9_])`)
	return re.MatchString(text)
}

func readExampleFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(examplesRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading examples/%s: %v", rel, err)
	}
	return string(data)
}

// TestEveryExampleIsListedInItsReadme: a README names each program in its own
// directory; a program in a directory with no README of its own is covered when
// the nearest README above names the directory it sits in.
func TestEveryExampleIsListedInItsReadme(t *testing.T) {
	programs := examplePrograms(t)
	if len(programs) == 0 {
		t.Fatal("found no programs under examples/")
	}
	unlisted := map[string][]string{}
	for _, p := range programs {
		if p.readme == "" {
			t.Errorf("examples/%s has no README at or above it", p.rel)
			continue
		}
		text := readExampleFile(t, p.readme)
		readmeDir := filepath.ToSlash(filepath.Dir(p.readme))
		programDir := filepath.ToSlash(filepath.Dir(p.rel))
		if readmeDir == programDir {
			if !mentions(text, filepath.Base(p.rel)) {
				unlisted[p.readme] = append(unlisted[p.readme], filepath.Base(p.rel))
			}
			continue
		}
		// The README is above the program: it has to name the directory.
		sub := programDir
		if readmeDir != "." {
			sub = strings.TrimPrefix(programDir, readmeDir+"/")
		}
		if !mentions(text, sub) && !mentions(text, sub+"/") {
			unlisted[p.readme] = append(unlisted[p.readme], sub+"/ (holding "+filepath.Base(p.rel)+")")
		}
	}
	readmes := make([]string, 0, len(unlisted))
	for r := range unlisted {
		readmes = append(readmes, r)
	}
	sort.Strings(readmes)
	for _, r := range readmes {
		items := dedupe(unlisted[r])
		t.Errorf("examples/%s does not mention %d program(s) or director(ies) it is responsible for: %s",
			r, len(items), strings.Join(items, ", "))
	}
}

// TestEveryListedExampleExists is the reverse: a README naming a program that
// is not there sends a reader to a file they cannot open.
func TestEveryListedExampleExists(t *testing.T) {
	named := regexp.MustCompile(`[A-Za-z0-9_./-]*[A-Za-z0-9_]\.mut\b`)
	byBase := map[string]bool{}
	for _, p := range examplePrograms(t) {
		byBase[filepath.Base(p.rel)] = true
	}
	checked := 0
	err := filepath.WalkDir(examplesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "README.md" {
			return nil
		}
		rel, _ := filepath.Rel(examplesRoot, path)
		rel = filepath.ToSlash(rel)
		dir := filepath.Dir(path)
		text := readExampleFile(t, rel)
		for _, loc := range named.FindAllStringIndex(text, -1) {
			name := text[loc[0]:loc[1]]
			if loc[0] > 0 && text[loc[0]-1] == '*' {
				continue // a pattern such as *_test.mut, not a file
			}
			checked++
			// A bare name refers to a program by its file name wherever it sits;
			// a name with a directory has to resolve exactly.
			if exampleResolves(dir, name) || (!strings.Contains(name, "/") && byBase[name]) {
				continue
			}
			t.Errorf("examples/%s names %s, which does not exist", rel, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no README under examples/ names a program; the scanner is broken")
	}
}

// exampleResolves accepts a name relative to the README, to examples/, or to
// the repository root -- the three ways the READMEs write paths.
func exampleResolves(readmeDir, name string) bool {
	for _, base := range []string{readmeDir, examplesRoot, filepath.Join(examplesRoot, "..")} {
		if _, err := os.Stat(filepath.Join(base, filepath.FromSlash(name))); err == nil {
			return true
		}
	}
	return false
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range items {
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}
