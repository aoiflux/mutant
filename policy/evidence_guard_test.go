package policy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// evidencePolicyDoc is named in every failure message so the reader learns the
// rule and not merely that they broke it.
const evidencePolicyDoc = "docs/EVIDENCE_HANDLING_POLICY.md"

// fsMutators are the standard-library calls that ask the operating system to
// change something on disk.
//
// Matching the selector alone -- not the package qualifier -- catches os.Create,
// an aliased import, and a method on an *os.File, all with one rule. `Write` and
// `WriteString` are deliberately absent: writing needs a handle opened for
// writing, and every way to obtain one is already on this list, so their absence
// costs nothing and spares the guard from deciding whether a `.Write(...)` is
// going to a file, a hash or a string builder.
var fsMutators = map[string]bool{
	"Create":     true,
	"CreateTemp": true,
	"WriteFile":  true,
	"Remove":     true,
	"RemoveAll":  true,
	"Rename":     true,
	"Truncate":   true,
	"Chmod":      true,
	"Chown":      true,
	"Lchown":     true,
	"Chtimes":    true,
	"Mkdir":      true,
	"MkdirAll":   true,
	"MkdirTemp":  true,
	"Symlink":    true,
	"Link":       true,
}

// scanEvidenceFiles parses every file in EvidenceReadOnlyFiles and returns each
// filesystem mutation it finds, plus the files it managed to read.
func scanEvidenceFiles(t *testing.T) (writes []finding, scanned map[string]bool) {
	t.Helper()

	scanned = map[string]bool{}
	fset := token.NewFileSet()

	for _, rel := range EvidenceReadOnlyFiles {
		path := filepath.Join(repositoryRoot, filepath.FromSlash(rel))
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("policy.EvidenceReadOnlyFiles names %s, which cannot be parsed: %v", rel, err)
			continue
		}
		scanned[rel] = true

		funcs := functionSpans(file)
		enclosing := func(pos token.Pos) string {
			for _, fn := range funcs {
				if pos >= fn.start && pos <= fn.end {
					return fn.name
				}
			}
			return ""
		}

		seen := map[int]bool{} // dedupe by line
		add := func(pos token.Pos, what string) {
			line := fset.Position(pos).Line
			if seen[line] {
				return
			}
			seen[line] = true
			writes = append(writes, finding{rel, line, enclosing(pos), what})
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if fsMutators[node.Sel.Name] {
					add(node.Pos(), node.Sel.Name)
				}

			case *ast.CallExpr:
				// OpenFile is the one call that can go either way, so it is judged
				// on its flags rather than its name.
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "OpenFile" || len(node.Args) < 2 {
					return true
				}
				if isReadOnlyFlag(node.Args[1]) {
					return true
				}
				add(node.Pos(), "OpenFile with a writable flag")
			}
			return true
		})
	}

	if len(scanned) == 0 {
		t.Fatalf("scanned none of the %d files in policy.EvidenceReadOnlyFiles -- "+
			"the walk is looking in the wrong place", len(EvidenceReadOnlyFiles))
	}
	return writes, scanned
}

// isReadOnlyFlag reports whether an OpenFile flag argument is exactly
// os.O_RDONLY. Anything else -- a variable, a bitwise combination, a constant
// this cannot read -- is treated as writable, because a guard that guesses in
// the permissive direction is not a guard.
func isReadOnlyFlag(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "O_RDONLY"
}

// The policy. Evidence-reading code does not modify anything on disk, except at
// the sites recorded in EvidenceWriteAllowlist.
func TestEvidenceCodeNeverWrites(t *testing.T) {
	writes, _ := scanEvidenceFiles(t)

	type key struct{ file, fn string }
	allowed := map[key]EvidenceWriteException{}
	for _, entry := range EvidenceWriteAllowlist {
		allowed[key{entry.File, entry.Func}] = entry
	}

	counts := map[key]int{}
	var unexpected []finding
	for _, w := range writes {
		k := key{w.file, w.fn}
		if _, ok := allowed[k]; !ok {
			unexpected = append(unexpected, w)
			continue
		}
		counts[k]++
	}

	if len(unexpected) > 0 {
		sort.Slice(unexpected, func(i, j int) bool {
			if unexpected[i].file != unexpected[j].file {
				return unexpected[i].file < unexpected[j].file
			}
			return unexpected[i].line < unexpected[j].line
		})

		var b strings.Builder
		fmt.Fprintf(&b, "%d filesystem mutation(s) in evidence-reading code:\n", len(unexpected))
		for _, u := range unexpected {
			fmt.Fprintf(&b, "  %s\n", u)
		}
		fmt.Fprintf(&b, "\nMutant does not modify evidence. Image, volume, hive and archive handles are\n"+
			"read-only by construction, and a case manifest states that as a fact about the\n"+
			"tool. If this write does not touch the source -- a temp file a library demands,\n"+
			"a working copy taken so the original is never opened writable -- add an entry to\n"+
			"policy.EvidenceWriteAllowlist saying which bytes it touches. If it does touch the\n"+
			"source, it does not belong in this code at all. See %s.", evidencePolicyDoc)
		t.Fatal(b.String())
	}

	for k, entry := range allowed {
		got := counts[k]
		if got == entry.Lines {
			continue
		}
		t.Errorf("%s: %s mutates the filesystem on %d line(s), but policy.EvidenceWriteAllowlist pins %d.\n"+
			"Failing here is not a defect -- it means update the allowlist and say why in the commit.\n"+
			"Reason on record: %s\nSee %s.",
			k.file, k.fn, got, entry.Lines, entry.Why, evidencePolicyDoc)
	}
}

// A renamed or deleted function must not leave a permanent hole in the guard.
func TestEvidenceWriteAllowlistHasNoStaleEntries(t *testing.T) {
	writes, scanned := scanEvidenceFiles(t)

	matched := map[string]bool{}
	for _, w := range writes {
		matched[w.file+"::"+w.fn] = true
	}

	for _, entry := range EvidenceWriteAllowlist {
		if matched[entry.File+"::"+entry.Func] {
			continue
		}
		if !scanned[entry.File] {
			t.Errorf("policy.EvidenceWriteAllowlist names %s, which is not in "+
				"policy.EvidenceReadOnlyFiles. Remove the entry or add the file.", entry.File)
			continue
		}
		t.Errorf("policy.EvidenceWriteAllowlist allows %s in %s, but nothing there mutates the\n"+
			"filesystem. The function was probably renamed or the write removed; either way the\n"+
			"entry is now a hole in the guard. Remove or update it. See %s.",
			entry.Func, entry.File, evidencePolicyDoc)
	}
}

func TestEvidenceWriteAllowlistEntriesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, entry := range EvidenceWriteAllowlist {
		id := entry.File + "::" + entry.Func
		if seen[id] {
			t.Errorf("policy.EvidenceWriteAllowlist has two entries for %s", id)
		}
		seen[id] = true

		if entry.Lines < 1 {
			t.Errorf("%s: Lines is %d; an entry that permits nothing should be deleted", id, entry.Lines)
		}
		if strings.TrimSpace(entry.Why) == "" {
			t.Errorf("%s: Why is empty. An exception without a justification is not reviewable.", id)
		}
		if filepath.ToSlash(entry.File) != entry.File {
			t.Errorf("%s: File must use forward slashes", entry.File)
		}
	}
}

// The guard must be able to see what it is guarding, and the list must not name
// files that have been renamed away.
func TestEvidencePolicyNamesFilesThatExist(t *testing.T) {
	if len(EvidenceReadOnlyFiles) == 0 {
		t.Fatal("policy.EvidenceReadOnlyFiles is empty; the guard would pass vacuously")
	}

	seen := map[string]bool{}
	for _, rel := range EvidenceReadOnlyFiles {
		if seen[rel] {
			t.Errorf("policy.EvidenceReadOnlyFiles lists %s twice", rel)
		}
		seen[rel] = true

		if filepath.ToSlash(rel) != rel {
			t.Errorf("%s: paths must use forward slashes", rel)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(rel))); err != nil {
			t.Errorf("policy.EvidenceReadOnlyFiles names %s, which does not exist: %v", rel, err)
		}
	}

	// The families the roadmap names explicitly, so a future edit cannot quietly
	// drop the ones this policy was written for.
	for _, want := range []string{
		"builtin/disk_image_parsers.go",
		"builtin/filesystem_parsers.go",
		"builtin/registry_forensics.go",
		"builtin/hive_builtins.go",
	} {
		if !seen[want] {
			t.Errorf("policy.EvidenceReadOnlyFiles no longer covers %s", want)
		}
	}

	if _, err := os.Stat(filepath.Join(repositoryRoot, evidencePolicyDoc)); err != nil {
		t.Errorf("every failure message points at %s, which is missing: %v", evidencePolicyDoc, err)
	}
}
