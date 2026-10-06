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
// writing, and every way to obtain one is already on this list or in
// flagJudgedOpeners, so their absence costs nothing and spares the guard from
// deciding whether a `.Write(...)` is going to a file, a hash or a string
// builder.
//
// `NewFile` is here because it hands back an *os.File for a descriptor opened
// somewhere this guard cannot see, which is a writable handle obtained without
// any of the calls above (M26-TEST-009). Nothing in the evidence path uses it
// today; if something has to, the entry it needs in EvidenceWriteAllowlist is
// the point.
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
	"NewFile":    true,
}

// flagJudgedOpeners are the opens whose name does not say which way they go, so
// they are judged on their flag argument instead of their name.
//
//	OpenFile(path, flag, perm)      os
//	Open(path, flag, perm)          syscall, golang.org/x/sys/unix
//	CreateFile(name, access, ...)   golang.org/x/sys/windows. Its second argument
//	                                is a desired-access mask and never
//	                                os.O_RDONLY, so this one always reports --
//	                                which is the intended answer: a CreateFile in
//	                                evidence code is a policy decision and
//	                                belongs in the allowlist with a reason.
//
// Only OpenFile was judged before, so syscall.Open with O_RDWR passed the guard
// (M26-TEST-009).
//
// These three, unlike fsMutators, are matched on the package behind the receiver
// and not on the selector alone, because `Open` is the commonest method name in
// forensics: `backend.Open(volumePath, region)` opens an NTFS volume read-only
// in seven *_open builtins, `sql.Open` opens the temp SQLite copy, and matching
// the name reported all ten as writable opens. os.Open is in the set and needs
// no flag check at all -- it takes one argument and is read-only by definition
// -- which is why the arity test below stays.
var flagJudgedOpeners = map[string]bool{
	"OpenFile":   true,
	"Open":       true,
	"CreateFile": true,
}

// osLevelPackages are the import paths whose opens take a flag argument.
//
// Resolved through the file's own import list rather than matched on the
// receiver's spelling, so an aliased `zsys "syscall"` is judged exactly like
// syscall is, and a package or variable that merely happens to be called
// something else is not.
var osLevelPackages = map[string]bool{
	"os":                       true,
	"syscall":                  true,
	"golang.org/x/sys/unix":    true,
	"golang.org/x/sys/windows": true,
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
		writes = append(writes, scanParsedGoFile(fset, file, rel)...)
	}

	if len(scanned) == 0 {
		t.Fatalf("scanned none of the %d files in policy.EvidenceReadOnlyFiles -- "+
			"the walk is looking in the wrong place", len(EvidenceReadOnlyFiles))
	}
	return writes, scanned
}

// scanParsedGoFile returns every filesystem mutation in one parsed file.
//
// Separate from the walk above so a test can hand it source of its own. A guard
// of this shape is worth exactly the cases it has been shown to catch, and the
// cases it has been shown NOT to catch (M26-TEST-009).
func scanParsedGoFile(fset *token.FileSet, file *ast.File, rel string) []finding {
	var writes []finding

	packages := importedPackagePaths(file)

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
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if fsMutators[sel.Sel.Name] {
				add(sel.Pos(), sel.Sel.Name)
				return true
			}
			// An open whose name does not say which way it goes is judged on its
			// flag argument. Reported permissively: anything that is not exactly
			// os.O_RDONLY -- a variable, a bitwise combination, a constant this
			// cannot read -- counts as writable, because a guard that guesses in
			// the other direction is not a guard.
			if !flagJudgedOpeners[sel.Sel.Name] || len(node.Args) < 2 {
				return true
			}
			receiver, ok := node.Fun.(*ast.SelectorExpr).X.(*ast.Ident)
			if !ok || !osLevelPackages[packages[receiver.Name]] {
				return true
			}
			if isReadOnlyFlag(node.Args[1]) {
				return true
			}
			add(node.Pos(), sel.Sel.Name+" with a writable flag")

		case *ast.SelectorExpr:
			// A mutator named but not called here: taken as a value to be called
			// somewhere else. Reported only when the receiver names an imported
			// package, and that condition is the whole point of this case.
			//
			// The rule used to match the selector wherever it appeared, which
			// read `entry.Link` in builtin/filesystem_report.go as a filesystem
			// mutation: a struct field whose name collides with os.Link. That is
			// a false positive in the one guard whose own comment says a rule
			// which can produce one is a rule nobody switches off, and it went
			// unseen because the file holding it was missing from the list
			// (M26-TEST-009).
			if !fsMutators[node.Sel.Name] {
				return true
			}
			ident, ok := node.X.(*ast.Ident)
			if !ok || packages[ident.Name] == "" {
				return true
			}
			add(node.Pos(), node.Sel.Name+" taken as a value")
		}
		return true
	})

	return writes
}

// importedPackagePaths maps each identifier in this file that names an imported
// package to that package's import path: the alias where there is one, and
// otherwise the last element of the path.
//
// The last element is the package's name for every import in this repository and
// for os, syscall, golang.org/x/sys/unix and golang.org/x/sys/windows, which are
// the only paths this guard reasons about. It is not a general rule --
// gopkg.in/yaml.v3 is package yaml -- and an import whose name it gets wrong
// costs a missed mutator taken as a value, never a false report.
func importedPackagePaths(file *ast.File) map[string]string {
	paths := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if spec.Name != nil {
			if spec.Name.Name != "_" && spec.Name.Name != "." {
				paths[spec.Name.Name] = path
			}
			continue
		}
		name := path
		if slash := strings.LastIndex(name, "/"); slash >= 0 {
			name = name[slash+1:]
		}
		if name != "" {
			paths[name] = path
		}
	}
	return paths
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

// evidenceStructuralMarkers says why a builtin file is image- or
// filesystem-reading code, and returns nothing when it is not.
//
// Three markers, none of which needs anything to be run:
//
//   - an import of an aoiflux lib* or partition package. Those are the readers
//     for ewf, vhdi, ntfs, fat, xfat, ext, hfs and xfs and for partition tables,
//     so a file importing one is holding an image open.
//   - a use of fsRegion, the type that says which part of a file a filesystem
//     occupies. Every *_open family goes through it.
//   - a use of fsFileReader, the type a file inside a mounted image is read out
//     through.
//
// This is the derived half of the policy. What it cannot see is a parser of a
// captured artifact -- an EVTX log, a LNK, a plist -- which opens a path and
// reads bytes with nothing structural about it to tell it apart from the rest of
// the standard library. Those entries stay a judgement in EvidenceReadOnlyFiles,
// and that is the soft edge the file says it is.
func evidenceStructuralMarkers(file *ast.File) []string {
	var markers []string

	var libraries []string
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.Contains(path, "aoiflux") {
			continue
		}
		name := path
		if slash := strings.LastIndex(name, "/"); slash >= 0 {
			name = name[slash+1:]
		}
		if strings.HasPrefix(name, "lib") || name == "partition" {
			libraries = append(libraries, name)
		}
	}
	if len(libraries) > 0 {
		sort.Strings(libraries)
		markers = append(markers, "imports "+strings.Join(libraries, ", "))
	}

	seams := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && (ident.Name == "fsRegion" || ident.Name == "fsFileReader") {
			seams[ident.Name] = true
		}
		return true
	})
	for _, seam := range []string{"fsFileReader", "fsRegion"} {
		if seams[seam] {
			markers = append(markers, "uses "+seam)
		}
	}

	return markers
}

// Adding an evidence family and forgetting the list used to be caught by
// nothing. Twelve files had gone in that way, among them the one holding the
// os.Open behind every *_open family and the one that writes recovered files
// (M26-TEST-009). For the image and filesystem family it is caught here.
func TestEveryImageReaderIsUnderTheGuard(t *testing.T) {
	listed := map[string]bool{}
	for _, rel := range EvidenceReadOnlyFiles {
		listed[rel] = true
	}

	dir := filepath.Join(repositoryRoot, "builtin")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var missing []string
	carriers := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("builtin/%s cannot be parsed: %v", name, err)
			continue
		}
		markers := evidenceStructuralMarkers(file)
		if len(markers) == 0 {
			continue
		}
		carriers++
		if rel := "builtin/" + name; !listed[rel] {
			missing = append(missing, "  "+rel+" -- "+strings.Join(markers, ", "))
		}
	}

	// Without this the test passes by finding nothing, which is what it would do
	// if the seams were renamed or the walk pointed at the wrong directory.
	if carriers == 0 {
		t.Fatal("no file in builtin/ carries any of the markers this test looks for, so it " +
			"would agree with whatever the list said. Either the fsRegion and fsFileReader " +
			"seams have been renamed, or the walk is looking in the wrong place")
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		var b strings.Builder
		fmt.Fprintf(&b, "%d of the %d file(s) that read disk images or filesystems are not in "+
			"policy.EvidenceReadOnlyFiles:", len(missing), carriers)
		for _, m := range missing {
			fmt.Fprintf(&b, "\n%s", m)
		}
		fmt.Fprintf(&b, "\n\nA listed file is scanned by the guard, so the fix is to add it "+
			"and run this package again. A write it then turns out to need is an entry in "+
			"policy.EvidenceWriteAllowlist saying which bytes it touches. See %s.", evidencePolicyDoc)
		t.Fatal(b.String())
	}
}

// The rule is worth the cases it has been shown to catch and the cases it has
// been shown not to, and both halves of that have been wrong here. syscall.Open
// with O_RDWR passed the guard for as long as OpenFile was the only call judged
// on its flags; and matching a mutator's name wherever it appeared reported a
// struct field called Link, seven read-only volume opens named Open and the
// SQLite temp copy's sql.Open (M26-TEST-009).
//
// The source below only has to parse. It names a type it does not define and
// uses its imports in a way a compiler would complain about, which is fine and
// is also the honest statement of this guard's limit: it reads the syntax tree
// and never the types.
func TestTheMutatorRuleSeesEveryWayToOpenForWriting(t *testing.T) {
	const source = `package p

import (
	"database/sql"
	"os"
	zsys "syscall"

	"github.com/aoiflux/libntfs"
)

type entry struct {
	Link   string
	Target string
}

func mustReport(p string, fd int, e entry) {
	f, _ := os.OpenFile(p, os.O_RDWR, 0)
	g, _ := zsys.Open(p, zsys.O_RDWR, 0)
	h := os.NewFile(uintptr(fd), p)
	remove := os.Remove
	_, _, _, _ = f, g, h, remove
}

func mustNotReport(p string, e entry, backend *libntfs.Backend) {
	a, _ := os.Open(p)
	b, _ := os.OpenFile(p, os.O_RDONLY, 0)
	c, _ := backend.Open(p, 0)
	d, _ := sql.Open("sqlite", p)
	link := e.Link
	_, _, _, _, _ = a, b, c, d, link
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("the synthetic source does not parse: %v", err)
	}

	got := map[string]string{} // what was reported -> the function it was reported in
	for _, w := range scanParsedGoFile(fset, file, "synthetic.go") {
		got[w.what] = w.fn
	}

	for _, want := range []string{
		"OpenFile with a writable flag",
		"Open with a writable flag",
		"NewFile",
		"Remove taken as a value",
	} {
		where, found := got[want]
		if !found {
			t.Errorf("the guard did not report %q; it reported %v", want, got)
			continue
		}
		if where != "mustReport" {
			t.Errorf("%q was reported in %s, which is not where it was written", want, where)
		}
	}

	for what, where := range got {
		if where != "mustReport" {
			t.Errorf("false positive: %q reported in %s, where nothing mutates the filesystem", what, where)
		}
	}
	if len(got) != 4 {
		t.Errorf("the guard made %d distinct reports, want 4: %v", len(got), got)
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
