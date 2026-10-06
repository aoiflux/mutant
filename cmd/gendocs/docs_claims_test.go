package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"mutant/builtin"
)

// These tests hold the prose to the tree it describes. Each one checks a kind
// of claim a reader acts on without checking it themselves: that a builtin by
// that name exists (D2), that a command line runs (D3), that a file it points
// at is there (D4), and that a link lands somewhere (D5).

// historyDocs record what used to be true. A changelog naming a builtin that
// was since renamed, or a file that was since deleted, is correct.
var historyDocs = map[string]bool{
	"CHANGELOG.md":                         true,
	"mutant-vscode-extension/CHANGELOG.md": true,
}

// isHistoryDoc reports whether a document's job is to record what used to be
// true. A published advisory's is: it describes the code before the fix, cites
// the lines it stood at then, and names flags and builtins that may since have
// been retired. Holding one to today's tree would mean rewriting the record of
// a vulnerability every time the code moved, which is the opposite of what it
// is for. Links are still checked, in every document.
func isHistoryDoc(rel string) bool {
	return historyDocs[rel] || strings.HasPrefix(rel, "docs/advisories/")
}

var (
	inlineCode  = regexp.MustCompile("`([^`\n]+)`")
	builtinCall = regexp.MustCompile(`^([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\(`)
)

// proseLines yields each line of a Markdown file that is outside a fence, with
// its 1-based line number. The scanner is in consistency.go, because
// `gendocs -check` reads the same documents the same way.
func proseLines(t *testing.T, rel string) []proseLine {
	t.Helper()
	lines, err := proseLinesOf(repoRoot, rel)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

// notBuiltins are snake_case calls the docs name on purpose although no
// builtin has that name, each with the reason it is named.
var notBuiltins = map[string]string{
	"disclose_to": "DISCLOSURE_POLICY states that the public-key grant is not built, by decision",
}

// TestDocumentedBuiltinsExist is D2: a `name(...)` in prose is a builtin a
// reader will call. A rename that forgets the docs leaves them calling nothing.
func TestDocumentedBuiltinsExist(t *testing.T) {
	registered := map[string]bool{}
	for _, b := range builtin.Builtins {
		registered[b.Name] = true
	}
	checked := 0
	for _, file := range markdownFiles(t) {
		if isHistoryDoc(file) {
			continue
		}
		for _, line := range proseLines(t, file) {
			for _, span := range inlineCode.FindAllStringSubmatch(line.text, -1) {
				m := builtinCall.FindStringSubmatch(strings.TrimSpace(span[1]))
				if m == nil {
					continue
				}
				checked++
				if registered[m[1]] || notBuiltins[m[1]] != "" {
					continue
				}
				t.Errorf("%s:%d: `%s(` is not a registered builtin", file, line.n, m[1])
			}
		}
	}
	if checked == 0 {
		t.Fatal("checked no builtin mentions; the scanner is broken")
	}
}

// cliSources are the files that define the command line.
var cliSources = []string{"main.go", "cli_debug.go", "cli_graph.go", "cli_test_coverage.go", "cli_tooling.go", "test_runner.go", "case_key_passphrase.go"}

// knownCLINames collects every string literal in the command-line sources, with
// leading dashes and any =value trimmed. A flag a document teaches has to be
// spelled somewhere in them.
func knownCLINames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	fset := token.NewFileSet()
	files := append([]string{}, cliSources...)
	for _, dir := range []string{"cli", "credential"} {
		matches, _ := filepath.Glob(filepath.Join(repoRoot, dir, "*.go"))
		for _, m := range matches {
			rel, _ := filepath.Rel(repoRoot, m)
			files = append(files, filepath.ToSlash(rel))
		}
	}
	for _, rel := range files {
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(repoRoot, filepath.FromSlash(rel)), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for field := range strings.FieldsSeq(s) {
				field = strings.TrimLeft(field, "-")
				field, _, _ = strings.Cut(field, "=")
				names[field] = true
			}
			return true
		})
	}
	return names
}

var (
	// mutantCommand matches mutant in command position: at the start of a line
	// (after an optional prompt) or after a shell separator, never as an
	// argument to something else (Get-FileHash ./mutant.exe).
	mutantCommand  = regexp.MustCompile(`(?:^\s*(?:\$|>|PS[^>]*>)?\s*|(?:&&|\|\||;|\|)\s*)(?:\./|\.\\)?mutant(?:\.exe)?((?:\s+[^\s|;&]+)*)`)
	deprecatedFlag = map[string]string{
		"pwd":      "--password-file, --password-stdin or --password-insecure",
		"password": "--password-file, --password-stdin or --password-insecure",
	}
	deprecationWords = regexp.MustCompile(`(?i)deprecat|refus|insecure|legacy|no longer|removed|never (?:existed|written)`)
)

// TestDocumentedCommandLinesExist is D3: a `mutant ...` line a reader copies
// must use flags the binary knows, and must not teach the forms it is retiring
// (`mutant run`, `-pwd`, `--password`) unless the line says they are retired.
func TestDocumentedCommandLinesExist(t *testing.T) {
	known := knownCLINames(t)
	shellLangs := map[string]bool{"bash": true, "sh": true, "shell": true, "powershell": true, "console": true, "ps1": true, "": true}
	checked := 0
	check := func(file string, line int, text, context string) {
		for _, m := range mutantCommand.FindAllStringSubmatch(text, -1) {
			args := strings.Fields(m[1])
			if len(args) == 0 {
				continue
			}
			checked++
			retiredOK := deprecationWords.MatchString(context)
			if args[0] == "run" && !retiredOK {
				t.Errorf("%s:%d: teaches `mutant run`, the legacy alias; teach `mutant gen` (or run the .mu directly)", file, line)
			}
			for _, a := range args {
				if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
					continue
				}
				name := strings.TrimLeft(a, "-")
				name, _, _ = strings.Cut(name, "=")
				if name == "" || strings.ContainsAny(name, "<>[]{}'\"`") {
					continue
				}
				if alt, retired := deprecatedFlag[name]; retired && !retiredOK {
					t.Errorf("%s:%d: teaches %s, which is retired; use %s", file, line, a, alt)
					continue
				}
				if !known[name] {
					t.Errorf("%s:%d: `%s` is not a flag any command-line source spells", file, line, a)
				}
			}
		}
	}
	for _, file := range markdownFiles(t) {
		if isHistoryDoc(file) {
			continue
		}
		for _, f := range fences(t, file) {
			if !shellLangs[f.lang] {
				continue
			}
			for i, l := range strings.Split(f.body, "\n") {
				check(file, f.line+1+i, l, l)
			}
		}
		for _, line := range proseLines(t, file) {
			for _, span := range inlineCode.FindAllStringSubmatch(line.text, -1) {
				if strings.HasPrefix(strings.TrimSpace(span[1]), "mutant ") {
					check(file, line.n, span[1], line.text)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("checked no command lines; the scanner is broken")
	}
}

// notInAClone are paths the docs cite that a clone legitimately lacks, each
// with the reason: build output, generated evidence, or a file the reader
// creates in their own workspace.
var notInAClone = map[string]string{
	"lsp/dist":                              "written by lsp/build.{sh,ps1}",
	"mutant-vscode-extension/bin":           "staged by the extension's packaging scripts",
	"examples/wasm-repl/mutant_repl.wasm":   "written by scripts/build.{sh,ps1}",
	"examples/wasm-repl/wasm_exec.js":       "copied from the Go toolchain by scripts/build.{sh,ps1}",
	"examples/workshop/case_quilldrop.body": "the generated bodyfile, which the evidence README cites relative to case_quilldrop/",
	".vscode/launch.json":                   "the reader's own workspace file",
	".vscode/tasks.json":                    "the reader's own workspace file",
	"dist":                                  "written by scripts/build.{sh,ps1}",
	"plans/review-2.6.0/embargo":            "security-finding detail held back until the fix ships; gitignored by design",
}

// excusedFromClone reports whether a path, or a directory above it, is one a
// clone legitimately lacks.
func excusedFromClone(p string) bool {
	p = strings.TrimSuffix(p, "/")
	for q := p; q != "." && q != "/" && q != ""; q = filepath.ToSlash(filepath.Dir(q)) {
		if notInAClone[q] != "" {
			return true
		}
	}
	return false
}

// ignoredTopLevel reads the top-level directories .gitignore excludes. A path
// cited under one of them -- plans/ is the case that bit -- exists on the
// machine that wrote it and in no clone.
func ignoredTopLevel(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, ".gitignore"))
	if err != nil {
		t.Fatalf("reading .gitignore: %v", err)
	}
	ignored := map[string]bool{}
	dir := regexp.MustCompile(`^/?([A-Za-z0-9_.-]+)/$`)
	for line := range strings.SplitSeq(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if m := dir.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			ignored[m[1]] = true
		}
	}
	return ignored
}

var citedPath = regexp.MustCompile(`^(?:\./)?([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)(?::\d+(?:[-,]\d+)*)?$`)

// topLevel lists the repository's top-level entries, so that a cited path is
// only checked when it claims to be inside this repository.
func topLevel(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	top := map[string]bool{}
	for _, e := range entries {
		top[e.Name()] = true
	}
	return top
}

// committableFiles returns the paths a commit of this tree can carry: the ones
// git tracks and the untracked ones it does not ignore, so a file added in the
// same change that first cites it passes before it is staged. It returns nil
// when this is not a git checkout (an exported tree), in which case only
// existence is checked.
func committableFiles(t *testing.T) map[string]bool {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Logf("not a git checkout (%v); checking that cited paths exist, not that git would carry them", err)
		return nil
	}
	committable := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		committable[line] = true
		for dir := filepath.ToSlash(filepath.Dir(line)); dir != "."; dir = filepath.ToSlash(filepath.Dir(dir)) {
			committable[dir] = true
		}
	}
	return committable
}

// resolveCited reports whether a cited path names something a reader of a
// clone can open: it exists, and, when git is available, git would carry it.
// A gitignored path such as plans/ exists on one machine and nowhere else.
func resolveCited(top, ignored, committable map[string]bool, fromDir, p string) (checked bool, ok bool) {
	first, _, _ := strings.Cut(p, "/")
	candidates := []string{}
	switch {
	case (first == "." || first == "..") && fromDir != "":
		candidates = append(candidates, filepath.ToSlash(filepath.Join(fromDir, p)))
	case top[first] || ignored[first]:
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		return false, true
	}
	for _, c := range candidates {
		if excusedFromClone(c) {
			return true, true
		}
		if head, _, _ := strings.Cut(c, "/"); ignored[head] {
			return true, false
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(strings.TrimSuffix(c, "/")))); err != nil {
			continue
		}
		if committable == nil || committable[strings.TrimSuffix(c, "/")] {
			return true, true
		}
	}
	return true, false
}

// TestCitedPathsExist is D4: a path a document or a Go comment cites has to be
// there in a clone. Four source comments once cited a debugger design note in
// the plans directory -- a file that existed nowhere, in a directory git
// ignores, so no reader could have followed any of them.
func TestCitedPathsExist(t *testing.T) {
	top, ignored, committable := topLevel(t), ignoredTopLevel(t), committableFiles(t)
	checked := 0
	for _, file := range markdownFiles(t) {
		if isHistoryDoc(file) {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(file))
		for _, line := range proseLines(t, file) {
			for _, span := range inlineCode.FindAllStringSubmatch(line.text, -1) {
				m := citedPath.FindStringSubmatch(strings.TrimSpace(span[1]))
				if m == nil || deprecationWords.MatchString(line.text) {
					continue
				}
				did, ok := resolveCited(top, ignored, committable, dir, m[1])
				if did {
					checked++
				}
				if !ok {
					t.Errorf("%s:%d: cites `%s`, which a clone of this repository does not have", file, line.n, m[1])
				}
			}
		}
	}

	commentPath := regexp.MustCompile(`\b((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:md|go|mut))\b`)
	fset := token.NewFileSet()
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if docsSkippedDirs[d.Name()] || d.Name() == "mutant-vscode-extension" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, path)
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil // another test owns parse errors
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				for _, m := range commentPath.FindAllStringSubmatch(c.Text, -1) {
					did, ok := resolveCited(top, ignored, committable, "", m[1])
					if did {
						checked++
					}
					if !ok {
						t.Errorf("%s:%d: a comment cites %s, which a clone of this repository does not have",
							rel, fset.Position(c.Pos()).Line, m[1])
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("checked no cited paths; the scanner is broken")
	}
}

// TestDocumentLinksResolve is D5: a relative link lands on a file that exists,
// and an anchor on a heading that exists. The check is in consistency.go, where
// `gendocs -check` can run it: a stale count in the generated reference moves
// the heading its index links to, so this is one of the things regenerating the
// artifacts breaks.
func TestDocumentLinksResolve(t *testing.T) {
	check, err := checkDocumentLinks(repoRoot)
	if err != nil {
		t.Fatalf("checking document links: %v", err)
	}
	reportDocCheck(t, check)
}

// sortedKeys is a small helper for stable failure output.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
