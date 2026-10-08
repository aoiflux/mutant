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

// TestOnlyReleaseIsDocumentedAsStrippingDebugInfo holds docs/MODULES.md and
// generator/generate.go to what the code actually does. Both used to say that
// `mutant release` "and any build with polymorphic mutation" strip the
// file-to-line map. Only release strips: StripDebugInfo is called under the
// release flag alone, so an artifact from `mutant gen` carries every module's
// file name and full source text at any mutation level, and a traceback from it
// names a module and quotes its line in a directory holding no source at all.
// The prose was the defect rather than the behaviour, which is published on
// purpose -- a reader acts on a sentence like that, and this one read as
// permission to hand a mutated artifact to someone they would not hand the
// source to (M26-DOC1-001).
//
// Both halves are checked, so whichever side moves next the other is reported
// instead of quietly diverging: the document must still say that release is the
// only build that strips, and the generator must still guard its call with the
// release flag. If polymorphism is ever made to strip, this test is what says
// the sentence has to change with it.
func TestOnlyReleaseIsDocumentedAsStrippingDebugInfo(t *testing.T) {
	const doc = "docs/MODULES.md"
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(doc)))
	if err != nil {
		t.Fatal(err)
	}
	// Collapsed to single spaces so the check does not depend on where the
	// paragraph happens to wrap.
	flat := strings.Join(strings.Fields(string(raw)), " ")

	const promise = "`mutant release` is the only build that strips it"
	if !strings.Contains(flat, promise) {
		t.Errorf("%s no longer says %q. Release is the only build that strips debug information; if that ever changes, the comment in generator/generate.go has to change with it", doc, promise)
	}
	for _, wrong := range []string{
		"any build with polymorphic mutation strip",
		"polymorphic mutation strips",
		"polymorphism strips",
	} {
		if strings.Contains(strings.ToLower(flat), wrong) {
			t.Errorf("%s says %q, and it does not: StripDebugInfo runs only under the release flag, so a gen artifact keeps the map at every mutation level", doc, wrong)
		}
	}

	const gen = "generator/generate.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(repoRoot, filepath.FromSlash(gen)), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	calls, guarded := 0, 0
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "StripDebugInfo" {
			calls++
		}
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if cond, ok := stmt.Cond.(*ast.Ident); !ok || cond.Name != "stripDebug" {
			return true
		}
		ast.Inspect(stmt.Body, func(inner ast.Node) bool {
			if sel, ok := inner.(*ast.SelectorExpr); ok && sel.Sel.Name == "StripDebugInfo" {
				guarded++
			}
			return true
		})
		return true
	})
	if calls == 0 {
		t.Fatalf("%s no longer calls StripDebugInfo at all, and %s describes when it runs", gen, doc)
	}
	if guarded != calls {
		t.Errorf("%s calls StripDebugInfo %d time(s) but only %d are guarded by stripDebug. %s says release is the only build that strips, so either the guard comes back or the document changes", gen, calls, guarded, doc)
	}
}

// The 30-minute tutorial installs in section 1 and runs `mutant release` in
// section 7, and those two have to agree. A binary from a plain `go build` or
// `go install` embeds no runtime assets -- .gitignore keeps releaseassets/data/
// out of the repository and un-ignores only placeholder.bin -- so the release
// step fails on it, which made the page contradict its own promise that
// "Everything below is a command that was run and an output that came back"
// (M26-DOC1-003).
//
// This is conditional on purpose. The page is only held to the build script for
// as long as it asks the reader to run `mutant release`; drop that section and
// the install step is free to be the shortest thing that works again.
func TestTutorialInstallsTheWayItsOwnReleaseStepNeeds(t *testing.T) {
	const doc = "docs/TUTORIAL_30_MIN.md"
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(doc)))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	if !strings.Contains(text, "mutant release") {
		return
	}

	start := strings.Index(text, "## 1.")
	if start < 0 {
		t.Fatalf("%s has no section 1, so there is no install step to check", doc)
	}
	end := strings.Index(text[start:], "\n## ")
	if end < 0 {
		t.Fatalf("%s section 1 never ends, so the install step cannot be isolated", doc)
	}
	install := text[start : start+end]

	if !strings.Contains(install, "scripts/build.sh") {
		t.Errorf("%s runs `mutant release` but its install step does not use scripts/build.sh. A binary built any other way has no embedded runtime assets, so that release step fails and the page shows output it cannot produce.", doc)
	}

	// A line that is nothing but `go install` or `go build ./...` is the install
	// path that cannot work here. Matched whole, so that `go install
	// golang.org/dl/go1.26.6@latest` -- which is advice about the toolchain, not
	// about installing mutant -- does not trip it.
	for _, line := range strings.Split(install, "\n") {
		switch strings.TrimSpace(line) {
		case "go install", "go install .", "go install ./...", "go build ./...", "go build .":
			t.Errorf("%s installs with %q, and a binary built that way refuses the `mutant release` step this page goes on to show. Use the build script, or stop showing release.", doc, strings.TrimSpace(line))
		}
	}
}

// The other half of the same defect, kept beside it: the error a reader reaches
// when they install the wrong way has to name the way out. The branch that
// fires is the one for an asset the embed does not hold, and it used to say
// only that the asset was "invalid" -- while the message that did name a remedy
// sat on a branch no reader could reach, because the manifest is committed and
// complete. releaseassets/assets_runtime_test.go checks the messages
// themselves; this checks that the split still exists at all, so that a later
// simplification back to one message is reported here rather than discovered by
// someone following this page.
func TestMissingAssetErrorDistinguishesAbsentFromCorrupt(t *testing.T) {
	const src = "releaseassets/assets_runtime.go"
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(src)))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	if !strings.Contains(body, "errors.Is(err, fs.ErrNotExist)") {
		t.Errorf("%s no longer separates an asset that was never embedded from one that is corrupt. Those have different remedies, and the first is what a plain `go build` produces.", src)
	}
	for _, want := range []string{"mutant gen assets", "scripts/build.sh"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s no longer names %q in any failure message, so a reader who built the wrong way is told what is wrong and not what to do.", src, want)
		}
	}
}
