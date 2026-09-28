package policy

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// repositoryRoot is relative to this package's directory, which is where `go
// test` runs from.
const repositoryRoot = ".."

// policyDoc is named in every failure message so the reader learns the rule and
// not merely that they broke it.
const policyDoc = "docs/CONFIGURATION_POLICY.md"

// skippedDirs are pruned during the walk. node_modules is not optional: it
// vendors third-party Go that has nothing to do with this policy.
var skippedDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".codegraph":   true,
	"dist":         true,
}

// mutantEnvName matches a Mutant-prefixed environment variable name. It is
// anchored, so the two known false positives need no allowlist entry: the
// MUTANT_LANGUAGE_REFERENCE.md mention in cmd/gendocs/sections.go sits inside a
// much larger literal (and "." is outside the character class), and the one in
// lsp/internal/analyzer is a comment, which is absent from the AST because we do
// not pass parser.ParseComments.
//
// The star rather than a plus is deliberate: it catches `"MUTANT_" + name` too.
var mutantEnvName = regexp.MustCompile(`^MUTANT_[A-Z0-9_]*$`)

// envFuncs are the selectors that read or write the process environment.
// Matching the selector alone -- not the package qualifier -- catches os.Getenv,
// syscall.Getenv, t.Setenv, an aliased import, and proc.Environ() or
// proc.EnvironWithContext() on a gopsutil process, all with one rule.
var envFuncs = map[string]bool{
	"Getenv":             true,
	"LookupEnv":          true,
	"Setenv":             true,
	"Unsetenv":           true,
	"ExpandEnv":          true,
	"Environ":            true,
	"EnvironWithContext": true,
	"Clearenv":           true,
}

// libraryEnvReads are standard-library functions that read the environment
// inside themselves (M26-DOC3-001: the keystore followed HOME through
// os.UserHomeDir, which no Getenv selector shows). These are matched by
// package as well as name, through whatever name the file imports the package
// under, because t.TempDir, or a method of the same name on anything else, is
// not them. net/http's default client and transport, and the package-level
// requests that use them, send through the proxy HTTP_PROXY, HTTPS_PROXY and
// NO_PROXY name (M26-NET-010).
var libraryEnvReads = map[string]map[string]bool{
	"os": {"UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true, "TempDir": true},
	"net/http": {
		"ProxyFromEnvironment": true, "DefaultTransport": true, "DefaultClient": true,
		"Get": true, "Head": true, "Post": true, "PostForm": true,
	},
}

// tempDirDefaults create a file or directory in os.TempDir when their directory
// argument is empty, which is how the temporary-directory variables are read in
// practice.
var tempDirDefaults = map[string]map[string]bool{
	"os":        {"MkdirTemp": true, "CreateTemp": true},
	"io/ioutil": {"TempDir": true, "TempFile": true},
}

// userLookups answer for the current user from $HOME and $USER when os/user is
// built without cgo on Linux and the uid is missing from /etc/passwd (os/user's
// lookup_stubs.go); Lookup and LookupId return Current's answer for the
// caller's own name or uid. Nowhere else do they read the environment, so they
// are flagged only in files that build for Linux without cgo.
var userLookups = map[string]bool{"Current": true, "Lookup": true, "LookupId": true}

// linuxEnvReads read the environment only in the Linux build: os/user's
// lookups, and crypto/x509's SystemCertPool, which takes the system's
// certificate authorities from SSL_CERT_FILE and SSL_CERT_DIR when they are set
// (M26-NET-010).
var linuxEnvReads = map[string]map[string]bool{
	"os/user":     userLookups,
	"crypto/x509": {"SystemCertPool": true},
}

// linuxWithoutCgo is the build Mutant ships for Linux, and the one in which
// linuxEnvReads read the environment.
var linuxWithoutCgo = func() build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", false
	return ctx
}()

type finding struct {
	file string // repo-relative, forward slashes
	line int
	fn   string // enclosing top-level func, "" at package level
	what string
}

func (f finding) String() string {
	where := f.fn
	if where == "" {
		where = "package level"
	}
	return fmt.Sprintf("%s:%d (%s): %s", f.file, f.line, where, f.what)
}

// scan walks the repository once and returns every Mutant-prefixed name literal
// and every environment access it finds, plus the set of files it read.
func scan(t *testing.T) (names []finding, access []finding, scanned map[string]bool) {
	t.Helper()

	scanned = map[string]bool{}
	fset := token.NewFileSet()

	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

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
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		scanned[rel] = true

		// go/parser reads build-tagged files regardless of the host GOOS, which
		// is essential here: most detection code lives behind
		// //go:build windows|linux|darwin, and a go/types or go/packages checker
		// would silently skip two thirds of it.
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		onLinux, err := linuxWithoutCgo.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return fmt.Errorf("match %s against the Linux build: %w", rel, err)
		}

		fileNames, fileAccess := inspectFile(fset, rel, file, onLinux)
		names = append(names, fileNames...)
		access = append(access, fileAccess...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	// Two sanity checks, so a broken walk fails loudly rather than passing
	// vacuously.
	if len(scanned) == 0 {
		t.Fatalf("scanned no .go files under %s -- the walk is looking in the wrong place", root)
	}
	if !scanned["security/sandbox_windows.go"] {
		t.Fatalf("security/sandbox_windows.go was not scanned -- build-tagged files are being skipped, " +
			"which would hide most of the detection code this guard exists to bound")
	}

	return names, access, scanned
}

// inspectFile returns the Mutant-prefixed name literals and the environment
// accesses in one parsed file. onLinux says whether the file builds for Linux
// without cgo, the only build in which userLookups read the environment.
func inspectFile(fset *token.FileSet, rel string, file *ast.File, onLinux bool) (names, access []finding) {
	funcs := functionSpans(file)
	enclosing := func(pos token.Pos) string {
		for _, fn := range funcs {
			if pos >= fn.start && pos <= fn.end {
				return fn.name
			}
		}
		return ""
	}

	seen := map[int]bool{} // dedupe access findings by line
	addAccess := func(pos token.Pos, what string) {
		line := fset.Position(pos).Line
		if seen[line] {
			return
		}
		seen[line] = true
		access = append(access, finding{rel, line, enclosing(pos), what})
	}

	imported := importedAs(file)
	packageFunc := func(expr ast.Expr) (string, string) {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return "", ""
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", ""
		}
		return imported[pkg.Name], sel.Sel.Name
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(node.Value)
			if err != nil {
				return true
			}
			if mutantEnvName.MatchString(value) {
				pos := fset.Position(node.Pos())
				names = append(names, finding{rel, pos.Line, enclosing(node.Pos()), value})
			}

		case *ast.SelectorExpr:
			// Walking every SelectorExpr rather than only CallExpr.Fun is what
			// catches the function-value shape, where the function is passed
			// rather than called: addWindowsEnvIndicators(os.LookupEnv, add).
			if envFuncs[node.Sel.Name] {
				addAccess(node.Pos(), node.Sel.Name)
			}
			pkg, name := packageFunc(node)
			if libraryEnvReads[pkg][name] || (onLinux && linuxEnvReads[pkg][name]) {
				addAccess(node.Pos(), path.Base(pkg)+"."+name)
			}

		case *ast.CallExpr:
			if fn, ok := node.Fun.(*ast.Ident); ok && fn.Name == "new" && len(node.Args) == 1 {
				if pkg, name := packageFunc(node.Args[0]); pkg == "net/http" && name == "Client" {
					addAccess(node.Pos(), "new(http.Client), which sends through net/http's default transport")
				}
			}
			if pkg, name := packageFunc(node.Fun); tempDirDefaults[pkg][name] && len(node.Args) > 0 {
				if dir, ok := node.Args[0].(*ast.BasicLit); ok && dir.Kind == token.STRING {
					if value, err := strconv.Unquote(dir.Value); err == nil && value == "" {
						addAccess(node.Pos(), path.Base(pkg)+"."+name+" in the default temporary directory")
					}
				}
			}

		case *ast.ImportSpec:
			// A dot-import would make os.Getenv appear as a bare Ident, which
			// the SelectorExpr rule structurally cannot see.
			if node.Name != nil && node.Name.Name == "." {
				importPath, err := strconv.Unquote(node.Path.Value)
				if err == nil && (importPath == "os" || importPath == "syscall" || importPath == "os/user") {
					addAccess(node.Pos(), "dot-import of "+importPath)
				}
			}

		case *ast.AssignStmt:
			// Assignment only. The fn.Env / macro.Env *reads* in evaluator/ are
			// not environment access, and must not fire.
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" {
					addAccess(sel.Pos(), "assignment to .Env")
				}
			}

		case *ast.CompositeLit:
			if pkg, name := packageFunc(node.Type); pkg == "net/http" && name == "Client" && !namesATransport(node) {
				addAccess(node.Pos(), "http.Client with no Transport, which sends through net/http's default transport")
			}
			// Narrowed to a Cmd literal so object.Function{Env: env} does not
			// fire. A locally defined struct with an Env field would be missed,
			// but any such construction still needs an os.Environ() the
			// SelectorExpr rule catches.
			if !isCmdType(node.Type) {
				return true
			}
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Env" {
					addAccess(kv.Pos(), "Env field in a Cmd literal")
				}
			}
		}
		return true
	})
	return names, access
}

// importedAs maps each name a file refers to an imported package by -- its
// alias, or the last element of its path -- to that package's import path.
// Blank and dot imports bind no name.
func importedAs(file *ast.File) map[string]string {
	imported := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			imported[name] = importPath
		}
	}
	return imported
}

type funcSpan struct {
	name  string
	start token.Pos
	end   token.Pos
}

// functionSpans precomputes top-level function extents so a finding inside a
// closure attributes to the function that contains it.
func functionSpans(file *ast.File) []funcSpan {
	var spans []funcSpan
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		spans = append(spans, funcSpan{fn.Name.Name, fn.Pos(), fn.End()})
	}
	return spans
}

// namesATransport reports whether an http.Client literal gives the client a
// transport of its own. A client without one, or with a nil one, sends through
// net/http's default transport.
func namesATransport(lit *ast.CompositeLit) bool {
	for i, elt := range lit.Elts {
		value := elt
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Transport" {
				continue
			}
			value = kv.Value
		} else if i != 0 {
			continue
		}
		ident, isIdent := value.(*ast.Ident)
		return !isIdent || ident.Name != "nil"
	}
	return false
}

func isCmdType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return strings.HasSuffix(t.Name, "Cmd")
	case *ast.SelectorExpr:
		return strings.HasSuffix(t.Sel.Name, "Cmd")
	case *ast.StarExpr:
		return isCmdType(t.X)
	}
	return false
}

// Rule 1. A Mutant-prefixed variable name in Go source is exactly what leads
// someone to try setting it. There is no allowlist for this one.
func TestNoMutantEnvironmentVariableNames(t *testing.T) {
	names, _, _ := scan(t)
	if len(names) == 0 {
		return
	}

	sort.Slice(names, func(i, j int) bool {
		if names[i].file != names[j].file {
			return names[i].file < names[j].file
		}
		return names[i].line < names[j].line
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%d Mutant-prefixed environment variable name(s) in Go source:\n", len(names))
	for _, n := range names {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	fmt.Fprintf(&b, "\nMutant takes no configuration from environment variables -- use a CLI flag.\n"+
		"This rule has no allowlist. See %s.", policyDoc)
	t.Fatal(b.String())
}

// Rules 2-5. Reading or writing the environment is permitted only where the
// value is observed rather than obeyed, and only at the sites recorded in
// EnvAccessAllowlist.
func TestNoEnvironmentAccessOutsideAllowlist(t *testing.T) {
	_, access, _ := scan(t)

	type key struct{ file, fn string }
	allowed := map[key]EnvAccessException{}
	for _, entry := range EnvAccessAllowlist {
		allowed[key{entry.File, entry.Func}] = entry
	}

	counts := map[key]int{}
	var unexpected []finding
	for _, a := range access {
		k := key{a.file, a.fn}
		if _, ok := allowed[k]; !ok {
			unexpected = append(unexpected, a)
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
		fmt.Fprintf(&b, "%d environment access(es) outside policy.EnvAccessAllowlist:\n", len(unexpected))
		for _, u := range unexpected {
			fmt.Fprintf(&b, "  %s\n", u)
		}
		fmt.Fprintf(&b, "\nMutant takes no configuration from environment variables. An access is\n"+
			"permitted only in one of six categories:\n"+
			"  detection  -- Mutant observing where it is running (sandbox, VM, debugger)\n"+
			"  evidence   -- Mutant reporting on a subject process\n"+
			"  toolchain  -- writing GOOS/GOARCH/CGO_ENABLED for a child `go build`\n"+
			"  display    -- a value Mutant prints and never acts on\n"+
			"  scratch    -- the temporary directory, for files removed before the call returns\n"+
			"  regression -- a test setting a variable to prove Mutant does not obey it\n"+
			"If this is configuration, use a CLI flag. If it is one of the six, add an\n"+
			"entry to policy.EnvAccessAllowlist and say why in the commit. See %s.", policyDoc)
		t.Fatal(b.String())
	}

	for k, entry := range allowed {
		got := counts[k]
		if got == entry.Lines {
			continue
		}
		t.Errorf("%s: %s touches the environment on %d line(s), but policy.EnvAccessAllowlist pins %d.\n"+
			"Failing here is not a defect -- it means update policy.EnvAccessAllowlist and say why in the\n"+
			"commit. Reason on record: %s\nSee %s.",
			k.file, k.fn, got, entry.Lines, entry.Why, policyDoc)
	}
}

// A renamed or deleted function must not leave a permanent hole in the guard.
func TestEnvAllowlistHasNoStaleEntries(t *testing.T) {
	_, access, scanned := scan(t)

	matched := map[string]bool{}
	for _, a := range access {
		matched[a.file+"::"+a.fn] = true
	}

	for _, entry := range EnvAccessAllowlist {
		if matched[entry.File+"::"+entry.Func] {
			continue
		}
		if !scanned[entry.File] {
			t.Errorf("policy.EnvAccessAllowlist names %s, which no longer exists. Remove the entry.", entry.File)
			continue
		}
		t.Errorf("policy.EnvAccessAllowlist allows %s in %s, but nothing there touches the environment.\n"+
			"The function was probably renamed or the access removed; either way the entry is now a hole\n"+
			"in the guard. Remove or update it. See %s.", entry.Func, entry.File, policyDoc)
	}
}

// Every entry must be classified, so a reader can tell at a glance which of the
// three arguments is being made.
func TestEnvAllowlistEntriesAreWellFormed(t *testing.T) {
	valid := map[string]bool{
		"detection": true, "evidence": true, "toolchain": true,
		"display": true, "scratch": true, "regression": true,
	}
	seen := map[string]bool{}

	for _, entry := range EnvAccessAllowlist {
		id := entry.File + "::" + entry.Func
		if seen[id] {
			t.Errorf("policy.EnvAccessAllowlist has two entries for %s", id)
		}
		seen[id] = true

		if !valid[entry.Category] {
			t.Errorf("%s: category %q is not one of detection, evidence, toolchain, display, scratch, regression",
				id, entry.Category)
		}
		if entry.Category == "regression" && !strings.HasSuffix(entry.File, "_test.go") {
			t.Errorf("%s: a regression entry is a test that sets a variable to prove it is not obeyed; "+
				"%s is not a test file", id, entry.File)
		}
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

// The guard must actually be able to see the tree it is guarding. This is
// separate from the in-scan sanity checks so a wrong repositoryRoot reports as
// its own failure rather than as a flood of stale-entry errors.
func TestGuardScansTheRepository(t *testing.T) {
	_, _, scanned := scan(t)

	for _, want := range []string{
		"main.go",
		"runner/runner.go",
		"security/sandbox_windows.go",
		"security/sandbox_linux.go",
		"security/sandbox_darwin.go",
		"policy/env_policy.go",
	} {
		if !scanned[want] {
			t.Errorf("the guard did not scan %s", want)
		}
	}

	if _, err := os.Stat(filepath.Join(repositoryRoot, policyDoc)); err != nil {
		t.Errorf("every failure message points at %s, which is missing: %v", policyDoc, err)
	}
}

// The keystore once followed HOME through os.UserHomeDir, a read no Getenv
// selector shows (M26-DOC3-001), and the TLS clients took the system's
// certificate authorities from SSL_CERT_FILE through crypto/x509 (M26-NET-010).
// The guard must see every standard-library call that reads the environment
// inside itself, under any import name, and must not mistake t.TempDir, or a
// temporary file in a directory the caller names, for one.
func TestTheGuardSeesLibraryCallsThatReadTheEnvironment(t *testing.T) {
	const src = `package fixture

import (
	"crypto/x509"
	stdos "os"
	"os/user"
	"testing"
)

func reads(dir string) {
	stdos.UserHomeDir()
	stdos.UserCacheDir()
	configDir := stdos.UserConfigDir
	stdos.TempDir()
	stdos.MkdirTemp("", "x-*")
	stdos.CreateTemp("", "x-*")
	stdos.MkdirTemp(dir, "x-*")
	user.Current()
	user.LookupId("0")
	x509.SystemCertPool()
	_ = configDir
}

func fine(t *testing.T) {
	t.TempDir()
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}

	always := []string{
		"os.UserHomeDir", "os.UserCacheDir", "os.UserConfigDir", "os.TempDir",
		"os.MkdirTemp in the default temporary directory",
		"os.CreateTemp in the default temporary directory",
	}
	for _, onLinux := range []bool{true, false} {
		want := append([]string(nil), always...)
		if onLinux {
			want = append(want, "user.Current", "user.LookupId", "x509.SystemCertPool")
		}
		_, access := inspectFile(fset, "fixture.go", file, onLinux)
		var got []string
		for _, a := range access {
			if a.fn != "reads" {
				t.Errorf("onLinux=%v: %s is not an environment read", onLinux, a)
			}
			got = append(got, a.what)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("onLinux=%v: the guard saw\n  %s\nwant\n  %s", onLinux,
				strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
}

// net/http's default transport sends a request through the proxy HTTP_PROXY,
// HTTPS_PROXY and NO_PROXY name, and the http_* builtins used it (M26-NET-010).
// The guard must see every way to reach it: the default client and transport,
// the package-level requests that use them, the proxy function itself, and a
// client made with no transport of its own. A client handed a transport, and a
// transport that names no proxy, are not it.
func TestTheGuardSeesNetHTTPsDefaultTransport(t *testing.T) {
	const src = `package fixture

import web "net/http"

func reads() {
	web.Get("http://feed.example.invalid/")
	web.PostForm("http://feed.example.invalid/", nil)
	_ = web.DefaultClient
	_ = web.DefaultTransport
	_ = web.ProxyFromEnvironment
	_ = &web.Client{}
	_ = web.Client{CheckRedirect: nil}
	_ = &web.Client{Transport: nil}
	_ = new(web.Client)
}

func fine(client *web.Client, transport web.RoundTripper) {
	client.Get("http://feed.example.invalid/")
	_ = &web.Client{Transport: transport}
	_ = &web.Transport{Proxy: nil}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http.Get", "http.PostForm", "http.DefaultClient", "http.DefaultTransport", "http.ProxyFromEnvironment",
		"http.Client with no Transport, which sends through net/http's default transport",
		"http.Client with no Transport, which sends through net/http's default transport",
		"http.Client with no Transport, which sends through net/http's default transport",
		"new(http.Client), which sends through net/http's default transport",
	}
	_, access := inspectFile(fset, "fixture.go", file, false)
	var got []string
	for _, a := range access {
		if a.fn != "reads" {
			t.Errorf("%s does not reach the default transport", a)
		}
		got = append(got, a.what)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the guard saw\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// os/user reads the environment only where it is built without cgo for Linux,
// so the guard asks the Linux build whether a file is in it: a file that only
// ever builds for macOS, Windows or with cgo has no such read.
func TestTheUserLookupRuleFollowsTheLinuxBuild(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		src     string
		inBuild bool
	}{
		"plain.go":       {"package p\n", true},
		"lookup_unix.go": {"//go:build unix\n\npackage p\n", true},
		"home_darwin.go": {"package p\n", false},
		"tagged.go":      {"//go:build windows\n\npackage p\n", false},
		"with_cgo.go":    {"//go:build cgo\n\npackage p\n", false},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(tc.src), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := linuxWithoutCgo.MatchFile(dir, name)
		if err != nil || got != tc.inBuild {
			t.Errorf("%s in the Linux build without cgo: %v, %v; want %v", name, got, err, tc.inBuild)
		}
	}
}
