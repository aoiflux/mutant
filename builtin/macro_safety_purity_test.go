package builtin

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The allowlist in macro_safety.go is an assertion about code: that every builtin
// on it computes and nothing more. An assertion about code decays as the code
// changes, so this test re-derives it from the source on every run.
//
// It reads the registry literal to find each allowlisted builtin's Go function,
// then walks forward through everything that function calls -- transitively,
// across the whole of package builtin, and on into any mutant/... package it
// reaches -- and checks every package a reached function actually uses.
//
// The check is DEFAULT-DENY on packages, which is the point. A denylist of
// "os, net, syscall" would pass io/fs, embed, runtime, unsafe, a new third-party
// package, and -- the one that matters -- a hop into mutant/mutil or
// mutant/security, where the work could be done out of sight. That is the same
// fail-open shape this boundary refuses in webrepl.BrowserSafe, and it does not
// belong in the test that is supposed to keep the boundary honest. So a package
// not named below is a failure, and adding a new import to a file an allowlisted
// builtin reaches turns this test red until somebody says why it is pure.
//
// What it cannot see, stated rather than implied:
//
//   - a method called on a value (`out.WriteString(...)`), because resolving the
//     receiver's type needs a type checker. This is not the hole it looks like: a
//     method's code cannot use a package the file does not import, and every
//     import of every file reached IS checked. What escapes is a method on a type
//     from an allowed package that is itself impure -- so the allowed set below
//     names members, not just packages, wherever a package mixes the two;
//   - dispatch through an interface or a function-typed field, where the
//     implementation is chosen at run time.
//
// Those two are why this test is one of four guards and not the only one. The
// others: every builtin must be classified at all, no allowlisted builtin may
// declare a parameter naming something on disk, and the engine must actually
// refuse every name the table refuses.

// Every entry here is one the walk actually reaches:
// TestEveryPureMembersEntryIsLoadBearing fails on a package nothing reaches,
// because an unreached entry pre-approves whatever reaches it next. Twenty were
// dropped on 2026-09-30 for that reason -- among them encoding/asn1, which the
// tree never imports, and crypto/cipher, which only the refused aes_ family uses.
//
// pureMembers maps a package an allowlisted builtin may reach to the members of
// it that may be used. A nil set means the whole package is pure.
//
// Where a package mixes pure and ambient work, the members are named one by one,
// because the package name alone would be a lie: time formats and time reads a
// clock, net parses an address and net opens a socket.
var pureMembers = map[string][]string{
	// Computation over values, with no way to reach anything else.
	"bytes":           nil,
	"math":            nil,
	"math/big":        nil,
	"regexp":          nil,
	"sort":            nil,
	"strconv":         nil,
	"strings":         nil,
	"unicode":         nil,
	"unicode/utf8":    nil,
	"unicode/utf16":   nil,
	"encoding/base32": nil,
	"encoding/base64": nil,
	"encoding/binary": nil,
	"encoding/csv":    nil,
	"encoding/hex":    nil,
	"encoding/json":   nil,
	"encoding/xml":    nil,
	"compress/gzip":   nil,
	"compress/zlib":   nil,
	"hash":            nil,
	"hash/crc32":      nil,
	"crypto/hmac":     nil,
	"crypto/md5":      nil,
	"crypto/sha1":     nil,
	"crypto/sha256":   nil,
	"crypto/sha512":   nil,
	"crypto/des":      nil,
	"net/url":         nil,
	"bufio":           nil,
	"io":              nil,

	// Formatting only. Print and Fprint reach a stream.
	"fmt": {"Sprintf", "Sprint", "Sprintln", "Errorf"},

	// errors.Is only, and only for comparing against io.EOF in json_parse's
	// one-value check. It is named rather than the package taken whole
	// because Is walks the error's Unwrap chain, which is interface dispatch
	// this walk cannot follow: the entry is sound only while every error an
	// allowlisted builtin asks about is one the standard library made, which
	// for a json.Decoder's Token() it is.
	"errors": {"Is"},

	// time formats and computes here; reading the clock is refused, and the
	// builtins that do it are not on the allowlist.
	"time": {
		"Time", "Duration", "Month", "Weekday", "Location", "UTC", "Local", "FixedZone",
		"Unix", "UnixMilli", "UnixMicro", "Date", "Parse", "ParseDuration", "ParseInLocation",
		"RFC3339", "RFC3339Nano", "RFC1123", "RFC1123Z", "RFC822", "RFC822Z", "RFC850", "ANSIC",
		"Kitchen", "Stamp", "StampMilli", "StampMicro", "StampNano", "DateOnly", "TimeOnly", "DateTime",
		"Nanosecond", "Microsecond", "Millisecond", "Second", "Minute", "Hour",
		"January", "February", "March", "April", "May", "June", "July",
		"August", "September", "October", "November", "December",
	},

	// net parses addresses here. Nothing on the allowlist dials or resolves.
	"net": {"ParseIP", "ParseCIDR", "CIDRMask", "IP", "IPNet", "IPMask", "IPv4", "IPv4len", "IPv6len"},

	// Mutant's own value types. object builds the values a builtin returns;
	// global holds the shared singletons (Null, True, False).
	"mutant/object": nil,
	"mutant/global": nil,

	// runtime, for two members only. newError labels a builtin's error with the
	// Go function that raised it, and those two are how it reads the stack. The
	// rest of the package is not pure: GOOS, GOARCH, Version and Stack all report
	// on the running process, and this same package uses them for the status
	// builtins, which are refused.
	"runtime": {"Callers", "CallersFrames", "Frame", "Frames"},

	// Third-party codecs over a value the builtin was handed. These four have no
	// filesystem or network API at all, so the whole package is named.
	"go.yaml.in/yaml/v3":                            nil,
	"github.com/fxamacker/cbor/v2":                  nil,
	"github.com/vmihailenco/msgpack/v5":             nil,
	"google.golang.org/protobuf/encoding/protowire": nil,

	// toml decodes a string here. It also has DecodeFile and DecodeFS, so this
	// one is named member by member rather than whole.
	"github.com/BurntSushi/toml": {"Decode", "NewEncoder"},

	// Third-party parsers of a value the builtin was handed.
	"golang.org/x/crypto/blake2b":   nil,
	"golang.org/x/crypto/md4":       nil,
	"golang.org/x/net/publicsuffix": nil,
}

// goPredeclared are the identifiers a call may name that are not functions in
// this repository. A call to anything else that cannot be resolved is reported,
// not skipped -- an unresolved callee is exactly where impure work would hide.
var goPredeclared = []string{
	"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len",
	"make", "max", "min", "new", "panic", "print", "println", "real", "recover",
	// Conversions and types that read as calls.
	"bool", "byte", "complex64", "complex128", "error", "float32", "float64",
	"int", "int8", "int16", "int32", "int64", "rune", "string",
	"uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any",
}

type loadedPackage struct {
	funcs   map[string]*ast.FuncDecl
	fileOf  map[*ast.FuncDecl]*ast.File
	imports map[*ast.File]map[string]string // local name -> import path
}

type purityWalk struct {
	t        *testing.T
	fset     *token.FileSet
	packages map[string]*loadedPackage // import path -> package
	visited  map[string]bool           // "path.Func"
	reached  map[string]bool           // "path.Member", for the report
	problems map[string]string         // problem -> where it was first seen
}

func newPurityWalk(t *testing.T) *purityWalk {
	return &purityWalk{
		t:        t,
		fset:     token.NewFileSet(),
		packages: map[string]*loadedPackage{},
		visited:  map[string]bool{},
		reached:  map[string]bool{},
		problems: map[string]string{},
	}
}

// dirFor turns an import path into a directory in this repository, or "" for a
// package outside it.
func dirFor(path string) string {
	if path == "mutant" {
		return ".."
	}
	if rest, isMutant := strings.CutPrefix(path, "mutant/"); isMutant {
		return filepath.Join("..", rest)
	}
	return ""
}

func (w *purityWalk) load(path string) *loadedPackage {
	if pkg, done := w.packages[path]; done {
		return pkg
	}
	w.packages[path] = nil

	dir := dirFor(path)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.t.Fatalf("reading %s for import %q: %v", dir, path, err)
	}

	pkg := &loadedPackage{
		funcs:   map[string]*ast.FuncDecl{},
		fileOf:  map[*ast.FuncDecl]*ast.File{},
		imports: map[*ast.File]map[string]string{},
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(w.fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			w.t.Fatalf("parsing %s: %v", name, err)
		}
		pkg.imports[file] = importNames(file)
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil {
				key = receiverType(fn.Recv) + "." + fn.Name.Name
			}
			pkg.funcs[key] = fn
			pkg.fileOf[fn] = file
		}
	}
	w.packages[path] = pkg
	return pkg
}

func importNames(file *ast.File) map[string]string {
	names := map[string]string{}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		local := path
		if slash := strings.LastIndex(path, "/"); slash >= 0 {
			local = path[slash+1:]
		}
		// A versioned module path ends in the version, not the package name.
		if strings.HasPrefix(local, "v") && len(local) > 1 && local[1] >= '0' && local[1] <= '9' {
			trimmed := strings.TrimSuffix(path, "/"+local)
			if slash := strings.LastIndex(trimmed, "/"); slash >= 0 {
				local = trimmed[slash+1:]
			}
		}
		local = strings.TrimSuffix(local, ".v3")
		local = strings.TrimSuffix(local, ".v2")
		if spec.Name != nil {
			local = spec.Name.Name
		}
		names[local] = path
	}
	return names
}

func receiverType(recv *ast.FieldList) string {
	if len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, isStar := expr.(*ast.StarExpr); isStar {
		expr = star.X
	}
	if ident, isIdent := expr.(*ast.Ident); isIdent {
		return ident.Name
	}
	return ""
}

func (w *purityWalk) note(problem, where string) {
	if _, seen := w.problems[problem]; !seen {
		w.problems[problem] = where
	}
}

// walk follows one function, and everything it calls, as far as it can be
// resolved from the source.
func (w *purityWalk) walk(pkgPath, key, origin string) {
	visitKey := pkgPath + "." + key
	if w.visited[visitKey] {
		return
	}
	w.visited[visitKey] = true

	pkg := w.load(pkgPath)
	if pkg == nil {
		return
	}
	fn, found := pkg.funcs[key]
	if !found || fn.Body == nil {
		return
	}
	imports := pkg.imports[pkg.fileOf[fn]]

	ast.Inspect(fn.Body, func(node ast.Node) bool {
		// Every use of an imported package is checked, whether it is a call, a
		// type, or a bare value like os.Stdout.
		if sel, isSel := node.(*ast.SelectorExpr); isSel {
			if ident, isIdent := sel.X.(*ast.Ident); isIdent {
				if path, isImport := imports[ident.Name]; isImport {
					w.checkMember(path, sel.Sel.Name, origin, key)
					if inRepo := dirFor(path); inRepo != "" {
						w.walk(path, sel.Sel.Name, origin)
					}
					return true
				}
			}
			return true
		}

		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent {
			return true
		}
		if slices.Contains(goPredeclared, ident.Name) {
			return true
		}
		if _, isLocal := pkg.funcs[ident.Name]; isLocal {
			w.walk(pkgPath, ident.Name, origin)
			return true
		}
		// A name that is neither a function in this package nor a predeclared
		// one is a function value: a package-level var, a parameter, or a
		// closure. Report it rather than passing over it.
		if ident.Obj == nil {
			w.note(fmt.Sprintf("%s calls %s, which this walk cannot resolve to a function", key, ident.Name), origin)
		}
		return true
	})
}

func (w *purityWalk) checkMember(path, member, origin, inFunc string) {
	w.reached[path+"."+member] = true

	members, allowed := pureMembers[path]
	if !allowed {
		w.note(fmt.Sprintf("reaches package %s (as %s.%s)", path, lastSegment(path), member), origin)
		return
	}
	if members == nil || slices.Contains(members, member) {
		return
	}
	w.note(fmt.Sprintf("reaches %s.%s, which is not one of the pure members of %s named in this test",
		lastSegment(path), member, path), origin)
}

// lastSegment is how a package is spelled in source: its last path segment,
// skipping a major-version segment, which is not the package's name.
func lastSegment(path string) string {
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		if len(segment) > 1 && segment[0] == 'v' && segment[1] >= '0' && segment[1] <= '9' {
			continue
		}
		return segment
	}
	return path
}

// registryGoFuncs reads the Builtins literal and returns, for each builtin name
// constant, the Go function the registry gives it -- or "" when the entry is an
// executor-native var, which the engine implements rather than the registry.
func registryGoFuncs(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "builtin.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing builtin.go: %v", err)
	}

	byConstant := map[string]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		value, isValue := node.(*ast.ValueSpec)
		if !isValue || len(value.Names) != 1 || value.Names[0].Name != "Builtins" {
			return true
		}
		literal, isLiteral := value.Values[0].(*ast.CompositeLit)
		if !isLiteral {
			t.Fatal("Builtins is no longer a composite literal; this test reads it to find each builtin's Go function")
		}
		for _, element := range literal.Elts {
			row, isRow := element.(*ast.CompositeLit)
			if !isRow || len(row.Elts) != 2 {
				continue
			}
			nameConst, isIdent := row.Elts[0].(*ast.Ident)
			if !isIdent {
				continue
			}
			switch second := row.Elts[1].(type) {
			case *ast.UnaryExpr: // &BuiltIn{GoFunc}
				inner, isInner := second.X.(*ast.CompositeLit)
				if !isInner || len(inner.Elts) != 1 {
					continue
				}
				if fn, isFn := inner.Elts[0].(*ast.Ident); isFn {
					byConstant[nameConst.Name] = fn.Name
				}
			case *ast.Ident: // an executor-native var
				byConstant[nameConst.Name] = ""
			}
		}
		return false
	})

	if len(byConstant) == 0 {
		t.Fatal("read no rows out of the Builtins literal")
	}
	return byConstant
}

// nameConstants maps a builtin's spelling back to its BuiltinName constant.
func nameConstants(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "names.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing names.go: %v", err)
	}

	byName := map[string]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		value, isValue := node.(*ast.ValueSpec)
		if !isValue || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		literal, isLiteral := value.Values[0].(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING {
			return true
		}
		byName[strings.Trim(literal.Value, `"`)] = value.Names[0].Name
		return true
	})
	return byName
}

// TestMacroSafeBuiltinsTouchNothing is the durability guard for the allowlist.
// walkEveryMacroSafeBuiltin walks every allowlisted builtin's implementation
// forward and hands back the finished walk. Two tests read it: one asks what the
// walk reached that is not established as pure, the other asks what pureMembers
// permits that nothing reaches.
func walkEveryMacroSafeBuiltin(t *testing.T) (*purityWalk, int, int) {
	t.Helper()
	goFuncs := registryGoFuncs(t)
	constants := nameConstants(t)
	walk := newPurityWalk(t)

	var walked, native int
	for _, name := range macroSafeBuiltins {
		constant, hasConstant := constants[name]
		if !hasConstant {
			t.Errorf("%s has no BuiltinName constant, so this test cannot find its implementation", name)
			continue
		}
		goFunc, inRegistry := goFuncs[constant]
		if !inRegistry {
			t.Errorf("%s (%s) is not in the Builtins literal", name, constant)
			continue
		}
		if goFunc == "" {
			// An executor-native: the engine implements it, not the registry.
			// TestTheOnlyMacroSafeExecutorNativesAreTheOnesThatJustCallBack is
			// what holds that set to the ones whose only effect is calling back.
			native++
			continue
		}
		walked++
		walk.walk("mutant/builtin", goFunc, name)
	}

	if walked == 0 {
		t.Fatal("walked no implementations, so this test proves nothing")
	}
	return walk, walked, native
}

func TestMacroSafeBuiltinsTouchNothing(t *testing.T) {
	walk, walked, native := walkEveryMacroSafeBuiltin(t)

	if len(walk.problems) > 0 {
		keys := make([]string, 0, len(walk.problems))
		for problem := range walk.problems {
			keys = append(keys, problem)
		}
		sort.Strings(keys)
		var report strings.Builder
		for _, problem := range keys {
			fmt.Fprintf(&report, "\n  %s\n    first reached from the macro-safe builtin %q", problem, walk.problems[problem])
		}
		t.Errorf(`%d thing(s) an allowlisted builtin reaches are not established as pure:%s

A builtin is macro-safe only if it computes. Either the code changed and the name
should come off macroSafeBuiltins in macro_safety.go, or the thing above really is
pure computation -- in which case add it to pureMembers in this file, with the
reason, so the next reader does not have to work it out again. Adding a package
here widens what every allowlisted builtin may reach, so name members rather than
whole packages whenever a package mixes computing with reaching.`,
			len(keys), report.String())
	}

	t.Logf("walked %d implementations (%d executor-native), reaching %d distinct package members",
		walked, native, len(walk.reached))
}

// TestEveryPureMembersEntryIsLoadBearing holds pureMembers to what the walk
// actually reaches. A dead entry is not harmless: pureMembers is the permission
// list the default-deny walk above consults, so a package nothing reaches today
// silently pre-approves whatever reaches it tomorrow -- and nothing else in this
// file would notice. encoding/asn1 was exactly that entry: builtin/format_binary.go
// names the package only in a comment saying why DerParse does NOT use it, and
// the entry was written from reading that comment instead of the walk's output.
func TestEveryPureMembersEntryIsLoadBearing(t *testing.T) {
	walk, _, _ := walkEveryMacroSafeBuiltin(t)

	var dead []string
	for path := range pureMembers {
		prefix := path + "."
		var reached bool
		for key := range walk.reached {
			if strings.HasPrefix(key, prefix) {
				reached = true
				break
			}
		}
		if !reached {
			dead = append(dead, path)
		}
	}
	sort.Strings(dead)

	if len(dead) > 0 {
		t.Errorf(`%d pureMembers entr(y/ies) nothing reaches: %s

Either an allowlisted builtin stopped using the package -- in which case take the
entry out, because it now permits something no reviewer has looked at -- or the
walk stopped following the call that got there, which is a hole in this test and
the more serious of the two.`, len(dead), strings.Join(dead, ", "))
	}
}
