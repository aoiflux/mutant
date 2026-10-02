// Package limitscan finds the values in Mutant's source that bound what the
// program will do -- allocation sizes, input caps, recursion depths, timeouts,
// retry counts, thresholds -- and reports the ones written as bare literals
// instead of as named, documented constants.
//
// It exists for two readers. The policy guard (policy/limit_guard_test.go)
// fails when a new unnamed limit appears, and cmd/gendocs renders every named
// limit into docs/LIMITS_REFERENCE.md, so the value an examiner is bounded by
// is written down once, with its reason, next to the flag that overrides it.
//
// A limit is named by declaring it as a package-level const whose doc comment
// carries a directive:
//
//	// maxArchiveEntries bounds how many members an archive may list before
//	// the reader stops, so a crafted index cannot exhaust memory.
//	//
//	//mutant:limit count
//	const maxArchiveEntries = 1 << 20
//
// A directive has no space after the slashes, so `go doc` hides it and the
// prose above it stays the documentation. `//mutant:format <reference>` marks a
// named constant that is a fact of a file format or protocol rather than a
// choice; it satisfies the naming rule and stays out of the reference.
//
// The scan is syntactic, over go/parser output, so it sees every build-tagged
// file on every host and needs no type information. The price is that the rules
// recognise limits by shape and by name, which is why each rule is narrow and
// why the guard's self-test pins what each one catches.
package limitscan

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Rule codes. The code is what a failure message and the policy document name;
// the description is what the code means.
const (
	RuleAllocation   = "L1"
	RuleIOCap        = "L2"
	RuleDuration     = "L3"
	RuleBound        = "L4"
	RuleLoop         = "L5"
	RuleFlagDefault  = "L6"
	RuleLimitField   = "L7"
	RuleLocalConst   = "L8"
	RuleLargeArg     = "L9"
	RuleUndocumented = "N1"
)

// RuleDescriptions explains each code in one line.
var RuleDescriptions = map[string]string{
	RuleAllocation:   "allocation size of 1024 or more written as a literal",
	RuleIOCap:        "input/output cap (Scanner.Buffer, LimitReader, CopyN, New*Size, MaxBytesReader) written as a literal",
	RuleDuration:     "duration written as a literal (n * time.Unit or time.Duration(n))",
	RuleBound:        "bound comparison against a literal (a depth, retry, budget ... or len/cap against 1024 or more)",
	RuleLoop:         "loop bound written as a literal (a retry loop, or 1000 or more iterations)",
	RuleFlagDefault:  "command-line flag default written as a literal",
	RuleLimitField:   "limit-named field or variable assigned a literal",
	RuleLocalConst:   "limit constant declared inside a function, where the reference cannot see it",
	RuleLargeArg:     "large literal passed as an argument (built with << or * to 1024 or more, or 65536 or more)",
	RuleUndocumented: "named limit constant without a //mutant:limit or //mutant:format directive",
}

// Units a //mutant:limit directive may name. A value counted in something
// other than bytes or nanoseconds says so -- an Argon2 cost in kibibytes, a
// timeout held as an integer of milliseconds -- so the reference can print it
// as the size or the duration it is.
var Units = map[string]bool{
	"bytes":        true,
	"bits":         true,
	"count":        true,
	"depth":        true,
	"duration":     true,
	"iterations":   true,
	"kibibytes":    true,
	"microseconds": true,
	"milliseconds": true,
	"percent":      true,
	"ratio":        true,
	"score":        true,
}

const (
	directivePrefix = "//mutant:"
	kindLimit       = "limit"
	kindFormat      = "format"

	// allocationFloor is the smallest literal make() size treated as a limit.
	// Smaller sizes in this tree are format facts: an 8-byte seed, a 4-byte
	// length prefix, a 16-byte GUID.
	allocationFloor = 1024

	// loopFloor is the smallest literal loop bound treated as a limit when the
	// loop variable does not itself say it counts retries.
	loopFloor = 1000

	// largeArgFloor is the smallest plain literal argument treated as a limit.
	// It sits above every format size this tree passes as a literal (a 4 KiB
	// page, a 64 KiB block) and below the caps it should catch (1_000_000 rows).
	largeArgFloor = 65536

	// maxShownExpression bounds how much of an expression a finding quotes, so
	// a failure message stays one line per finding.
	//
	//mutant:limit bytes
	maxShownExpression = 80
)

var (
	// strongBoundName is a name that means "a bound" whatever its magnitude.
	strongBoundName = regexp.MustCompile(`(?i)(depth|recursion|nest|retr(y|ies)|attempt|tries|budget|iteration|hops|redirect|worker|handler|backlog|pending|timeout|elapsed|deadline)`)

	// weakBoundName is a name that is a bound only when compared with a large
	// value; `size < 8` in a parser is a format check, `count > 1000000` is a cap.
	weakBoundName = regexp.MustCompile(`(?i)(count|total|entries|rows|records|items|results|hits|matches|lines|bytes|size|length|limit|max)`)

	// retryName is a loop variable that counts attempts.
	retryName = regexp.MustCompile(`(?i)^(attempt|attempts|retry|retries|try|tries|round|rounds)$`)

	// limitWords are the words that make a name a limit wherever they sit in
	// it: sqliteMaxRows, WalkMaxTime and maxServeHandlers all qualify.
	limitWords = map[string]bool{
		"max": true, "min": true, "maximum": true, "minimum": true,
		"limit": true, "limits": true, "budget": true, "cap": true, "capacity": true,
		"deadline": true, "threshold": true, "timeout": true, "ttl": true,
		"retries": true, "attempts": true, "interval": true, "backlog": true, "workers": true,
	}

	// leadingLimitWords qualify a name only as its first word: defaultPolymorphicLevel
	// is a default, but a word "default" inside a name usually is not.
	leadingLimitWords = map[string]bool{"default": true}

	// trailingLimitWords qualify a name only as its last word: DefaultSegmentSize
	// and classifiedWalkDepth are sizes and depths; sizeOfHeader is not.
	trailingLimitWords = map[string]bool{"size": true, "depth": true}

	timeUnits = map[string]time.Duration{
		"Nanosecond":  time.Nanosecond,
		"Microsecond": time.Microsecond,
		"Millisecond": time.Millisecond,
		"Second":      time.Second,
		"Minute":      time.Minute,
		"Hour":        time.Hour,
	}

	conversionTypes = map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"uintptr": true, "byte": true, "rune": true, "float32": true, "float64": true,
	}
)

// IsLimitName reports whether an identifier names a limit: it contains a limit
// word (max, timeout, budget ...), starts with "default", or ends in "size" or
// "depth". Words are split at underscores and at case changes, so
// maxHTTPBodyBytes is max, http, body, bytes.
func IsLimitName(name string) bool {
	words := camelWords(name)
	if len(words) == 0 {
		return false
	}
	if leadingLimitWords[words[0]] || trailingLimitWords[words[len(words)-1]] {
		return true
	}
	for _, w := range words {
		if limitWords[w] {
			return true
		}
	}
	return false
}

// camelWords splits an identifier into lower-cased words.
func camelWords(name string) []string {
	var words []string
	runes := []rune(name)
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(string(runes[start:end])))
		}
		start = end
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '_':
			flush(i)
			start = i + 1
		case i > start && isUpper(r) && !isUpper(runes[i-1]):
			flush(i) // fooBar
		case i > start && isUpper(r) && i+1 < len(runes) && isUpper(runes[i-1]) && isLower(runes[i+1]):
			flush(i) // HTTPBody
		case i > start && isDigit(r) != isDigit(runes[i-1]) && !isUpper(r):
			flush(i) // v3Size, size64
		}
	}
	flush(len(runes))
	return words
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// Finding is one unnamed or undocumented limit.
type Finding struct {
	File string // repository-relative, forward slashes
	Line int
	Func string // enclosing top-level function, "" at package level
	Rule string
	Text string // the expression as written
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d (%s): %s %s: %s", f.File, f.Line, f.where(), f.Rule, RuleDescriptions[f.Rule], f.Text)
}

// Key names a finding without its line: the rule, the function it is in and
// the expression as written. A budget lists findings by key, so an edit that
// moves a limit down the file leaves its entry standing, and naming one limit
// cannot make room for a new one beside it.
func (f Finding) Key() string {
	return f.Rule + " " + f.where() + ": " + f.Text
}

func (f Finding) where() string {
	if f.Func == "" {
		return "package level"
	}
	return f.Func
}

// Limit is a named limit constant, as the reference renders it.
type Limit struct {
	Package  string // directory relative to the repository root
	Name     string
	File     string
	BuildTag string // the //go:build constraint of its file, "" when none
	Expr     string // the initialiser as written
	Value    string // the folded value in readable form; the expression when it cannot be folded
	Unit     string
	Flag     string // the command-line flag that overrides it, "" when none
	Reason   string // the first paragraph of the doc comment
}

// Problem is a malformed directive. Problems are never budgeted: a directive
// that does not parse is a claim nobody can check.
type Problem struct {
	File string
	Line int
	What string
}

func (p Problem) String() string { return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.What) }

// Result is everything one scan found.
type Result struct {
	Findings []Finding
	Limits   []Limit
	Formats  int // named constants marked //mutant:format
	Problems []Problem
	Scanned  map[string]bool // repository-relative paths of the files read

	// Imports maps each package to the mutant packages its non-test files
	// import, and Mains holds the packages that are programs. Together they
	// say which packages a program is built from, which is how the reference
	// tells the limits of a run from those of the tools that build and test it.
	Imports map[string]map[string]bool
	Mains   map[string]bool
}

// skippedDirs are pruned from the walk. testdata holds fixtures, not program
// code; the extension and its node_modules vendor code that is not Mutant's;
// plans is the review's own working material, which .gitignore keeps out of
// the repository and which may hold whole scratch programs of its own.
var skippedDirs = map[string]bool{
	".git":                    true,
	".codegraph":              true,
	"plans":                   true,
	"node_modules":            true,
	"dist":                    true,
	"testdata":                true,
	"mutant-vscode-extension": true,
}

// Scan reads every non-test Go file under root and applies the rules.
func Scan(root string) (*Result, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	s := newScanner()
	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return s.add(filepath.ToSlash(rel), src)
	})
	if err != nil {
		return nil, err
	}
	return s.finish(), nil
}

// ScanSource applies the rules to one file's source. The guard's self-test uses
// it to pin what each rule catches without writing files.
func ScanSource(rel string, src []byte) (*Result, error) {
	s := newScanner()
	if err := s.add(rel, src); err != nil {
		return nil, err
	}
	return s.finish(), nil
}

type parsedFile struct {
	rel      string
	pkg      string // directory relative to the root
	file     *ast.File
	src      []byte
	buildTag string
	imports  map[string]string // local name -> repository directory, for mutant/... imports
}

type constDecl struct {
	file *parsedFile
	spec *ast.ValueSpec
	idx  int
	expr ast.Expr
	doc  *ast.CommentGroup // the spec's own doc, else the block's
	name string
	line int
}

type scanner struct {
	fset     *token.FileSet
	files    []*parsedFile
	consts   map[string]map[string]*constDecl // pkg -> name -> decl
	folded   map[string]constant.Value        // "pkg.name" -> value
	folding  map[string]bool
	result   *Result
	seenRoot map[token.Pos]bool
}

func newScanner() *scanner {
	return &scanner{
		fset:     token.NewFileSet(),
		consts:   map[string]map[string]*constDecl{},
		folded:   map[string]constant.Value{},
		folding:  map[string]bool{},
		result:   &Result{Scanned: map[string]bool{}, Imports: map[string]map[string]bool{}, Mains: map[string]bool{}},
		seenRoot: map[token.Pos]bool{},
	}
}

func (s *scanner) add(rel string, src []byte) error {
	file, err := parser.ParseFile(s.fset, rel, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("parse %s: %w", rel, err)
	}
	if isGenerated(file) || buildTag(file) == "ignore" {
		return nil
	}
	s.result.Scanned[rel] = true
	pkg := filepath.ToSlash(filepath.Dir(rel))
	pf := &parsedFile{rel: rel, pkg: pkg, file: file, src: src, buildTag: buildTag(file), imports: map[string]string{}}
	if file.Name.Name == "main" {
		s.result.Mains[pkg] = true
	}
	if s.result.Imports[pkg] == nil {
		s.result.Imports[pkg] = map[string]bool{}
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !strings.HasPrefix(path, "mutant/") {
			continue
		}
		dir := strings.TrimPrefix(path, "mutant/")
		s.result.Imports[pkg][dir] = true
		local := dir[strings.LastIndex(dir, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		pf.imports[local] = dir
	}
	s.files = append(s.files, pf)

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			doc := vs.Doc
			if doc == nil {
				doc = gen.Doc
			}
			for i, name := range vs.Names {
				if name.Name == "_" || i >= len(vs.Values) {
					continue
				}
				if s.consts[pkg] == nil {
					s.consts[pkg] = map[string]*constDecl{}
				}
				s.consts[pkg][name.Name] = &constDecl{
					file: pf, spec: vs, idx: i, expr: vs.Values[i], doc: doc,
					name: name.Name, line: s.fset.Position(name.Pos()).Line,
				}
			}
		}
	}
	return nil
}

func (s *scanner) finish() *Result {
	for _, pf := range s.files {
		s.checkFile(pf)
	}
	s.collectNamed()
	r := s.result
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].File != r.Findings[j].File {
			return r.Findings[i].File < r.Findings[j].File
		}
		return r.Findings[i].Line < r.Findings[j].Line
	})
	sort.Slice(r.Limits, func(i, j int) bool {
		if r.Limits[i].Package != r.Limits[j].Package {
			return r.Limits[i].Package < r.Limits[j].Package
		}
		return r.Limits[i].Name < r.Limits[j].Name
	})
	sort.Slice(r.Problems, func(i, j int) bool {
		if r.Problems[i].File != r.Problems[j].File {
			return r.Problems[i].File < r.Problems[j].File
		}
		return r.Problems[i].Line < r.Problems[j].Line
	})
	return r
}

// checkFile applies rules L1-L8 to everything outside package-level constant
// declarations, and rejects directives placed anywhere but on a constant.
func (s *scanner) checkFile(pf *parsedFile) {
	for _, decl := range pf.file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			switch d.Tok {
			case token.CONST:
				continue // naming a value is the point; rule N1 reads these
			case token.VAR:
				s.rejectDirectives(pf, d.Doc, "a var declaration")
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					s.rejectDirectives(pf, vs.Doc, "a var declaration")
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							s.checkNamedValue(pf, "", name.Name, vs.Values[i])
							s.walk(pf, "", vs.Values[i])
						}
					}
				}
			case token.TYPE:
				s.rejectDirectives(pf, d.Doc, "a type declaration")
			}
		case *ast.FuncDecl:
			s.rejectDirectives(pf, d.Doc, "a function")
			if d.Body != nil {
				s.walk(pf, d.Name.Name, d.Body)
			}
		}
	}
}

func (s *scanner) rejectDirectives(pf *parsedFile, doc *ast.CommentGroup, where string) {
	if doc == nil {
		return
	}
	for _, c := range doc.List {
		if strings.HasPrefix(c.Text, directivePrefix) {
			s.problem(pf, c.Pos(), fmt.Sprintf("%s directive on %s; directives belong on package-level constants", strings.Fields(c.Text)[0], where))
		}
	}
}

func (s *scanner) problem(pf *parsedFile, pos token.Pos, what string) {
	s.result.Problems = append(s.result.Problems, Problem{File: pf.rel, Line: s.fset.Position(pos).Line, What: what})
}

func (s *scanner) report(pf *parsedFile, fn, rule string, root ast.Expr) {
	if s.seenRoot[root.Pos()] {
		return
	}
	s.seenRoot[root.Pos()] = true
	s.result.Findings = append(s.result.Findings, Finding{
		File: pf.rel,
		Line: s.fset.Position(root.Pos()).Line,
		Func: fn,
		Rule: rule,
		Text: s.text(pf, root),
	})
}

func (s *scanner) text(pf *parsedFile, n ast.Node) string {
	start := s.fset.Position(n.Pos()).Offset
	end := s.fset.Position(n.End()).Offset
	if start < 0 || end > len(pf.src) || start >= end {
		return ""
	}
	t := strings.Join(strings.Fields(string(pf.src[start:end])), " ")
	if len(t) > maxShownExpression {
		t = t[:maxShownExpression] + "..."
	}
	return t
}

// walk applies the context rules to every node under n.
func (s *scanner) walk(pf *parsedFile, fn string, n ast.Node) {
	ast.Inspect(n, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.DeclStmt:
			gen, ok := x.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			switch gen.Tok {
			case token.CONST:
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i < len(vs.Values) && IsLimitName(name.Name) {
							if ce := s.constExpr(vs.Values[i]); ce.ok && ce.hasLit {
								s.report(pf, fn, RuleLocalConst, vs.Values[i])
							}
						}
					}
				}
				return false
			case token.VAR:
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							s.checkNamedValue(pf, fn, name.Name, vs.Values[i])
						}
					}
				}
			}
		case *ast.CallExpr:
			s.checkCall(pf, fn, x)
		case *ast.BinaryExpr:
			s.checkBinary(pf, fn, x)
		case *ast.ForStmt:
			s.checkFor(pf, fn, x)
		case *ast.RangeStmt:
			s.checkRange(pf, fn, x)
		case *ast.KeyValueExpr:
			if key, ok := x.Key.(*ast.Ident); ok {
				s.checkNamedValue(pf, fn, key.Name, x.Value)
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					if name := lastName(lhs); name != "" {
						s.checkNamedValue(pf, fn, name, x.Rhs[i])
					}
				}
			}
		}
		return true
	})
}

// checkNamedValue is rule L7: a limit-named field, variable or assignment
// target given a literal. Hex values are left alone: a `Size: 0x40` in a
// format table is a layout fact.
func (s *scanner) checkNamedValue(pf *parsedFile, fn, name string, value ast.Expr) {
	if !IsLimitName(name) {
		return
	}
	ce := s.constExpr(value)
	if !ce.ok || !ce.hasLit || !ce.decimal {
		return
	}
	if ce.unit {
		s.report(pf, fn, RuleDuration, value)
		return
	}
	if !isTrivial(ce.value) {
		s.report(pf, fn, RuleLimitField, value)
	}
}

func (s *scanner) checkCall(pf *parsedFile, fn string, call *ast.CallExpr) {
	// Deferred so the specific rules below claim an argument first; a finding
	// is reported once, under the first rule that sees it.
	if !isIdent(call.Fun, "make") {
		defer s.checkLargeArgs(pf, fn, call)
	}
	arg := func(i int) ast.Expr {
		if i < len(call.Args) {
			return call.Args[i]
		}
		return nil
	}
	switch f := call.Fun.(type) {
	case *ast.Ident:
		if f.Name == "make" {
			for i := 1; i < len(call.Args); i++ {
				ce := s.constExpr(call.Args[i])
				if ce.ok && ce.hasLit && atLeast(ce.value, allocationFloor) {
					s.report(pf, fn, RuleAllocation, call.Args[i])
				}
			}
		}
	case *ast.SelectorExpr:
		name := f.Sel.Name
		var capArg ast.Expr
		switch {
		case name == "Buffer" && len(call.Args) == 2:
			capArg = arg(1)
		case name == "LimitReader" && len(call.Args) == 2:
			capArg = arg(1)
		case name == "CopyN" && len(call.Args) == 3:
			capArg = arg(2)
		case (name == "NewReaderSize" || name == "NewWriterSize") && len(call.Args) == 2:
			capArg = arg(1)
		case name == "MaxBytesReader" && len(call.Args) == 3:
			capArg = arg(2)
		case isIdent(f.X, "time") && name == "Duration" && len(call.Args) == 1:
			if ce := s.constExpr(call.Args[0]); ce.ok && ce.hasLit && !isTrivial(ce.value) {
				s.report(pf, fn, RuleDuration, call)
			}
			return
		}
		if capArg != nil {
			if ce := s.constExpr(capArg); ce.ok && ce.hasLit && !isTrivial(ce.value) {
				s.report(pf, fn, RuleIOCap, capArg)
			}
			return
		}
		s.checkFlagDefault(pf, fn, call, name)
	}
}

// checkLargeArgs is rule L9: a size handed to a function as a literal. Built
// arithmetic (1<<20, 64*1024) is a size somebody computed; a plain literal of
// 65536 or more is too large to be a field width or a format constant.
func (s *scanner) checkLargeArgs(pf *parsedFile, fn string, call *ast.CallExpr) {
	for _, a := range call.Args {
		ce := s.constExpr(a)
		if !ce.ok || !ce.hasLit || ce.unit {
			continue
		}
		_, built := a.(*ast.BinaryExpr)
		if (built && atLeast(ce.value, allocationFloor)) || atLeast(ce.value, largeArgFloor) {
			s.report(pf, fn, RuleLargeArg, a)
		}
	}
}

// checkFlagDefault is rule L6. A flag definition is recognised by its shape --
// a string name, a default, a string usage -- rather than by its receiver, so a
// *flag.FlagSet under any variable name is covered.
func (s *scanner) checkFlagDefault(pf *parsedFile, fn string, call *ast.CallExpr, name string) {
	numeric := map[string]bool{"Int": true, "Int64": true, "Uint": true, "Uint64": true, "Float64": true, "Duration": true}
	var def ast.Expr
	switch {
	case numeric[name] && len(call.Args) == 3 && isStringLit(call.Args[0]) && isStringLit(call.Args[2]):
		def = call.Args[1]
	case strings.HasSuffix(name, "Var") && numeric[strings.TrimSuffix(name, "Var")] &&
		len(call.Args) == 4 && isStringLit(call.Args[1]) && isStringLit(call.Args[3]):
		def = call.Args[2]
	default:
		return
	}
	if ce := s.constExpr(def); ce.ok && ce.hasLit && !isTrivial(ce.value) {
		s.report(pf, fn, RuleFlagDefault, def)
	}
}

func (s *scanner) checkBinary(pf *parsedFile, fn string, b *ast.BinaryExpr) {
	// A duration built from a literal: 30 * time.Second, or any constant
	// arithmetic that contains a time unit.
	if b.Op == token.MUL {
		if ce := s.constExpr(b); ce.ok && ce.hasLit && ce.unit {
			s.report(pf, fn, RuleDuration, b)
			return
		}
	}
	switch b.Op {
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
	default:
		return
	}
	for _, pair := range [][2]ast.Expr{{b.X, b.Y}, {b.Y, b.X}} {
		lit, other := pair[0], pair[1]
		ce := s.constExpr(lit)
		if !ce.ok || !ce.hasLit || ce.unit || !ce.decimal || isTrivial(ce.value) {
			continue
		}
		if call, ok := other.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
				if atLeast(ce.value, allocationFloor) {
					s.report(pf, fn, RuleBound, lit)
				}
				return
			}
		}
		name := lastName(other)
		switch {
		case name == "":
		case strongBoundName.MatchString(name):
			s.report(pf, fn, RuleBound, lit)
		case weakBoundName.MatchString(name) && atLeast(ce.value, allocationFloor):
			s.report(pf, fn, RuleBound, lit)
		}
		return
	}
}

func (s *scanner) checkFor(pf *parsedFile, fn string, f *ast.ForStmt) {
	cond, ok := f.Cond.(*ast.BinaryExpr)
	if !ok || (cond.Op != token.LSS && cond.Op != token.LEQ) {
		return
	}
	ce := s.constExpr(cond.Y)
	if !ce.ok || !ce.hasLit || !ce.decimal || ce.unit || isTrivial(ce.value) {
		return
	}
	if atLeast(ce.value, loopFloor) || retryName.MatchString(lastName(cond.X)) {
		s.report(pf, fn, RuleLoop, cond.Y)
	}
}

func (s *scanner) checkRange(pf *parsedFile, fn string, r *ast.RangeStmt) {
	ce := s.constExpr(r.X)
	if !ce.ok || !ce.hasLit || !ce.decimal || ce.unit || isTrivial(ce.value) {
		return
	}
	key := ""
	if id, ok := r.Key.(*ast.Ident); ok {
		key = id.Name
	}
	if atLeast(ce.value, loopFloor) || retryName.MatchString(key) {
		s.report(pf, fn, RuleLoop, r.X)
	}
}

// collectNamed applies rule N1 and gathers the reference entries, reading each
// package-level constant's directive.
func (s *scanner) collectNamed() {
	for _, byName := range s.consts {
		for _, cd := range byName {
			dir, problems := parseDirective(cd.doc)
			for _, p := range problems {
				s.problem(cd.file, cd.spec.Pos(), p)
			}
			value, folded := s.fold(cd.file.pkg, cd.name)
			numeric := folded && (value.Kind() == constant.Int || value.Kind() == constant.Float)
			if !folded {
				numeric = s.constExpr(cd.expr).hasLit
			}
			switch dir.kind {
			case kindFormat:
				s.result.Formats++
			case kindLimit:
				s.result.Limits = append(s.result.Limits, Limit{
					Package:  cd.file.pkg,
					Name:     cd.name,
					File:     cd.file.rel,
					BuildTag: cd.file.buildTag,
					Expr:     s.text(cd.file, cd.expr),
					Value:    s.render(cd, value, folded, dir.unit),
					Unit:     dir.unit,
					Flag:     dir.flag,
					Reason:   dir.reason,
				})
			default:
				if numeric && IsLimitName(cd.name) {
					s.result.Findings = append(s.result.Findings, Finding{
						File: cd.file.rel,
						Line: cd.line,
						Rule: RuleUndocumented,
						Text: cd.name + " = " + s.text(cd.file, cd.expr),
					})
				}
			}
		}
	}
}

type directive struct {
	kind   string
	unit   string
	flag   string
	format string
	reason string
}

// parseDirective reads the //mutant: line of a doc comment and the prose around
// it. The prose is required: a limit whose reason is not written down is the
// hidden default the reference exists to remove.
func parseDirective(doc *ast.CommentGroup) (directive, []string) {
	var d directive
	var problems []string
	if doc == nil {
		return d, nil
	}
	var prose []string
	for _, c := range doc.List {
		text := c.Text
		if !strings.HasPrefix(text, directivePrefix) {
			prose = append(prose, commentText(text))
			continue
		}
		if d.kind != "" {
			problems = append(problems, "more than one //mutant: directive")
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(text, directivePrefix))
		if len(fields) == 0 {
			problems = append(problems, "empty //mutant: directive")
			continue
		}
		switch fields[0] {
		case kindLimit:
			d.kind = kindLimit
			if len(fields) < 2 || !Units[fields[1]] {
				problems = append(problems, fmt.Sprintf("//mutant:limit needs a unit, one of %s", strings.Join(sortedUnits(), ", ")))
				break
			}
			d.unit = fields[1]
			for _, extra := range fields[2:] {
				if flag, ok := strings.CutPrefix(extra, "flag="); ok && strings.HasPrefix(flag, "--") && len(flag) > 2 {
					d.flag = flag
					continue
				}
				problems = append(problems, fmt.Sprintf("//mutant:limit: %q is not flag=--name", extra))
			}
		case kindFormat:
			d.kind = kindFormat
			d.format = strings.Join(fields[1:], " ")
			if d.format == "" {
				problems = append(problems, "//mutant:format needs the specification it follows, e.g. //mutant:format MS-SHLLINK 2.1")
			}
		default:
			problems = append(problems, fmt.Sprintf("unknown directive //mutant:%s (known: limit, format)", fields[0]))
		}
	}
	d.reason = firstParagraph(prose)
	if d.kind == kindLimit && d.reason == "" {
		problems = append(problems, "//mutant:limit without a written reason; say in the doc comment why the value is what it is")
	}
	return d, problems
}

func commentText(c string) string {
	switch {
	case strings.HasPrefix(c, "//"):
		return strings.TrimPrefix(strings.TrimPrefix(c, "//"), " ")
	case strings.HasPrefix(c, "/*"):
		return strings.TrimSuffix(strings.TrimPrefix(c, "/*"), "*/")
	}
	return c
}

func firstParagraph(lines []string) string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, " ")
}

func sortedUnits() []string {
	units := make([]string, 0, len(Units))
	for u := range Units {
		units = append(units, u)
	}
	sort.Strings(units)
	return units
}

// constExpression describes an expression built only from literals, constant
// arithmetic, numeric conversions and time units.
type constExpression struct {
	ok      bool
	hasLit  bool // contains at least one numeric literal
	unit    bool // contains a time unit
	decimal bool // every literal in it is written in decimal
	value   constant.Value
}

func (s *scanner) constExpr(e ast.Expr) constExpression {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT && x.Kind != token.FLOAT {
			return constExpression{}
		}
		v := constant.MakeFromLiteral(x.Value, x.Kind, 0)
		return constExpression{ok: true, hasLit: true, decimal: isDecimal(x.Value), value: v}
	case *ast.ParenExpr:
		return s.constExpr(x.X)
	case *ast.UnaryExpr:
		inner := s.constExpr(x.X)
		if !inner.ok {
			return inner
		}
		switch x.Op {
		case token.SUB, token.ADD, token.XOR:
			inner.value = safeUnary(x.Op, inner.value)
			return inner
		}
		return constExpression{}
	case *ast.BinaryExpr:
		l, r := s.constExpr(x.X), s.constExpr(x.Y)
		if !l.ok || !r.ok {
			return constExpression{}
		}
		out := constExpression{
			ok:      true,
			hasLit:  l.hasLit || r.hasLit,
			unit:    l.unit || r.unit,
			decimal: (l.decimal || !l.hasLit) && (r.decimal || !r.hasLit),
			value:   safeBinary(x.Op, l.value, r.value),
		}
		return out
	case *ast.SelectorExpr:
		if isIdent(x.X, "time") {
			if d, ok := timeUnits[x.Sel.Name]; ok {
				return constExpression{ok: true, unit: true, decimal: true, value: constant.MakeInt64(int64(d))}
			}
		}
	case *ast.CallExpr:
		if len(x.Args) != 1 {
			return constExpression{}
		}
		switch f := x.Fun.(type) {
		case *ast.Ident:
			if conversionTypes[f.Name] {
				return s.constExpr(x.Args[0])
			}
		case *ast.SelectorExpr:
			if isIdent(f.X, "time") && f.Sel.Name == "Duration" {
				return s.constExpr(x.Args[0])
			}
		}
	}
	return constExpression{}
}

// fold evaluates a package-level constant, following references to other
// constants in its own package and in other mutant packages.
func (s *scanner) fold(pkg, name string) (constant.Value, bool) {
	key := pkg + "." + name
	if v, ok := s.folded[key]; ok {
		return v, v != nil
	}
	if s.folding[key] {
		return nil, false
	}
	cd := s.consts[pkg][name]
	if cd == nil {
		return nil, false
	}
	s.folding[key] = true
	v := s.foldExpr(cd.file, cd.expr)
	delete(s.folding, key)
	s.folded[key] = v
	return v, v != nil
}

func (s *scanner) foldExpr(pf *parsedFile, e ast.Expr) constant.Value {
	switch x := e.(type) {
	case *ast.BasicLit:
		v := constant.MakeFromLiteral(x.Value, x.Kind, 0)
		if v.Kind() == constant.Unknown {
			return nil
		}
		return v
	case *ast.ParenExpr:
		return s.foldExpr(pf, x.X)
	case *ast.Ident:
		if v, ok := s.fold(pf.pkg, x.Name); ok {
			return v
		}
		return nil
	case *ast.UnaryExpr:
		if v := s.foldExpr(pf, x.X); v != nil {
			return safeUnary(x.Op, v)
		}
	case *ast.BinaryExpr:
		l, r := s.foldExpr(pf, x.X), s.foldExpr(pf, x.Y)
		if l == nil || r == nil {
			return nil
		}
		v := safeBinary(x.Op, l, r)
		if v.Kind() == constant.Unknown {
			return nil
		}
		return v
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if id.Name == "time" {
				if d, ok := timeUnits[x.Sel.Name]; ok {
					return constant.MakeInt64(int64(d))
				}
				return nil
			}
			if dir, ok := pf.imports[id.Name]; ok {
				if v, ok := s.fold(dir, x.Sel.Name); ok {
					return v
				}
			}
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			switch f := x.Fun.(type) {
			case *ast.Ident:
				if conversionTypes[f.Name] {
					return s.foldExpr(pf, x.Args[0])
				}
			case *ast.SelectorExpr:
				if isIdent(f.X, "time") && f.Sel.Name == "Duration" {
					return s.foldExpr(pf, x.Args[0])
				}
			}
		}
	}
	return nil
}

// render writes a folded value the way a reader thinks of it: 1 GiB rather than
// 1073741824, 30s rather than 30000000000.
func (s *scanner) render(cd *constDecl, v constant.Value, folded bool, unit string) string {
	if !folded {
		return s.text(cd.file, cd.expr)
	}
	isDuration := unit == "duration" || isDurationType(cd.spec.Type) || s.constExpr(cd.expr).unit
	if v.Kind() == constant.Int {
		n, exact := constant.Int64Val(v)
		if exact {
			switch {
			case unit == "milliseconds":
				return (time.Duration(n) * time.Millisecond).String()
			case unit == "microseconds":
				return (time.Duration(n) * time.Microsecond).String()
			case unit == "kibibytes":
				return humanBytes(n << 10)
			case isDuration:
				return time.Duration(n).String()
			case unit == "bytes":
				return humanBytes(n)
			}
			return groupDigits(n)
		}
	}
	return v.ExactString()
}

func humanBytes(n int64) string {
	units := []struct {
		size int64
		name string
	}{{1 << 40, "TiB"}, {1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}}
	for _, u := range units {
		if n >= u.size && n%u.size == 0 {
			return fmt.Sprintf("%d %s", n/u.size, u.name)
		}
	}
	return groupDigits(n) + " bytes"
}

func groupDigits(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	digits := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i, d := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(d)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func isDurationType(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, "time") && sel.Sel.Name == "Duration"
}

func safeUnary(op token.Token, v constant.Value) (out constant.Value) {
	defer func() {
		if recover() != nil {
			out = constant.MakeUnknown()
		}
	}()
	return constant.UnaryOp(op, v, 0)
}

func safeBinary(op token.Token, l, r constant.Value) (out constant.Value) {
	defer func() {
		if recover() != nil {
			out = constant.MakeUnknown()
		}
	}()
	switch op {
	case token.SHL, token.SHR:
		shift, ok := constant.Uint64Val(constant.ToInt(r))
		if !ok {
			return constant.MakeUnknown()
		}
		return constant.Shift(l, op, uint(shift))
	case token.QUO:
		if l.Kind() == constant.Int && r.Kind() == constant.Int {
			return constant.BinaryOp(l, token.QUO_ASSIGN, r)
		}
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
		return constant.MakeUnknown()
	}
	return constant.BinaryOp(l, op, r)
}

// isTrivial reports the values that are never a limit: -1, 0, 1 and 2.
func isTrivial(v constant.Value) bool {
	if v == nil || v.Kind() == constant.Unknown {
		return true
	}
	for _, t := range []int64{-1, 0, 1, 2} {
		if constant.Compare(v, token.EQL, constant.MakeInt64(t)) {
			return true
		}
	}
	return false
}

func atLeast(v constant.Value, floor int64) bool {
	if v == nil || v.Kind() == constant.Unknown {
		return false
	}
	return constant.Compare(v, token.GEQ, constant.MakeInt64(floor))
}

// isDecimal reports a literal written in base ten. Hex, octal and binary
// literals in a comparison are how this tree spells format checks
// (len(data) < 0x40), and are left alone.
func isDecimal(lit string) bool {
	l := strings.ToLower(lit)
	if strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0o") || strings.HasPrefix(l, "0b") {
		return false
	}
	return !(len(l) > 1 && l[0] == '0' && l[1] >= '0' && l[1] <= '9')
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isStringLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// lastName is the final identifier of a name or selector: maxDepth, s.maxDepth
// and cfg.limits.maxDepth all give maxDepth.
func lastName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return lastName(x.X)
	case *ast.ParenExpr:
		return lastName(x.X)
	}
	return ""
}

func isGenerated(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "// Code generated ") && strings.HasSuffix(c.Text, " DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}

func buildTag(f *ast.File) string {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if tag, ok := strings.CutPrefix(c.Text, "//go:build "); ok {
				return strings.TrimSpace(tag)
			}
		}
	}
	return ""
}
