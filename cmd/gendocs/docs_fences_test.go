package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"mutant/ast"
	"mutant/compiler"
	"mutant/evaluator"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// repoRoot is the repository, relative to this package.
const repoRoot = "../.."

// fragmentMarker, on the line before a fence, says the fence is deliberately
// not a whole program: an excerpt, a wrong example, or output. Everything else
// fenced as `mutant` is a program a reader will paste, and has to compile.
const fragmentMarker = "<!-- mutant:fragment -->"

// docsSkippedDirs are not documentation a reader of this repository reads.
var docsSkippedDirs = map[string]bool{
	".git": true, ".codegraph": true, "node_modules": true, "dist": true, "plans": true,
	"example_output": true,
}

type fence struct {
	file     string // repository-relative
	line     int    // line of the opening ```
	lang     string
	body     string
	fragment bool
}

var fenceOpen = regexp.MustCompile("^(\\s*)```+\\s*([A-Za-z0-9_+-]*)\\s*$")

// markdownFiles lists every Markdown file a reader of the repository sees.
func markdownFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if docsSkippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking documentation: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("found no Markdown under %s", repoRoot)
	}
	return files
}

// fences returns every fenced block in a Markdown file.
func fences(t *testing.T, rel string) []fence {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var out []fence
	for i := 0; i < len(lines); i++ {
		m := fenceOpen.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent := m[1]
		f := fence{file: rel, line: i + 1, lang: strings.ToLower(m[2])}
		for j := i - 1; j >= 0; j-- {
			prev := strings.TrimSpace(lines[j])
			if prev == "" {
				continue
			}
			f.fragment = prev == fragmentMarker
			break
		}
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == strings.Repeat("`", 3) || strings.HasPrefix(strings.TrimSpace(lines[j]), "```") && strings.TrimSpace(strings.Trim(strings.TrimSpace(lines[j]), "`")) == "" {
				break
			}
			body = append(body, strings.TrimPrefix(lines[j], indent))
		}
		f.body = strings.Join(body, "\n")
		out = append(out, f)
		i = j
	}
	return out
}

var (
	undefinedVariable = regexp.MustCompile(`undefined variable: ([A-Za-z_][A-Za-z0-9_]*)`)
	undefinedType     = regexp.MustCompile(`undefined struct type: `)
	builtinShapedName = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)
)

// maxFenceStubs bounds how many free names one excerpt may lean on before the
// test stops declaring them and reports the fence.
const maxFenceStubs = 64

// compileExcerpt compiles a fence that may be an excerpt. A documentation fence
// often uses a variable a previous fence defined -- `disk`, `path`, `rows` --
// and that is not a defect, so each undefined variable is declared as a stub and
// the fence compiled again. What remains is a real error: a syntax the parser
// no longer accepts, a construct the compiler refuses, or a call to a
// builtin-shaped name (snake_case with an underscore) that is neither a builtin
// nor defined in the fence, which is how a renamed or misspelt builtin shows.
func compileExcerpt(src string) error {
	var stubs []string
	for len(stubs) <= maxFenceStubs {
		var prelude strings.Builder
		for _, name := range stubs {
			fmt.Fprintf(&prelude, "let %s = 0;\n", name)
		}
		err := compileFence(prelude.String() + src)
		if err == nil {
			break
		}
		if undefinedType.MatchString(err.Error()) {
			return nil // a struct declared in another fence; nothing to stub it with
		}
		m := undefinedVariable.FindStringSubmatch(err.Error())
		if m == nil {
			return err
		}
		stubs = append(stubs, m[1])
	}
	if len(stubs) > maxFenceStubs {
		return fmt.Errorf("leans on more than %d names defined elsewhere", maxFenceStubs)
	}
	for _, name := range stubs {
		if builtinShapedName.MatchString(name) && strings.Contains(src, name+"(") {
			return fmt.Errorf("calls `%s(`, which is not a builtin and is not defined in the fence", name)
		}
	}
	return nil
}

// compileFence runs a fence through the production front end: parse, expand
// macros, compile. It does not run the program.
func compileFence(src string) error {
	p := parser.New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		return fmt.Errorf("parse: %s", strings.Join(errs, "; "))
	}
	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	expanded, err := evaluator.ExpandMacros(program, macroEnv)
	if err != nil {
		return fmt.Errorf("macro expansion: %v", err)
	}
	prog, ok := expanded.(*ast.Program)
	if !ok {
		return fmt.Errorf("macro expansion did not yield a program")
	}
	if err := compiler.New().Compile(prog); err != nil {
		return fmt.Errorf("compile: %v", err)
	}
	return nil
}

// TestDocumentedProgramsCompile is D1: a `mutant` fence is code a reader will
// paste, so it has to lex, parse and compile, allowing for names an earlier
// fence defined (see compileExcerpt). A fence that is deliberately not code --
// schematic grammar, a wrong example -- says so with <!-- mutant:fragment -->
// on the line before it.
func TestDocumentedProgramsCompile(t *testing.T) {
	total, fragments := 0, 0
	for _, file := range markdownFiles(t) {
		for _, f := range fences(t, file) {
			if f.lang != "mutant" {
				continue
			}
			total++
			if f.fragment {
				fragments++
				continue
			}
			if err := compileExcerpt(f.body); err != nil {
				t.Errorf("%s:%d: this `mutant` fence does not compile: %v\n"+
					"Fix it, or mark a deliberate excerpt with %s on the line before the fence.",
					f.file, f.line, firstLine(err.Error()), fragmentMarker)
			}
		}
	}
	if total == 0 {
		t.Fatal("found no `mutant` fences; the fence scanner is broken")
	}
	t.Logf("%d mutant fences, %d marked as fragments", total, fragments)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
