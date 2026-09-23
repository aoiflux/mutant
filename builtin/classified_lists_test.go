package builtin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The editor warns about classified plaintext by reading ClassifiedSinks and
// ClassifiedSources, and the run time refuses it by what the code does. These
// two tests read the code and hold the lists to it: a sink added without the
// list, or a list entry whose builtin stopped refusing, fails here rather than
// leaving the editor saying something the run time no longer does.

// builtinSources parses every non-test Go file of this package.
func builtinSources(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files = append(files, file)
	}
	return files
}

// builtinNameConstants maps each BuiltinName constant to the name it spells.
func builtinNameConstants(files []*ast.File) map[string]string {
	values := make(map[string]string)
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if i >= len(value.Values) || !strings.HasPrefix(ident.Name, "BuiltinName") {
						continue
					}
					if lit, ok := value.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if text, err := strconv.Unquote(lit.Value); err == nil {
							values[ident.Name] = text
						}
					}
				}
			}
		}
	}
	return values
}

func sortedSet(names []string) []string {
	out := slices.Clone(names)
	slices.Sort(out)
	return slices.Compact(out)
}

func TestClassifiedSinksAreTheBuiltinsThatRefuse(t *testing.T) {
	files := builtinSources(t)
	constants := builtinNameConstants(files)

	var refusing []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok || callee.Name != "refuseClassified" || len(call.Args) == 0 {
				return true
			}
			op, ok := call.Args[0].(*ast.Ident)
			if !ok {
				t.Errorf("refuseClassified called with a name that is not a BuiltinName constant: %T", call.Args[0])
				return true
			}
			name, known := constants[op.Name]
			if !known {
				t.Errorf("refuseClassified called with %s, which is not a BuiltinName constant", op.Name)
				return true
			}
			// The refusal numbers the argument it found, and so does the
			// editor. They agree only while the builtin hands over its whole
			// argument list, in order.
			rest, isIdent := call.Args[len(call.Args)-1].(*ast.Ident)
			if len(call.Args) != 2 || !call.Ellipsis.IsValid() || !isIdent || rest.Name != "args" {
				t.Errorf("%s calls refuseClassified without `args...`, so its \"argument N\" is not the Nth argument the script wrote", name)
			}
			refusing = append(refusing, name)
			return true
		})
	}

	if got, want := sortedSet(refusing), sortedSet(ClassifiedSinks()); !slices.Equal(got, want) {
		t.Errorf("the builtins that refuse classified plaintext are\n  %v\nbut ClassifiedSinks lists\n  %v", got, want)
	}
}

func TestClassifiedSourcesAreTheBuiltinsThatMark(t *testing.T) {
	files := builtinSources(t)

	// Every function that builds a marked buffer calls recordClassification.
	var marking []string
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "recordClassification" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callee, ok := call.Fun.(*ast.Ident); ok && callee.Name == "recordClassification" {
					marking = append(marking, fn.Name.Name)
				}
				return true
			})
		}
	}

	var listed []string
	for _, name := range ClassifiedSources() {
		var fn BuiltinFunction
		for _, def := range Builtins {
			if def.Name == name {
				fn = def.Builtin.Fn
			}
		}
		if fn == nil {
			t.Fatalf("ClassifiedSources lists %s, which is not registered", name)
		}
		full := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		listed = append(listed, full[strings.LastIndex(full, ".")+1:])
	}

	if got, want := sortedSet(marking), sortedSet(listed); !slices.Equal(got, want) {
		t.Errorf("the functions that mark plaintext are\n  %v\nbut ClassifiedSources names\n  %v", got, want)
	}
}
