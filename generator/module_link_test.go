package generator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/errrs"
	"mutant/module"
)

// writeProgram lays out a multi-file program in a fresh temporary directory
// and returns the directory. Keys are slash-separated relative paths.
func writeProgram(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

const modulePassword = "correct horse battery"

// TestCompileLinksAnImportedModule is the end-to-end check that the whole
// pipeline holds together: resolve, link, expand macros in link order, and
// drive every module through one compiler.
func TestCompileLinksAnImportedModule(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"main.mut":     "import \"lib/util.mut\";\nlet answer = util.double(21);\n",
		"lib/util.mut": "let double = fn(n) {\n\treturn n * 2;\n};\n",
	})

	artifact, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err != nil {
		t.Fatalf("compile: %v (%v)", err, details)
	}
	if len(artifact) == 0 {
		t.Fatal("compile produced no artifact")
	}
}

// TestCompileResolvesThroughModulePath pins that the flag's directories are
// searched, and searched only after the importing file's own.
func TestCompileResolvesThroughModulePath(t *testing.T) {
	lib := writeProgram(t, map[string]string{
		"util.mut": "let double = fn(n) {\n\treturn n * 2;\n};\n",
	})
	root := writeProgram(t, map[string]string{
		"main.mut": "import \"util.mut\";\nlet answer = util.double(21);\n",
	})
	entry := filepath.Join(root, "main.mut")

	if _, err, _, _ := compile(entry, nil, false, modulePassword, 0, 7, testSigningKey(t)); err == nil {
		t.Fatal("expected the import to fail without a --module-path")
	}

	if _, err, _, _ := compile(entry, []string{lib}, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("compile with --module-path: %v", err)
	}
}

// TestCompileReportsAnImportedModulesParseErrorAsAParseError keeps the CLI's
// output shape right: a module that will not parse must print as parser errors,
// one per line, whether it was the entry or something the entry imported.
func TestCompileReportsAnImportedModulesParseErrorAsAParseError(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"main.mut":   "import \"broken.mut\";\n",
		"broken.mut": "let = ;\n",
	})

	_, err, errType, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err == nil {
		t.Fatal("expected a failure")
	}
	if errType != errrs.PARSER_ERROR {
		t.Fatalf("error type = %q, want %q", errType, errrs.PARSER_ERROR)
	}
	if len(details) == 0 {
		t.Fatal("a parse failure must carry the individual parser messages")
	}

	var parseErr *module.ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected a *module.ParseError, got %T", err)
	}
	if filepath.Base(parseErr.Path) != "broken.mut" {
		t.Fatalf("blamed %s, want broken.mut", parseErr.Path)
	}
}

// TestCompileReportsACycleAsAnOrdinaryError: nothing was compiled, so it is not
// a compiler error, and the message is the chain itself.
func TestCompileReportsACycleAsAnOrdinaryError(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"main.mut": "import \"a.mut\";\n",
		"a.mut":    "import \"b.mut\";\n",
		"b.mut":    "import \"a.mut\";\n",
	})

	_, err, errType, _ := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err == nil {
		t.Fatal("expected a cycle failure")
	}
	if errType != errrs.ERROR {
		t.Fatalf("error type = %q, want %q", errType, errrs.ERROR)
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Fatalf("message does not name the problem: %s", err)
	}
	if strings.Count(err.Error(), "->") != 3 {
		t.Fatalf("message is not the chain that closed the cycle: %s", err)
	}
}

// TestCompileSharesMacrosInLinkOrder: a macro an imported module defines is
// usable by the file that imports it, because one macro environment is filled
// in link order.
func TestCompileSharesMacrosInLinkOrder(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"macros.mut": "let add = macro(a, b) {\n" +
			"\tquote(unquote(a) + unquote(b));\n" +
			"};\n",
		"main.mut": "import \"macros.mut\";\n" +
			"let total = add(2, 3);\n",
	})

	if _, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("compile: %v (%v)", err, details)
	}
}

// TestCompileCompilesADiamondOnce guards against a shared dependency being
// compiled twice, which would redefine every name it declares.
func TestCompileCompilesADiamondOnce(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"main.mut":   "import \"a.mut\";\nimport \"b.mut\";\nlet total = a.fromA + b.fromB;\n",
		"a.mut":      "import \"shared.mut\";\nlet fromA = shared.base + 1;\n",
		"b.mut":      "import \"shared.mut\";\nlet fromB = shared.base + 2;\n",
		"shared.mut": "let base = 10;\n",
	})

	if _, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("compile: %v (%v)", err, details)
	}
}

// TestCompileGivesEachModuleItsOwnTopLevel walks the real linker, so it also
// pins that a module's key and the key its importer records for it agree --
// two spellings of one path that disagreed would make every ns.name miss.
func TestCompileGivesEachModuleItsOwnTopLevel(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"lib/util.mut": "let label = fn() {\n\treturn \"lib\";\n};\n",
		"main.mut": "import \"lib/util.mut\";\n" +
			"let label = fn() {\n\treturn \"main\";\n};\n" +
			"let mine = label();\n" +
			"let theirs = util.label();\n",
	})

	if _, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("compile: %v (%v)", err, details)
	}
}

// TestCompileRefusesAnUnqualifiedCrossModuleName. An import is not a textual
// include: it binds one namespace and nothing else, so a name the importing
// file never declared stays undefined.
func TestCompileRefusesAnUnqualifiedCrossModuleName(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"lib/util.mut": "let double = fn(n) {\n\treturn n * 2;\n};\n",
		"main.mut":     "import \"lib/util.mut\";\nlet answer = double(21);\n",
	})

	_, err, errType, _ := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err == nil {
		t.Fatal("an imported module's name resolved without its namespace")
	}
	if errType != errrs.COMPILER_ERROR {
		t.Fatalf("error type = %q, want %q", errType, errrs.COMPILER_ERROR)
	}
	if !strings.Contains(err.Error(), "double") {
		t.Fatalf("error %q does not name the unresolved identifier", err)
	}
}

// TestCompileRefusesAPrivateNameThroughANamespace is Phase 4 end to end.
func TestCompileRefusesAPrivateNameThroughANamespace(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"lib/util.mut": "let _secret = 41;\nlet shown = 1;\n",
		"main.mut":     "import \"lib/util.mut\";\nlet answer = util._secret + util.shown;\n",
	})

	_, err, _, _ := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err == nil {
		t.Fatal("a module-private name was reachable through its namespace")
	}
	if !strings.Contains(err.Error(), "_secret") || !strings.Contains(err.Error(), "private") {
		t.Fatalf("error %q does not explain the export rule", err)
	}
}

// TestCompileBindsNamespacesPerImporter. Two files each import something
// called `util` and mean two different files. A namespace table shared across
// the program would silently give one of them the other's functions -- and it
// would compile, which is what makes this worth a test rather than a comment.
func TestCompileBindsNamespacesPerImporter(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"one/util.mut": "let only_in_one = 1;\n",
		"two/util.mut": "let only_in_two = 2;\n",
		"a.mut":        "import \"one/util.mut\";\nlet fromA = util.only_in_one;\n",
		"b.mut":        "import \"two/util.mut\";\nlet fromB = util.only_in_two;\n",
		"main.mut":     "import \"a.mut\";\nimport \"b.mut\";\nlet total = a.fromA + b.fromB;\n",
	})

	if _, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("compile: %v (%v)", err, details)
	}

	// The mirror image: a.mut reaching for the name only two/util.mut has must
	// fail, or the test above would pass with one shared namespace table too.
	crossed := writeProgram(t, map[string]string{
		"one/util.mut": "let only_in_one = 1;\n",
		"two/util.mut": "let only_in_two = 2;\n",
		"a.mut":        "import \"one/util.mut\";\nlet fromA = util.only_in_two;\n",
		"b.mut":        "import \"two/util.mut\";\nlet fromB = util.only_in_two;\n",
		"main.mut":     "import \"a.mut\";\nimport \"b.mut\";\nlet total = a.fromA + b.fromB;\n",
	})

	if _, err, _, _ := compile(
		filepath.Join(crossed, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err == nil {
		t.Fatal("a.mut reached a name only the other util.mut declares")
	}
}

// TestCompileRefusesTwoModulesDeclaringOneType. Struct and enum names are
// program-wide because that is how they travel in the bytecode; the collision
// has to be an error rather than one module quietly getting the other fields.
func TestCompileRefusesTwoModulesDeclaringOneType(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"lib/shapes.mut": "struct Point { x, y }\n",
		"main.mut":       "import \"lib/shapes.mut\";\nstruct Point { a, b }\n",
	})

	_, err, _, _ := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t))
	if err == nil {
		t.Fatal("two modules each declared Point without complaint")
	}
	for _, want := range []string{"Point", "shapes.mut", "main.mut"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestCompileSharesTypesAcrossModules is the other half of that rule: one
// declaration is visible everywhere, with no namespace needed, because a type
// name is not a value.
func TestCompileSharesTypesAcrossModules(t *testing.T) {
	root := writeProgram(t, map[string]string{
		"lib/shapes.mut": "struct Point { x, y }\n",
		"main.mut":       "import \"lib/shapes.mut\";\nlet p = Point{x: 1, y: 2};\n",
	})

	if _, err, _, details := compile(
		filepath.Join(root, "main.mut"), nil, false, modulePassword, 0, 7, testSigningKey(t)); err != nil {
		t.Fatalf("a type declared in an imported module was not usable: %v (%v)", err, details)
	}
}
