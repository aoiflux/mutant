package compiler

import (
	"strings"
	"testing"

	"mutant/builtin"
)

// newRootTable builds the root symbol table the way every real entry point
// does: a fresh table with the whole builtin registry defined into it.
func newRootTable() *SymbolTable {
	table := NewSymbolTable()
	for i, v := range builtin.Builtins {
		table.DefineBuiltin(i, v.Name)
	}
	return table
}

// TestTwoModulesMayDeclareTheSameName is the point of the whole exercise. Both
// modules are driven through one table, which before module keys meant the
// second `helper` overwrote the first and every call in the first module
// silently retargeted.
func TestTwoModulesMayDeclareTheSameName(t *testing.T) {
	table := NewSymbolTable()

	table.SetCurrentModule("a")
	first := table.Define("helper")

	table.SetCurrentModule("b")
	second := table.Define("helper")

	if first.Index == second.Index {
		t.Fatalf("both modules got global slot %d; one overwrote the other", first.Index)
	}
	if first.Name != "helper" || second.Name != "helper" {
		t.Fatalf("Symbol.Name must stay the bare name, got %q and %q", first.Name, second.Name)
	}

	if got, ok := table.ResolveIn("a", "helper"); !ok || got.Index != first.Index {
		t.Fatalf("a.helper resolved to %+v (ok=%v), want slot %d", got, ok, first.Index)
	}
	if got, ok := table.ResolveIn("b", "helper"); !ok || got.Index != second.Index {
		t.Fatalf("b.helper resolved to %+v (ok=%v), want slot %d", got, ok, second.Index)
	}
}

// TestAModuleCannotSeeAnothersNamesUnqualified: a module's global scope is its
// own top level plus the builtins, and nothing else. Without this an import
// would be a textual include with the last definition winning.
func TestAModuleCannotSeeAnothersNamesUnqualified(t *testing.T) {
	table := NewSymbolTable()

	table.SetCurrentModule("a")
	table.Define("hidden")

	table.SetCurrentModule("b")
	if symbol, ok := table.Resolve("hidden"); ok {
		t.Fatalf("module b resolved module a's `hidden` to %+v", symbol)
	}
}

// TestBuiltinsStayVisibleFromEveryModule. Builtins are stored unqualified, so
// the qualified-then-bare lookup has to fall through to them -- otherwise
// every module would have to import `len`.
func TestBuiltinsStayVisibleFromEveryModule(t *testing.T) {
	table := newRootTable()
	table.SetCurrentModule("somewhere/deep/module.mut")

	symbol, ok := table.Resolve("len")
	if !ok {
		t.Fatal("len is not resolvable inside a module")
	}
	if symbol.Scope != BuiltinScope {
		t.Fatalf("len resolved to scope %q, want %q", symbol.Scope, BuiltinScope)
	}
}

// TestAModuleNameShadowsABuiltin pins the order of the two-step: the module's
// own top level is tried first, so a module that declares `len` gets its own.
func TestAModuleNameShadowsABuiltin(t *testing.T) {
	table := newRootTable()
	table.SetCurrentModule("m")
	own := table.Define("len")

	symbol, ok := table.Resolve("len")
	if !ok {
		t.Fatal("len stopped resolving after the module declared it")
	}
	if symbol.Scope != GlobalScope || symbol.Index != own.Index {
		t.Fatalf("len resolved to %+v, want the module's own slot %d", symbol, own.Index)
	}
}

// TestNoModuleMeansNoQualification is the compatibility guarantee: the REPL,
// the playground and every single-file compile never call SetCurrentModule,
// and for them the table behaves exactly as it did before modules existed.
func TestNoModuleMeansNoQualification(t *testing.T) {
	table := NewSymbolTable()
	defined := table.Define("a")

	resolved, ok := table.Resolve("a")
	if !ok || resolved != defined {
		t.Fatalf("resolved %+v (ok=%v), want %+v", resolved, ok, defined)
	}
	if table.CurrentModule() != "" {
		t.Fatalf("current module is %q, want empty", table.CurrentModule())
	}
}

// TestNamespacesAreKeyedByImporter. Two files may both import something called
// `util` and mean two different files; a namespace map shared across the
// program would make the second import silently retarget the first file.
func TestNamespacesAreKeyedByImporter(t *testing.T) {
	table := NewSymbolTable()

	table.SetCurrentModule("a")
	table.BindNamespace("util", "lib/one.mut")

	table.SetCurrentModule("b")
	table.BindNamespace("util", "lib/two.mut")

	table.SetCurrentModule("a")
	if key, ok := table.LookupNamespace("util"); !ok || key != "lib/one.mut" {
		t.Fatalf("inside a, util is %q (ok=%v), want lib/one.mut", key, ok)
	}

	table.SetCurrentModule("c")
	if key, ok := table.LookupNamespace("util"); ok {
		t.Fatalf("module c, which imports nothing, sees util as %q", key)
	}
}

// TestFunctionBodiesBelongToTheirModule. The current module lives on the root
// table and is reached through root(), so an enclosed table -- a function body,
// a block inside it -- resolves against the module that declared the function,
// however deeply it nests.
func TestFunctionBodiesBelongToTheirModule(t *testing.T) {
	table := NewSymbolTable()
	table.SetCurrentModule("a")
	global := table.Define("top")

	inner := NewEnclosedSymbolTable(NewEnclosedSymbolTable(table))
	symbol, ok := inner.Resolve("top")
	if !ok {
		t.Fatal("a nested scope cannot see its own module's top level")
	}
	if symbol.Scope != GlobalScope || symbol.Index != global.Index {
		t.Fatalf("resolved %+v, want the module global %+v", symbol, global)
	}
	if inner.CurrentModule() != "a" {
		t.Fatalf("nested table reports module %q, want a", inner.CurrentModule())
	}
}

// TestModuleNamesLeavesOutPrivateOnes is what `ns.` completion is fed from,
// and the private rule has to hold there too or the editor would offer names
// the compiler refuses.
func TestModuleNamesLeavesOutPrivateOnes(t *testing.T) {
	table := NewSymbolTable()
	table.SetCurrentModule("a")
	table.Define("visible")
	table.Define("_hidden")
	table.SetCurrentModule("b")
	table.Define("elsewhere")

	names := table.ModuleNames("a")
	if len(names) != 1 || names[0] != "visible" {
		t.Fatalf("ModuleNames(a) = %v, want [visible]", names)
	}
}

// TestGlobalNamesReportsBareNames. GlobalNames feeds REPL completion from the
// raw store, and a store key inside a modular program carries a qualifier no
// user ever typed.
func TestGlobalNamesReportsBareNames(t *testing.T) {
	table := NewSymbolTable()
	table.SetCurrentModule("some/module.mut")
	table.Define("answer")

	for _, name := range table.GlobalNames() {
		if strings.Contains(name, moduleSeparator) || name == "some/module.mut" {
			t.Fatalf("GlobalNames leaked a qualified key: %q", name)
		}
		if name != "answer" {
			t.Fatalf("GlobalNames = %v, want [answer]", table.GlobalNames())
		}
	}
}

// TestIsModulePrivate states the export rule in one place.
func TestIsModulePrivate(t *testing.T) {
	for name, want := range map[string]bool{
		"_hidden": true,
		"_":       true,
		"visible": false,
		"with_":   false,
		"":        false,
	} {
		if got := IsModulePrivate(name); got != want {
			t.Errorf("IsModulePrivate(%q) = %v, want %v", name, got, want)
		}
	}
}

// compileModules drives src through one compiler the way the linker does, one
// ModuleScope at a time, and returns the first error.
func compileModules(t *testing.T, modules []ModuleScope, sources []string) error {
	t.Helper()

	if len(modules) != len(sources) {
		t.Fatalf("%d scopes for %d sources", len(modules), len(sources))
	}

	comp := New()
	for i, scope := range modules {
		comp.EnterModule(scope)
		if err := comp.Compile(parse(sources[i])); err != nil {
			return err
		}
	}
	return nil
}

// TestPrivateNameThroughNamespaceIsRefused is Phase 4's whole surface: the
// underscore means something only when another module reaches for it.
func TestPrivateNameThroughNamespaceIsRefused(t *testing.T) {
	err := compileModules(t,
		[]ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{
			"let _secret = 1;\nlet shown = 2;\n",
			"let x = util._secret;\n",
		},
	)
	if err == nil {
		t.Fatal("reaching a module-private name through a namespace compiled")
	}
	for _, want := range []string{"util._secret", "private", "lib/util.mut"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestPrivateNameIsUsableInsideItsOwnModule. The rule is about reach, not about
// the spelling: a module's own `_helper` is an ordinary name to it.
func TestPrivateNameIsUsableInsideItsOwnModule(t *testing.T) {
	if err := compileModules(t,
		[]ModuleScope{{Key: "lib", Display: "lib/util.mut"}},
		[]string{"let _secret = 1;\nlet doubled = _secret + _secret;\n"},
	); err != nil {
		t.Fatalf("a module cannot use its own private name: %v", err)
	}
}

// TestNamespaceMemberThatDoesNotExist names the module rather than leaving the
// reader to guess which file was supposed to have it.
func TestNamespaceMemberThatDoesNotExist(t *testing.T) {
	err := compileModules(t,
		[]ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{"let shown = 2;\n", "let x = util.missing;\n"},
	)
	if err == nil {
		t.Fatal("a namespace member that does not exist compiled")
	}
	if !strings.Contains(err.Error(), "lib/util.mut") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error %q names neither the module nor the member", err)
	}
}

// TestBuiltinNamespaceResolves is Phase 5: fs.read is fs_read, derived rather
// than tabulated.
func TestBuiltinNamespaceResolves(t *testing.T) {
	if err := compileModules(t, []ModuleScope{{}}, []string{"let s = str.upper(\"x\");\n"}); err != nil {
		t.Fatalf("str.upper did not compile: %v", err)
	}
}

// TestBuiltinNamespaceLosesToABinding. `A bound variable named fs still wins`
// is what keeps every program written before namespaces existed meaning what
// it meant: a struct in a variable called `str` still gets field access.
func TestBuiltinNamespaceLosesToABinding(t *testing.T) {
	comp := New()
	err := comp.Compile(parse("struct Holder { upper }\nlet str = Holder{upper: 1};\nlet v = str.upper;\n"))
	if err != nil {
		t.Fatalf("a binding named str stopped shadowing the builtin namespace: %v", err)
	}

	// OpGetField, not OpGetBuiltin: the field access must survive.
	if !strings.Contains(comp.ByteCode().Instructions.String(), "OpGetField") {
		t.Fatal("str.upper on a struct did not compile to a field access")
	}
}

// TestTypeNamesCollideAcrossModules. Struct and enum names travel in the
// bytecode keyed by bare name, so two modules cannot each have a Point -- and
// the failure has to be an error naming both files, not a silent overwrite
// that gives one module the other's fields.
func TestTypeNamesCollideAcrossModules(t *testing.T) {
	err := compileModules(t,
		[]ModuleScope{
			{Key: "a", Display: "lib/a.mut"},
			{Key: "b", Display: "lib/b.mut"},
		},
		[]string{"struct Point { x, y }\n", "struct Point { a, b }\n"},
	)
	if err == nil {
		t.Fatal("two modules each declared Point without complaint")
	}
	for _, want := range []string{"Point", "lib/a.mut", "lib/b.mut"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestOneModuleMayRedeclareItsOwnType keeps the REPL working: it compiles each
// line separately against one compiler, and a redeclared type there is the
// user editing, not two files disagreeing.
func TestOneModuleMayRedeclareItsOwnType(t *testing.T) {
	comp := New()
	if err := comp.Compile(parse("struct Point { x, y }\n")); err != nil {
		t.Fatalf("first declaration: %v", err)
	}
	if err := comp.Compile(parse("struct Point { x, y, z }\n")); err != nil {
		t.Fatalf("a single compilation unit cannot redeclare its own type: %v", err)
	}
}

// TestAssignmentThroughANamespaceIsRefused. It would read as "give that module
// a different value", which the write cannot deliver: the target is another
// file's global slot and the change would be invisible at its declaration.
func TestAssignmentThroughANamespaceIsRefused(t *testing.T) {
	err := compileModules(t,
		[]ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{"let count = 1;\n", "util.count = 2;\n"},
	)
	if err == nil {
		t.Fatal("assigning through an import namespace compiled")
	}
	if !strings.Contains(err.Error(), "util.count") || !strings.Contains(err.Error(), "lib/util.mut") {
		t.Fatalf("error %q does not say what cannot be assigned or where it lives", err)
	}
}
