package vm

import (
	"testing"

	"mutant/compiler"
	"mutant/object"
)

// compileModuleProgram drives several modules through one compiler the way the
// linker does, and returns the single ByteCode they link into.
//
// Compiling is not enough to prove module scoping works: two modules that each
// declare `label` compile happily whatever the symbol table does with them. It
// is running the result that shows whether each call reached the function its
// own file declared, so these tests go all the way to the VM.
func compileModuleProgram(t *testing.T, scopes []compiler.ModuleScope, sources []string) *compiler.ByteCode {
	t.Helper()

	comp := compiler.New()
	for i, scope := range scopes {
		comp.EnterModule(scope)
		if err := comp.Compile(parse(sources[i])); err != nil {
			t.Fatalf("compiling %s: %v", scope.Display, err)
		}
	}
	return comp.ByteCode()
}

// TestEachModuleCallsItsOwnFunction. Both files declare `label`, and main calls
// its own unqualified. Before module keys the second definition overwrote the
// first in one flat global scope, so this returned the library's answer.
func TestEachModuleCallsItsOwnFunction(t *testing.T) {
	bc := compileModuleProgram(t,
		[]compiler.ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{
			"let label = fn() { return \"from lib\"; };\n",
			"let label = fn() { return \"from main\"; };\nlabel();\n",
		},
	)

	machine, err := runSealed(t, bc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertStringResult(t, machine, "from main")
}

// TestANamespaceReachesTheOtherModulesFunction is the same program asking for
// the other answer, which is the only way to tell scoping from hiding.
func TestANamespaceReachesTheOtherModulesFunction(t *testing.T) {
	bc := compileModuleProgram(t,
		[]compiler.ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{
			"let label = fn() { return \"from lib\"; };\n",
			"let label = fn() { return \"from main\"; };\nutil.label();\n",
		},
	)

	machine, err := runSealed(t, bc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertStringResult(t, machine, "from lib")
}

// TestAModulesPrivateNameWorksInsideIt. A private name is still an ordinary
// global to its own module, including from inside a function body compiled
// after the definition.
func TestAModulesPrivateNameWorksInsideIt(t *testing.T) {
	bc := compileModuleProgram(t,
		[]compiler.ModuleScope{
			{Key: "lib", Display: "lib/util.mut"},
			{Key: "main", Display: "main.mut", Namespaces: map[string]string{"util": "lib"}},
		},
		[]string{
			"let _prefix = \"hidden:\";\nlet show = fn(s) { return _prefix + s; };\n",
			"util.show(\"ok\");\n",
		},
	)

	machine, err := runSealed(t, bc)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertStringResult(t, machine, "hidden:ok")
}

// TestANamespacedBuiltinRuns. Compiling str.upper proves the compiler resolved
// it; running proves the operand it emitted reaches the same builtin the flat
// spelling does.
func TestANamespacedBuiltinRuns(t *testing.T) {
	comp := compiler.New()
	if err := comp.Compile(parse("str.upper(\"shout\");\n")); err != nil {
		t.Fatalf("compile: %v", err)
	}

	machine, err := runSealed(t, comp.ByteCode())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertStringResult(t, machine, "SHOUT")
}

func assertStringResult(t *testing.T, machine *VM, want string) {
	t.Helper()

	result := machine.LastPoppedStackElement()
	str, ok := result.(*object.String)
	if !ok {
		t.Fatalf("result is %T (%v), want a string", result, result)
	}
	if str.Value != want {
		t.Fatalf("result is %q, want %q", str.Value, want)
	}
}
