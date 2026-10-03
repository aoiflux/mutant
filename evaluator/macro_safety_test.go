package evaluator

import (
	"strings"
	"testing"

	"mutant/object"
)

// A macro body runs while the compiler is running. Every one of these cases
// used to compile, which meant `mutant gen` on somebody else's source ran
// whatever that source felt like running -- before the program was started,
// before a password was asked for, and with none of the run time's controls in
// existence yet. Importing a module is enough: expansion covers every module in
// the linked graph, so a macro in a library runs at the importer's compile.
//
// The cases are grouped by the door they go through, because the first fix
// anybody writes closes one of them and leaves the rest open.

// expandRefusal expands source that must be refused and returns the message.
func expandRefusal(t *testing.T, source string) string {
	t.Helper()

	message := expandExpectingError(t, source)
	if strings.Contains(message, "identifier not found") {
		t.Fatalf("a refused builtin was reported as an unknown name, which hides it:\n%s", message)
	}
	if !strings.Contains(message, "not available at macro expansion time") {
		t.Fatalf("expansion failed, but not with the refusal:\n%s", message)
	}
	return message
}

// expandOK expands source that must still work.
func expandOK(t *testing.T, source string) string {
	t.Helper()

	program := testParseProgram(source)
	env := object.NewEnvironment()
	DefineMacros(program, env)

	expanded, err := ExpandMacros(program, env)
	if err != nil {
		t.Fatalf("expansion failed and should not have:\nsource: %s\nerror:  %s", source, err)
	}
	return expanded.String()
}

// TestABuiltinThatTouchesTheHostIsRefusedDuringMacroExpansion is the first
// door: an identifier resolved against the builtin table.
func TestABuiltinThatTouchesTheHostIsRefusedDuringMacroExpansion(t *testing.T) {
	cases := []struct{ name, source, wantName string }{
		{
			"writes a file",
			`let m = macro() { fs_write("ran.txt", "hello"); quote(1) }; m();`,
			"fs_write",
		},
		{
			"runs a program",
			`let m = macro() { exec_string("whoami"); quote(1) }; m();`,
			"exec_string",
		},
		{
			"lists processes",
			`let m = macro() { process_list(); quote(1) }; m();`,
			"process_list",
		},
		{
			"runs a Lua script, whose sandbox can still read files",
			`let m = macro() { lua_run_string("return 1"); quote(1) }; m();`,
			"lua_run_string",
		},
		{
			"writes to the program's output",
			`let m = macro() { putln("hi"); quote(1) }; m();`,
			"putln",
		},
		{
			"reads the clock, so expansion would not be reproducible",
			`let m = macro() { time_now(); quote(1) }; m();`,
			"time_now",
		},
		{
			"draws entropy, so expansion would not be reproducible",
			`let m = macro() { rand_bytes(4); quote(1) }; m();`,
			"rand_bytes",
		},
		{
			"writes process-global state the compiled program would then read",
			`let m = macro() { policy_load("p", "package p"); quote(1) }; m();`,
			"policy_load",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			message := expandRefusal(t, testCase.source)
			if !strings.Contains(message, testCase.wantName) {
				t.Errorf("the refusal does not name the builtin %q:\n%s", testCase.wantName, message)
			}
		})
	}
}

// TestTheDottedSpellingOfARefusedBuiltinIsRefusedInAMacroToo is the second
// door, and the one a fix aimed at evalIdentifier leaves wide open. sema folds
// an unbound `fs.write` to the flat name `fs_write`, and the field expression
// reads the builtin table itself: no identifier for the builtin is ever built,
// so a gate on identifiers never sees it.
func TestTheDottedSpellingOfARefusedBuiltinIsRefusedInAMacroToo(t *testing.T) {
	cases := []struct{ source, wantSpelling string }{
		{`let m = macro() { fs.write("ran.txt", "hello"); quote(1) }; m();`, "fs.write"},
		{`let m = macro() { exec.string("whoami"); quote(1) }; m();`, "exec.string"},
		{`let m = macro() { process.list(); quote(1) }; m();`, "process.list"},
		{`let m = macro() { http.get("http://example.invalid"); quote(1) }; m();`, "http.get"},
	}

	for _, testCase := range cases {
		t.Run(testCase.wantSpelling, func(t *testing.T) {
			message := expandRefusal(t, testCase.source)
			if !strings.Contains(message, testCase.wantSpelling) {
				t.Errorf("the refusal does not repeat the spelling the author wrote (%q):\n%s",
					testCase.wantSpelling, message)
			}
		})
	}
}

// TestWithResourceIsRefusedDuringMacroExpansion is the third door. with_resource
// resolves its closer from a STRING at run time, so no rule that reads names in
// the source can see what it would call -- the same reason the browser REPL
// already denies it by name. Refusing with_resource itself is what makes that
// resolution unreachable during expansion.
func TestWithResourceIsRefusedDuringMacroExpansion(t *testing.T) {
	message := expandRefusal(t,
		`let m = macro() { with_resource("h", "str_upper", fn(x) { return 1; }); quote(1) }; m();`)
	if !strings.Contains(message, "with_resource") {
		t.Errorf("the refusal does not name with_resource:\n%s", message)
	}
}

// TestARefusedBuiltinIsRefusedAsAValueToo keeps the gate upstream of the call.
// applyFunction dispatches the executor-native builtins before it ever calls
// Fn, so a guard written at the call would miss with_resource, spawn and the
// nineteen others. Refusing at the point a name becomes a builtin also stops a
// refused builtin being handed to one that is allowed.
func TestARefusedBuiltinIsRefusedAsAValueToo(t *testing.T) {
	for _, source := range []string{
		`let m = macro() { let f = fs_read; quote(1) }; m();`,
		`let m = macro() { let f = exec.string; quote(1) }; m();`,
		`let m = macro() { map([1], fs.read); quote(1) }; m();`,
	} {
		expandRefusal(t, source)
	}
}

// TestSpawnIsNotAvailableDuringMacroExpansion covers the handle. spawn puts an
// entry in a process-global task table even for a wholly pure callback, and a
// handle is spelled as a plain integer -- which is one of the five shapes that
// can be unquoted into the program the compiler then emits.
func TestSpawnIsNotAvailableDuringMacroExpansion(t *testing.T) {
	expandRefusal(t, `let m = macro() { spawn(fn(x) { return 1; }, 1); quote(1) }; m();`)
}

// TestARefusalReachesAFunctionTheMacroDefines is the marker-inheritance case.
// An environment is a store plus a pointer to the one outside it, and the
// enclosing constructor copies nothing else -- so a mark checked on the exact
// environment is absent the moment a macro body defines a function and calls
// it.
func TestARefusalReachesAFunctionTheMacroDefines(t *testing.T) {
	expandRefusal(t,
		`let m = macro() { let f = fn(p) { return fs_read(p); }; f("secret"); quote(1) }; m();`)
}

// TestARefusalReachesALoopBodyInsideAMacro is the same case through the other
// four environments a body can build.
func TestARefusalReachesALoopBodyInsideAMacro(t *testing.T) {
	for _, source := range []string{
		`let m = macro() { for (x in [1]) { fs_write("ran.txt", "x"); } quote(1) }; m();`,
		`let m = macro() { for (let i = 0; i < 1; i++) { process_list(); } quote(1) }; m();`,
	} {
		expandRefusal(t, source)
	}
}

// TestARefusedBuiltinInsideUnquoteIsRefused covers the second way into the
// evaluator. unquote evaluates its argument in the same environment the body
// runs in, and it is the natural place to hide the call.
func TestARefusedBuiltinInsideUnquoteIsRefused(t *testing.T) {
	expandRefusal(t, `let m = macro() { quote(unquote(time_ms())) }; m();`)
}

// TestARefusedBuiltinInsideATemplateHoleStopsExpansion is the quiet one. A hole
// used to be evaluated through the exported entry point, which unwraps the
// fatal signal into an ordinary error value -- so the guard on the next line
// never fired, the refusal's text was written into the string, and expansion
// SUCCEEDED. A gate that reports itself by baking its own message into the
// program is worse than no gate, because it reads as working.
func TestARefusedBuiltinInsideATemplateHoleStopsExpansion(t *testing.T) {
	message := expandRefusal(t,
		`let m = macro() { let s = "when=${ time.now() }"; quote(unquote(s)) }; m();`)
	if !strings.Contains(message, "time.now") {
		t.Errorf("the refusal does not name time.now:\n%s", message)
	}
}

// TestAMacroSafeBuiltinStillRunsDuringExpansion is the other half of the
// contract: pure computation at expansion time is the point of a macro, and it
// keeps working.
func TestAMacroSafeBuiltinStillRunsDuringExpansion(t *testing.T) {
	for _, source := range []string{
		`let m = macro() { quote(unquote(len("shout"))) }; m();`,
		`let m = macro() { quote(unquote(str_upper("shout"))) }; m();`,
		`let m = macro() { quote(unquote(str.upper("shout"))) }; m();`,
		`let m = macro() { quote(unquote(hash_sha256("x"))) }; m();`,
		`let m = macro() { quote(unquote(max(1, 2))) }; m();`,
	} {
		expandOK(t, source)
	}
}

// TestAnUnknownNameInAMacroIsStillAnUnknownName pins the message that was
// already promised. The refusal sits between the environment lookup and the
// not-found answer, and refuses only names that ARE builtins -- so a name that
// is not one reads exactly as it did.
func TestAnUnknownNameInAMacroIsStillAnUnknownName(t *testing.T) {
	message := expandExpectingError(t, `let bad = macro() { quote(unquote(nowhere)); }; bad();`)
	if !strings.Contains(message, "identifier not found: nowhere") {
		t.Errorf("want the unchanged not-found message, got: %s", message)
	}
}

// TestTheRunTimeKeepsEveryBuiltin is the blast-radius test. The restriction is
// carried by the environment a macro body is evaluated in, and no environment a
// caller holds is ever marked, so nothing outside expansion can reach it.
func TestTheRunTimeKeepsEveryBuiltin(t *testing.T) {
	for _, source := range []string{`fs_write;`, `with_resource;`, `spawn;`, `fs.write;`} {
		program := testParseProgram(source)
		result := Eval(program, object.NewEnvironment())
		if failed, isErr := result.(*object.Error); isErr {
			t.Errorf("%s: the run time refused a builtin it should still have: %s", source, failed.Message)
		}
	}
}
