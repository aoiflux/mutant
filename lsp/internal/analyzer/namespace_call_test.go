package analyzer

import (
	"strings"
	"testing"

	mast "mutant/ast"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// lintMessages runs the default ruleset over src and returns every message.
func lintMessages(t *testing.T, src string) []string {
	t.Helper()

	diagnostics := Diagnostics(New().Analyze(src), DefaultLintConfig())
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		messages = append(messages, diagnostic.Message)
	}
	return messages
}

func mentions(messages []string, needle string) bool {
	for _, message := range messages {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

// TestNamespacedCallIsNotAnUndefinedIdentifier is the false positive the two
// spellings created: `str.upper(x)` reported `undefined identifier str` at
// error severity, and `mutant lint` exits non-zero on any error whatever the
// flags -- so the linter was unusable on a file that used the new spelling.
func TestNamespacedCallIsNotAnUndefinedIdentifier(t *testing.T) {
	if undefinedNames(t, "let x = str.upper(\"a\");\nx;\n")["str"] {
		t.Fatal("str in str.upper was reported as an undefined identifier")
	}
}

// TestNamespacedCallIsArgumentChecked is the other half: going quiet is not an
// acceptable answer either. Both spellings name one builtin and must be held
// to one contract.
func TestNamespacedCallIsArgumentChecked(t *testing.T) {
	dotted := lintMessages(t, "let x = str.upper(42);\nx;\n")
	flat := lintMessages(t, "let x = str_upper(42);\nx;\n")

	if !mentions(flat, "argument 1 to `str_upper`") {
		t.Fatalf("the flat spelling stopped being checked: %v", flat)
	}
	if !mentions(dotted, "argument 1 to `str_upper`") {
		t.Fatalf("the namespaced spelling is not argument-checked: %v", dotted)
	}
}

// TestABindingBeatsTheBuiltinFamily. `A bound variable named fs still wins` is
// what keeps programs written before namespaces existed meaning what they
// meant -- here a struct whose field happens to be called `upper`.
func TestABindingBeatsTheBuiltinFamily(t *testing.T) {
	src := "struct Holder { upper }\nlet str = Holder{upper: 42};\nlet v = str.upper;\nv;\n"
	if mentions(lintMessages(t, src), "str_upper") {
		t.Fatalf("a local named str was checked as the builtin family: %v", lintMessages(t, src))
	}
}

// TestAnImportedNamespaceBeatsTheBuiltinFamily. An import that binds `str`
// means that file's functions, and checking them against str_upper's contract
// would be a diagnostic about a different function entirely.
func TestAnImportedNamespaceBeatsTheBuiltinFamily(t *testing.T) {
	src := "import str \"lib/str.mut\";\nlet x = str.upper(42);\nx;\n"
	if mentions(lintMessages(t, src), "str_upper") {
		t.Fatalf("an imported namespace was checked as the builtin family: %v", lintMessages(t, src))
	}
}

// TestFieldAccessOnAnUnknownReceiverStaysQuiet. `p.x` where p is undefined is
// still one report about p, not an invented builtin called p_x.
func TestFieldAccessOnAnUnknownReceiverStaysQuiet(t *testing.T) {
	names := undefinedNames(t, "let v = p.x;\nv;\n")
	if !names["p"] {
		t.Fatal("an undefined receiver stopped being reported")
	}
	if mentions(lintMessages(t, "let v = p.x;\nv;\n"), "p_x") {
		t.Fatal("field access on an unknown receiver was treated as a builtin")
	}
}

// TestBuiltinCalleeResolvesBothSpellings states the helper's contract on its
// own, including the two shapes that are never a namespace.
func TestBuiltinCalleeResolvesBothSpellings(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		want   string
		wantOK bool
	}{
		{"flat", "str_upper(\"a\");\n", "str_upper", true},
		{"namespaced", "str.upper(\"a\");\n", "str_upper", true},
		{"not a builtin family", "thing.method(1);\n", "", false},
		{"chained receiver", "a.b.c(1);\n", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := firstCall(t, New().Analyze(tt.src))
			name, anchor, ok := builtinCallee(call.Function, nil)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (name %q)", ok, tt.wantOK, name)
			}
			if !ok {
				return
			}
			if name != tt.want {
				t.Fatalf("name = %q, want %q", name, tt.want)
			}
			if anchor == nil {
				t.Fatal("a resolved callee must carry an anchor for the squiggle")
			}
		})
	}
}

// TestBuiltinFamilyMembersAreDerived. The member list comes from the registry,
// so a family works the day a builtin joins it.
func TestBuiltinFamilyMembersAreDerived(t *testing.T) {
	members := builtinFamilyMembers("str")
	if len(members) == 0 {
		t.Fatal("the str family offered no members")
	}
	for _, member := range members {
		if strings.HasPrefix(member, "str_") {
			t.Fatalf("member %q still carries the family prefix", member)
		}
		if member == "" {
			t.Fatal("the empty member means a bare `str_` was counted as a family member")
		}
	}
	if len(builtinFamilyMembers("definitelynotafamily")) != 0 {
		t.Fatal("a name that is not a family offered members")
	}
}

// TestImportHoverNamesTheNamespace. Without an arm of its own, hovering an
// import printed the literal text *ast.ImportStatement.
func TestImportHoverNamesTheNamespace(t *testing.T) {
	snapshot := New().Analyze("import \"lib/util.mut\";\n")
	text, _, ok := snapshot.HoverText(lsp.Position{Line: 0, Character: 1})
	if !ok {
		t.Fatal("hovering an import produced nothing")
	}
	if strings.Contains(text, "ast.ImportStatement") {
		t.Fatalf("hover leaked the node type: %q", text)
	}
	if !strings.Contains(text, "util") || !strings.Contains(text, "lib/util.mut") {
		t.Fatalf("hover names neither the namespace nor the path: %q", text)
	}
}

// TestImportIsACompletionKeyword. The completion list is taken from the lexer
// now; the hand-written copy it replaced had already drifted.
func TestImportIsACompletionKeyword(t *testing.T) {
	for _, item := range New().Analyze("").CompletionItemsAt(lsp.Position{}) {
		if item.Label == "import" {
			return
		}
	}
	t.Fatal("import is not offered as a keyword completion")
}

// firstCall returns the first top-level call expression in the snapshot's
// program.
func firstCall(t *testing.T, snapshot *Snapshot) *mast.CallExpression {
	t.Helper()

	if snapshot == nil || snapshot.Program == nil {
		t.Fatal("no program")
	}
	for _, stmt := range snapshot.Program.Statements {
		expr, ok := stmt.(*mast.ExpressionStatement)
		if !ok || expr == nil {
			continue
		}
		if call, ok := expr.Expression.(*mast.CallExpression); ok && call != nil {
			return call
		}
	}
	t.Fatal("the program contains no call expression")
	return nil
}

// unusedNames returns the names the unusedDeclaration rule reports.
func unusedNames(t *testing.T, src string) map[string]bool {
	t.Helper()

	names := make(map[string]bool)
	for _, message := range lintMessages(t, src) {
		const prefix = "unused declaration `"
		if !strings.HasPrefix(message, prefix) {
			continue
		}
		names[strings.TrimSuffix(strings.TrimPrefix(message, prefix), "`")] = true
	}
	return names
}

// TestAModulesExportsAreNotUnused. A file that only declares things is a
// module: the uses are in whatever imports it, which one-file linting cannot
// see. Reporting them would put a warning on every module in a project, on
// exactly the names the module exists to provide.
func TestAModulesExportsAreNotUnused(t *testing.T) {
	src := "import \"other.mut\";\n" +
		"let sum = fn(a, b) { return a + b; };\n" +
		"let label = \"stats\";\n"

	if names := unusedNames(t, src); len(names) != 0 {
		t.Fatalf("a module's exports were reported unused: %v", names)
	}
}

// TestADeadTopLevelHelperIsStillUnused is the case the rule is for, and the
// reason the module exemption is narrow: a file that runs something at its top
// level is a whole program, and a helper nothing there calls is dead.
func TestADeadTopLevelHelperIsStillUnused(t *testing.T) {
	src := "let helper = fn() { return 1; };\nputln(\"hi\");\n"

	if !unusedNames(t, src)["helper"] {
		t.Fatal("a dead helper in a running program stopped being reported")
	}
}

// TestInnerDeclarationsAreStillUnusedInAModule. The exemption is per
// identifier node, not per name, so a local inside a module's function is
// still reportable.
func TestInnerDeclarationsAreStillUnusedInAModule(t *testing.T) {
	src := "let compute = fn(a) {\n\tlet scratch = a * 2;\n\treturn a;\n};\n"

	if !unusedNames(t, src)["scratch"] {
		t.Fatalf("a local inside a module's function stopped being reported: %v", unusedNames(t, src))
	}
}
