package analyzer

import (
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/lexer"
	"mutant/parser"
)

// assignmentTargetMessages returns the messages of every assignmentTarget
// diagnostic in src. Both of them name an assignment target, and nothing else
// in the lint set does.
func assignmentTargetMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source == nil || *d.Source != "mutant-lint" {
			continue
		}
		if strings.Contains(d.Message, "no variable under it") ||
			strings.Contains(d.Message, "index before the last one") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The compiler refuses both of these. Without this rule the first anyone hears
// of either is a failed build, which is the thing CONTRIBUTING's editor-parity
// rule exists to stop.
func TestAssignmentTargetFiresOnWhatTheCompilerRefuses(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"an array literal has nowhere to store the result",
			`[1, 2][0] = 9;`,
			"no variable under it",
		},
		{
			"a call has nowhere to store the result",
			`let pick = fn() { return [1, 2]; };
pick()[0] = 9;`,
			"no variable under it",
		},
		{
			"a call as an index before the last one",
			`let a = [[1]];
let f = fn() { return 0; };
a[f()][0] = 1;`,
			"index before the last one",
		},
		{
			"an expression as an index before the last one",
			`let a = [[1]];
let i = 0;
a[i + 0][0] = 1;`,
			"index before the last one",
		},
		{
			"deep enough that the offending index is in the middle",
			`let a = [[[1]]];
let f = fn() { return 0; };
a[0][f()][0] = 1;`,
			"index before the last one",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			messages := assignmentTargetMessages(t, testCase.src)
			if len(messages) == 0 {
				t.Fatalf("no diagnostic, want one naming %q", testCase.want)
			}
			if !strings.Contains(messages[0], testCase.want) {
				t.Errorf("diagnostic was %q, want it to name %q", messages[0], testCase.want)
			}
		})
	}
}

// A rule that reports a program the compiler would have built is worse than no
// rule, because it tells someone their correct code is wrong. Every row here is
// something the compiler accepts -- including the nested writes the compiler
// gained a write-back chain for, which are the whole reason this is narrow.
func TestAssignmentTargetIsSilentOnWhatCompiles(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"a plain variable", `let x = 1; x = 2;`},
		{"one index", `let a = [1]; a[0] = 9;`},
		{"one key", `let h = {"a": 1}; h["a"] = 2;`},
		{"one field", `struct P { x; }; let p = P { x: 1 }; p.x = 2;`},
		{"two containers deep", `let g = [[1, 2]]; g[0][1] = 9;`},
		{"three containers deep", `let d = [[[1]]]; d[0][0][0] = 5;`},
		{"a name as the inner index", `let i = 0; let g = [[1, 2]]; g[i][1] = 9;`},
		{"a string literal as the inner key", `let h = {"a": [1]}; h["a"][0] = 2;`},
		{"a field between two indexes", `struct T { rows; }; let t = T { rows: [[1]] }; t.rows[0][0] = 2;`},
		{"a call as the last index, which is compiled once", `let f = fn() { return 0; }; let a = [[1]]; let i = 0; a[i][f()] = 1;`},
		{"a call as the only index", `let f = fn() { return 0; }; let a = [1]; a[f()] = 9;`},
		{"compound assignment through two containers", `let c = {"n": [10]}; c["n"][0] += 5;`},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if messages := assignmentTargetMessages(t, testCase.src); len(messages) != 0 {
				t.Errorf("reported %q, which compiles: %q", testCase.src, messages)
			}
		})
	}
}

// The rule restates a decision the compiler makes, and two copies of a decision
// drift. This runs both over the same programs and fails when they disagree,
// which is the only thing that keeps the editor's answer and the build's answer
// the same answer.
//
// The compiler is a test-only import here: the shipped language server does not
// link it, and should not -- it analyzes files that do not compile yet.
func TestTheEditorAndTheCompilerRefuseTheSameTargets(t *testing.T) {
	sources := []string{
		`[1, 2][0] = 9;`,
		`let pick = fn() { return [1, 2]; }; pick()[0] = 9;`,
		`let a = [[1]]; let f = fn() { return 0; }; a[f()][0] = 1;`,
		`let a = [[1]]; let i = 0; a[i + 0][0] = 1;`,
		`let a = [[[1]]]; let f = fn() { return 0; }; a[0][f()][0] = 1;`,
		`let x = 1; x = 2;`,
		`let a = [1]; a[0] = 9;`,
		`let h = {"a": 1}; h["a"] = 2;`,
		`struct P { x; }; let p = P { x: 1 }; p.x = 2;`,
		`let g = [[1, 2]]; g[0][1] = 9;`,
		`let d = [[[1]]]; d[0][0][0] = 5;`,
		`let i = 0; let g = [[1, 2]]; g[i][1] = 9;`,
		`let h = {"a": [1]}; h["a"][0] = 2;`,
		`struct T { rows; }; let t = T { rows: [[1]] }; t.rows[0][0] = 2;`,
		`let f = fn() { return 0; }; let a = [[1]]; let i = 0; a[i][f()] = 1;`,
		`let f = fn() { return 0; }; let a = [1]; a[f()] = 9;`,
		`let c = {"n": [10]}; c["n"][0] += 5;`,
	}

	for _, src := range sources {
		editorRefused := len(assignmentTargetMessages(t, src)) > 0

		err := compiler.New().Compile(parser.New(lexer.New(src)).ParseProgram())
		compilerRefused := err != nil &&
			(strings.Contains(err.Error(), "invalid assignment target") ||
				strings.Contains(err.Error(), "evaluated more than once"))

		if editorRefused != compilerRefused {
			t.Errorf("disagreement on %q: editor refused=%v, compiler refused=%v (%v)",
				src, editorRefused, compilerRefused, err)
		}
	}
}
