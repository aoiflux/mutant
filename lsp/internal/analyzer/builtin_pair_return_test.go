package analyzer

import (
	"strings"
	"testing"
)

// pairReturnMessages returns the messages of every builtinPairReturn diagnostic
// in src. That rule's messages are the only lint messages that read "holds the
// pair itself".
func pairReturnMessages(t *testing.T, src string) []string {
	t.Helper()
	return pairReturnMessagesWithConfig(t, src, DefaultLintConfig())
}

func pairReturnMessagesWithConfig(t *testing.T, src string, config LintConfig) []string {
	t.Helper()
	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "holds the pair itself") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The three cases below are the defects that prompted the rule, reduced to their
// shape. All three shipped in the examples and all three ran without complaint:
// a pair prints as its value, so nothing about them looks wrong until the name
// reaches something that inspects it.
func TestBuiltinPairReturnFiresOnSingleBinding(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			// portscan_service/handler.mut: is_null(conn) was never true, so the
			// standalone notice its own header documents never printed.
			"a null check that can never fire",
			`let conn = serve_conn();
if (is_null(conn)) { putln("standalone"); };`,
			"`conn` holds the pair itself",
		},
		{
			// dependency_version_auditor.mut: fs_write was handed the MULTI_VALUE
			// and the seeded package.json was silently never written.
			"the pair passed on to another builtin",
			`let package_seed = json_stringify({"a": 1});
let ok, err = fs_write("package.json", package_seed);`,
			"not the STRING it carries",
		},
		{
			"the pair used in arithmetic",
			`let banner = serve_arg();
putln(banner + "\r\n");`,
			"not the value it carries",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pairReturnMessages(t, tc.src)
			if len(got) != 1 {
				t.Fatalf("expected exactly one diagnostic, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], tc.want) {
				t.Fatalf("message does not explain the problem.\ngot:  %s\nwant substring: %s", got[0], tc.want)
			}
			if !strings.Contains(got[0], "Bind two names") {
				t.Fatalf("message does not say what to do instead: %s", got[0])
			}
		})
	}
}

// Everything below is a case the rule must stay silent on. 286 of the 409
// builtins return a pair, so this rule sees more code than any other in the
// analyzer; one wrong report would be worth more than every right one.
func TestBuiltinPairReturnStaysSilent(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"the correct destructuring", `let data, err = fs_read("f.txt");
putln(data);`},
		{"the error discarded on purpose", `let data, _ = fs_read("f.txt");
putln(data);`},
		{"one name from a single-return builtin", `let items = push([], 1);
putln(items);`},
		{"a user function, not a builtin", `let read = fn(p) { return 1; };
let data = read("f.txt");
putln(data);`},
		{"an unknown name", `let data = not_a_builtin("f.txt");
putln(data);`},
		{"the builtin name is shadowed at the top level", `let fs_read = fn(p) { return 1; };
let data = fs_read("f.txt");
putln(data);`},
		{"the builtin name is shadowed by a local", `let f = fn() {
    let fs_read = fn(p) { return 1; };
    let data = fs_read("f.txt");
    return data;
};`},
		{"a call that is not an identifier callee", `let fns = [fn() { return 1; }];
let data = fns[0]();
putln(data);`},
		{"not a call at all", `let data = 42;
putln(data);`},
		{"the discard name", `let _ = fs_read("f.txt");`},
		// The three ways a program can legitimately hold a pair. Each was run
		// through the VM before being accepted as a guard.
		{"the pair is indexed", `let r = json_stringify({"a": 1});
putln(r[0]);`},
		{"the pair is forwarded out of a function", `let encode = fn(h) {
    let r = json_stringify(h);
    return r;
};
let text, err = encode({"a": 1});
putln(text);`},
		{"the pair is destructured a statement later", `let r = json_stringify({"a": 1});
let text, err = r;
putln(text);`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pairReturnMessages(t, tc.src); len(got) != 0 {
				t.Fatalf("rule fired on correct code: %v", got)
			}
		})
	}
}

// The suppression has to survive being buried. namesHeldAsPairs walks the whole
// program rather than the binding's own statement list, because the use that
// proves the author meant to hold a pair is rarely next to the binding.
func TestBuiltinPairReturnFindsAHeldPairAnywhere(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"inside an if", `let r = json_stringify({"a": 1});
if (true) { putln(r[0]); };`},
		{"inside a for body", `let r = json_stringify({"a": 1});
for (let i = 0; i < 2; i = i + 1) { putln(r[0]); };`},
		{"inside a nested function", `let r = json_stringify({"a": 1});
let show = fn() { return fn() { putln(r[1]); }; };
show();`},
		{"inside an else branch", `let r = json_stringify({"a": 1});
if (false) { putln("no"); } else { putln(r[0]); };`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pairReturnMessages(t, tc.src); len(got) != 0 {
				t.Fatalf("rule fired although the pair is held: %v", got)
			}
		})
	}
}

// An `if` with no `else` puts a nil *ast.BlockStatement into a Statement
// interface, which is not an untyped nil. The first version of the walk let that
// reach a case that dereferenced it and took the whole `mutant lint` process
// down with a Go panic -- on the very first real program it was pointed at.
func TestBuiltinPairReturnSurvivesAnAbsentElseBranch(t *testing.T) {
	src := `let conn = serve_conn();
if (is_null(conn)) {
    putln("standalone");
};
for (let i = 0; i < 1; i = i + 1) {
    if (true) { putln("x"); };
};`

	got := pairReturnMessages(t, src)
	if len(got) != 1 {
		t.Fatalf("expected the binding to be reported, got %d: %v", len(got), got)
	}
}

func TestBuiltinPairReturnRespectsSeverityOff(t *testing.T) {
	src := `let data = fs_read("f.txt");
putln(data);`

	config := DefaultLintConfig()
	if got := pairReturnMessagesWithConfig(t, src, config); len(got) != 1 {
		t.Fatalf("expected the rule on by default, got %d diagnostics", len(got))
	}

	config.BuiltinPairReturn = LintSeverityOff
	if got := pairReturnMessagesWithConfig(t, src, config); len(got) != 0 {
		t.Fatalf("rule still fired with severity off: %v", got)
	}
}

// Turning this rule off must not disturb the two rules it shares a walk with,
// nor the one it mirrors.
func TestBuiltinPairReturnOffLeavesTheOtherRulesAlone(t *testing.T) {
	config := DefaultLintConfig()
	config.BuiltinPairReturn = LintSeverityOff

	arity := make([]string, 0, 1)
	for _, d := range Diagnostics(New().Analyze(`let x = abs(1, 2);`), config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "takes") {
			arity = append(arity, d.Message)
		}
	}
	if len(arity) == 0 {
		t.Fatal("switching off builtinPairReturn also silenced builtinArity")
	}
	if got := argTypeMessagesWithConfig(t, `let x = str_upper(42);`, config); len(got) == 0 {
		t.Fatal("switching off builtinPairReturn also silenced builtinArgType")
	}
	if got := singleReturnMessagesWithConfig(t, `let updated, err = push([], 1);`, config); len(got) == 0 {
		t.Fatal("switching off builtinPairReturn also silenced builtinSingleReturn")
	}
}

// The two rules are mirrors, and a program can only be on one side of the
// mistake at a time. If either ever reported the other's shape, one of them
// would be telling the author to write what the other forbids.
func TestTheTwoReturnRulesNeverBothFire(t *testing.T) {
	cases := []string{
		`let data = fs_read("f.txt");
putln(data);`,
		`let updated, err = push([], 1);
putln(updated);`,
		`let data, err = fs_read("f.txt");
putln(data);`,
		`let items = push([], 1);
putln(items);`,
	}

	for _, src := range cases {
		pair := pairReturnMessages(t, src)
		single := singleReturnMessages(t, src)
		if len(pair) > 0 && len(single) > 0 {
			t.Fatalf("both rules fired on the same program:\n%s\npair:   %v\nsingle: %v", src, pair, single)
		}
	}
}
