package analyzer

import (
	"strings"
	"testing"

	mast "mutant/ast"
)

// M26-LSP-025. The parser records a return's first value twice -- as
// ReturnValue and as ReturnValues[0] -- and two of the package's walkers
// followed both. Every rule built on forEachBuiltinCall reported a call written
// in a `return` twice, and forEachStatementInScope visited the statements of an
// `if` or `match` a return hands back twice.

func TestACallInAReturnIsReportedOnce(t *testing.T) {
	src := `let dump = fn(r) {
    return putln(record_read(r, 0, 4));
};
let shell = fn(host) {
    return exec_string("whois " + host);
};
let reopen = fn(path) {
    return case_key_open(path, {"passphrase": "hunter2"});
};
`
	snapshot := New().Analyze(src)
	counts := map[string]int{}
	markers := map[string]string{
		"classifiedPlaintext": "refuses classified plaintext",
		"commandInjection":    "gives to a shell",
		"secretOption":        caseRuleMarkers["secretOption"],
	}
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		for rule, marker := range markers {
			if strings.Contains(d.Message, marker) {
				counts[rule]++
			}
		}
	}
	for rule := range markers {
		if counts[rule] != 1 {
			t.Errorf("%s reported the call in a return %d times, want once", rule, counts[rule])
		}
	}
}

func TestAStatementInsideAReturnedBlockIsVisitedOnce(t *testing.T) {
	src := `let pick = fn(c) {
    return if (c) { let a = 1; a } else { let b = 2; b };
};
`
	program := New().Analyze(src).Program
	if program == nil || len(program.Statements) != 1 {
		t.Fatal("the program did not parse into one statement")
	}
	let, ok := program.Statements[0].(*mast.LetStatement)
	if !ok {
		t.Fatalf("got %T, want a let", program.Statements[0])
	}
	literal, ok := let.Value.(*mast.FunctionLiteral)
	if !ok || literal.Body == nil {
		t.Fatalf("got %T, want a function literal", let.Value)
	}
	visits := map[mast.Statement]int{}
	forEachStatementInScope(literal.Body.Statements, func(stmt mast.Statement) { visits[stmt]++ })
	lets := 0
	for stmt, n := range visits {
		if n != 1 {
			t.Errorf("%q was visited %d times, want once", stmt.String(), n)
		}
		if _, isLet := stmt.(*mast.LetStatement); isLet {
			lets++
		}
	}
	if lets != 2 {
		t.Errorf("visited %d of the two lets in the returned arms", lets)
	}
}
