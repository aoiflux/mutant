package analyzer

import (
	"strings"
	"testing"
)

// TestDiagnosticsSurviveATreeWithHolesInIt pins the outage M26-LEX-010 caused.
//
// didOpen of `f()[-,] = 1;` took the whole language server out at rc=2. The
// stack ran PrefixExpression.String <- IndexExpression.String <-
// lintAssignmentTargets <- Diagnostics <- publishDiagnostics <- didOpen, on
// jsonrpc2's reader goroutine, and nothing on it recovers: not
// publishDiagnostics, not glsp, not jsonrpc2. The parse of that text leaves a
// nil where the index expression's operand should be -- parseExpression
// appends an error and returns nil when no prefix function claims the token --
// and the lint prints the target to name it in the message.
//
// Every input here is a transient editing state: text somebody is part-way
// through typing, which the server is asked about on the keystroke. Three of
// them did NOT crash, and they are kept because the reason is accidental: the
// parser drops the index there, since expectPeek(']') fails before the nil is
// ever stored. Nothing says the next edit to the parser keeps that true.
//
// The assertion is on Diagnostics as a whole rather than on one rule. The
// defect was not that a particular rule was careless; it was that a tree with
// holes in it could not be printed, and any rule that printed one was an
// outage.
func TestDiagnosticsSurviveATreeWithHolesInIt(t *testing.T) {
	sources := []string{
		"f()[-,] = 1;",    // the one that killed the process
		"[1][1 + ,] = 3;", // the second one reported
		"a[-] = v;",       // did not crash: the parser drops the index
		"a[-][0] = 1;",    // did not crash, same reason
		"a[i + ][0] = 3;", // did not crash, same reason
		"1 + ;",           // a nil infix operand
		"-;",              // a nil prefix operand
		"!",               // a prefix operator and then end of file
		"let x = ;",       // a nil let value
		"x = ;",           // a nil assignment value
		"x += ;",          // the compound form of the same
		"f(1, , 2);",      // a nil call argument
		"{1: };",          // a nil hash value
		"[1, , 2];",       // a nil array element
		"x.;",             // a nil field
		"if () { }",       // a nil condition
		"while () { }",    // the same in the other loop
		"match (x) { => 1 };",
		"let s = \"abc", // an unterminated literal, which produces no node
		"for (;;) {",    // an unclosed block
	}

	for _, src := range sources {
		t.Run(strings.TrimSpace(src), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Diagnostics panicked on %q: %v", src, r)
				}
			}()
			// The count is not asserted: what these inputs produce is the
			// parser's business and several of them produce nothing. That the
			// call returns at all is the whole contract.
			Diagnostics(New().Analyze(src), DefaultLintConfig())
		})
	}
}

// TestADiagnosticNamesAMissingChildRatherThanHidingIt is the half that is not
// about crashing: the message is built by printing the target, so what it
// prints has to be what the file says.
//
// Both inputs are the ones that killed the process, and both keep their hole
// all the way into the tree -- which not every malformed input does. An empty
// element in a list does not: parseExpressionList drops it, so `f(1, , 2)`
// reaches the tree as a call of two arguments, and the program is refused by
// the parser either way with "no prefix parse function for , found". There is
// nothing silent in that one, which is why it is not the input used here.
func TestADiagnosticNamesAMissingChildRatherThanHidingIt(t *testing.T) {
	for src, want := range map[string]string{
		"f()[-,] = 1;":    "(f()[(-<missing>)])",
		"[1][1 + ,] = 3;": "([1][(1 + <missing>)])",
	} {
		messages := assignmentTargetMessages(t, src)
		if len(messages) == 0 {
			t.Errorf("%q: no assignment-target diagnostic, so nothing printed the tree", src)
			continue
		}
		if !strings.Contains(messages[0], want) {
			t.Errorf("%q: diagnostic quoted %q, want it to contain %q", src, messages[0], want)
		}
	}
}
