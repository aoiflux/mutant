package analyzer

import (
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// A for-in loop declares its bindings in its header, and nothing else in the
// file declares them. Every walk that tracks what is in scope has to say so,
// and until L-8 phase 4 none of them did: the name a loop body is written
// around was undefined to the analyzer.
//
// That is the worst shape a false positive can take. undefinedDeclaration is
// the one rule that defaults to error severity, and `mutant lint` exits
// non-zero on an error whatever its flags -- so linting any program that used
// the loop failed, on correct code, with a red squiggle under the loop
// variable.
func TestAForInBindingIsNotUndefined(t *testing.T) {
	sources := map[string]string{
		"one binding":   "let xs = [1, 2];\nfor (v in xs) { putln(\"${v}\"); }\n",
		"two bindings":  "let xs = [1, 2];\nfor (i, v in xs) { putln(\"${i}${v}\"); }\n",
		"over a hash":   "let h = {\"a\": 1};\nfor (k, v in h) { putln(\"${k}${v}\"); }\n",
		"over a string": "for (c in \"ab\") { putln(\"${c}\"); }\n",
		"nested":        "let rows = [[1], [2]];\nfor (row in rows) { for (cell in row) { putln(\"${cell}\"); } }\n",
	}

	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			if names := undefinedNames(t, src); len(names) != 0 {
				t.Fatalf("a for-in binding was reported undefined: %v", names)
			}
		})
	}
}

// The other half: the walk must not become blind. A name nothing declares is
// still undefined when it is read beside a loop that declares one.
func TestATypoIsStillUndefinedInsideAForIn(t *testing.T) {
	src := "let xs = [1, 2];\nfor (v in xs) { putln(\"${vv}\"); }\n"
	if !undefinedNames(t, src)["vv"] {
		t.Errorf("a misspelled name inside a for-in body went unreported")
	}
}

// The binding is a declaration, so the editor has to answer for it: hovering
// or go-to-definition on the loop variable inside the body must find the
// header, and completion inside the body must offer it.
func TestAForInBindingResolvesAndCompletes(t *testing.T) {
	src := "let xs = [1, 2];\nfor (v in xs) { putln(\"${v}\"); }\n"
	snapshot := New().Analyze(src)

	// Line 1 (0-based), the `v` inside the hole.
	pos := lsp.Position{Line: 1, Character: 25}
	if _, ok := snapshot.DefinitionLocation("file:///t.mut", pos); !ok {
		t.Errorf("go-to-definition on a for-in binding found nothing")
	}

	found := false
	for _, item := range snapshot.CompletionItemsAt(pos) {
		if item.Label == "v" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("completion inside a for-in body did not offer the loop binding")
	}
}

// A loop binding that shadows a builtin is a binding, not the builtin. Without
// the header in this collector's scope, `for (max in xs) { max(1, 2); }` is
// held to max's declared contract and reports an arity error on a call the
// program never makes to the builtin.
func TestAForInBindingShadowsABuiltin(t *testing.T) {
	src := "let xs = [1, 2];\nfor (max in xs) { putln(\"${max}\"); }\n"
	if messages := lintMessages(t, src); mentions(messages, "max") {
		t.Errorf("a loop binding named after a builtin drew a builtin diagnostic: %v", messages)
	}
}
