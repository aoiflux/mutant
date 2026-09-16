package analyzer

import (
	"testing"
)

// TestANameUsedOnlyInAWhileConditionIsUsed is the false-positive class every
// walker arm added for L-8 exists to prevent: a name a loop reads and nothing
// else reads would otherwise be reported as never used -- a warning on correct
// code, which is worse than no warning.
func TestANameUsedOnlyInAWhileConditionIsUsed(t *testing.T) {
	src := "let limit = 10;\nlet i = 0;\nwhile (i < limit) { i = i + 1; }\nputln(\"${i}\");\n"
	if unusedNames(t, src)["limit"] {
		t.Errorf("`limit` is read by the loop condition and was still reported unused")
	}
}

func TestANameUsedOnlyInAWhileBodyIsUsed(t *testing.T) {
	src := "let step = 2;\nlet i = 0;\nwhile (i < 6) { i = i + step; }\nputln(\"${i}\");\n"
	if unusedNames(t, src)["step"] {
		t.Errorf("`step` is read inside the loop body and was still reported unused")
	}
}

func TestAnUnusedNameIsStillUnusedBesideAWhile(t *testing.T) {
	// The other half: the arms must not make the rule blind. A name nothing
	// reads is still reported when a loop stands next to it.
	src := "let spare = 1;\nlet i = 0;\nwhile (i < 3) { i = i + 1; }\nputln(\"${i}\");\n"
	if !unusedNames(t, src)["spare"] {
		t.Errorf("`spare` is never read and should still be reported")
	}
}

func TestATypoInAWhileConditionIsUndefined(t *testing.T) {
	src := "let limit = 10;\nlet i = 0;\nwhile (i < limti) { i = i + 1; }\n"
	if !mentions(lintMessages(t, src), "limti") {
		t.Errorf("a misspelled name in a while condition went unreported")
	}
}

func TestACallInAWhileConditionIsArgumentChecked(t *testing.T) {
	// The condition is an ordinary expression, so every builtin rule reaches it.
	src := "while (str_upper(42) == \"\") { break; }\n"
	if !mentions(lintMessages(t, src), "str_upper") {
		t.Errorf("a builtin call in a while condition was not checked")
	}
}

func TestANameUsedOnlyAsAnIterableIsUsed(t *testing.T) {
	src := "let xs = [1, 2, 3];\nfor (v in xs) { putln(\"${v}\"); }\n"
	if unusedNames(t, src)["xs"] {
		t.Errorf("`xs` is what the loop walks and was still reported unused")
	}
}

// TestALoopBindingIsNotUndefined is the other false-positive direction: the
// binding is a declaration the loop introduces, so every use of it inside the
// body has to resolve.
func TestALoopBindingIsNotUndefined(t *testing.T) {
	src := "let xs = [1, 2, 3];\nfor (i, v in xs) { putln(\"${i}${v}\"); }\n"
	messages := lintMessages(t, src)
	for _, name := range []string{"\"i\"", "\"v\""} {
		if mentions(messages, name) {
			t.Errorf("the loop binding %s was reported as undefined: %v", name, messages)
		}
	}
}

func TestATypoInAnIterableIsUndefined(t *testing.T) {
	src := "let xs = [1, 2, 3];\nfor (v in sx) { putln(\"${v}\"); }\n"
	if !mentions(lintMessages(t, src), "sx") {
		t.Errorf("a misspelled iterable went unreported")
	}
}

func TestACallInAnIterableIsArgumentChecked(t *testing.T) {
	src := "for (v in str_upper(42)) { putln(\"${v}\"); }\n"
	if !mentions(lintMessages(t, src), "str_upper") {
		t.Errorf("a builtin call in an iterable was not checked")
	}
}
