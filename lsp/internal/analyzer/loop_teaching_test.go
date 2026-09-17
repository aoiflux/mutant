package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Mutant has three loop constructs and they are three different things: a
// three-clause `for`, a `for ... in` over a collection, and a `while`. Hover
// used to describe two of them with one card, because *mast.ForStatement and
// *mast.ForInStatement were both dispatched to keywordHoverDocs["for"] -- the
// entry that opens "Loop construct with init, condition, and post expressions".
// A reader hovering `for (host in hosts)` was told about an init, a condition
// and a post section that construct does not have.
//
// The text that does describe it was already in the table, under "in", and was
// reachable from nowhere: `in` is not an AST node, so a cursor on it lands on
// the enclosing ForInStatement and got the `for` card too.
//
// These tests assert on what the card says rather than merely that the two
// differ, because two wrong cards that differ would pass the weaker check.

// hoverAt is the position-free form used throughout this file: every fixture is
// one line, so a column is enough.
func hoverAt(t *testing.T, src string, col int) string {
	t.Helper()
	text, _, ok := New().Analyze(src).HoverText(lsp.Position{Character: lsp.UInteger(col)})
	if !ok {
		t.Fatalf("hovering %q at column %d produced nothing", src, col)
	}
	return text
}

// TestEachLoopConstructHasItsOwnCard is the defect. The three cards must differ
// from each other; before the fix two of them were byte-identical.
func TestEachLoopConstructHasItsOwnCard(t *testing.T) {
	classic := hoverAt(t, "for (let i = 0; i < 3; i = i + 1) { }", 1)
	forIn := hoverAt(t, "for (v in [1, 2, 3]) { }", 1)
	while := hoverAt(t, "while (true) { }", 1)

	cards := map[string]string{"for": classic, "for ... in": forIn, "while": while}
	for a, textA := range cards {
		for b, textB := range cards {
			if a < b && textA == textB {
				t.Errorf("the %s and %s cards are identical:\n%s", a, b, textA)
			}
		}
	}
}

// TestTheForInCardDescribesForIn pins the facts that card exists to carry. Each
// one is a thing the three-clause card cannot say and a reader cannot infer.
func TestTheForInCardDescribesForIn(t *testing.T) {
	card := hoverAt(t, "for (v in [1, 2, 3]) { }", 1)

	// It must not be the three-clause card.
	if strings.Contains(card, "post section before re-testing") {
		t.Fatalf("for ... in still hovers as the three-clause loop:\n%s", card)
	}

	for _, want := range []string{
		"for (k, v in xs)",            // the two-binding form
		"**key**",                     // one binding over a hash yields keys, not values
		"sorted key order",            // hash iteration order is deterministic
		"rune",                        // strings iterate by rune
		"bytes",                       // and a bytes buffer does not
		"advance is the post section", // what continue does here
	} {
		if !strings.Contains(card, want) {
			t.Errorf("the for ... in card does not mention %q:\n%s", want, card)
		}
	}
}

// TestTheThreeClauseCardDescribesTheThreeClauseLoop is the control. A fix that
// simply swapped which card both constructs got would fail here.
func TestTheThreeClauseCardDescribesTheThreeClauseLoop(t *testing.T) {
	card := hoverAt(t, "for (let i = 0; i < 3; i = i + 1) { }", 1)

	for _, want := range []string{
		"for (init; cond; post)",
		"for (;;)",                       // the endless form, which while cannot spell
		"post section before re-testing", // what continue does here
	} {
		if !strings.Contains(card, want) {
			t.Errorf("the three-clause card does not mention %q:\n%s", want, card)
		}
	}
}

// TestTheWhileCardSaysTheConditionIsRequired. `while ()` is a parse error rather
// than an endless loop, which is the one thing about `while` a reader coming
// from `for (;;)` would guess wrong.
func TestTheWhileCardSaysTheConditionIsRequired(t *testing.T) {
	card := hoverAt(t, "while (true) { }", 1)

	for _, want := range []string{"while ()", "while (true)", "straight back to the condition"} {
		if !strings.Contains(card, want) {
			t.Errorf("the while card does not mention %q:\n%s", want, card)
		}
	}
}

// TestEveryLoopCardSaysTheBindingIsShared. Neither engine gives a fresh binding
// per iteration -- the evaluator re-Sets one loop environment, the compiler
// defines the symbol once so the slot is stable -- so a closure made in a loop
// body sees the final value. That is the loop fact most likely to be assumed
// the other way, and no card said it.
func TestEveryLoopCardSaysTheBindingIsShared(t *testing.T) {
	for name, src := range map[string]string{
		"for":        "for (let i = 0; i < 3; i = i + 1) { }",
		"for ... in": "for (v in [1, 2, 3]) { }",
	} {
		card := hoverAt(t, src, 1)
		if !strings.Contains(card, "fresh") {
			t.Errorf("the %s card does not say the binding is not fresh per iteration:\n%s", name, card)
		}
	}
}

// TestKeywordCompletionCarriesDocumentation. The descriptions sat one file away
// from the completion items and were not attached to them, which left `in`,
// `else`, `true` and `false` documented nowhere a reader could reach: none is an
// AST node of its own, so hover on one lands on whatever encloses it.
func TestKeywordCompletionCarriesDocumentation(t *testing.T) {
	items := New().Analyze("").CompletionItemsAt(lsp.Position{})

	documented := make(map[string]bool, len(items))
	for _, item := range items {
		if item.Kind == nil || *item.Kind != lsp.CompletionItemKindKeyword {
			continue
		}
		content, ok := item.Documentation.(lsp.MarkupContent)
		documented[item.Label] = ok && strings.TrimSpace(content.Value) != ""
	}

	for _, keyword := range []string{"for", "in", "while", "break", "continue", "else", "true", "false"} {
		seen, present := documented[keyword]
		if !present {
			t.Errorf("keyword %q is not offered in completion at all", keyword)
			continue
		}
		if !seen {
			t.Errorf("keyword %q is offered with no documentation", keyword)
		}
	}
}
