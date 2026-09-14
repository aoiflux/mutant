package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// grammarPath is the checked-in grammar, relative to this package.
const grammarPath = "../../" + defaultGrammarPath

func readGrammar(t *testing.T) string {
	t.Helper()

	document, err := os.ReadFile(filepath.FromSlash(grammarPath))
	if err != nil {
		t.Fatalf("reading %s: %v", grammarPath, err)
	}
	return string(document)
}

// TestGrammarHighlightsEveryBuiltin is the check ED-1 exists for, and it is
// deliberately written against the property a reader relies on rather than
// against the bytes: every registered builtin is highlighted, and the grammar
// names nothing that is not a builtin.
//
// Nothing in the suite had an opinion about this file before, which is exactly
// how 414 of 490 builtins came to be unhighlighted without a single red test.
// A generator alone would not have fixed that -- it would only have moved the
// moment the drift became possible from "someone forgets to edit the grammar"
// to "someone forgets to run the generator".
func TestGrammarHighlightsEveryBuiltin(t *testing.T) {
	match, err := grammarBuiltinMatch(readGrammar(t))
	if err != nil {
		t.Fatalf("reading the builtin rule out of %s: %v", grammarPath, err)
	}

	highlighted, err := grammarBuiltinNames(match)
	if err != nil {
		t.Fatalf("%s: %v", grammarPath, err)
	}
	registered, err := builtinNames()
	if err != nil {
		t.Fatalf("builtinNames: %v", err)
	}

	inGrammar := make(map[string]struct{}, len(highlighted))
	for _, name := range highlighted {
		inGrammar[name] = struct{}{}
	}
	inRegistry := make(map[string]struct{}, len(registered))
	for _, name := range registered {
		inRegistry[name] = struct{}{}
	}

	missing := difference(registered, inGrammar)
	if len(missing) > 0 {
		t.Errorf("%d of %d builtins are not highlighted by %s (%s); run `go run ./cmd/gendocs`",
			len(missing), len(registered), defaultGrammarPath, sample(missing))
	}

	// The other direction matters too: a name the grammar still paints after
	// the builtin behind it was renamed or removed is a call site the editor
	// says is fine and the compiler does not.
	stale := difference(highlighted, inRegistry)
	if len(stale) > 0 {
		t.Errorf("%s highlights %d name(s) that are not registered builtins (%s); run `go run ./cmd/gendocs`",
			defaultGrammarPath, len(stale), sample(stale))
	}
}

// TestGrammarIsUpToDate is the byte-level gate behind the property test: it
// catches an edit that keeps the same set of names but changes the pattern
// around them, which is the shape a hand-edit of a generated file takes.
func TestGrammarIsUpToDate(t *testing.T) {
	existing := readGrammar(t)

	want, err := renderGrammar(existing)
	if err != nil {
		t.Fatalf("renderGrammar: %v", err)
	}

	// The working tree may be checked out with CRLF endings, which says
	// nothing about whether the content drifted.
	if normalizeNewlines(existing) != normalizeNewlines(want) {
		t.Fatalf("%s is out of date; run `go run ./cmd/gendocs`", defaultGrammarPath)
	}
}

// TestGrammarOrdersPrefixesAfterWhatTheyPrefix pins the ordering the generator
// promises. The trailing `\b` means a shorter name cannot actually swallow a
// longer one here, so this is not load-bearing today -- it is pinned because
// the ordering is the only reason that stays true if the delimiter around the
// alternation is ever changed.
func TestGrammarOrdersPrefixesAfterWhatTheyPrefix(t *testing.T) {
	match, err := grammarBuiltinMatch(readGrammar(t))
	if err != nil {
		t.Fatalf("reading the builtin rule: %v", err)
	}
	names, err := grammarBuiltinNames(match)
	if err != nil {
		t.Fatalf("%s: %v", grammarPath, err)
	}

	position := make(map[string]int, len(names))
	for i, name := range names {
		position[name] = i
	}

	for _, shorter := range names {
		for _, longer := range names {
			if shorter == longer || !strings.HasPrefix(longer, shorter) {
				continue
			}
			if position[shorter] < position[longer] {
				t.Errorf("%q is listed before %q, which it prefixes", shorter, longer)
			}
		}
	}
}

// TestRenderGrammarTouchesOnlyTheBuiltinRule is the safety property that lets
// the rest of the grammar stay hand-written: the generator rewrites one string
// and leaves every other byte, including the line endings, where it found them.
func TestRenderGrammarTouchesOnlyTheBuiltinRule(t *testing.T) {
	const before = `\b(?:len|putln)\b(?=\s*\()`
	fixture := `{
  "name": "Mutant",
  "repository": {
    "keywords": {
      "patterns": [
        {
          "name": "keyword.control.mutant",
          "match": "\\b(?:fn|let|match)\\b"
        }
      ]
    },
    "builtins": {
      "patterns": [
        {
          "name": "` + builtinScope + `",
          "match": ` + quoted(t, before) + `
        }
      ]
    }
  }
}
`

	rendered, err := renderGrammar(fixture)
	if err != nil {
		t.Fatalf("renderGrammar: %v", err)
	}

	after, err := builtinAlternation()
	if err != nil {
		t.Fatalf("builtinAlternation: %v", err)
	}

	// Putting the old pattern back has to reproduce the input exactly. Anything
	// else means the rewrite reached outside the rule it owns.
	restored := strings.Replace(rendered, quoted(t, after), quoted(t, before), 1)
	if restored != fixture {
		t.Errorf("renderGrammar changed something other than the %s pattern", builtinScope)
	}
}

// TestRenderGrammarRefusesAGrammarWithoutTheRule covers the failure that would
// otherwise be silent: a grammar the generator cannot find its rule in would
// be written back unchanged, and -check would then pass on a file that
// highlights nothing.
func TestRenderGrammarRefusesAGrammarWithoutTheRule(t *testing.T) {
	if _, err := renderGrammar(`{"repository": {"keywords": {"patterns": []}}}`); err == nil {
		t.Error("renderGrammar accepted a grammar with no builtin rule")
	}
}

// TestGrammarBuiltinNamesRejectsAForeignShape makes sure the drift report
// cannot mistake a hand-written pattern for an empty one and quietly report
// that every builtin is missing from a file that is merely shaped differently.
func TestGrammarBuiltinNamesRejectsAForeignShape(t *testing.T) {
	if _, err := grammarBuiltinNames(`(?:len|putln)`); err == nil {
		t.Error("grammarBuiltinNames accepted a pattern that is not the generated shape")
	}
}

// quoted renders a pattern the way it appears inside the grammar's JSON.
func quoted(t *testing.T, pattern string) string {
	t.Helper()

	encoded, err := json.Marshal(pattern)
	if err != nil {
		t.Fatalf("encoding %q: %v", pattern, err)
	}
	return string(encoded)
}

// difference returns the names in want that are not in have, sorted.
func difference(want []string, have map[string]struct{}) []string {
	missing := make([]string, 0)
	for _, name := range want {
		if _, ok := have[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// sample keeps a failure message readable when hundreds of names are missing:
// the first few say which families drifted, and the count says how far.
func sample(names []string) string {
	const shown = 8
	if len(names) <= shown {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:shown], ", ") + ", ..."
}
