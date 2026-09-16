// The builtin half of the VS Code grammar is generated here, for the same
// reason the capability reference is: it was a hand-copied list of names, and a
// hand-copied list of 490 names is a list that falls behind. It carried 76 of
// them when this was written — none stale, but missing every builtin added in
// the last four rounds of work, `report_*` and `case_*` and `stix_*` included.
//
// Exactly one thing in the grammar is generated: the `match` pattern of the
// support.function.builtin.mutant rule. The rest — strings, keywords,
// operators, the declaration captures — is hand-written and stays that way. A
// full render would put carefully authored regexes under a generator that
// knows nothing about them, which trades one kind of drift for a worse one.
//
// What this closes is cosmetic, and worth being precise about: hover,
// completion, signature help and every diagnostic come from the language
// server, which derives them from builtin/metadata.go and so cannot fall
// behind. What a missing name costs is that a `report_new` call reads as an
// unknown identifier next to a highlighted `putln` — which tells the reader
// the wrong thing about what the language knows.

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"mutant/builtin"
)

const (
	defaultGrammarPath = "mutant-vscode-extension/syntaxes/mutant.tmLanguage.json"

	// builtinScope names the one rule in the grammar that gendocs owns.
	builtinScope = "support.function.builtin.mutant"

	// The alternation is wrapped so that a builtin is highlighted only where it
	// is called: `\b` keeps `fs_read` out of `my_fs_read`, and the lookahead
	// keeps a variable that shares a builtin's name unpainted.
	alternationPrefix = `\b(?:`
	alternationSuffix = `)\b(?=\s*\()`
)

// plainIdentifier is what a name must look like to go into the alternation
// unescaped. Every builtin has always looked like this; the check is here so
// that the day one does not, the generator says so instead of emitting a
// pattern with a live regex metacharacter in it.
var plainIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// grammarBuiltinRule finds the builtin rule's match assignment in the grammar
// text. It is anchored on the scope name rather than on position, so the
// rewrite cannot land in a neighbouring rule if the file is reordered.
var grammarBuiltinRule = regexp.MustCompile(
	`("name"\s*:\s*"` + regexp.QuoteMeta(builtinScope) + `"\s*,\s*"match"\s*:\s*)"(?:[^"\\]|\\.)*"`)

// builtinAlternation builds the match pattern from the registry.
//
// The names are sorted longest first so a shorter name cannot shadow a longer
// one it prefixes: `bytes_read_u16_be` and `bytes_read_u16_le` share sixteen
// characters, and an engine that commits to the first alternative it can match
// would paint half the call and leave the rest as plain text. The trailing
// `\b` makes the ordering belt-and-braces rather than load-bearing, which is
// the point — the pattern should not depend on which of the two it is.
func builtinAlternation() (string, error) {
	names, err := builtinNames()
	if err != nil {
		return "", err
	}
	sortLongestFirst(names)
	return alternationPrefix + strings.Join(names, "|") + alternationSuffix, nil
}

// builtinNames is the registry as the grammar sees it: every registered name,
// once each, in registration order.
func builtinNames() ([]string, error) {
	names := make([]string, 0, len(builtin.Builtins))
	seen := make(map[string]struct{}, len(builtin.Builtins))
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		if !plainIdentifier.MatchString(def.Name) {
			return nil, fmt.Errorf("builtin %q is not a plain identifier, so it cannot go into the grammar's alternation unescaped", def.Name)
		}
		if _, duplicate := seen[def.Name]; duplicate {
			continue
		}
		seen[def.Name] = struct{}{}
		names = append(names, def.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no builtins to write into the grammar")
	}
	return names, nil
}

// sortLongestFirst orders by descending length, then alphabetically so that
// two runs of the generator over the same registry produce the same bytes.
func sortLongestFirst(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
}

// grammarBuiltinMatch reads the builtin rule's pattern out of a grammar
// document. It parses the JSON rather than scraping it, so the answer is what
// VS Code would actually load.
func grammarBuiltinMatch(document string) (string, error) {
	var parsed struct {
		Repository map[string]struct {
			Patterns []struct {
				Name  string `json:"name"`
				Match string `json:"match"`
			} `json:"patterns"`
		} `json:"repository"`
	}
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return "", fmt.Errorf("parsing the grammar: %w", err)
	}

	for _, rule := range parsed.Repository {
		for _, pattern := range rule.Patterns {
			if pattern.Name == builtinScope {
				return pattern.Match, nil
			}
		}
	}
	return "", fmt.Errorf("the grammar has no %s rule", builtinScope)
}

// grammarBuiltinNames splits a match pattern back into the names it
// highlights, so a drift report can name the builtins that are missing rather
// than only say that something changed.
func grammarBuiltinNames(match string) ([]string, error) {
	if !strings.HasPrefix(match, alternationPrefix) || !strings.HasSuffix(match, alternationSuffix) {
		return nil, fmt.Errorf("the %s pattern is not the generated %s...%s shape", builtinScope, alternationPrefix, alternationSuffix)
	}
	body := match[len(alternationPrefix) : len(match)-len(alternationSuffix)]
	if body == "" {
		return nil, nil
	}
	return strings.Split(body, "|"), nil
}

// renderGrammar returns the grammar with the builtin alternation replaced and
// everything else exactly as it was found, line endings included. It takes the
// existing document rather than building one from scratch because the
// hand-written rules around the builtins are not gendocs's to rewrite.
func renderGrammar(document string) (string, error) {
	alternation, err := builtinAlternation()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(alternation)
	if err != nil {
		return "", fmt.Errorf("encoding the alternation as a JSON string: %w", err)
	}

	found := grammarBuiltinRule.FindAllStringIndex(document, -1)
	if len(found) != 1 {
		return "", fmt.Errorf("expected exactly one %s rule with a match pattern, found %d", builtinScope, len(found))
	}

	rendered := grammarBuiltinRule.ReplaceAllStringFunc(document, func(rule string) string {
		return grammarBuiltinRule.FindStringSubmatch(rule)[1] + string(encoded)
	})

	// Read the result back through the parser rather than trusting the
	// substitution. A rewrite that produced invalid JSON would ship a grammar
	// VS Code silently declines to load, and a file that highlights nothing at
	// all looks a lot like a file that is simply not a Mutant file.
	got, err := grammarBuiltinMatch(rendered)
	if err != nil {
		return "", fmt.Errorf("the rewritten grammar does not parse back: %w", err)
	}
	if got != alternation {
		return "", fmt.Errorf("the rewritten grammar's %s pattern is not the one that was written", builtinScope)
	}
	return rendered, nil
}
