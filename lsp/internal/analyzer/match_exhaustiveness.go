package analyzer

// A match has to produce a value, so a subject no arm matches is a run-time
// error naming the value rather than a null flowing onward (L-8 decision 7).
// That is the right run-time answer and the wrong development one: the program
// that hits it has already shipped. This rule moves the report to the editor
// for the one case where the set of possible values is written down in the
// source -- an enum.
//
// The case it exists for is adding a variant. `enum Status { Ok, Failed }`
// grows a `Pending`, and every match over Status in the program is now one arm
// short. Nothing else notices: the code compiles, the tests that use Ok and
// Failed pass, and the gap surfaces the first time something is Pending.
//
// So the rule fires only where it can be certain, which means five guards:
//
//  1. Every arm's every pattern is `E.V` -- an identifier, a dot, a name. A
//     literal anywhere in the arms means the match is not a match over an enum
//     and this rule has nothing to say about what a total set of its values is.
//  2. All of them name the same E. Two enums in one match is a program doing
//     something this rule does not model.
//  3. No arm is `_`. A wildcard makes a match total by construction, which is
//     the whole point of having one.
//  4. E is declared as an enum in this document. An imported enum's pattern is
//     `mod.Status.Ok`, whose root is the namespace, so it fails this guard on
//     its own -- deliberately: the variants live in another file, and being
//     wrong about them would mean reporting a missing arm for a variant that
//     does not exist.
//  5. Nothing in the document binds E with a `let`. If a name is both an enum
//     and a variable, which one the pattern means is a question this rule
//     should not be answering.
//
// What is left is a match whose arms are variants of a known enum, with a
// variant of that enum absent. That is a fact about the source, not a guess
// about the program.

import (
	"fmt"
	"sort"
	"strings"

	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintMatchExhaustiveness(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("matchExhaustiveness")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	bound := namesBoundAnywhere(snapshot.Program.Statements)

	result := make([]lsp.Diagnostic, 0, 1)
	for node := range snapshot.Program.NodePositions {
		match, ok := node.(*mast.MatchExpression)
		if !ok || match == nil {
			continue
		}

		enumName, missing, ok := missingEnumVariants(snapshot, match, bound)
		if !ok {
			continue
		}

		// The subject rather than the whole match: an enum match is several
		// lines tall, and underlining all of them says "something here" where
		// the useful answer is "this value has a case you did not write".
		var anchor mast.Node = match
		if match.Subject != nil {
			anchor = match.Subject
		}
		rng, ok := snapshot.Program.RangeOf(anchor)
		if !ok {
			continue
		}

		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message: fmt.Sprintf(
				"this match covers only part of `%s`: %s %s no arm. A subject no arm matches is a run-time error, so add %s, or `_` for the rest.",
				enumName, quoteVariants(enumName, missing), haveOrHas(missing), theArm(missing)),
		})
	}

	// NodePositions iterates in map order, so the reports need an order of
	// their own or the same file lints differently twice in a row.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Range.Start.Line != result[j].Range.Start.Line {
			return result[i].Range.Start.Line < result[j].Range.Start.Line
		}
		return result[i].Range.Start.Character < result[j].Range.Start.Character
	})

	if len(result) == 0 {
		return nil
	}
	return result
}

// missingEnumVariants reports the variants of a single declared enum that this
// match's arms do not name, and whether the match qualifies at all.
func missingEnumVariants(snapshot *Snapshot, match *mast.MatchExpression, bound map[string]struct{}) (string, []string, bool) {
	if len(match.Arms) == 0 {
		return "", nil, false
	}

	enumName := ""
	covered := make(map[string]struct{}, len(match.Arms))
	for _, arm := range match.Arms {
		if arm == nil || arm.IsWildcard() {
			return "", nil, false
		}
		for _, pattern := range arm.Patterns {
			owner, variant, ok := enumVariantPattern(pattern)
			if !ok {
				return "", nil, false
			}
			if enumName == "" {
				enumName = owner
			} else if owner != enumName {
				return "", nil, false
			}
			covered[variant] = struct{}{}
		}
	}
	if enumName == "" {
		return "", nil, false
	}
	if _, rebound := bound[enumName]; rebound {
		return "", nil, false
	}

	variants, ok := snapshot.enumVariantNames(enumName)
	if !ok || len(variants) == 0 {
		return "", nil, false
	}

	missing := make([]string, 0, len(variants))
	for _, variant := range variants {
		if _, ok := covered[variant]; !ok {
			missing = append(missing, variant)
		}
	}
	if len(missing) == 0 {
		return "", nil, false
	}
	// Declaration order, not sorted: that is the order the arms will be read
	// against and the order an editor will show the enum in.
	return enumName, missing, true
}

// enumVariantPattern matches exactly `E.V` and nothing deeper. A longer chain
// is a namespaced enum from another file, whose variants this document cannot
// see.
func enumVariantPattern(pattern mast.Expression) (string, string, bool) {
	field, ok := pattern.(*mast.FieldExpression)
	if !ok || field == nil || field.Field == nil {
		return "", "", false
	}
	owner, ok := field.Left.(*mast.Identifier)
	if !ok || owner == nil || owner.Value == "" || field.Field.Value == "" {
		return "", "", false
	}
	return owner.Value, field.Field.Value, true
}

func quoteVariants(enumName string, variants []string) string {
	quoted := make([]string, 0, len(variants))
	for _, variant := range variants {
		quoted = append(quoted, fmt.Sprintf("`%s.%s`", enumName, variant))
	}
	if len(quoted) < 3 {
		return strings.Join(quoted, " and ")
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
}

func haveOrHas(variants []string) string {
	if len(variants) == 1 {
		return "has"
	}
	return "have"
}

func theArm(variants []string) string {
	if len(variants) == 1 {
		return "that arm"
	}
	return "those arms"
}
