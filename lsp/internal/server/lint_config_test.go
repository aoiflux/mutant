package server

import (
	"reflect"
	"testing"
	"unicode"

	"mutant/lsp/internal/analyzer"
)

// ruleNameForField derives the settings key for a LintConfig field. Every rule
// is spelled as its field name with a lower-case first letter —
// DuplicateTopLevelDeclaration ⇒ duplicateTopLevelDeclaration.
func ruleNameForField(field string) string {
	if field == "" {
		return ""
	}
	runes := []rune(field)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

// TestEveryLintRuleIsSettable walks LintConfig by reflection and checks each
// field can actually be driven from `mutant.lint.rules.<name>.severity`.
//
// This is the seam where a new rule goes quietly wrong: forget the
// applyRuleSeverity line and the setting exists in package.json, is accepted
// without complaint, and does nothing. Enumerating the fields rather than
// listing rule names means a rule added later is covered without anyone
// remembering to extend this test.
func TestEveryLintRuleIsSettable(t *testing.T) {
	configType := reflect.TypeOf(analyzer.LintConfig{})
	if configType.NumField() == 0 {
		t.Fatal("LintConfig has no fields")
	}

	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)
		rule := ruleNameForField(field.Name)

		t.Run(rule, func(t *testing.T) {
			settings := map[string]any{
				"mutant": map[string]any{
					"lint": map[string]any{
						"rules": map[string]any{
							rule: map[string]any{"severity": "off"},
						},
					},
				},
			}

			config := parseLintConfig(settings)
			got := reflect.ValueOf(config).Field(i).Interface()
			if got != analyzer.LintSeverityOff {
				t.Fatalf("setting %s to \"off\" left %s = %v; is applyRuleSeverity wired for it?",
					rule, field.Name, got)
			}

			// The other rules must be untouched — one knob moves one rule.
			defaults := analyzer.DefaultLintConfig()
			for j := 0; j < configType.NumField(); j++ {
				if j == i {
					continue
				}
				other := reflect.ValueOf(config).Field(j).Interface()
				want := reflect.ValueOf(defaults).Field(j).Interface()
				if other != want {
					t.Errorf("setting %s also changed %s: got %v, want %v",
						rule, configType.Field(j).Name, other, want)
				}
			}
		})
	}
}

func TestParseLintConfigFallsBackToDefaults(t *testing.T) {
	defaults := analyzer.DefaultLintConfig()

	for _, settings := range []any{
		nil,
		map[string]any{},
		map[string]any{"mutant": map[string]any{}},
		map[string]any{"mutant": map[string]any{"lint": map[string]any{}}},
		map[string]any{"mutant": map[string]any{"lint": map[string]any{"rules": "not a map"}}},
		"not settings at all",
	} {
		if got := parseLintConfig(settings); got != defaults {
			t.Errorf("parseLintConfig(%#v) = %+v, want the defaults %+v", settings, got, defaults)
		}
	}
}
