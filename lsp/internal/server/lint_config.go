package server

import (
	"strings"

	"mutant/lsp/internal/analyzer"
)

func parseLintConfig(settings any) analyzer.LintConfig {
	config := analyzer.DefaultLintConfig()
	applyLintConfig(&config, settings)
	return config
}

func applyLintConfig(config *analyzer.LintConfig, settings any) {
	if config == nil || settings == nil {
		return
	}

	root, ok := settings.(map[string]any)
	if !ok {
		return
	}

	if nested, ok := root["mutant"]; ok {
		applyLintConfig(config, nested)
		return
	}

	lintValue, ok := root["lint"]
	if !ok {
		return
	}
	lintMap, ok := lintValue.(map[string]any)
	if !ok {
		return
	}
	rulesValue, ok := lintMap["rules"]
	if !ok {
		return
	}
	rulesMap, ok := rulesValue.(map[string]any)
	if !ok {
		return
	}

	applyRuleSeverity(rulesMap, "duplicateTopLevelDeclaration", &config.DuplicateTopLevelDeclaration)
	applyRuleSeverity(rulesMap, "unusedDeclaration", &config.UnusedDeclaration)
	applyRuleSeverity(rulesMap, "undefinedDeclaration", &config.UndefinedDeclaration)
	applyRuleSeverity(rulesMap, "nestingComplexity", &config.NestingComplexity)
	applyRuleSeverity(rulesMap, "semicolon", &config.Semicolon)
	applyRuleSeverity(rulesMap, "unreachableCode", &config.UnreachableCode)
	applyRuleSeverity(rulesMap, "platformSupport", &config.PlatformSupport)
	applyRuleSeverity(rulesMap, "builtinArity", &config.BuiltinArity)
	applyRuleSeverity(rulesMap, "builtinArgType", &config.BuiltinArgType)
	applyRuleSeverity(rulesMap, "builtinSingleReturn", &config.BuiltinSingleReturn)
}

// parseStrictFormatting reads `mutant.strictFormatting`, defaulting to true.
//
// It is intentionally a single boolean. The setting decides *whether* the
// server formats, never *how* — exposing style options would defeat the
// purpose of a canonical formatter.
func parseStrictFormatting(settings any) bool {
	enabled := true
	readStrictFormatting(&enabled, settings)
	return enabled
}

func readStrictFormatting(enabled *bool, settings any) {
	if enabled == nil || settings == nil {
		return
	}

	root, ok := settings.(map[string]any)
	if !ok {
		return
	}

	if nested, ok := root["mutant"]; ok {
		readStrictFormatting(enabled, nested)
		return
	}

	raw, ok := root["strictFormatting"]
	if !ok {
		return
	}
	if value, ok := raw.(bool); ok {
		*enabled = value
	}
}

func applyRuleSeverity(rules map[string]any, ruleName string, target *analyzer.LintSeverity) {
	if target == nil {
		return
	}
	rawRule, ok := rules[ruleName]
	if !ok {
		return
	}
	ruleMap, ok := rawRule.(map[string]any)
	if !ok {
		return
	}
	rawSeverity, ok := ruleMap["severity"]
	if !ok {
		return
	}
	severityText, ok := rawSeverity.(string)
	if !ok {
		return
	}
	switch analyzer.LintSeverity(strings.ToLower(strings.TrimSpace(severityText))) {
	case analyzer.LintSeverityError,
		analyzer.LintSeverityWarning,
		analyzer.LintSeverityInformation,
		analyzer.LintSeverityHint,
		analyzer.LintSeverityOff:
		*target = analyzer.LintSeverity(strings.ToLower(strings.TrimSpace(severityText)))
	}
}
