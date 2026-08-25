package analyzer

import (
	"fmt"
	"strings"

	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

var keywordHoverDocs = map[string]string{
	"fn":       "Defines an anonymous function literal. Functions can capture outer variables and be assigned to names.",
	"let":      "Declares a new binding. Use let name = value; to store values for later use.",
	"if":       "Conditional expression. Executes the consequence block when the condition is truthy, otherwise runs else if present.",
	"else":     "Alternative branch for an if expression.",
	"return":   "Returns one or more values from the current function.",
	"for":      "Loop construct with init, condition, and post expressions: for (init; cond; post) { ... }.",
	"break":    "Exits the nearest enclosing loop immediately.",
	"continue": "Skips to the next iteration of the nearest enclosing loop.",
	"struct":   "Declares a struct type with named fields.",
	"enum":     "Declares a closed set of named variants.",
	"macro":    "Declares a macro literal for AST-level metaprogramming.",
	"true":     "Boolean literal representing truth.",
	"false":    "Boolean literal representing falsehood.",
}

var macroSpecialFormDocs = map[string]struct {
	signature string
	summary   string
}{
	"quote":   {signature: "quote(node)", summary: "Macro special form that captures an expression as AST without evaluating it."},
	"unquote": {signature: "unquote(expr)", summary: "Macro special form that evaluates an expression inside quote and splices the resulting AST/value back in."},
}

func isMacroSpecialFormName(name string) bool {
	_, ok := macroSpecialFormDocs[name]
	return ok
}

func macroSpecialFormHoverText(name string) (string, bool) {
	doc, ok := macroSpecialFormDocs[name]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("macro special form `%s`\n\n%s", doc.signature, doc.summary), true
}

func macroSpecialFormSignatureInformation(name string) (lsp.SignatureInformation, bool) {
	doc, ok := macroSpecialFormDocs[name]
	if !ok {
		return lsp.SignatureInformation{}, false
	}
	return lsp.SignatureInformation{
		Label:         doc.signature,
		Documentation: lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: doc.summary},
	}, true
}

// builtinHoverText renders the hover card for a builtin.
//
// Every registered builtin has a teaching doc — metadata_return_test.go and
// metadata_param_test.go both fail otherwise — so there is no degraded path
// here any more. The family-summary and "Builtin function." fallbacks this used
// to carry became unreachable once coverage reached all 399, and leaving them in
// would have hidden a future gap behind a card that looked almost right.
func builtinHoverText(name string) (string, bool) {
	card, ok := builtinCard(name)
	if !ok {
		return "", false
	}
	return card.render(), true
}

// builtinFooter builds the card's trailing lines: the capability category the
// builtin belongs to and, for platform-constrained builtins, the supported OS
// set and/or a behavioural caveat.
func builtinFooter(name string) []string {
	var lines []string
	if category := builtin.CapabilityCategory(name); category != "" {
		lines = append(lines, fmt.Sprintf("_Category: %s_", category))
	}
	platforms, note := builtin.PlatformSupport(name)
	if len(platforms) > 0 {
		lines = append(lines, fmt.Sprintf("**Platforms:** %s — not supported on other operating systems.",
			strings.Join(platforms, ", ")))
	}
	if note != "" {
		lines = append(lines, fmt.Sprintf("_Note: %s_", note))
	}
	return lines
}

func keywordHoverText(keyword string) (string, bool) {
	doc, ok := keywordHoverDocs[keyword]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("keyword `%s`\n\n%s", keyword, doc), true
}

func languageSnippetCompletionItems() []lsp.CompletionItem {
	snippetKind := lsp.CompletionItemKindSnippet
	snippetFormat := lsp.InsertTextFormatSnippet

	return []lsp.CompletionItem{
		{
			Label:            "if / else",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("if (${1:condition}) {\n  ${2:// todo}\n} else {\n  ${3:// todo}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Conditional block with an else branch.",
			},
		},
		{
			Label:            "if guard return",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("if (!(${1:condition})) {\n  return ${2:nil};\n}\n${3:// continue}"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Guard clause with early return."},
		},
		{
			Label:            "for loop",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:let i = 0}; ${2:i < n}; ${3:i = i + 1}) {\n  ${4:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Classic for-loop template.",
			},
		},
		{
			Label:            "for loop over array",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:let i = 0}; i < len(${2:items}); i = i + 1) {\n  let ${3:item} = ${2:items}[i];\n  ${4:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Loop over all array elements by index."},
		},
		{
			Label:            "function declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:name} = fn(${2:param}) {\n  ${3:// body}\n};"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "User-defined function binding.",
			},
		},
		{
			Label:            "function declaration with docs",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("// ${1:Describe what this function does}\nlet ${2:name} = fn(${3:param}) {\n  ${4:// body}\n};"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Function template with leading doc comment."},
		},
		{
			Label:            "struct declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("struct ${1:Name} { ${2:field1}; ${3:field2}; }"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Struct type declaration.",
			},
		},
		{
			Label:            "struct value",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:instance} = ${2:Type} { ${3:field}: ${4:value} };"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Construct a struct value."},
		},
		{
			Label:            "enum declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("enum ${1:Name} { ${2:VariantA}, ${3:VariantB} }"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Enum declaration with named variants.",
			},
		},
		{
			Label:            "enum variant usage",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:value} = ${2:Enum}.${3:Variant};"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Reference an enum variant."},
		},
	}
}

func builtinSignatureInformation(name string) (lsp.SignatureInformation, bool) {
	if _, summary, params, ok := builtin.TeachingDoc(name); ok {
		label, spans, _ := builtinSignatureLabel(name)
		sig := lsp.SignatureInformation{Label: label}
		sig.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: summary}
		if len(params) == 0 {
			return sig, true
		}

		// Parameters are addressed by offset rather than by name. A string
		// label has to be a substring of the signature label and is matched by
		// first occurrence, which the type annotations would make ambiguous;
		// the offset pair says exactly which span to highlight.
		paramInfos := make([]lsp.ParameterInformation, 0, len(params))
		for i, p := range params {
			param := lsp.ParameterInformation{Label: spans[i]}
			if doc := paramDocumentation(p); doc != "" {
				param.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: doc}
			}
			paramInfos = append(paramInfos, param)
		}
		sig.Parameters = paramInfos
		return sig, true
	}

	if hover, ok := builtinHoverText(name); ok {
		return lsp.SignatureInformation{
			Label:         fmt.Sprintf("%s(...)", name),
			Documentation: lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: hover},
		}, true
	}

	return lsp.SignatureInformation{}, false
}

func strPtr(s string) *string { return &s }
