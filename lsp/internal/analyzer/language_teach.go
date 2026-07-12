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

func builtinHoverText(name string) (string, bool) {
	if signature, summary, params, ok := builtin.TeachingDoc(name); ok {
		if len(params) == 0 {
			return fmt.Sprintf("builtin `%s`\n\n%s", signature, summary), true
		}

		parts := make([]string, 0, len(params))
		for _, p := range params {
			parts = append(parts, fmt.Sprintf("- `%s`: %s", p.Name, p.Doc))
		}
		return fmt.Sprintf("builtin `%s`\n\n%s\n\n%s", signature, summary, strings.Join(parts, "\n")), true
	}

	if summary, ok := builtin.TeachingFamilySummary(name); ok {
		return fmt.Sprintf("builtin `%s(...)`\n\n%s", name, summary), true
	}
	if builtin.GetBuiltinByName(name) != nil {
		return fmt.Sprintf("builtin `%s(...)`\n\nBuiltin function.", name), true
	}

	return "", false
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
	if signature, summary, params, ok := builtin.TeachingDoc(name); ok {
		sig := lsp.SignatureInformation{Label: signature}
		sig.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: summary}
		if len(params) == 0 {
			return sig, true
		}

		paramInfos := make([]lsp.ParameterInformation, 0, len(params))
		for _, p := range params {
			param := lsp.ParameterInformation{Label: p.Name}
			if p.Doc != "" {
				param.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: p.Doc}
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
