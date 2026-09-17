package analyzer

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

var keywordHoverDocs = map[string]string{
	"fn":       "Defines an anonymous function literal. Functions can capture outer variables and be assigned to names.",
	"let":      "Declares a new binding. Use let name = value; to store values for later use.",
	"if":       "Conditional expression. Executes the consequence block when the condition is truthy, otherwise runs else if present.",
	"else":     "Alternative branch for an if expression.",
	"return":   "Returns one or more values from the current function.",
	"for": "Three-clause loop: for (init; cond; post) { ... }. The parentheses are required and all three clauses are optional -- for (;;) { ... } is the endless form. init may be a let or an expression, and runs once, in a scope created for the loop. continue runs the post section before re-testing, so the increment is not skipped. The loop variable is one binding for the whole loop, not a fresh one per iteration, so a closure made in the body sees the final value.",
	"in": "Walks a collection: for (v in xs) { ... } binds each element, and for (k, v in xs) { ... } binds " +
		"both halves. Four things iterate, and what one binding yields differs:\n\n" +
		"| iterable | two bindings | one binding |\n" +
		"| --- | --- | --- |\n" +
		"| array | index, element | element |\n" +
		"| hash | key, value | **key** |\n" +
		"| string | rune index, one-character string | character |\n" +
		"| bytes | index, byte as INTEGER | byte as INTEGER |\n\n" +
		"A hash is walked in sorted key order, the same order a hash renders in, so two runs visit it the same way. " +
		"A string is walked by rune and a bytes buffer by byte, which is why the two are not interchangeable here. " +
		"Anything else is a run-time error. continue advances the iterator -- a for ... in has no post section, so " +
		"the advance is the post section. The bindings are one slot for the whole loop rather than a fresh pair per " +
		"iteration, so a closure made in the body sees the final values. Binding the same name twice is refused.",
	"while": "Repeats its body while the condition stays truthy: while (cond) { ... }. The condition is required -- while () is refused rather than read as endless, so write while (true) when that is what you mean. Unlike for it has no init or post section, so continue goes straight back to the condition and the body itself has to make progress. Truthiness follows the same rule as if: the condition need not be a boolean.",
	"match":    "Expression that takes the first arm whose pattern equals the subject: match (x) { 1 | 2 => \"few\", Status.Ok => \"ok\", _ => \"other\" }. A pattern is a literal, a negated number, an enum variant, or `_` for anything, and alternatives are joined with `|`. An arm body is one expression or a block, and the match evaluates to it. Without a `_` arm, a subject that no arm matches is a run-time error rather than null.",
	"break":    "Exits the nearest enclosing loop immediately.",
	"continue": "Skips to the next iteration of the nearest enclosing loop.",
	"struct":   "Declares a struct type with named fields.",
	"enum":     "Declares a closed set of named variants.",
	"macro":    "Declares a macro literal for AST-level metaprogramming.",
	"import": "Loads another file as a module: import \"lib/util.mut\"; binds the namespace `util`, and import u \"lib/util.mut\"; binds `u` instead. " +
		"Reach into it with `util.name`; the module's own top-level names are not visible unqualified, and a name beginning with _ is private to the file that declares it. " +
		"The path resolves relative to this file's directory first, then against each --module-path directory in the order given. Top level only: an import inside a block is an error.",
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
	if line := stabilityFooterLine(name); line != "" {
		lines = append(lines, line)
	}
	return lines
}

// stabilityFooterLine states a builtin's stability tier, and says nothing at all
// for the stable ones -- which is almost all of them, and where a line saying so
// would be noise on every hover in the language.
//
// The tier is worth showing because it is now true rather than aspirational:
// until bytecode stopped addressing builtins by registry ordinal, nothing could
// be renamed or retired, so "deprecated" was advice with no path behind it.
func stabilityFooterLine(name string) string {
	stability, ok := builtin.StabilityOf(name)
	if !ok {
		return ""
	}
	switch stability {
	case builtin.StabilityDeprecated:
		if replacement, deprecated := builtin.DeprecatedBy(name); deprecated && replacement != "" {
			return fmt.Sprintf("**Deprecated** — use `%s` instead. This name keeps working so existing programs still run.", replacement)
		}
		return "**Deprecated** — kept only so existing programs still run."
	case builtin.StabilityExperimental:
		return "**Experimental** — this builtin's name and arguments may change in a minor release."
	default:
		return ""
	}
}

// forInHoverText is the card for `for (v in xs)`.
//
// It used to render keywordHoverDocs["for"] -- the three-clause loop's
// card, describing an init, a condition and a post section that a for ... in
// does not have -- because both constructs are dispatched from a `for`
// token. They are separate AST nodes with separate semantics and they need
// separate cards.
//
// The prose was already in the table under "in", reachable by nothing:
// `in` is not a node of its own, so a cursor on it lands on the enclosing
// ForInStatement and got the `for` card too. This is what makes that entry
// live, and it stays the single source of the text.
func forInHoverText() (string, bool) {
	doc, ok := keywordHoverDocs["in"]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("keyword `for ... in`\n\n%s", doc), true
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
		// The index walk this replaces -- `for (let i = 0; i < len(items); ...)`
		// with the element fished out by hand -- was offered as the way to walk
		// an array, and the language has had `for ... in` all along. The editor
		// was teaching the longer form of something it could have written.
		// These two match the extension's own forin/forkv snippets, so whichever
		// set fires the advice is the same.
		{
			Label:            "for ... in loop",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:item} in ${2:items}) {\n  ${3:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Walk a collection. One binding yields each element -- or, over a hash, each key.",
			},
		},
		{
			Label:            "for ... in loop, both halves",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:key}, ${2:value} in ${3:collection}) {\n  ${4:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Bind both halves: index and element over an array, key and value over a hash.",
			},
		},
		{
			Label:            "while loop",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("while (${1:condition}) {\n  ${2:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Repeat while the condition holds. The condition is required; write `while (true)` for an endless loop.",
			},
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

// importHoverText renders what an `import` actually bound, above the keyword's
// own documentation.
//
// The namespace is the useful half: an unaliased import derives it from the
// file name, so it is the one thing about the statement that is not written
// out in front of the reader. Namespace() is asked rather than the base name
// re-derived here, so hover cannot disagree with the compiler about what the
// import is called.
func importHoverText(node *mast.ImportStatement) string {
	path := ""
	if node != nil && node.Path != nil {
		path = node.Path.Value
	}

	header := "module"
	switch {
	case node == nil:
	case node.Namespace() != "":
		header = fmt.Sprintf("module `%s`", node.Namespace())
	default:
		// Nothing usable could be derived -- an empty path, or a name that is
		// all separators. Saying so is more use than an empty pair of ticks.
		header = "module (no namespace could be derived from this path -- give it an alias)"
	}
	if path != "" {
		header += fmt.Sprintf(" from `%s`", path)
	}

	if doc, ok := keywordHoverDocs["import"]; ok {
		return header + "\n\n" + doc
	}
	return header
}
