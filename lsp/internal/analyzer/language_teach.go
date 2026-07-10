package analyzer

import (
	"fmt"
	"strings"

	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

type builtinDoc struct {
	signature string
	summary   string
	params    []builtinParamDoc
}

type builtinParamDoc struct {
	name string
	doc  string
}

var builtinDocs = map[string]builtinDoc{
	"len": {
		signature: "len(value)",
		summary:   "Returns the length of a string, array, hash, or bytes value.",
		params:    []builtinParamDoc{{name: "value", doc: "String, array, hash, or bytes value to measure."}},
	},
	"putln": {signature: "putln(value)", summary: "Prints a value followed by a newline."},
	"putf": {
		signature: "putf(format, ...values)",
		summary:   "Formats and prints values using a format string.",
		params: []builtinParamDoc{
			{name: "format", doc: "Printf-style format string."},
			{name: "...values", doc: "Values interpolated into format."},
		},
	},
	"gets":                 {signature: "gets()", summary: "Reads a line of input from stdin."},
	"first":                {signature: "first(array)", summary: "Returns the first element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"last":                 {signature: "last(array)", summary: "Returns the last element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"rest":                 {signature: "rest(array)", summary: "Returns a new array without the first element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"push":                 {signature: "push(array, value)", summary: "Returns a new array with value appended.", params: []builtinParamDoc{{name: "array", doc: "Source array."}, {name: "value", doc: "Element to append."}}},
	"pop":                  {signature: "pop(array)", summary: "Returns a new array without the last element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"fs_read":              {signature: "fs_read(path)", summary: "Reads file contents from disk.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}}},
	"fs_write":             {signature: "fs_write(path, data)", summary: "Writes data to a file, replacing existing contents.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	"fs_append":            {signature: "fs_append(path, data)", summary: "Appends data to the end of a file.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	"fs_exists":            {signature: "fs_exists(path)", summary: "Returns whether a file or directory exists.", params: []builtinParamDoc{{name: "path", doc: "Path to check."}}},
	"http_get":             {signature: "http_get(url)", summary: "Performs an HTTP GET request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}}},
	"http_post":            {signature: "http_post(url, body)", summary: "Performs an HTTP POST request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}, {name: "body", doc: "Request body value."}}},
	"http_request":         {signature: "http_request(method, url, opts)", summary: "Performs a configurable HTTP request.", params: []builtinParamDoc{{name: "method", doc: "HTTP verb (GET/POST/etc)."}, {name: "url", doc: "Absolute request URL."}, {name: "opts", doc: "Headers/body/timeout options."}}},
	"json_parse":           {signature: "json_parse(text)", summary: "Parses JSON text into Mutant values.", params: []builtinParamDoc{{name: "text", doc: "JSON string input."}}},
	"json_stringify":       {signature: "json_stringify(value)", summary: "Serializes Mutant values into JSON text.", params: []builtinParamDoc{{name: "value", doc: "Value to serialize."}}},
	"lua_run_string":       {signature: "lua_run_string(code)", summary: "Runs a Lua script from a string."},
	"lua_run_file":         {signature: "lua_run_file(path)", summary: "Runs a Lua script from a file."},
	"net_resolve":          {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses."},
	"net_dial":             {signature: "net_dial(address)", summary: "Opens a network connection."},
	"db_open":              {signature: "db_open()", summary: "Creates an in-memory graph database handle."},
	"db_open_disk":         {signature: "db_open_disk(path)", summary: "Opens or creates a disk-backed graph database."},
	"db_add_node":          {signature: "db_add_node(db, label, props)", summary: "Adds a node to the graph database."},
	"db_add_edge":          {signature: "db_add_edge(db, from, to, label, props)", summary: "Adds an edge between graph nodes."},
	"security_diagnostics": {signature: "security_diagnostics()", summary: "Returns security diagnostics for the current runtime."},
	"sandbox_status":       {signature: "sandbox_status()", summary: "Returns sandbox-detection status information."},
	"debug_status":         {signature: "debug_status()", summary: "Returns runtime/debugger status information."},
}

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
	if doc, ok := builtinDocs[name]; ok {
		if len(doc.params) == 0 {
			return fmt.Sprintf("builtin `%s`\n\n%s", doc.signature, doc.summary), true
		}

		parts := make([]string, 0, len(doc.params))
		for _, p := range doc.params {
			parts = append(parts, fmt.Sprintf("- `%s`: %s", p.name, p.doc))
		}
		return fmt.Sprintf("builtin `%s`\n\n%s\n\n%s", doc.signature, doc.summary, strings.Join(parts, "\n")), true
	}

	if strings.HasPrefix(name, "bytes_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nBytes utility for reading/writing binary data.", name), true
	}
	if strings.HasPrefix(name, "db_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nGraph database helper for nodes, edges, indexing, or traversal.", name), true
	}
	if strings.HasPrefix(name, "fs_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nFilesystem helper for reading/writing/managing files and directories.", name), true
	}
	if strings.HasPrefix(name, "http_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nHTTP helper for network requests.", name), true
	}
	if strings.HasPrefix(name, "net_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nNetwork helper for address resolution and socket operations.", name), true
	}
	if strings.HasPrefix(name, "cmd_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nCommand execution helper.", name), true
	}
	if strings.HasPrefix(name, "json_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nJSON serialization/parsing helper.", name), true
	}
	if strings.HasPrefix(name, "lua_") {
		return fmt.Sprintf("builtin `%s(...)`\n\nLua execution helper.", name), true
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
	if doc, ok := builtinDocs[name]; ok {
		sig := lsp.SignatureInformation{Label: doc.signature}
		sig.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: doc.summary}
		if len(doc.params) == 0 {
			return sig, true
		}

		params := make([]lsp.ParameterInformation, 0, len(doc.params))
		for _, p := range doc.params {
			param := lsp.ParameterInformation{Label: p.name}
			if p.doc != "" {
				param.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: p.doc}
			}
			params = append(params, param)
		}
		sig.Parameters = params
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
