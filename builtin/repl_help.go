package builtin

import (
	"fmt"
	"sort"
	"strings"

	"mutant/object"
	"mutant/token"
)

const MutantDocsURL = "https://mudocs.aoiflux.xyz"

type ReplHelpOptions struct {
	Mode              string
	SupportedBuiltins map[string]struct{}
	Symbols           []string
}

type completionKind int

const (
	completionKindSymbol completionKind = iota
	completionKindMetaHelp
	completionKindHelpCall
	completionKindKeyword
	completionKindBuiltin
	completionKindOther
)

type completionEntry struct {
	value string
	kind  completionKind
}

var replHelpTopics = []string{"keywords", "builtins", "examples", "docs"}
var replHelpModes = []string{"supported", "all"}

var replKeywordDocs = map[string]string{
	"fn":       "Defines an anonymous function literal and can capture outer bindings.",
	"let":      "Declares one or more bindings for values you want to reuse.",
	"if":       "Conditional expression with optional else branch.",
	"else":     "Alternative branch for an if expression.",
	"return":   "Returns one or more values from the current function.",
	"for":      "Loop construct with init, condition, and post clauses.",
	"break":    "Exits the nearest enclosing loop.",
	"continue": "Skips to the next loop iteration.",
	"struct":   "Declares a struct type with named fields.",
	"enum":     "Declares a closed set of named variants.",
	"macro":    "Declares macro literals for AST-level metaprogramming.",
	"true":     "Boolean truth literal.",
	"false":    "Boolean false literal.",
}

type replExample struct {
	topic    string
	snippet  string
	location string
}

var replExamples = []replExample{
	{topic: "loops", snippet: "for (let i = 0; i < len(items); i = i + 1) { putln(items[i]); }", location: "examples/basics/for_loop_control.mut"},
	{topic: "struct", snippet: "struct Person { name; role; }\nlet p = Person { name: \"Ada\", role: \"analyst\" };", location: "examples/basics/structs_example.mut"},
	{topic: "enum", snippet: "enum Severity { Low, High }\nlet level = Severity.High;", location: "examples/basics/enums_example.mut"},
	{topic: "text", snippet: "let parts = text_split(\"a,b,c\", \",\");", location: "examples/text/text_matching_example.mut"},
	{topic: "bytes", snippet: "let value = bytes_read_u32_le(blob, 0);", location: "examples/bytes/bytes_parser_example.mut"},
	{topic: "policy", snippet: "let decision, err = policy_eval(\"allow_all\", {\"action\": \"read\"});", location: "examples/policy/policy_eval_example.mut"},
}

func Help(args ...object.Object) object.Object {
	if len(args) > 2 {
		return newError("wrong number of arguments. got=%d, want=0..2", len(args))
	}

	topic := ""
	mode := ""
	if len(args) >= 1 {
		value, ok := args[0].(*object.String)
		if !ok {
			return newError("argument 1 to help must be STRING, got %s", args[0].Type())
		}
		topic = value.Value
	}
	if len(args) == 2 {
		value, ok := args[1].(*object.String)
		if !ok {
			return newError("argument 2 to help must be STRING, got %s", args[1].Type())
		}
		mode = value.Value
	}

	return &object.String{Value: RenderReplHelp(topic, ReplHelpOptions{Mode: mode})}
}

func RenderReplHelp(topic string, options ReplHelpOptions) string {
	normalizedTopic := strings.ToLower(strings.TrimSpace(topic))
	if normalizedTopic == "" || normalizedTopic == "overview" || normalizedTopic == "learn" {
		return renderOverviewHelp()
	}

	mode := normalizeHelpMode(options.Mode)
	switch normalizedTopic {
	case "docs", "documentation", "website":
		return fmt.Sprintf("Mutant docs: %s", MutantDocsURL)
	case "keywords", "keyword":
		return renderKeywordsHelp()
	case "builtins", "builtin", "functions", "function":
		return renderBuiltinsHelp(mode, options.SupportedBuiltins)
	case "examples", "example":
		return renderExamplesHelp("")
	}

	if doc, ok := replKeywordDocs[normalizedTopic]; ok {
		return fmt.Sprintf("keyword %s\n\n%s", normalizedTopic, doc)
	}

	if detail := renderBuiltinDetail(normalizedTopic, mode, options.SupportedBuiltins); detail != "" {
		return detail
	}

	if example := renderExamplesHelp(normalizedTopic); example != "" {
		return example
	}

	return fmt.Sprintf("No help found for %q. Try: help(\"keywords\"), help(\"builtins\"), help(\"examples\"), help(\"docs\").", topic)
}

func ReplCompletionCandidates(prefix string, options ReplHelpOptions) []string {
	entries := make([]completionEntry, 0, 16+len(options.Symbols)+len(Builtins))
	for _, symbol := range options.Symbols {
		trimmed := strings.TrimSpace(symbol)
		if trimmed == "" {
			continue
		}
		entries = append(entries, completionEntry{value: trimmed, kind: completionKindSymbol})
	}

	entries = append(entries,
		completionEntry{value: ":help", kind: completionKindMetaHelp},
		completionEntry{value: ":help keywords", kind: completionKindMetaHelp},
		completionEntry{value: ":help builtins", kind: completionKindMetaHelp},
		completionEntry{value: ":help examples", kind: completionKindMetaHelp},
		completionEntry{value: ":help docs", kind: completionKindMetaHelp},
		completionEntry{value: "help()", kind: completionKindHelpCall},
		completionEntry{value: "help(\"keywords\")", kind: completionKindHelpCall},
		completionEntry{value: "help(\"builtins\")", kind: completionKindHelpCall},
		completionEntry{value: "help(\"examples\")", kind: completionKindHelpCall},
	)

	for _, keyword := range token.KeywordLiterals() {
		entries = append(entries, completionEntry{value: keyword, kind: completionKindKeyword})
	}

	mode := normalizeHelpMode(options.Mode)
	for _, name := range builtinNamesForMode(mode, options.SupportedBuiltins) {
		entries = append(entries, completionEntry{value: name, kind: completionKindBuiltin})
	}

	return filterAndRankCompletions(entries, strings.TrimSpace(prefix), nil)
}

func ReplCompletionCandidatesForLine(line string, options ReplHelpOptions) []string {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, ":help") {
		parts := strings.Fields(trimmed)
		if len(parts) <= 2 {
			prefix := ""
			if len(parts) == 2 {
				prefix = parts[1]
			}
			entries := make([]completionEntry, 0, len(replHelpTopics))
			for _, topic := range replHelpTopics {
				entries = append(entries, completionEntry{value: topic, kind: completionKindMetaHelp})
			}
			return filterAndRankCompletions(entries, prefix, map[completionKind]int{completionKindMetaHelp: 0})
		}

		modePrefix := parts[2]
		entries := make([]completionEntry, 0, len(replHelpModes))
		for _, mode := range replHelpModes {
			entries = append(entries, completionEntry{value: mode, kind: completionKindOther})
		}
		return filterAndRankCompletions(entries, modePrefix, nil)
	}

	if strings.HasPrefix(lower, "help(") {
		inner := strings.TrimSpace(trimmed[len("help("):])
		inner = strings.TrimSuffix(inner, ")")
		inner = strings.TrimSpace(inner)
		quotePrefix := ""
		argIndex := helpCallArgIndex(inner)
		argPrefix := helpCallArgPrefix(inner)
		if strings.HasPrefix(argPrefix, "\"") {
			quotePrefix = "\""
			argPrefix = strings.TrimPrefix(argPrefix, "\"")
		}

		if argIndex == 0 {
			entries := make([]completionEntry, 0, len(replHelpTopics)+len(Builtins))
			for _, topic := range replHelpTopics {
				entries = append(entries, completionEntry{value: quotePrefix + topic, kind: completionKindHelpCall})
			}
			for _, name := range builtinNamesForMode(normalizeHelpMode(options.Mode), options.SupportedBuiltins) {
				entries = append(entries, completionEntry{value: quotePrefix + name, kind: completionKindBuiltin})
			}
			filterPrefix := argPrefix
			if quotePrefix != "" {
				filterPrefix = quotePrefix + argPrefix
			}
			return filterAndRankCompletions(entries, filterPrefix, map[completionKind]int{completionKindHelpCall: 0, completionKindBuiltin: 1})
		}

		if argIndex == 1 {
			entries := make([]completionEntry, 0, len(replHelpModes))
			for _, mode := range replHelpModes {
				entries = append(entries, completionEntry{value: quotePrefix + mode, kind: completionKindOther})
			}
			filterPrefix := argPrefix
			if quotePrefix != "" {
				filterPrefix = quotePrefix + argPrefix
			}
			return filterAndRankCompletions(entries, filterPrefix, nil)
		}
	}

	return ReplCompletionCandidates(completionPrefixFromLine(trimmed), options)
}

func filterAndRankCompletions(entries []completionEntry, prefix string, kindPriority map[completionKind]int) []string {
	lowerPrefix := strings.ToLower(strings.TrimSpace(prefix))
	deduped := make([]completionEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.value) == "" {
			continue
		}
		if _, ok := seen[entry.value]; ok {
			continue
		}
		if lowerPrefix != "" && !strings.HasPrefix(strings.ToLower(entry.value), lowerPrefix) {
			continue
		}
		seen[entry.value] = struct{}{}
		deduped = append(deduped, entry)
	}

	sort.SliceStable(deduped, func(i, j int) bool {
		left := deduped[i]
		right := deduped[j]

		leftExact := strings.EqualFold(left.value, prefix)
		rightExact := strings.EqualFold(right.value, prefix)
		if leftExact != rightExact {
			return leftExact
		}

		leftPriority := completionKindOther
		rightPriority := completionKindOther
		if kindPriority != nil {
			if p, ok := kindPriority[left.kind]; ok {
				leftPriority = completionKind(p)
			}
			if p, ok := kindPriority[right.kind]; ok {
				rightPriority = completionKind(p)
			}
		} else {
			leftPriority = defaultKindOrder(left.kind)
			rightPriority = defaultKindOrder(right.kind)
		}
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}

		return strings.ToLower(left.value) < strings.ToLower(right.value)
	})

	out := make([]string, 0, len(deduped))
	for _, entry := range deduped {
		out = append(out, entry.value)
	}
	return out
}

func defaultKindOrder(kind completionKind) completionKind {
	switch kind {
	case completionKindSymbol:
		return 0
	case completionKindMetaHelp:
		return 1
	case completionKindHelpCall:
		return 2
	case completionKindKeyword:
		return 3
	case completionKindBuiltin:
		return 4
	default:
		return 5
	}
}

func completionPrefixFromLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}

	lastSpace := strings.LastIndexAny(trimmed, " \t")
	lastDelim := strings.LastIndexAny(trimmed, "(,:")
	index := lastSpace
	if lastDelim > index {
		index = lastDelim
	}
	if index < 0 || index+1 >= len(trimmed) {
		return trimmed
	}
	return trimmed[index+1:]
}

func helpCallArgIndex(inner string) int {
	index := 0
	inQuotes := false
	for _, r := range inner {
		if r == '"' {
			inQuotes = !inQuotes
			continue
		}
		if r == ',' && !inQuotes {
			index++
		}
	}
	return index
}

func helpCallArgPrefix(inner string) string {
	inQuotes := false
	lastSplit := 0
	for i, r := range inner {
		if r == '"' {
			inQuotes = !inQuotes
			continue
		}
		if r == ',' && !inQuotes {
			lastSplit = i + 1
		}
	}
	return strings.TrimSpace(inner[lastSplit:])
}

func renderOverviewHelp() string {
	return strings.Join([]string{
		"Mutant REPL help",
		"",
		"Learn the language: " + MutantDocsURL,
		"",
		"Topics:",
		"- keywords  : list language keywords and quick meaning",
		"- builtins  : list builtin functions (use help(\"name\") for details)",
		"- examples  : show curated learning snippets and example locations",
		"- docs      : show documentation website",
		"",
		"Usage:",
		"- :help <topic>",
		"- help()",
		"- help(\"builtins\")",
		"- help(\"text_split\")",
	}, "\n")
}

func renderKeywordsHelp() string {
	keywords := token.KeywordLiterals()
	lines := make([]string, 0, len(keywords)+3)
	lines = append(lines, "Mutant keywords:", "")
	for _, keyword := range keywords {
		if doc, ok := replKeywordDocs[keyword]; ok {
			lines = append(lines, fmt.Sprintf("- %s: %s", keyword, doc))
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s", keyword))
	}
	lines = append(lines, "", "Tip: run help(\"if\") or help(\"for\") for focused guidance.")
	return strings.Join(lines, "\n")
}

func renderBuiltinsHelp(mode string, supported map[string]struct{}) string {
	names := builtinNamesForMode(mode, supported)
	if len(names) == 0 {
		return "No builtins available for the selected mode."
	}
	lines := make([]string, 0, len(names)+6)
	if mode == "all" && len(supported) > 0 {
		lines = append(lines, "Mutant builtins (all; unsupported in wasm are marked):", "")
	} else {
		lines = append(lines, "Mutant builtins:", "")
	}
	for _, name := range names {
		if mode == "all" && len(supported) > 0 {
			if _, ok := supported[name]; !ok {
				lines = append(lines, "- "+name+" (unsupported in wasm)")
				continue
			}
		}
		lines = append(lines, "- "+name)
	}
	lines = append(lines, "", "Tip: run help(\"<builtin_name>\") for signature and parameter docs.")
	return strings.Join(lines, "\n")
}

func renderBuiltinDetail(name, mode string, supported map[string]struct{}) string {
	signature, summary, params, ok := TeachingDoc(name)
	if !ok {
		if GetBuiltinByName(name) == nil {
			return ""
		}
		signature = name + "(...)"
		summary = "Builtin function."
	}

	lines := []string{"builtin " + signature, "", summary}
	if len(params) > 0 {
		lines = append(lines, "", "Parameters:")
		for _, param := range params {
			if strings.TrimSpace(param.Doc) == "" {
				lines = append(lines, "- "+param.Name)
				continue
			}
			lines = append(lines, fmt.Sprintf("- %s: %s", param.Name, param.Doc))
		}
	}

	if mode == "supported" && len(supported) > 0 {
		if _, ok := supported[name]; !ok {
			lines = append(lines, "", "Note: this builtin is not available in the browser/wasm REPL.")
		}
	}
	if mode == "all" && len(supported) > 0 {
		if _, ok := supported[name]; !ok {
			lines = append(lines, "", "Note: unsupported in browser/wasm REPL.")
		}
	}

	if familySummary, ok := TeachingFamilySummary(name); ok {
		lines = append(lines, "", familySummary)
	}
	return strings.Join(lines, "\n")
}

func renderExamplesHelp(topic string) string {
	normalizedTopic := strings.ToLower(strings.TrimSpace(topic))
	if normalizedTopic == "" {
		lines := []string{"Mutant examples (curated snippets):", ""}
		for _, example := range replExamples {
			lines = append(lines, fmt.Sprintf("- %s: %s", example.topic, example.location))
		}
		lines = append(lines, "", "Tip: run help(\"text\") or help(\"loops\") for a snippet.")
		return strings.Join(lines, "\n")
	}

	for _, example := range replExamples {
		if example.topic != normalizedTopic {
			continue
		}
		return strings.Join([]string{
			fmt.Sprintf("example %s", example.topic),
			"",
			example.snippet,
			"",
			"More examples: " + example.location,
		}, "\n")
	}
	return ""
}

func normalizeHelpMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "supported", "safe", "default":
		return "supported"
	case "all", "full":
		return "all"
	default:
		return "supported"
	}
}

func builtinNamesForMode(mode string, supported map[string]struct{}) []string {
	names := make([]string, 0, len(Builtins))
	for _, entry := range Builtins {
		if entry.Name == "" {
			continue
		}
		if mode == "supported" && len(supported) > 0 {
			if _, ok := supported[entry.Name]; !ok {
				continue
			}
		}
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	return names
}
