package server

import (
	"strings"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

type formatterConfig struct {
	indentUnit string
}

func newFormatterConfig(options lsp.FormattingOptions) formatterConfig {
	insertSpaces := true
	if raw, ok := options["insertSpaces"]; ok {
		if value, ok := raw.(bool); ok {
			insertSpaces = value
		}
	}

	tabSize := 2
	if raw, ok := options["tabSize"]; ok {
		switch value := raw.(type) {
		case int:
			if value > 0 {
				tabSize = value
			}
		case float64:
			if int(value) > 0 {
				tabSize = int(value)
			}
		}
	}

	if !insertSpaces {
		return formatterConfig{indentUnit: "\t"}
	}
	return formatterConfig{indentUnit: strings.Repeat(" ", tabSize)}
}

func formatSnapshotText(snapshot *analyzer.Snapshot, config formatterConfig) string {
	if snapshot == nil || snapshot.Program == nil || len(snapshot.ParseErrors) > 0 {
		if snapshot == nil {
			return ""
		}
		return normalizeDocumentWhitespace(snapshot.Source)
	}

	// Use a source-layout formatter when comments/blank lines are present so we
	// keep authored structure while still applying a deterministic code style.
	if hasLineComments(snapshot.Source) || hasIntentionalBlankLines(snapshot.Source) {
		return formatSourceLayout(snapshot.Source, config)
	}

	var b strings.Builder
	statements := make([]string, 0, len(snapshot.Program.Statements))
	for _, stmt := range snapshot.Program.Statements {
		formatted := formatStatement(stmt, 0, config)
		if formatted == "" {
			continue
		}
		statements = append(statements, formatted)
	}
	b.WriteString(strings.Join(statements, "\n"))

	formatted := strings.TrimSpace(b.String())
	if formatted == "" {
		return ""
	}
	return formatted + "\n"
}

func formatStatement(stmt mast.Statement, indent int, config formatterConfig) string {
	if stmt == nil {
		return ""
	}
	prefix := strings.Repeat(config.indentUnit, indent)

	switch node := stmt.(type) {
	case *mast.LetStatement:
		name := ""
		if len(node.Names) > 0 {
			parts := make([]string, 0, len(node.Names))
			for _, ident := range node.Names {
				if ident != nil {
					parts = append(parts, ident.Value)
				}
			}
			name = strings.Join(parts, ", ")
		} else if node.Name != nil {
			name = node.Name.Value
		}
		return prefix + "let " + name + " = " + formatExpression(node.Value, indent, config) + ";"
	case *mast.ReturnStatement:
		if len(node.ReturnValues) > 0 {
			parts := make([]string, 0, len(node.ReturnValues))
			for _, expr := range node.ReturnValues {
				parts = append(parts, formatExpression(expr, indent, config))
			}
			return prefix + "return " + strings.Join(parts, ", ") + ";"
		}
		if node.ReturnValue == nil {
			return prefix + "return;"
		}
		return prefix + "return " + formatExpression(node.ReturnValue, indent, config) + ";"
	case *mast.ExpressionStatement:
		if _, ok := node.Expression.(*mast.IfExpression); ok {
			return prefix + formatExpression(node.Expression, indent, config)
		}
		return prefix + formatExpression(node.Expression, indent, config) + ";"
	case *mast.BlockStatement:
		return formatBlock(node, indent, config)
	case *mast.ForStatement:
		return prefix + formatForStatement(node, indent, config)
	case *mast.StructStatement:
		fields := make([]string, 0, len(node.Fields))
		for _, field := range node.Fields {
			if field != nil {
				fields = append(fields, field.Value)
			}
		}
		body := ""
		if len(fields) > 0 {
			body = " " + strings.Join(fields, "; ") + "; "
		}
		name := ""
		if node.Name != nil {
			name = node.Name.Value
		}
		return prefix + "struct " + name + " {" + body + "}"
	case *mast.EnumStatement:
		variants := make([]string, 0, len(node.Variants))
		for _, variant := range node.Variants {
			if variant != nil {
				variants = append(variants, variant.Value)
			}
		}
		body := ""
		if len(variants) > 0 {
			body = " " + strings.Join(variants, ", ") + " "
		}
		name := ""
		if node.Name != nil {
			name = node.Name.Value
		}
		return prefix + "enum " + name + " {" + body + "}"
	case *mast.BreakStatement:
		return prefix + "break;"
	case *mast.ContinueStatement:
		return prefix + "continue;"
	default:
		return prefix + strings.TrimSpace(stmt.String())
	}
}

func formatExpression(expr mast.Expression, indent int, config formatterConfig) string {
	if expr == nil {
		return ""
	}

	switch node := expr.(type) {
	case *mast.Identifier:
		return node.Value
	case *mast.IntegerLiteral, *mast.FloatLiteral, *mast.Boolean:
		return expr.String()
	case *mast.StringLiteral:
		escaped := strings.ReplaceAll(node.Value, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
		return "\"" + escaped + "\""
	case *mast.PrefixExpression:
		return "(" + node.Operator + formatExpression(node.Right, indent, config) + ")"
	case *mast.InfixExpression:
		return "(" + formatExpression(node.Left, indent, config) + " " + node.Operator + " " + formatExpression(node.Right, indent, config) + ")"
	case *mast.AssignExpression:
		return formatExpression(node.Left, indent, config) + " = " + formatExpression(node.Value, indent, config)
	case *mast.CallExpression:
		parts := make([]string, 0, len(node.Arguments))
		for _, arg := range node.Arguments {
			parts = append(parts, formatExpression(arg, indent, config))
		}
		return formatExpression(node.Function, indent, config) + "(" + strings.Join(parts, ", ") + ")"
	case *mast.FunctionLiteral:
		params := make([]string, 0, len(node.Parameters))
		for _, p := range node.Parameters {
			if p != nil {
				params = append(params, p.Value)
			}
		}
		return "fn(" + strings.Join(params, ", ") + ") " + formatBlock(node.Body, indent, config)
	case *mast.MacroLiteral:
		params := make([]string, 0, len(node.Parameters))
		for _, p := range node.Parameters {
			if p != nil {
				params = append(params, p.Value)
			}
		}
		return "macro(" + strings.Join(params, ", ") + ") " + formatBlock(node.Body, indent, config)
	case *mast.IfExpression:
		result := "if " + formatCondition(node.Condition, indent, config) + " " + formatBlock(node.Consequence, indent, config)
		if node.Alternative != nil {
			result += " else " + formatBlock(node.Alternative, indent, config)
		}
		return result
	case *mast.ArrayLiteral:
		parts := make([]string, 0, len(node.Elements))
		for _, element := range node.Elements {
			parts = append(parts, formatExpression(element, indent, config))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *mast.IndexExpression:
		return formatExpression(node.Left, indent, config) + "[" + formatExpression(node.Index, indent, config) + "]"
	case *mast.FieldExpression:
		field := ""
		if node.Field != nil {
			field = node.Field.Value
		}
		return formatExpression(node.Left, indent, config) + "." + field
	case *mast.StructLiteral:
		fields := make([]string, 0, len(node.Fields))
		for _, field := range node.Fields {
			if field == nil || field.Name == nil {
				continue
			}
			fields = append(fields, field.Name.Value+": "+formatExpression(field.Value, indent, config))
		}
		name := ""
		if node.Name != nil {
			name = node.Name.Value + " "
		}
		return name + "{" + strings.Join(fields, ", ") + "}"
	case *mast.HashLiteral:
		parts := make([]string, 0, len(node.Pairs))
		for key, value := range node.Pairs {
			parts = append(parts, formatExpression(key, indent, config)+": "+formatExpression(value, indent, config))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return strings.TrimSpace(expr.String())
	}
}

func formatCondition(expr mast.Expression, indent int, config formatterConfig) string {
	formatted := formatExpression(expr, indent, config)
	if strings.HasPrefix(formatted, "(") && strings.HasSuffix(formatted, ")") {
		return formatted
	}
	return "(" + formatted + ")"
}

func formatBlock(block *mast.BlockStatement, indent int, config formatterConfig) string {
	if block == nil || len(block.Statements) == 0 {
		return "{}"
	}

	var b strings.Builder
	b.WriteString("{\n")
	for i, stmt := range block.Statements {
		formatted := formatStatement(stmt, indent+1, config)
		if formatted == "" {
			continue
		}
		b.WriteString(formatted)
		if i < len(block.Statements)-1 {
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(config.indentUnit, indent))
	b.WriteString("}")
	return b.String()
}

func formatForStatement(stmt *mast.ForStatement, indent int, config formatterConfig) string {
	if stmt == nil {
		return ""
	}
	init := ""
	if stmt.Init != nil {
		init = strings.TrimSpace(formatStatement(stmt.Init, 0, config))
		init = strings.TrimSuffix(init, ";")
	}
	cond := ""
	if stmt.Condition != nil {
		cond = formatExpression(stmt.Condition, indent, config)
	}
	post := ""
	if stmt.Post != nil {
		post = formatExpression(stmt.Post, indent, config)
	}
	return "for (" + init + "; " + cond + "; " + post + ") " + formatBlock(stmt.Body, indent, config)
}

func normalizeDocumentWhitespace(input string) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	if normalized == "" {
		return ""
	}

	lines := strings.Split(normalized, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	joined := strings.Join(lines, "\n")
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return ""
	}
	return joined + "\n"
}

func hasLineComments(input string) bool {
	normalized := strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	if normalized == "" {
		return false
	}

	lines := strings.Split(normalized, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			return true
		}
		if idx := strings.Index(line, "//"); idx >= 0 {
			// Inline comments should be preserved as authored.
			return true
		}
	}
	return false
}

func hasIntentionalBlankLines(input string) bool {
	normalized := strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	return strings.Contains(normalized, "\n\n")
}

func formatSourceLayout(input string, config formatterConfig) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	if normalized == "" {
		return ""
	}

	lines := collapseStandaloneOpeningBraces(strings.Split(normalized, "\n"))
	formatted := make([]string, 0, len(lines))
	indent := 0

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, " \t")
		if strings.TrimSpace(line) == "" {
			formatted = append(formatted, "")
			continue
		}

		codePart, commentPart, hasInlineComment := splitCodeAndInlineComment(line)
		code := normalizeCodeSpacing(strings.TrimSpace(codePart))

		leadingClosers := leadingClosingBraceCount(code)
		if leadingClosers > 0 {
			indent -= leadingClosers
			if indent < 0 {
				indent = 0
			}
		}

		prefix := strings.Repeat(config.indentUnit, indent)
		if code == "" {
			comment := strings.TrimSpace(commentPart)
			formatted = append(formatted, prefix+comment)
			continue
		}

		lineOut := prefix + code
		if hasInlineComment {
			comment := strings.TrimSpace(commentPart)
			if comment != "" {
				lineOut += " " + comment
			}
		}
		formatted = append(formatted, lineOut)

		delta := braceDelta(code)
		indent += delta + leadingClosers
		if indent < 0 {
			indent = 0
		}
	}

	joined := strings.Join(formatted, "\n")
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return ""
	}
	return joined + "\n"
}

func collapseStandaloneOpeningBraces(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "{" {
			out = append(out, line)
			continue
		}

		attachTo := -1
		for i := len(out) - 1; i >= 0; i-- {
			if strings.TrimSpace(out[i]) == "" {
				continue
			}
			attachTo = i
			break
		}

		if attachTo >= 0 && canAttachOpeningBrace(strings.TrimSpace(out[attachTo])) {
			out[attachTo] = strings.TrimRight(out[attachTo], " \t") + " {"
			continue
		}

		out = append(out, line)
	}

	return out
}

func canAttachOpeningBrace(previous string) bool {
	if previous == "" || strings.HasPrefix(previous, "//") || strings.Contains(previous, "//") {
		return false
	}
	if strings.HasSuffix(previous, "{") {
		return false
	}

	if previous == "else" {
		return true
	}
	if strings.HasPrefix(previous, "if ") || strings.HasPrefix(previous, "for ") {
		return true
	}
	if strings.HasPrefix(previous, "fn(") || strings.HasPrefix(previous, "macro(") {
		return true
	}
	if strings.HasPrefix(previous, "struct ") || strings.HasPrefix(previous, "enum ") {
		return true
	}

	return strings.HasSuffix(previous, ")")
}

func splitCodeAndInlineComment(line string) (string, string, bool) {
	inString := false
	escaped := false
	runes := []rune(line)

	for i := 0; i < len(runes)-1; i++ {
		ch := runes[i]
		next := runes[i+1]

		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			continue
		}

		if ch == '/' && next == '/' {
			return string(runes[:i]), string(runes[i:]), true
		}
	}

	return line, "", false
}

func leadingClosingBraceCount(code string) int {
	count := 0
	for _, ch := range code {
		if ch == '}' {
			count++
			continue
		}
		break
	}
	return count
}

func braceDelta(code string) int {
	if code == "" {
		return 0
	}

	delta := 0
	inString := false
	escaped := false
	runes := []rune(code)

	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			continue
		}

		if ch == '{' {
			delta++
		} else if ch == '}' {
			delta--
		}
	}

	return delta
}

func normalizeCodeSpacing(code string) string {
	if code == "" {
		return ""
	}

	tokens := tokenizeCode(code)
	if len(tokens) == 0 {
		return ""
	}

	var b strings.Builder
	for i, tok := range tokens {
		if i == 0 {
			b.WriteString(tok)
			continue
		}

		prev := tokens[i-1]
		if needsSpace(prev, tok) {
			b.WriteByte(' ')
		}
		b.WriteString(tok)
	}

	return b.String()
}

func tokenizeCode(code string) []string {
	runes := []rune(code)
	tokens := make([]string, 0, len(runes)/2)

	for i := 0; i < len(runes); {
		ch := runes[i]

		if ch == ' ' || ch == '\t' {
			i++
			continue
		}

		if ch == '"' {
			start := i
			i++
			escaped := false
			for i < len(runes) {
				if escaped {
					escaped = false
					i++
					continue
				}
				if runes[i] == '\\' {
					escaped = true
					i++
					continue
				}
				if runes[i] == '"' {
					i++
					break
				}
				i++
			}
			tokens = append(tokens, string(runes[start:i]))
			continue
		}

		if isIdentifierStart(ch) {
			start := i
			i++
			for i < len(runes) && isIdentifierPart(runes[i]) {
				i++
			}
			tokens = append(tokens, string(runes[start:i]))
			continue
		}

		if isDigit(ch) {
			start := i
			i++
			for i < len(runes) && (isDigit(runes[i]) || runes[i] == '.') {
				i++
			}
			tokens = append(tokens, string(runes[start:i]))
			continue
		}

		if i+1 < len(runes) {
			two := string(runes[i : i+2])
			switch two {
			case "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", ":=":
				tokens = append(tokens, two)
				i += 2
				continue
			}
		}

		tokens = append(tokens, string(ch))
		i++
	}

	return tokens
}

func needsSpace(prev, next string) bool {
	if next == "" || prev == "" {
		return false
	}
	if next == "(" {
		return prev == "if" || prev == "for"
	}

	if next == "," || next == ";" || next == ")" || next == "]" || next == "}" || next == "." || next == ":" {
		return false
	}
	if prev == "(" || prev == "[" || prev == "{" || prev == "." {
		return false
	}
	if prev == ":" || prev == "," {
		return true
	}
	if isOperator(prev) || isOperator(next) {
		return true
	}

	return true
}

func isOperator(tok string) bool {
	switch tok {
	case "=", "+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "!", ":=":
		return true
	default:
		return false
	}
}

func isIdentifierStart(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentifierPart(ch rune) bool {
	return isIdentifierStart(ch) || isDigit(ch)
}

func isDigit(ch rune) bool {
	return ch >= '0' && ch <= '9'
}
