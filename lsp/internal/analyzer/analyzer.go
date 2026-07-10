package analyzer

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	"mutant/lexer"
	mutantparser "mutant/parser"
	"mutant/token"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(src string) *Snapshot {
	p := mutantparser.New(lexer.New(src))
	program := p.ParseProgram()
	return &Snapshot{
		Source:      src,
		Program:     program,
		ParseErrors: p.TypedErrors(),
	}
}

func (s *Snapshot) NodeAt(pos lsp.Position) (mast.Node, mast.Range, bool) {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil, mast.Range{}, false
	}

	var best mast.Node
	var bestRange mast.Range
	bestSize := int(^uint(0) >> 1)

	for node, rng := range s.Program.NodePositions {
		if !rng.IsValid() {
			continue
		}
		if !contains(rng, pos) {
			continue
		}
		size := rng.End.Offset - rng.Start.Offset
		if size < bestSize || (size == bestSize && nodeSpecificity(node) > nodeSpecificity(best)) {
			best = node
			bestRange = rng
			bestSize = size
		}
	}

	if best == nil {
		return nil, mast.Range{}, false
	}
	return best, bestRange, true
}

func (s *Snapshot) HoverText(pos lsp.Position) (string, mast.Range, bool) {
	node, rng, ok := s.NodeAt(pos)
	if !ok {
		return "", mast.Range{}, false
	}

	switch n := node.(type) {
	case *mast.Identifier:
		if resolved, ok := s.resolveDefinition(pos); ok {
			if resolved.kind == lsp.CompletionItemKindFunction {
				if literal, ok := s.functionLiteralForBindingIdent(resolved.ident); ok {
					name := n.Value
					display := functionLiteralSignature(literal, functionDisplayName(name, literal.Name)).Label
					params := parameterNames(literal.Parameters)
					doc := s.leadingLineCommentForIdentifier(resolved.ident)

					var b strings.Builder
					b.WriteString("function `")
					b.WriteString(display)
					b.WriteString("`")

					if len(params) > 0 {
						b.WriteString("\n\nparams: `")
						b.WriteString(strings.Join(params, "`, `"))
						b.WriteString("`")
					}

					if doc != "" {
						b.WriteString("\n\n")
						b.WriteString(doc)
					}

					return b.String(), rng, true
				}
			}

			if _, ok := s.ReferenceLocations("", pos, true); ok {
				switch resolved.kind {
				case lsp.CompletionItemKindField:
					return fmt.Sprintf("field `%s`", n.Value), rng, true
				case lsp.CompletionItemKindEnumMember:
					return fmt.Sprintf("enum member `%s`", n.Value), rng, true
				}
			}
		}
		if text, ok := builtinHoverText(n.Value); ok {
			return text, rng, true
		}
		return fmt.Sprintf("identifier `%s`", n.Value), rng, true
	case *mast.IntegerLiteral:
		return fmt.Sprintf("integer `%d`", n.Value), rng, true
	case *mast.FloatLiteral:
		return fmt.Sprintf("float `%v`", n.Value), rng, true
	case *mast.StringLiteral:
		return fmt.Sprintf("string `%s`", n.Value), rng, true
	case *mast.Boolean:
		return fmt.Sprintf("boolean `%t`", n.Value), rng, true
	case *mast.FunctionLiteral:
		if text, ok := keywordHoverText("fn"); ok {
			if n.Name != "" {
				return fmt.Sprintf("function `%s(%s)`\n\n%s", n.Name, joinIdentifiers(n.Parameters), strings.TrimPrefix(text, "keyword `fn`\n\n")), rng, true
			}
			return fmt.Sprintf("function `fn(%s)`\n\n%s", joinIdentifiers(n.Parameters), strings.TrimPrefix(text, "keyword `fn`\n\n")), rng, true
		}
		if n.Name != "" {
			return fmt.Sprintf("function `%s(%s)`", n.Name, joinIdentifiers(n.Parameters)), rng, true
		}
		return fmt.Sprintf("function `fn(%s)`", joinIdentifiers(n.Parameters)), rng, true
	case *mast.LetStatement:
		if n.Name != nil {
			if text, ok := keywordHoverText("let"); ok {
				return fmt.Sprintf("binding `%s`\n\n%s", n.Name.Value, strings.TrimPrefix(text, "keyword `let`\n\n")), rng, true
			}
			return fmt.Sprintf("binding `%s`", n.Name.Value), rng, true
		}
	case *mast.StructStatement:
		if n.Name != nil {
			if text, ok := keywordHoverText("struct"); ok {
				return fmt.Sprintf("struct `%s`\n\n%s", n.Name.Value, strings.TrimPrefix(text, "keyword `struct`\n\n")), rng, true
			}
			return fmt.Sprintf("struct `%s`", n.Name.Value), rng, true
		}
	case *mast.EnumStatement:
		if n.Name != nil {
			if text, ok := keywordHoverText("enum"); ok {
				return fmt.Sprintf("enum `%s`\n\n%s", n.Name.Value, strings.TrimPrefix(text, "keyword `enum`\n\n")), rng, true
			}
			return fmt.Sprintf("enum `%s`", n.Name.Value), rng, true
		}
	case *mast.IfExpression:
		if text, ok := keywordHoverText("if"); ok {
			return text, rng, true
		}
	case *mast.ForStatement:
		if text, ok := keywordHoverText("for"); ok {
			return text, rng, true
		}
	case *mast.ReturnStatement:
		if text, ok := keywordHoverText("return"); ok {
			return text, rng, true
		}
	case *mast.BreakStatement:
		if text, ok := keywordHoverText("break"); ok {
			return text, rng, true
		}
	case *mast.ContinueStatement:
		if text, ok := keywordHoverText("continue"); ok {
			return text, rng, true
		}
	case *mast.MacroLiteral:
		if text, ok := keywordHoverText("macro"); ok {
			return text, rng, true
		}
	}

	return fmt.Sprintf("%T", node), rng, true
}

func (s *Snapshot) PrepareRename(pos lsp.Position) (string, mast.Range, bool) {
	if s == nil || s.Program == nil {
		return "", mast.Range{}, false
	}

	_, locationsOK := s.ReferenceLocations("", pos, true)
	if !locationsOK {
		return "", mast.Range{}, false
	}

	node, rng, ok := s.NodeAt(pos)
	if !ok {
		return "", mast.Range{}, false
	}
	ident, ok := node.(*mast.Identifier)
	if !ok || ident == nil || ident.Value == "" {
		return "", mast.Range{}, false
	}

	return ident.Value, rng, true
}

func (s *Snapshot) CompletionItems() []lsp.CompletionItem {
	return s.CompletionItemsAt(lsp.Position{})
}

func (s *Snapshot) CompletionItemsAt(pos lsp.Position) []lsp.CompletionItem {
	items := make([]lsp.CompletionItem, 0, len(keywords)+len(builtin.Builtins)+8)
	seen := make(map[string]struct{}, len(keywords)+len(builtin.Builtins)+8)
	for _, keyword := range keywords {
		kind := lsp.CompletionItemKindKeyword
		items = append(items, lsp.CompletionItem{Label: keyword, Kind: &kind})
		seen[keyword] = struct{}{}
	}
	for _, b := range builtin.Builtins {
		kind := lsp.CompletionItemKindFunction
		detail := "builtin"
		completion := lsp.CompletionItem{Label: b.Name, Kind: &kind, Detail: &detail}
		if doc, ok := builtinHoverText(b.Name); ok {
			completion.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: doc}
		}
		items = append(items, completion)
		seen[b.Name] = struct{}{}
	}
	for _, snippet := range languageSnippetCompletionItems() {
		if _, ok := seen[snippet.Label]; ok {
			continue
		}
		items = append(items, snippet)
		seen[snippet.Label] = struct{}{}
	}
	if s == nil || s.Program == nil {
		return stableCompletionItems(items)
	}

	bindings := s.VisibleBindingsAt(pos)
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].ident.Value < bindings[j].ident.Value
	})
	for _, bind := range bindings {
		if bind.ident == nil {
			continue
		}
		if _, ok := seen[bind.ident.Value]; ok {
			continue
		}
		kind := bind.kind
		items = append(items, lsp.CompletionItem{Label: bind.ident.Value, Kind: &kind})
		seen[bind.ident.Value] = struct{}{}
	}

	return stableCompletionItems(items)
}

func stableCompletionItems(items []lsp.CompletionItem) []lsp.CompletionItem {
	sort.SliceStable(items, func(i, j int) bool {
		leftCat := completionCategory(items[i])
		rightCat := completionCategory(items[j])
		if leftCat != rightCat {
			return leftCat < rightCat
		}

		leftLabel := strings.ToLower(items[i].Label)
		rightLabel := strings.ToLower(items[j].Label)
		if leftLabel != rightLabel {
			return leftLabel < rightLabel
		}

		if items[i].Label != items[j].Label {
			return items[i].Label < items[j].Label
		}

		return kindValue(items[i].Kind) < kindValue(items[j].Kind)
	})

	for i := range items {
		sortText := fmt.Sprintf("%02d:%s:%04d", completionCategory(items[i]), strings.ToLower(items[i].Label), i)
		items[i].SortText = &sortText
	}

	return items
}

func completionCategory(item lsp.CompletionItem) int {
	if item.Detail != nil && *item.Detail == "builtin" {
		return 1
	}
	if item.Kind != nil {
		switch *item.Kind {
		case lsp.CompletionItemKindSnippet:
			return 3
		case lsp.CompletionItemKindKeyword:
			return 2
		}
	}
	return 0
}

func kindValue(kind *lsp.CompletionItemKind) int {
	if kind == nil {
		return int(lsp.CompletionItemKindText)
	}
	return int(*kind)
}

func (s *Snapshot) DocumentSymbols() []lsp.DocumentSymbol {
	if s == nil || s.Program == nil {
		return nil
	}

	symbols := make([]lsp.DocumentSymbol, 0, len(s.Program.Statements))
	for _, stmt := range s.Program.Statements {
		symbol, ok := s.documentSymbol(stmt)
		if ok {
			symbols = append(symbols, symbol)
		}
	}
	return symbols
}

func (s *Snapshot) documentSymbol(stmt mast.Statement) (lsp.DocumentSymbol, bool) {
	stmtRange, ok := s.Program.RangeOf(stmt)
	if !ok {
		return lsp.DocumentSymbol{}, false
	}

	switch n := stmt.(type) {
	case *mast.LetStatement:
		if n.Name == nil {
			return lsp.DocumentSymbol{}, false
		}
		selection := stmtRange
		if nameRange, ok := s.Program.RangeOf(n.Name); ok {
			selection = nameRange
		}
		kind := lsp.SymbolKindVariable
		if _, ok := n.Value.(*mast.FunctionLiteral); ok {
			kind = lsp.SymbolKindFunction
		}
		return lsp.DocumentSymbol{
			Name:           n.Name.Value,
			Kind:           kind,
			Range:          toLSPRange(stmtRange),
			SelectionRange: toLSPRange(selection),
		}, true
	case *mast.StructStatement:
		if n.Name == nil {
			return lsp.DocumentSymbol{}, false
		}
		selection := stmtRange
		if nameRange, ok := s.Program.RangeOf(n.Name); ok {
			selection = nameRange
		}
		children := make([]lsp.DocumentSymbol, 0, len(n.Fields))
		for _, field := range n.Fields {
			fieldRange, ok := s.Program.RangeOf(field)
			if !ok {
				continue
			}
			children = append(children, lsp.DocumentSymbol{
				Name:           field.Value,
				Kind:           lsp.SymbolKindField,
				Range:          toLSPRange(fieldRange),
				SelectionRange: toLSPRange(fieldRange),
			})
		}
		return lsp.DocumentSymbol{
			Name:           n.Name.Value,
			Kind:           lsp.SymbolKindStruct,
			Range:          toLSPRange(stmtRange),
			SelectionRange: toLSPRange(selection),
			Children:       children,
		}, true
	case *mast.EnumStatement:
		if n.Name == nil {
			return lsp.DocumentSymbol{}, false
		}
		selection := stmtRange
		if nameRange, ok := s.Program.RangeOf(n.Name); ok {
			selection = nameRange
		}
		children := make([]lsp.DocumentSymbol, 0, len(n.Variants))
		for _, variant := range n.Variants {
			variantRange, ok := s.Program.RangeOf(variant)
			if !ok {
				continue
			}
			children = append(children, lsp.DocumentSymbol{
				Name:           variant.Value,
				Kind:           lsp.SymbolKindEnumMember,
				Range:          toLSPRange(variantRange),
				SelectionRange: toLSPRange(variantRange),
			})
		}
		return lsp.DocumentSymbol{
			Name:           n.Name.Value,
			Kind:           lsp.SymbolKindEnum,
			Range:          toLSPRange(stmtRange),
			SelectionRange: toLSPRange(selection),
			Children:       children,
		}, true
	default:
		return lsp.DocumentSymbol{}, false
	}
}

func joinIdentifiers(idents []*mast.Identifier) string {
	if len(idents) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(idents)*4)
	for i, ident := range idents {
		if ident == nil {
			continue
		}
		if i > 0 {
			buf = append(buf, ',', ' ')
		}
		buf = append(buf, ident.Value...)
	}
	return string(buf)
}

func parameterNames(params []*mast.Identifier) []string {
	if len(params) == 0 {
		return nil
	}

	names := make([]string, 0, len(params))
	for _, param := range params {
		if param == nil || param.Value == "" {
			continue
		}
		names = append(names, param.Value)
	}
	return names
}

func (s *Snapshot) leadingLineCommentForIdentifier(ident *mast.Identifier) string {
	if s == nil || s.Program == nil || ident == nil || s.Source == "" {
		return ""
	}

	rng, ok := s.Program.RangeOf(ident)
	if !ok || rng.Start.Line <= 1 {
		return ""
	}

	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(s.Source, "\r\n", "\n"), "\r", "\n"), "\n")
	lineIdx := rng.Start.Line - 2
	comments := make([]string, 0, 3)
	for lineIdx >= 0 {
		line := strings.TrimSpace(lines[lineIdx])
		if line == "" {
			if len(comments) == 0 {
				lineIdx--
				continue
			}
			break
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		comment := strings.TrimSpace(strings.TrimPrefix(line, "//"))
		comments = append(comments, comment)
		lineIdx--
	}

	if len(comments) == 0 {
		return ""
	}

	for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
		comments[i], comments[j] = comments[j], comments[i]
	}
	return strings.Join(comments, "\n")
}

func contains(rng mast.Range, pos lsp.Position) bool {
	line := int(pos.Line) + 1
	col := int(pos.Character) + 1
	if isBefore(line, col, rng.Start.Line, rng.Start.Column) {
		return false
	}
	if !isBefore(line, col, rng.End.Line, rng.End.Column) && !(line == rng.End.Line && col == rng.End.Column) {
		return false
	}
	return true
}

func isBefore(lineA, colA, lineB, colB int) bool {
	if lineA != lineB {
		return lineA < lineB
	}
	return colA < colB
}

func toLSPRange(rng mast.Range) lsp.Range {
	return lsp.Range{
		Start: lsp.Position{Line: lsp.UInteger(rng.Start.Line - 1), Character: lsp.UInteger(rng.Start.Column - 1)},
		End:   lsp.Position{Line: lsp.UInteger(rng.End.Line - 1), Character: lsp.UInteger(rng.End.Column - 1)},
	}
}

func nodeSpecificity(node mast.Node) int {
	if node == nil {
		return 0
	}

	switch node.(type) {
	case *mast.Identifier, *mast.IntegerLiteral, *mast.FloatLiteral, *mast.StringLiteral, *mast.Boolean:
		return 100
	case *mast.CallExpression, *mast.FunctionLiteral, *mast.IfExpression, *mast.ForStatement, *mast.StructStatement, *mast.EnumStatement:
		return 90
	case *mast.ExpressionStatement:
		return 20
	default:
		return 50
	}
}

var keywords = []string{
	"fn",
	"let",
	"true",
	"false",
	"if",
	"else",
	"return",
	"macro",
	"for",
	"break",
	"continue",
	"struct",
	"enum",
}

var semanticTokenTypes = []string{"keyword", "string", "number", "function", "variable", "type", "enum", "enumMember", "parameter", "property", "operator", "punctuation"}

var semanticTokenModifiers = []string{"defaultLibrary"}

var semanticTokenTypeIndex = map[string]uint32{
	"keyword":     0,
	"string":      1,
	"number":      2,
	"function":    3,
	"variable":    4,
	"type":        5,
	"enum":        6,
	"enumMember":  7,
	"parameter":   8,
	"property":    9,
	"operator":    10,
	"punctuation": 11,
}

var semanticTokenModifierIndex = map[string]uint32{
	"defaultLibrary": 0,
}

type semanticTokenOverride struct {
	typeID   uint32
	modifier uint32
}

type semanticToken struct {
	line   uint32
	start  uint32
	length uint32
	typeID uint32
	mod    uint32
}

func SemanticTokenLegend() lsp.SemanticTokensLegend {
	return lsp.SemanticTokensLegend{TokenTypes: semanticTokenTypes, TokenModifiers: semanticTokenModifiers}
}

func (s *Snapshot) SemanticTokensData() []lsp.UInteger {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil
	}

	overrides := collectSemanticTokenTypeOverrides(s.Program)

	tokens := make([]semanticToken, 0, len(s.Program.NodePositions)/4)
	tokens = append(tokens, lexicalSemanticTokens(s.Source)...)
	for node, rng := range s.Program.NodePositions {
		if !rng.IsValid() {
			continue
		}
		typeID, mod, ok := semanticTokenTypeForNode(node, overrides)
		if !ok {
			continue
		}
		length := tokenLength(node, rng)
		if length == 0 {
			continue
		}
		tokens = append(tokens, semanticToken{
			line:   uint32(rng.Start.Line - 1),
			start:  uint32(rng.Start.Column - 1),
			length: length,
			typeID: typeID,
			mod:    mod,
		})
	}

	if len(tokens) == 0 {
		return nil
	}

	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].line != tokens[j].line {
			return tokens[i].line < tokens[j].line
		}
		if tokens[i].start != tokens[j].start {
			return tokens[i].start < tokens[j].start
		}
		if tokens[i].length != tokens[j].length {
			return tokens[i].length < tokens[j].length
		}
		if tokens[i].typeID != tokens[j].typeID {
			return tokens[i].typeID < tokens[j].typeID
		}
		return tokens[i].mod < tokens[j].mod
	})

	// De-duplicate exact overlaps to keep payload stable.
	compact := make([]semanticToken, 0, len(tokens))
	for _, tok := range tokens {
		if len(compact) > 0 {
			last := compact[len(compact)-1]
			if last.line == tok.line && last.start == tok.start && last.length == tok.length && last.typeID == tok.typeID && last.mod == tok.mod {
				continue
			}
		}
		compact = append(compact, tok)
	}

	data := make([]lsp.UInteger, 0, len(compact)*5)
	var prevLine uint32
	var prevStart uint32
	for i, tok := range compact {
		deltaLine := tok.line
		deltaStart := tok.start
		if i > 0 {
			deltaLine = tok.line - prevLine
			if deltaLine == 0 {
				deltaStart = tok.start - prevStart
			}
		}
		data = append(data,
			lsp.UInteger(deltaLine),
			lsp.UInteger(deltaStart),
			lsp.UInteger(tok.length),
			lsp.UInteger(tok.typeID),
			lsp.UInteger(tok.mod),
		)
		prevLine = tok.line
		prevStart = tok.start
	}

	return data
}

func semanticTokenTypeForNode(node mast.Node, overrides map[mast.Node]semanticTokenOverride) (uint32, uint32, bool) {
	if overrides != nil {
		if override, ok := overrides[node]; ok {
			return override.typeID, override.modifier, true
		}
	}

	switch n := node.(type) {
	case *mast.IntegerLiteral, *mast.FloatLiteral:
		return semanticTokenTypeIndex["number"], 0, true
	case *mast.StringLiteral:
		return semanticTokenTypeIndex["string"], 0, true
	case *mast.Identifier:
		if n == nil || n.Value == "" {
			return 0, 0, false
		}
		switch token.LookupIdent(n.Value) {
		case token.IDENT:
			return semanticTokenTypeIndex["variable"], 0, true
		case token.TRUE, token.FALSE, token.FUNCTION, token.LET, token.IF, token.ELSE, token.RETURN, token.MACRO, token.FOR, token.BREAK, token.CONTINUE, token.STRUCT, token.ENUM:
			return semanticTokenTypeIndex["keyword"], 0, true
		default:
			return semanticTokenTypeIndex["variable"], 0, true
		}
	case *mast.FunctionLiteral:
		return semanticTokenTypeIndex["function"], 0, true
	case *mast.StructStatement:
		return semanticTokenTypeIndex["type"], 0, true
	case *mast.EnumStatement:
		return semanticTokenTypeIndex["enum"], 0, true
	default:
		return 0, 0, false
	}
}

func lexicalSemanticTokens(src string) []semanticToken {
	l := lexer.New(src)
	out := make([]semanticToken, 0, len(src)/8)
	for {
		tok := l.NextToken()
		if tok.Type == token.EOF {
			break
		}
		typeID, ok := semanticTokenTypeForLexToken(tok.Type)
		if !ok {
			continue
		}
		if !tok.Start.IsValid() || !tok.End.IsValid() || tok.End.Line != tok.Start.Line {
			continue
		}
		length := uint32(tok.End.Column - tok.Start.Column)
		if length == 0 {
			length = uint32(len([]rune(tok.Literal)))
		}
		if length == 0 {
			continue
		}
		out = append(out, semanticToken{
			line:   uint32(tok.Start.Line - 1),
			start:  uint32(tok.Start.Column - 1),
			length: length,
			typeID: typeID,
			mod:    0,
		})
	}
	return out
}

func semanticTokenTypeForLexToken(tokenType token.TokenType) (uint32, bool) {
	switch tokenType {
	case token.ASSIGN, token.PLUS, token.MINUS, token.ASTERISK, token.FSLASH, token.MODULO, token.LT, token.GT, token.BANG, token.EQUALITY, token.INEQUALITY:
		return semanticTokenTypeIndex["operator"], true
	case token.LPAREN, token.RPAREN, token.LBRACE, token.RBRACE, token.LSQUARE, token.RSQUARE, token.COMMA, token.SEMICOLON, token.COLON, token.DOT:
		return semanticTokenTypeIndex["punctuation"], true
	default:
		return 0, false
	}
}

func collectSemanticTokenTypeOverrides(program *mast.Program) map[mast.Node]semanticTokenOverride {
	if program == nil {
		return nil
	}

	overrides := make(map[mast.Node]semanticTokenOverride)
	for _, stmt := range program.Statements {
		collectStatementTokenOverrides(stmt, overrides)
	}

	if len(overrides) == 0 {
		return nil
	}
	return overrides
}

func collectStatementTokenOverrides(stmt mast.Statement, overrides map[mast.Node]semanticTokenOverride) {
	if isNilInterface(stmt) {
		return
	}

	switch s := stmt.(type) {
	case *mast.ExpressionStatement:
		collectExpressionTokenOverrides(s.Expression, overrides)
	case *mast.LetStatement:
		collectExpressionTokenOverrides(s.Value, overrides)
	case *mast.ReturnStatement:
		if len(s.ReturnValues) > 0 {
			for _, value := range s.ReturnValues {
				collectExpressionTokenOverrides(value, overrides)
			}
			break
		}
		collectExpressionTokenOverrides(s.ReturnValue, overrides)
	case *mast.BlockStatement:
		for _, nested := range s.Statements {
			collectStatementTokenOverrides(nested, overrides)
		}
	case *mast.ForStatement:
		collectStatementTokenOverrides(s.Init, overrides)
		collectExpressionTokenOverrides(s.Condition, overrides)
		collectExpressionTokenOverrides(s.Post, overrides)
		collectStatementTokenOverrides(s.Body, overrides)
	case *mast.StructStatement:
		for _, field := range s.Fields {
			if field != nil {
				overrides[field] = semanticTokenOverride{typeID: semanticTokenTypeIndex["property"], modifier: 0}
			}
		}
	case *mast.EnumStatement:
		for _, variant := range s.Variants {
			if variant != nil {
				overrides[variant] = semanticTokenOverride{typeID: semanticTokenTypeIndex["enumMember"], modifier: 0}
			}
		}
	}
}

func collectExpressionTokenOverrides(expr mast.Expression, overrides map[mast.Node]semanticTokenOverride) {
	if isNilInterface(expr) {
		return
	}

	switch e := expr.(type) {
	case *mast.PrefixExpression:
		collectExpressionTokenOverrides(e.Right, overrides)
	case *mast.InfixExpression:
		collectExpressionTokenOverrides(e.Left, overrides)
		collectExpressionTokenOverrides(e.Right, overrides)
	case *mast.IfExpression:
		collectExpressionTokenOverrides(e.Condition, overrides)
		collectStatementTokenOverrides(e.Consequence, overrides)
		collectStatementTokenOverrides(e.Alternative, overrides)
	case *mast.FunctionLiteral:
		for _, parameter := range e.Parameters {
			if parameter != nil {
				overrides[parameter] = semanticTokenOverride{typeID: semanticTokenTypeIndex["parameter"], modifier: 0}
			}
		}
		collectStatementTokenOverrides(e.Body, overrides)
	case *mast.MacroLiteral:
		for _, parameter := range e.Parameters {
			if parameter != nil {
				overrides[parameter] = semanticTokenOverride{typeID: semanticTokenTypeIndex["parameter"], modifier: 0}
			}
		}
		collectStatementTokenOverrides(e.Body, overrides)
	case *mast.CallExpression:
		if ident, ok := e.Function.(*mast.Identifier); ok && ident != nil && ident.Value != "" {
			if builtin.GetBuiltinByName(ident.Value) != nil {
				overrides[ident] = semanticTokenOverride{
					typeID:   semanticTokenTypeIndex["function"],
					modifier: semanticTokenModifierBit("defaultLibrary"),
				}
			}
		}
		collectExpressionTokenOverrides(e.Function, overrides)
		for _, arg := range e.Arguments {
			collectExpressionTokenOverrides(arg, overrides)
		}
	case *mast.ArrayLiteral:
		for _, element := range e.Elements {
			collectExpressionTokenOverrides(element, overrides)
		}
	case *mast.IndexExpression:
		collectExpressionTokenOverrides(e.Left, overrides)
		collectExpressionTokenOverrides(e.Index, overrides)
	case *mast.HashLiteral:
		for key, value := range e.Pairs {
			collectExpressionTokenOverrides(key, overrides)
			collectExpressionTokenOverrides(value, overrides)
		}
	case *mast.AssignExpression:
		collectExpressionTokenOverrides(e.Left, overrides)
		collectExpressionTokenOverrides(e.Value, overrides)
	case *mast.FieldExpression:
		collectExpressionTokenOverrides(e.Left, overrides)
		if e.Field != nil {
			overrides[e.Field] = semanticTokenOverride{typeID: semanticTokenTypeIndex["property"], modifier: 0}
		}
	case *mast.StructLiteral:
		if e.Name != nil {
			overrides[e.Name] = semanticTokenOverride{typeID: semanticTokenTypeIndex["type"], modifier: 0}
		}
		for _, field := range e.Fields {
			if field == nil {
				continue
			}
			if field.Name != nil {
				overrides[field.Name] = semanticTokenOverride{typeID: semanticTokenTypeIndex["property"], modifier: 0}
			}
			collectExpressionTokenOverrides(field.Value, overrides)
		}
	}
}

func semanticTokenModifierBit(name string) uint32 {
	idx, ok := semanticTokenModifierIndex[name]
	if !ok {
		return 0
	}
	return 1 << idx
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func tokenLength(node mast.Node, rng mast.Range) uint32 {
	if !rng.IsValid() {
		return 0
	}
	switch n := node.(type) {
	case *mast.Identifier:
		if n == nil {
			return 0
		}
		return uint32(len([]rune(n.Value)))
	case *mast.IntegerLiteral:
		return uint32(len([]rune(n.TokenLiteral())))
	case *mast.FloatLiteral:
		return uint32(len([]rune(n.TokenLiteral())))
	case *mast.StringLiteral:
		return uint32(len([]rune(n.TokenLiteral())))
	default:
		if rng.End.Line != rng.Start.Line || rng.End.Column <= rng.Start.Column {
			return 0
		}
		return uint32(rng.End.Column - rng.Start.Column)
	}
}
