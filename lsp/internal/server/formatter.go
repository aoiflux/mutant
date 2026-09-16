package server

import (
	"sort"
	"strings"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"
	"mutant/token"
)

// Canonical Mutant style. These are constants, not settings.
//
// Mutant formatting is strict in the gofmt tradition: one canonical rendering
// per valid program, with no knobs. The language server deliberately ignores
// the client's `tabSize` and `insertSpaces` FormattingOptions — honouring them
// would mean two developers with different editor settings produce different
// bytes for the same source, which is exactly what this formatter exists to
// prevent.
const (
	// indentUnit is four spaces. Never a tab.
	indentUnit = "    "
)

// formatSnapshotText renders snapshot as canonical Mutant source.
//
// When the document has hard parse errors the AST cannot be trusted, so the
// formatter degrades to whitespace normalisation rather than emitting a
// mangled program. Recoverable problems (a missing or redundant `;`) do not
// trigger the fallback — repairing those is the formatter's job, and it
// happens naturally: terminators are emitted from Statement.RequiresSemicolon
// rather than copied from the source, and stray semicolons never reach the
// tree in the first place.
// FormatSource returns the canonical formatting of Mutant source. It is the
// exported entry point used by the `mutant fmt` CLI (via lsp/api); on a hard
// parse error it degrades to whitespace normalization rather than mangling.
func FormatSource(src string) string {
	return formatSnapshotText(analyzer.New().Analyze(src))
}

func formatSnapshotText(snapshot *analyzer.Snapshot) string {
	if snapshot == nil {
		return ""
	}
	if snapshot.Program == nil || len(snapshot.ParseErrors) > 0 {
		return normalizeDocumentWhitespace(snapshot.Source)
	}

	p := newPrinter(snapshot.Program)
	body := p.statements(snapshot.Program.Statements, 0, endOfSourceOffset(snapshot.Source))

	formatted := strings.TrimRight(body, "\n")
	if formatted == "" {
		return ""
	}
	return formatted + "\n"
}

// endOfSourceOffset is the offset past the final byte, used as the flush
// boundary for comments trailing the last statement in the file.
func endOfSourceOffset(src string) int { return len(src) }

// printer walks the AST in source order, emitting canonical text.
//
// Comments are not part of the AST; they arrive as a position-ordered side
// table on the Program. The printer re-attaches them by consuming that table
// with a monotonically advancing cursor as it walks. This is only correct
// because the walk itself is strictly source-ordered — statements in order,
// and any block nested inside a statement visited at the point where it
// appears — so a comment is always reached at the position it was authored.
type printer struct {
	program  *mast.Program
	comments []token.Comment
	next     int

	// lastLine is the source line of the most recently emitted construct.
	// Comparing it against the next construct's start line is how authored
	// blank lines survive: a gap of two or more lines becomes exactly one
	// blank line, which keeps the transform idempotent.
	lastLine int
}

func newPrinter(program *mast.Program) *printer {
	comments := make([]token.Comment, len(program.Comments))
	copy(comments, program.Comments)
	// The lexer emits comments in order; sorting makes the cursor invariant
	// explicit and cheap to rely on.
	sort.SliceStable(comments, func(i, j int) bool {
		return comments[i].Start.Offset < comments[j].Start.Offset
	})

	return &printer{program: program, comments: comments}
}

func indent(level int) string {
	if level <= 0 {
		return ""
	}
	return strings.Repeat(indentUnit, level)
}

// statements renders a statement list — a whole file or a block body —
// including interleaved comments and preserved blank lines. endOffset bounds
// the region so comments trailing the final statement are flushed at the
// right indent instead of leaking to an outer scope.
func (p *printer) statements(stmts []mast.Statement, level int, endOffset int) string {
	var b strings.Builder

	for _, stmt := range stmts {
		if stmt == nil {
			continue
		}

		rng, hasRange := p.program.RangeOf(stmt)
		if hasRange {
			b.WriteString(p.flushCommentsBefore(rng.Start.Offset, level))
			b.WriteString(p.blankLineBefore(rng.Start.Line))
		}

		text := p.statement(stmt, level)
		if strings.TrimSpace(text) == "" {
			continue
		}

		b.WriteString(text)
		if stmt.RequiresSemicolon() {
			b.WriteString(";")
		}

		if hasRange {
			p.lastLine = rng.End.Line
			b.WriteString(p.trailingCommentOn(rng.End.Line))
		}
		b.WriteString("\n")
	}

	// Comments sitting after the last statement but still inside this scope.
	b.WriteString(p.flushCommentsBefore(endOffset, level))

	return b.String()
}

// flushCommentsBefore emits every pending comment that starts before offset
// as its own line at the given indent, preserving authored blank lines
// between them.
func (p *printer) flushCommentsBefore(offset int, level int) string {
	var b strings.Builder

	for p.next < len(p.comments) {
		comment := p.comments[p.next]
		if comment.Start.Offset >= offset {
			break
		}

		b.WriteString(p.blankLineBefore(comment.Start.Line))
		b.WriteString(indent(level))
		b.WriteString(strings.TrimRight(comment.Text, " \t"))
		b.WriteString("\n")

		p.lastLine = comment.End.Line
		p.next++
	}

	return b.String()
}

// trailingCommentOn consumes a comment that begins on line, if any, and
// renders it as ` // ...` appended to the construct just emitted.
func (p *printer) trailingCommentOn(line int) string {
	if p.next >= len(p.comments) {
		return ""
	}
	comment := p.comments[p.next]
	if comment.Start.Line != line {
		return ""
	}

	p.next++
	p.lastLine = comment.End.Line
	return " " + strings.TrimRight(comment.Text, " \t")
}

// blankLineBefore returns a single newline when the source had at least one
// blank line between the previous construct and startLine. Runs of blank
// lines collapse to one, so re-formatting formatted output is a no-op.
func (p *printer) blankLineBefore(startLine int) string {
	if p.lastLine == 0 || startLine <= p.lastLine+1 {
		return ""
	}
	return "\n"
}

func (p *printer) statement(stmt mast.Statement, level int) string {
	if stmt == nil {
		return ""
	}
	prefix := indent(level)

	switch node := stmt.(type) {
	case *mast.LetStatement:
		return prefix + "let " + letNames(node) + " = " + p.expression(node.Value, level)
	case *mast.ReturnStatement:
		return prefix + "return" + p.returnValues(node, level)
	case *mast.ExpressionStatement:
		return prefix + p.expression(node.Expression, level)
	case *mast.BlockStatement:
		return prefix + p.block(node, level)
	case *mast.ForStatement:
		return prefix + p.forStatement(node, level)
	case *mast.WhileStatement:
		return prefix + p.whileStatement(node, level)
	case *mast.ForInStatement:
		return prefix + p.forInStatement(node, level)
	case *mast.StructStatement:
		return prefix + "struct " + identValue(node.Name) + " {" + bracedIdents(node.Fields, "; ", ";") + "}"
	case *mast.EnumStatement:
		return prefix + "enum " + identValue(node.Name) + " {" + bracedIdents(node.Variants, ", ", "") + "}"
	case *mast.BreakStatement:
		return prefix + "break"
	case *mast.ContinueStatement:
		return prefix + "continue"
	case *mast.ImportStatement:
		return prefix + importStatement(node)
	default:
		return prefix + strings.TrimSpace(stmt.String())
	}
}

func (p *printer) returnValues(node *mast.ReturnStatement, level int) string {
	if len(node.ReturnValues) > 0 {
		parts := make([]string, 0, len(node.ReturnValues))
		for _, expr := range node.ReturnValues {
			parts = append(parts, p.expression(expr, level))
		}
		return " " + strings.Join(parts, ", ")
	}
	if node.ReturnValue == nil {
		return ""
	}
	return " " + p.expression(node.ReturnValue, level)
}

func (p *printer) expression(expr mast.Expression, level int) string {
	if expr == nil {
		return ""
	}

	switch node := expr.(type) {
	case *mast.Identifier:
		return node.Value
	case *mast.IntegerLiteral, *mast.FloatLiteral, *mast.Boolean:
		return expr.String()
	case *mast.StringLiteral:
		// A raw or triple-quoted literal is reprinted as written. Re-quoting
		// its value would be correct and useless: it would turn r"C:\Users"
		// back into "C:\\Users" and collapse a block of text onto one line
		// with \n between the pieces, undoing the two things those spellings
		// exist to do. An ordinary literal carries no spelling and is
		// re-quoted, which is what canonicalises its escapes.
		if node.Token.Raw != "" {
			return node.Token.Raw
		}
		return quoteString(node.Value)
	case *mast.TemplateLiteral:
		// Likewise, and for one more reason: a hole holds an expression whose
		// printed form would have to be re-escaped to survive being put back
		// inside a string.
		if node.Token.Raw != "" {
			return node.Token.Raw
		}
		return node.String()
	case *mast.PrefixExpression:
		// Mutant's canonical form parenthesises every operator expression, so
		// precedence is always explicit in the printed text.
		return "(" + node.Operator + p.expression(node.Right, level) + ")"
	case *mast.InfixExpression:
		return "(" + p.expression(node.Left, level) + " " + node.Operator + " " + p.expression(node.Right, level) + ")"
	case *mast.AssignExpression:
		if node.Postfix != "" {
			return p.expression(node.Left, level) + node.Postfix
		}
		if node.Operator != "" {
			return p.expression(node.Left, level) + " " + node.Operator + "= " + p.expression(node.Value, level)
		}
		return p.expression(node.Left, level) + " = " + p.expression(node.Value, level)
	case *mast.CallExpression:
		return p.expression(node.Function, level) + "(" + p.expressionList(node.Arguments, level) + ")"
	case *mast.FunctionLiteral:
		return "fn(" + joinIdents(node.Parameters, ", ") + ") " + p.block(node.Body, level)
	case *mast.MacroLiteral:
		return "macro(" + joinIdents(node.Parameters, ", ") + ") " + p.block(node.Body, level)
	case *mast.IfExpression:
		result := "if " + p.condition(node.Condition, level) + " " + p.block(node.Consequence, level)
		if node.Alternative != nil {
			result += " else " + p.block(node.Alternative, level)
		}
		return result
	case *mast.MatchExpression:
		return p.matchExpression(node, level)
	case *mast.ArrayLiteral:
		return "[" + p.expressionList(node.Elements, level) + "]"
	case *mast.IndexExpression:
		return p.expression(node.Left, level) + "[" + p.expression(node.Index, level) + "]"
	case *mast.FieldExpression:
		return p.expression(node.Left, level) + "." + identValue(node.Field)
	case *mast.StructLiteral:
		return p.structLiteral(node, level)
	case *mast.HashLiteral:
		return p.hashLiteral(node, level)
	default:
		return strings.TrimSpace(expr.String())
	}
}

// matchExpression prints one arm per line, each ending in a comma including the
// last. The parser accepts that trailing comma, and writing it means adding an
// arm touches one line instead of two.
func (p *printer) matchExpression(node *mast.MatchExpression, level int) string {
	subject := "match " + p.condition(node.Subject, level)
	if len(node.Arms) == 0 {
		// The parser refuses an empty match, so this is unreachable from real
		// source; it exists so a half-built tree from an editor buffer still
		// prints something rather than a stray brace.
		return subject + " {}"
	}

	var out strings.Builder
	out.WriteString(subject)
	out.WriteString(" {\n")
	for _, arm := range node.Arms {
		if arm == nil {
			continue
		}
		out.WriteString(indent(level + 1))
		out.WriteString(p.matchArm(arm, level+1))
		out.WriteString(",\n")
	}
	out.WriteString(indent(level))
	out.WriteString("}")
	return out.String()
}

// matchArm prints `pattern => body`, keeping the author's choice of a braced or
// a bare body. A block is how an arm does more than one thing, and rewriting
// one form into the other would churn every file that picked the other.
func (p *printer) matchArm(arm *mast.MatchArm, level int) string {
	// The wildcard is stored as no patterns at all, so the `_` is written back
	// here rather than read off the tree.
	patterns := "_"
	if !arm.IsWildcard() {
		parts := make([]string, 0, len(arm.Patterns))
		for _, pattern := range arm.Patterns {
			parts = append(parts, p.matchPattern(pattern, level))
		}
		patterns = strings.Join(parts, " | ")
	}

	if !arm.Braced {
		if bare, ok := bareArmValue(arm.Body); ok {
			return patterns + " => " + p.expression(bare, level)
		}
	}
	return patterns + " => " + p.block(arm.Body, level)
}

// matchPattern prints one pattern, which is not quite printing an expression.
//
// The canonical form parenthesises every operator expression so precedence is
// explicit, and a negated number is one -- but a pattern has no precedence to
// make explicit, and the pattern grammar admits a literal, a dotted path and a
// leading `-`, nothing else. Printing `(-1)` would emit source the parser then
// rejects, which is the one thing a formatter must never do.
func (p *printer) matchPattern(pattern mast.Expression, level int) string {
	if prefix, ok := pattern.(*mast.PrefixExpression); ok && prefix != nil {
		return prefix.Operator + p.matchPattern(prefix.Right, level)
	}
	return p.expression(pattern, level)
}

// bareArmValue unwraps the single-statement block the parser builds for an
// unbraced arm body, so the formatter can print back the form that was written.
func bareArmValue(body *mast.BlockStatement) (mast.Expression, bool) {
	if body == nil || len(body.Statements) != 1 {
		return nil, false
	}
	es, ok := body.Statements[0].(*mast.ExpressionStatement)
	if !ok || es.Expression == nil {
		return nil, false
	}
	return es.Expression, true
}

func (p *printer) expressionList(exprs []mast.Expression, level int) string {
	parts := make([]string, 0, len(exprs))
	for _, expr := range exprs {
		parts = append(parts, p.expression(expr, level))
	}
	return strings.Join(parts, ", ")
}

func (p *printer) structLiteral(node *mast.StructLiteral, level int) string {
	fields := make([]string, 0, len(node.Fields))
	for _, field := range node.Fields {
		if field == nil || field.Name == nil {
			continue
		}
		fields = append(fields, field.Name.Value+": "+p.expression(field.Value, level))
	}

	name := ""
	if node.Name != nil {
		name = node.Name.Value + " "
	}
	return name + "{" + strings.Join(fields, ", ") + "}"
}

// hashLiteral emits entries in the order the author wrote them.
//
// HashLiteral.Pairs is a Go map, so ranging over it yields a random order —
// printing that directly would make the formatter non-deterministic and break
// idempotency outright. Recovering the authored order from each key's source
// range fixes that without reordering anyone's code; keys the parser did not
// record fall back to their rendered text so the result is still total.
func (p *printer) hashLiteral(node *mast.HashLiteral, level int) string {
	type entry struct {
		text     string
		offset   int
		hasRange bool
	}

	entries := make([]entry, 0, len(node.Pairs))
	for key, value := range node.Pairs {
		e := entry{text: p.expression(key, level) + ": " + p.expression(value, level)}
		if rng, ok := p.program.RangeOf(key); ok {
			e.offset = rng.Start.Offset
			e.hasRange = true
		}
		entries = append(entries, e)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].hasRange != entries[j].hasRange {
			return entries[i].hasRange
		}
		if entries[i].hasRange && entries[i].offset != entries[j].offset {
			return entries[i].offset < entries[j].offset
		}
		return entries[i].text < entries[j].text
	})

	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, e.text)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func (p *printer) condition(expr mast.Expression, level int) string {
	formatted := p.expression(expr, level)
	if strings.HasPrefix(formatted, "(") && strings.HasSuffix(formatted, ")") {
		return formatted
	}
	return "(" + formatted + ")"
}

// block renders a brace-delimited body. The opening brace stays on the
// declaration's line and the closing brace gets its own line at the parent's
// indent. A block with neither statements nor comments collapses to `{}`.
func (p *printer) block(block *mast.BlockStatement, level int) string {
	if block == nil {
		return "{}"
	}

	endOffset := 0
	if rng, ok := p.program.RangeOf(block); ok {
		endOffset = rng.End.Offset
		// Anchor blank-line accounting to the opening brace. Without this,
		// lastLine still refers to the line before the enclosing statement
		// began, and the first statement in the body would look like it was
		// separated by blank lines that the author never wrote.
		p.lastLine = rng.Start.Line
	}

	body := p.statements(block.Statements, level+1, endOffset)
	if strings.TrimSpace(body) == "" {
		return "{}"
	}

	return "{\n" + strings.TrimRight(body, "\n") + "\n" + indent(level) + "}"
}

func (p *printer) forStatement(stmt *mast.ForStatement, level int) string {
	if stmt == nil {
		return ""
	}

	init := ""
	if stmt.Init != nil {
		init = strings.TrimSpace(p.statement(stmt.Init, 0))
	}
	cond := ""
	if stmt.Condition != nil {
		cond = p.expression(stmt.Condition, level)
	}
	post := ""
	if stmt.Post != nil {
		post = p.expression(stmt.Post, level)
	}

	return "for (" + init + "; " + cond + "; " + post + ") " + p.block(stmt.Body, level)
}

func (p *printer) forInStatement(stmt *mast.ForInStatement, level int) string {
	if stmt == nil {
		return ""
	}

	names := identValue(stmt.Value)
	if stmt.Key != nil {
		names = identValue(stmt.Key) + ", " + names
	}

	iterable := ""
	if stmt.Iterable != nil {
		iterable = p.expression(stmt.Iterable, level)
	}

	return "for (" + names + " in " + iterable + ") " + p.block(stmt.Body, level)
}

func (p *printer) whileStatement(stmt *mast.WhileStatement, level int) string {
	if stmt == nil {
		return ""
	}

	if stmt.Condition == nil {
		return "while () " + p.block(stmt.Body, level)
	}

	// condition() rather than expression(): an infix condition already prints
	// its own parentheses, and wrapping it again gives `while ((i < 10))`.
	return "while " + p.condition(stmt.Condition, level) + " " + p.block(stmt.Body, level)
}

func letNames(node *mast.LetStatement) string {
	if len(node.Names) > 0 {
		parts := make([]string, 0, len(node.Names))
		for _, ident := range node.Names {
			if ident != nil {
				parts = append(parts, ident.Value)
			}
		}
		return strings.Join(parts, ", ")
	}
	return identValue(node.Name)
}

// importStatement renders `import "path.mut"` or `import ns "path.mut"`.
//
// It deliberately stops short of the terminator: statements() appends `;`
// for every statement whose RequiresSemicolon reports true, so emitting one
// here would double it.
func importStatement(node *mast.ImportStatement) string {
	var b strings.Builder
	b.WriteString("import ")
	if alias := identValue(node.Alias); alias != "" {
		b.WriteString(alias)
		b.WriteString(" ")
	}
	if node.Path != nil {
		b.WriteString(quoteString(node.Path.Value))
	}
	return b.String()
}

func identValue(ident *mast.Identifier) string {
	if ident == nil {
		return ""
	}
	return ident.Value
}

// joinIdents renders an identifier list with sep between entries and no
// surrounding padding. Used for parameter lists, where `fn(a, b)` hugs its
// parentheses.
func joinIdents(idents []*mast.Identifier, sep string) string {
	parts := make([]string, 0, len(idents))
	for _, ident := range idents {
		if ident != nil {
			parts = append(parts, ident.Value)
		}
	}
	return strings.Join(parts, sep)
}

// bracedIdents renders a declaration body that sits inside braces, padded
// away from them. Struct fields are semicolon-terminated including the last
// (`struct P { x; y; }`); enum variants are comma-separated but not
// comma-terminated (`enum C { Red, Green }`). An empty list yields `{}`.
func bracedIdents(idents []*mast.Identifier, sep string, terminator string) string {
	joined := joinIdents(idents, sep)
	if joined == "" {
		return ""
	}
	return " " + joined + terminator + " "
}

// quoteString renders a decoded string value back as Mutant source. It has to
// undo exactly what the lexer's readString did -- \n \r \t \" \\ \0 -- and it
// used to re-escape only the backslash and the quote, so every other escape came
// back as the raw control byte it decodes to.
//
// That is worse than ugly. A carriage return inside a source file is invisible,
// and anything that normalises line endings -- git's autocrlf, an editor, a CI
// checkout -- would quietly turn a formatted "HTTP/1.1 200 OK\r\n" into a string
// carrying a bare newline, changing the bytes the program puts on the wire. The
// escape exists precisely so the byte survives text processing.
//
// Byte-oriented to match the lexer: every byte of a multi-byte rune is >= 0x80
// and passes through untouched.
func quoteString(value string) string {
	var out strings.Builder
	out.Grow(len(value) + 2)
	out.WriteByte('"')
	for i := 0; i < len(value); i++ {
		// ${ has to be escaped back, or formatting a string that merely
		// contains those two characters turns it into one that interpolates.
		// Only the pair matters: a lone $ is a $ to the lexer too.
		if value[i] == '$' && i+1 < len(value) && value[i+1] == '{' {
			out.WriteString(`\$`)
			continue
		}
		switch c := value[i]; c {
		case '\\':
			out.WriteString(`\\`)
		case '"':
			out.WriteString(`\"`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case 0:
			out.WriteString(`\0`)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// normalizeDocumentWhitespace is the degraded path used when the document
// does not parse: strip trailing whitespace, normalise line endings, and
// guarantee a single trailing newline, without touching structure.
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
