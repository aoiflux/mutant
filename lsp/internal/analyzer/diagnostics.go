package analyzer

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// hostGOOS is the operating system the language server is running on. Because the
// server runs on the developer's machine, this is the platform their program will
// actually execute against — so it is the correct target for the platform-support
// diagnostic. It is a package variable (not a direct runtime.GOOS call) so tests
// can simulate other platforms.
var hostGOOS = runtime.GOOS

type LintSeverity string

const (
	LintSeverityError       LintSeverity = "error"
	LintSeverityWarning     LintSeverity = "warning"
	LintSeverityInformation LintSeverity = "information"
	LintSeverityHint        LintSeverity = "hint"
	LintSeverityOff         LintSeverity = "off"
)

// DiagnosticSourceFormat tags diagnostics raised by the strict formatting
// rules, as distinct from "mutant-parser" (hard syntax errors) and
// "mutant-lint" (style and correctness rules). Quick fixes key off it.
const DiagnosticSourceFormat = "mutant-format"

type LintConfig struct {
	DuplicateTopLevelDeclaration LintSeverity
	UnusedDeclaration            LintSeverity
	UndefinedDeclaration         LintSeverity
	NestingComplexity            LintSeverity
	Semicolon                    LintSeverity
	UnreachableCode              LintSeverity
	PlatformSupport              LintSeverity
}

func DefaultLintConfig() LintConfig {
	return LintConfig{
		DuplicateTopLevelDeclaration: LintSeverityWarning,
		UnusedDeclaration:            LintSeverityWarning,
		UndefinedDeclaration:         LintSeverityError,
		NestingComplexity:            LintSeverityWarning,
		// Mutant mandates semicolons, but a missing one still parses into a
		// usable tree and the formatter repairs it on save, so this is a
		// warning rather than an error.
		Semicolon: LintSeverityWarning,
		// Statements after an unconditional return/break/continue can never run.
		UnreachableCode: LintSeverityWarning,
		// A builtin that cannot work on the host OS is a warning (not an error):
		// the program may be authored on one platform to run on another, and the
		// call still parses/compiles — it just fails at runtime on this host.
		PlatformSupport: LintSeverityWarning,
	}
}

func (c LintConfig) severityForRule(rule string) (*lsp.DiagnosticSeverity, bool) {
	severityName := LintSeverityWarning
	switch rule {
	case "duplicateTopLevelDeclaration":
		severityName = c.DuplicateTopLevelDeclaration
	case "unusedDeclaration":
		severityName = c.UnusedDeclaration
	case "undefinedDeclaration":
		severityName = c.UndefinedDeclaration
	case "nestingComplexity":
		severityName = c.NestingComplexity
	case "semicolon":
		severityName = c.Semicolon
	case "unreachableCode":
		severityName = c.UnreachableCode
	case "platformSupport":
		severityName = c.PlatformSupport
	default:
		return nil, false
	}

	if severityName == "" {
		severityName = LintSeverityWarning
	}

	var severity lsp.DiagnosticSeverity
	switch severityName {
	case LintSeverityError:
		severity = lsp.DiagnosticSeverityError
	case LintSeverityWarning:
		severity = lsp.DiagnosticSeverityWarning
	case LintSeverityInformation:
		severity = lsp.DiagnosticSeverityInformation
	case LintSeverityHint:
		severity = lsp.DiagnosticSeverityHint
	case LintSeverityOff:
		return nil, false
	default:
		severity = lsp.DiagnosticSeverityWarning
	}
	return &severity, true
}

func Diagnostics(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil {
		return nil
	}

	diagnostics := make([]lsp.Diagnostic, 0, len(snapshot.ParseErrors)+4)

	severity := lsp.DiagnosticSeverityError
	source := "mutant-parser"
	for _, parseErr := range snapshot.ParseErrors {
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(parseErr.Range),
			Severity: &severity,
			Source:   &source,
			Message:  parseErr.Msg,
		})
	}
	diagnostics = append(diagnostics, syntaxBalanceDiagnostics(snapshot.Source)...)

	duplicateDiagnostics := lintDuplicateTopLevelDeclarations(snapshot, lintConfig)
	diagnostics = append(diagnostics, duplicateDiagnostics...)
	diagnostics = append(diagnostics, lintUnusedDeclarations(snapshot, lintConfig, duplicateNamesFromDiagnostics(duplicateDiagnostics))...)
	diagnostics = append(diagnostics, lintUndefinedDeclarations(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintNestingComplexity(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintSemicolons(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintUnreachableCode(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintPlatformSupport(snapshot, lintConfig)...)

	if len(diagnostics) == 0 {
		return nil
	}
	return diagnostics
}

// lintPlatformSupport warns when a program calls a builtin that does not work on
// the operating system the language server is running on. The builtin's supported
// platforms come from builtin.PlatformSupport / builtin.UnsupportedOn (populated
// in builtin/metadata.go). This is what makes the editor OS-aware: on macOS, for
// example, a call to a Windows/Linux-only builtin such as process_modules is
// flagged before the program is ever run.
func lintPlatformSupport(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("platformSupport")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	result := make([]lsp.Diagnostic, 0, 2)
	for node := range snapshot.Program.NodePositions {
		call, ok := node.(*mast.CallExpression)
		if !ok || call == nil {
			continue
		}
		ident, ok := call.Function.(*mast.Identifier)
		if !ok || ident == nil || ident.Value == "" {
			continue
		}
		if !builtin.UnsupportedOn(ident.Value, hostGOOS) {
			continue
		}
		rng, ok := snapshot.Program.RangeOf(ident)
		if !ok {
			continue
		}
		platforms, _ := builtin.PlatformSupport(ident.Value)
		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message: fmt.Sprintf("builtin `%s` is not supported on %s (supported: %s)",
				ident.Value, hostGOOS, strings.Join(platforms, ", ")),
		})
	}

	// NodePositions is a map, so sort for deterministic output.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Range.Start.Line != result[j].Range.Start.Line {
			return result[i].Range.Start.Line < result[j].Range.Start.Line
		}
		return result[i].Range.Start.Character < result[j].Range.Start.Character
	})

	if len(result) == 0 {
		return nil
	}
	return result
}

// lintUnreachableCode flags the first statement that follows an unconditional
// return/break/continue within a statement list (the top-level program and every
// block body). Control-flow through if/for is not modeled; only a literal
// terminating statement makes what follows unreachable.
func lintUnreachableCode(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("unreachableCode")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	result := make([]lsp.Diagnostic, 0, 2)

	scan := func(statements []mast.Statement) {
		for i, stmt := range statements {
			kind, terminating := terminatingStatementKind(stmt)
			if !terminating {
				continue
			}
			if i+1 >= len(statements) {
				return
			}
			next := statements[i+1]
			rng, ok := snapshot.Program.RangeOf(next)
			if !ok {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    localprotocol.ToLSPRange(rng),
				Severity: severity,
				Source:   &source,
				Message:  fmt.Sprintf("unreachable code after `%s`", kind),
			})
			return
		}
	}

	scan(snapshot.Program.Statements)
	for node := range snapshot.Program.NodePositions {
		if block, ok := node.(*mast.BlockStatement); ok && block != nil {
			scan(block.Statements)
		}
	}

	// Deterministic order (NodePositions iteration is random).
	sort.Slice(result, func(i, j int) bool {
		if result[i].Range.Start.Line != result[j].Range.Start.Line {
			return result[i].Range.Start.Line < result[j].Range.Start.Line
		}
		return result[i].Range.Start.Character < result[j].Range.Start.Character
	})

	if len(result) == 0 {
		return nil
	}
	return result
}

// terminatingStatementKind reports whether a statement unconditionally ends the
// current statement list, and the keyword to name in the diagnostic.
func terminatingStatementKind(stmt mast.Statement) (string, bool) {
	switch stmt.(type) {
	case *mast.ReturnStatement:
		return "return", true
	case *mast.BreakStatement:
		return "break", true
	case *mast.ContinueStatement:
		return "continue", true
	default:
		return "", false
	}
}

// lintSemicolons reports the parser's recoverable semicolon problems.
//
// These never appear in ParseErrors — the tree parsed fine — so without this
// rule a missing `;` would be invisible until the formatter silently fixed
// it on save. Surfacing them lets the editor show the problem and offer a
// targeted quick fix.
func lintSemicolons(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil {
		return nil
	}

	problems := snapshot.SemicolonProblems()
	if len(problems) == 0 {
		return nil
	}

	severity, ok := lintConfig.severityForRule("semicolon")
	if !ok {
		return nil
	}

	source := DiagnosticSourceFormat
	result := make([]lsp.Diagnostic, 0, len(problems))
	for _, problem := range problems {
		rng := localprotocol.ToLSPRange(problem.Range)
		if !problem.Range.IsValid() {
			continue
		}
		result = append(result, lsp.Diagnostic{
			Range:    widenZeroWidthRange(rng),
			Severity: severity,
			Source:   &source,
			Message:  problem.Msg,
		})
	}

	return result
}

// widenZeroWidthRange makes an insertion point visible.
//
// A missing-semicolon problem is recorded as a zero-width range so it can be
// used directly as an insertion point, but editors render a zero-width
// diagnostic as little or nothing. Extending it one character to the left
// underlines the statement's final token instead, while quick fixes keep
// using the range's End as the true insertion point.
func widenZeroWidthRange(rng lsp.Range) lsp.Range {
	if rng.Start != rng.End || rng.Start.Character == 0 {
		return rng
	}
	widened := rng
	widened.Start.Character--
	return widened
}

func lintDuplicateTopLevelDeclarations(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("duplicateTopLevelDeclaration")
	if !ok {
		return nil
	}
	source := "mutant-lint"
	usageCache := make(map[*mast.Identifier]bool)
	collector := &duplicateCollector{
		snapshot:   snapshot,
		severity:   severity,
		source:     &source,
		usageCache: usageCache,
		result:     make([]lsp.Diagnostic, 0, 2),
	}

	root := newDeclarationScope(nil, 0)
	for _, stmt := range snapshot.Program.Statements {
		collector.collectStatement(stmt, root)
	}

	return collector.result
}

type declarationScope struct {
	parent *declarationScope
	depth  int
	decls  map[string]declInfo
}

type declInfo struct {
	ident            *mast.Identifier
	fromMultiNameLet bool
	topLevel         bool
}

type duplicateCollector struct {
	snapshot   *Snapshot
	severity   *lsp.DiagnosticSeverity
	source     *string
	usageCache map[*mast.Identifier]bool
	result     []lsp.Diagnostic
}

func newDeclarationScope(parent *declarationScope, depth int) *declarationScope {
	return &declarationScope{parent: parent, depth: depth, decls: make(map[string]declInfo)}
}

func (s *declarationScope) find(name string) (declInfo, bool) {
	for current := s; current != nil; current = current.parent {
		info, ok := current.decls[name]
		if ok {
			return info, true
		}
	}
	return declInfo{}, false
}

func (s *declarationScope) define(name string, info declInfo) {
	if s == nil || name == "" || info.ident == nil {
		return
	}
	s.decls[name] = info
}

func (c *duplicateCollector) collectStatement(stmt mast.Statement, current *declarationScope) {
	if c == nil || c.snapshot == nil || current == nil {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}

		if len(names) == 1 {
			c.collectDeclaration(names[0], current, false)
		} else {
			for _, ident := range names {
				c.collectDeclaration(ident, current, true)
			}
		}

		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}

		if len(names) > 1 {
			for _, ident := range names {
				if ident == nil || ident.Value == "" || ident.Value == "_" {
					continue
				}
				current.define(ident.Value, declInfo{ident: ident, fromMultiNameLet: true, topLevel: current.depth == 0})
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			c.collectExpression(expr, current)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			c.collectExpression(node.ReturnValue, current)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			c.collectExpression(node.Expression, current)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			c.collectStatement(inner, current)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			c.collectStatement(node.Init, current)
		}
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Post != nil {
			c.collectExpression(node.Post, current)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, current)
		}
	case *mast.StructStatement:
		c.collectDeclaration(node.Name, current, false)
	case *mast.EnumStatement:
		c.collectDeclaration(node.Name, current, false)
	}
}

func (c *duplicateCollector) collectExpression(expr mast.Expression, current *declarationScope) {
	if c == nil || c.snapshot == nil || current == nil || expr == nil {
		return
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		child := newDeclarationScope(current, current.depth+1)
		for _, param := range node.Parameters {
			c.collectDeclaration(param, child, false)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	case *mast.MacroLiteral:
		child := newDeclarationScope(current, current.depth+1)
		for _, param := range node.Parameters {
			c.collectDeclaration(param, child, false)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Consequence != nil {
			c.collectStatement(node.Consequence, current)
		}
		if node.Alternative != nil {
			c.collectStatement(node.Alternative, current)
		}
	case *mast.CallExpression:
		if ident, ok := node.Function.(*mast.Identifier); ok && ident != nil && isMacroSpecialFormName(ident.Value) {
			for _, arg := range node.Arguments {
				c.collectExpression(arg, current)
			}
			return
		}
		if node.Function != nil {
			c.collectExpression(node.Function, current)
		}
		for _, arg := range node.Arguments {
			c.collectExpression(arg, current)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Index != nil {
			c.collectExpression(node.Index, current)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
	case *mast.StructLiteral:
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			c.collectExpression(field.Value, current)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			c.collectExpression(element, current)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key, current)
			c.collectExpression(value, current)
		}
	}
}

func (c *duplicateCollector) collectDeclaration(ident *mast.Identifier, current *declarationScope, fromMultiNameLet bool) {
	// `_` is the discard identifier — it may be bound repeatedly (e.g. the error
	// half of several `let value, _ = ...` bindings), so it is never a duplicate.
	if ident == nil || ident.Value == "" || ident.Value == "_" || current == nil || c == nil || c.snapshot == nil {
		return
	}

	rng, ok := c.snapshot.Program.RangeOf(ident)
	if !ok {
		return
	}

	if previous, exists := current.find(ident.Value); exists {
		if !shouldSuppressDuplicateDiagnostic(c.snapshot, previous, c.usageCache) {
			message := fmt.Sprintf("duplicate declaration `%s`", ident.Value)
			if current.depth == 0 {
				message = fmt.Sprintf("duplicate top-level declaration `%s`", ident.Value)
			}
			c.result = append(c.result, lsp.Diagnostic{
				Range:    localprotocol.ToLSPRange(rng),
				Severity: c.severity,
				Source:   c.source,
				Message:  message,
			})
		}
		return
	}

	if !fromMultiNameLet {
		current.define(ident.Value, declInfo{ident: ident, fromMultiNameLet: false, topLevel: current.depth == 0})
	}
}

func shouldSuppressDuplicateDiagnostic(snapshot *Snapshot, previous declInfo, usageCache map[*mast.Identifier]bool) bool {
	if snapshot == nil || previous.ident == nil || !previous.fromMultiNameLet {
		return false
	}

	if used, ok := usageCache[previous.ident]; ok {
		return used
	}

	rng, ok := snapshot.Program.RangeOf(previous.ident)
	if !ok {
		usageCache[previous.ident] = false
		return false
	}

	pos := lsp.Position{Line: lsp.UInteger(rng.Start.Line - 1), Character: lsp.UInteger(rng.Start.Column - 1)}
	locations, ok := snapshot.ReferenceLocations("", pos, false)
	if !ok || len(locations) == 0 {
		usageCache[previous.ident] = false
		return false
	}

	nextLine := lsp.UInteger(rng.Start.Line)
	for _, location := range locations {
		if location.Range.Start.Line == nextLine {
			usageCache[previous.ident] = true
			return true
		}
	}

	usageCache[previous.ident] = false
	return false
}

func isMultiNameLet(stmt mast.Statement) bool {
	letStmt, ok := stmt.(*mast.LetStatement)
	if !ok || letStmt == nil {
		return false
	}
	return len(letStmt.Names) > 1
}

func syntaxBalanceDiagnostics(sourceText string) []lsp.Diagnostic {
	if sourceText == "" {
		return nil
	}

	type delimiter struct {
		token string
		line  int
		col   int
	}

	severity := lsp.DiagnosticSeverityError
	source := "mutant-parser"

	stack := make([]delimiter, 0, 8)
	diagnostics := make([]lsp.Diagnostic, 0, 4)

	normalized := strings.ReplaceAll(strings.ReplaceAll(sourceText, "\r\n", "\n"), "\r", "\n")
	line := 0
	col := 0
	inString := false
	escaped := false
	inLineComment := false

	for i := 0; i < len(normalized); i++ {
		ch := normalized[i]

		if ch == '\n' {
			line++
			col = 0
			inLineComment = false
			escaped = false
			continue
		}

		if inLineComment {
			col++
			continue
		}

		if inString {
			if escaped {
				escaped = false
				col++
				continue
			}
			if ch == '\\' {
				escaped = true
				col++
				continue
			}
			if ch == '"' {
				inString = false
			}
			col++
			continue
		}

		if ch == '"' {
			inString = true
			col++
			continue
		}

		if ch == '/' && i+1 < len(normalized) && normalized[i+1] == '/' {
			inLineComment = true
			col += 2
			i++
			continue
		}

		switch ch {
		case '(', '[', '{':
			stack = append(stack, delimiter{token: string(ch), line: line, col: col})
		case ')', ']', '}':
			if len(stack) == 0 {
				diagnostics = append(diagnostics, lsp.Diagnostic{
					Range:    singleCharRange(line, col),
					Severity: &severity,
					Source:   &source,
					Message:  fmt.Sprintf("unexpected closing delimiter `%c`", ch),
				})
				col++
				continue
			}

			top := stack[len(stack)-1]
			if !delimitersMatch(top.token, string(ch)) {
				diagnostics = append(diagnostics, lsp.Diagnostic{
					Range:    singleCharRange(line, col),
					Severity: &severity,
					Source:   &source,
					Message:  fmt.Sprintf("mismatched delimiter `%c`", ch),
				})
				col++
				continue
			}

			stack = stack[:len(stack)-1]
		}

		col++
	}

	for i := len(stack) - 1; i >= 0; i-- {
		open := stack[i]
		diagnostics = append(diagnostics, lsp.Diagnostic{
			Range:    singleCharRange(open.line, open.col),
			Severity: &severity,
			Source:   &source,
			Message:  fmt.Sprintf("unclosed delimiter `%s`", open.token),
		})
	}

	if len(diagnostics) == 0 {
		return nil
	}

	return diagnostics
}

func delimitersMatch(open, close string) bool {
	return (open == "(" && close == ")") ||
		(open == "[" && close == "]") ||
		(open == "{" && close == "}")
}

func singleCharRange(line, col int) lsp.Range {
	start := lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(col)}
	end := lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(col + 1)}
	return lsp.Range{Start: start, End: end}
}

func lintUnusedDeclarations(snapshot *Snapshot, lintConfig LintConfig, skipNames map[string]struct{}) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("unusedDeclaration")
	if !ok {
		return nil
	}
	source := "mutant-lint"
	result := make([]lsp.Diagnostic, 0, 4)
	candidates := collectUnusedCandidates(snapshot)

	for _, ident := range candidates {
		if ident == nil || ident.Value == "" || ident.Value == "_" {
			continue
		}
		if _, skip := skipNames[ident.Value]; skip {
			continue
		}

		rng, ok := snapshot.Program.RangeOf(ident)
		if !ok {
			continue
		}

		pos := lsp.Position{Line: lsp.UInteger(rng.Start.Line - 1), Character: lsp.UInteger(rng.Start.Column - 1)}
		locations, ok := snapshot.ReferenceLocations("", pos, false)
		if ok && len(locations) > 0 {
			continue
		}

		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message:  fmt.Sprintf("unused declaration `%s`", ident.Value),
		})
	}

	return result
}

func lintUndefinedDeclarations(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("undefinedDeclaration")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	knownBuiltins := make(map[string]struct{}, len(builtin.Builtins))
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		knownBuiltins[def.Name] = struct{}{}
	}

	collector := &undefinedCollector{
		snapshot: snapshot,
		severity: severity,
		source:   &source,
		builtins: knownBuiltins,
		result:   make([]lsp.Diagnostic, 0, 4),
	}

	root := newDeclarationScope(nil, 0)
	for _, stmt := range snapshot.Program.Statements {
		collector.collectStatement(stmt, root)
	}

	return collector.result
}

func lintNestingComplexity(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("nestingComplexity")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	collector := &nestingCollector{
		snapshot: snapshot,
		severity: severity,
		source:   &source,
		result:   make([]lsp.Diagnostic, 0, 2),
	}

	for _, stmt := range snapshot.Program.Statements {
		collector.collectStatement(stmt, false, 0)
	}

	return collector.result
}

type nestingCollector struct {
	snapshot *Snapshot
	severity *lsp.DiagnosticSeverity
	source   *string
	result   []lsp.Diagnostic
}

func (c *nestingCollector) collectStatement(stmt mast.Statement, inFunction bool, depth int) {
	if c == nil || c.snapshot == nil || stmt == nil {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		if node.Value != nil {
			c.collectExpression(node.Value, inFunction, depth)
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			c.collectExpression(expr, inFunction, depth)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			c.collectExpression(node.ReturnValue, inFunction, depth)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			c.collectExpression(node.Expression, inFunction, depth)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			c.collectStatement(inner, inFunction, depth)
		}
	case *mast.ForStatement:
		nextDepth := depth
		if inFunction {
			nextDepth = depth + 1
			c.maybeAddNestingDiagnostic(node, nextDepth)
		}

		if node.Init != nil {
			c.collectStatement(node.Init, inFunction, depth)
		}
		if node.Condition != nil {
			c.collectExpression(node.Condition, inFunction, depth)
		}
		if node.Post != nil {
			c.collectExpression(node.Post, inFunction, depth)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, inFunction, nextDepth)
		}
	}
}

func (c *nestingCollector) collectExpression(expr mast.Expression, inFunction bool, depth int) {
	if c == nil || c.snapshot == nil || expr == nil {
		return
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		if node.Body != nil {
			c.collectStatement(node.Body, true, 0)
		}
	case *mast.MacroLiteral:
		if node.Body != nil {
			c.collectStatement(node.Body, true, 0)
		}
	case *mast.IfExpression:
		nextDepth := depth
		if inFunction {
			nextDepth = depth + 1
			c.maybeAddNestingDiagnostic(node, nextDepth)
		}

		if node.Condition != nil {
			c.collectExpression(node.Condition, inFunction, depth)
		}
		if node.Consequence != nil {
			c.collectStatement(node.Consequence, inFunction, nextDepth)
		}
		if node.Alternative != nil {
			c.collectStatement(node.Alternative, inFunction, nextDepth)
		}
	case *mast.CallExpression:
		if node.Function != nil {
			c.collectExpression(node.Function, inFunction, depth)
		}
		for _, arg := range node.Arguments {
			c.collectExpression(arg, inFunction, depth)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			c.collectExpression(node.Right, inFunction, depth)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, inFunction, depth)
		}
		if node.Right != nil {
			c.collectExpression(node.Right, inFunction, depth)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, inFunction, depth)
		}
		if node.Index != nil {
			c.collectExpression(node.Index, inFunction, depth)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, inFunction, depth)
		}
		if node.Value != nil {
			c.collectExpression(node.Value, inFunction, depth)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, inFunction, depth)
		}
	case *mast.StructLiteral:
		for _, field := range node.Fields {
			if field == nil || field.Value == nil {
				continue
			}
			c.collectExpression(field.Value, inFunction, depth)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			c.collectExpression(element, inFunction, depth)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key, inFunction, depth)
			c.collectExpression(value, inFunction, depth)
		}
	}
}

func (c *nestingCollector) maybeAddNestingDiagnostic(node mast.Node, depth int) {
	if c == nil || c.snapshot == nil || node == nil || depth <= 2 {
		return
	}

	rng, ok := c.snapshot.Program.RangeOf(node)
	if !ok {
		return
	}

	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.severity,
		Source:   c.source,
		Message:  fmt.Sprintf("nesting depth %d exceeds recommended maximum 2; prefer guard clauses, early returns, or extracting helper functions", depth),
	})
}

type undefinedCollector struct {
	snapshot *Snapshot
	severity *lsp.DiagnosticSeverity
	source   *string
	builtins map[string]struct{}
	result   []lsp.Diagnostic
}

func (c *undefinedCollector) collectStatement(stmt mast.Statement, current *declarationScope) {
	if c == nil || c.snapshot == nil || current == nil || stmt == nil {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}

		if len(names) == 1 {
			c.defineDeclaration(names[0], current, false)
		}

		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}

		if len(names) > 1 {
			for _, ident := range names {
				c.defineDeclaration(ident, current, true)
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			c.collectExpression(expr, current)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			c.collectExpression(node.ReturnValue, current)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			c.collectExpression(node.Expression, current)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			c.collectStatement(inner, current)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			c.collectStatement(node.Init, current)
		}
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Post != nil {
			c.collectExpression(node.Post, current)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, current)
		}
	case *mast.StructStatement:
		c.defineDeclaration(node.Name, current, false)
	case *mast.EnumStatement:
		c.defineDeclaration(node.Name, current, false)
	}
}

func (c *undefinedCollector) collectExpression(expr mast.Expression, current *declarationScope) {
	if c == nil || c.snapshot == nil || current == nil || expr == nil {
		return
	}

	switch node := expr.(type) {
	case *mast.Identifier:
		if node.Value == "" || node.Value == "_" {
			return
		}
		if _, ok := c.builtins[node.Value]; ok {
			return
		}
		if _, ok := current.find(node.Value); ok {
			return
		}
		rng, ok := c.snapshot.Program.RangeOf(node)
		if !ok {
			return
		}
		c.result = append(c.result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: c.severity,
			Source:   c.source,
			Message:  fmt.Sprintf("undefined identifier `%s`", node.Value),
		})
	case *mast.FunctionLiteral:
		child := newDeclarationScope(current, current.depth+1)
		for _, param := range node.Parameters {
			c.defineDeclaration(param, child, false)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	case *mast.MacroLiteral:
		child := newDeclarationScope(current, current.depth+1)
		for _, param := range node.Parameters {
			c.defineDeclaration(param, child, false)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, child)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Consequence != nil {
			c.collectStatement(node.Consequence, current)
		}
		if node.Alternative != nil {
			c.collectStatement(node.Alternative, current)
		}
	case *mast.CallExpression:
		if ident, ok := node.Function.(*mast.Identifier); ok && ident != nil && isMacroSpecialFormName(ident.Value) {
			for _, arg := range node.Arguments {
				c.collectExpression(arg, current)
			}
			return
		}
		if node.Function != nil {
			c.collectExpression(node.Function, current)
		}
		for _, arg := range node.Arguments {
			c.collectExpression(arg, current)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Right != nil {
			c.collectExpression(node.Right, current)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Index != nil {
			c.collectExpression(node.Index, current)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
		if node.Value != nil {
			c.collectExpression(node.Value, current)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			c.collectExpression(node.Left, current)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			c.collectExpression(node.Name, current)
		}
		for _, field := range node.Fields {
			if field == nil || field.Value == nil {
				continue
			}
			c.collectExpression(field.Value, current)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			c.collectExpression(element, current)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key, current)
			c.collectExpression(value, current)
		}
	}
}

func (c *undefinedCollector) defineDeclaration(ident *mast.Identifier, current *declarationScope, fromMultiNameLet bool) {
	if c == nil || c.snapshot == nil || current == nil || ident == nil || ident.Value == "" {
		return
	}
	current.define(ident.Value, declInfo{ident: ident, fromMultiNameLet: fromMultiNameLet, topLevel: current.depth == 0})
}

func duplicateNamesFromDiagnostics(diagnostics []lsp.Diagnostic) map[string]struct{} {
	names := make(map[string]struct{})
	for _, diagnostic := range diagnostics {
		message := diagnostic.Message
		start := strings.Index(message, "`")
		if start < 0 {
			continue
		}
		end := strings.Index(message[start+1:], "`")
		if end < 0 {
			continue
		}
		name := message[start+1 : start+1+end]
		if name == "" {
			continue
		}
		names[name] = struct{}{}
	}
	return names
}

func collectUnusedCandidates(snapshot *Snapshot) []*mast.Identifier {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	out := make([]*mast.Identifier, 0, len(snapshot.Program.Statements)+4)
	for _, stmt := range snapshot.Program.Statements {
		collectUnusedCandidatesFromStatement(stmt, &out)
	}
	return out
}

func collectUnusedCandidatesFromStatement(stmt mast.Statement, out *[]*mast.Identifier) {
	if stmt == nil || out == nil {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		for _, ident := range names {
			if ident != nil {
				*out = append(*out, ident)
			}
		}
		if node.Value != nil {
			collectUnusedCandidatesFromExpression(node.Value, out)
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			collectUnusedCandidatesFromExpression(expr, out)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			collectUnusedCandidatesFromExpression(node.ReturnValue, out)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			collectUnusedCandidatesFromExpression(node.Expression, out)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			collectUnusedCandidatesFromStatement(inner, out)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			collectUnusedCandidatesFromStatement(node.Init, out)
		}
		if node.Condition != nil {
			collectUnusedCandidatesFromExpression(node.Condition, out)
		}
		if node.Post != nil {
			collectUnusedCandidatesFromExpression(node.Post, out)
		}
		if node.Body != nil {
			collectUnusedCandidatesFromStatement(node.Body, out)
		}
	}
}

func collectUnusedCandidatesFromExpression(expr mast.Expression, out *[]*mast.Identifier) {
	if expr == nil || out == nil {
		return
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		if node.Body != nil {
			collectUnusedCandidatesFromStatement(node.Body, out)
		}
	case *mast.MacroLiteral:
		if node.Body != nil {
			collectUnusedCandidatesFromStatement(node.Body, out)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			collectUnusedCandidatesFromExpression(node.Condition, out)
		}
		if node.Consequence != nil {
			collectUnusedCandidatesFromStatement(node.Consequence, out)
		}
		if node.Alternative != nil {
			collectUnusedCandidatesFromStatement(node.Alternative, out)
		}
	case *mast.CallExpression:
		if node.Function != nil {
			collectUnusedCandidatesFromExpression(node.Function, out)
		}
		for _, arg := range node.Arguments {
			collectUnusedCandidatesFromExpression(arg, out)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			collectUnusedCandidatesFromExpression(node.Right, out)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			collectUnusedCandidatesFromExpression(node.Left, out)
		}
		if node.Right != nil {
			collectUnusedCandidatesFromExpression(node.Right, out)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			collectUnusedCandidatesFromExpression(node.Left, out)
		}
		if node.Index != nil {
			collectUnusedCandidatesFromExpression(node.Index, out)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			collectUnusedCandidatesFromExpression(node.Left, out)
		}
		if node.Value != nil {
			collectUnusedCandidatesFromExpression(node.Value, out)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			collectUnusedCandidatesFromExpression(node.Left, out)
		}
	case *mast.StructLiteral:
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			collectUnusedCandidatesFromExpression(field.Value, out)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			collectUnusedCandidatesFromExpression(element, out)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			collectUnusedCandidatesFromExpression(key, out)
			collectUnusedCandidatesFromExpression(value, out)
		}
	}
}
