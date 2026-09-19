package analyzer

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/sema"

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
	BuiltinArity                 LintSeverity
	BuiltinArgType               LintSeverity
	BuiltinSingleReturn          LintSeverity
	BuiltinPairReturn            LintSeverity
	BuiltinDeprecated            LintSeverity
	SpawnGlobalWrite             LintSeverity
	UnclosedResource             LintSeverity
	UncheckedError               LintSeverity
	MatchExhaustiveness          LintSeverity
	TlsVerificationDisabled      LintSeverity
	UnboundedResource            LintSeverity
	WeakCrypto                   LintSeverity
	HardcodedSecret              LintSeverity
	CommandInjection             LintSeverity
	EvidenceMutation             LintSeverity
	AssignmentTarget             LintSeverity
	PathTraversal                LintSeverity
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
		// A wrong-argument-count call to a fixed-arity builtin is a guaranteed
		// runtime error, but it still parses/compiles, so warning (matching the
		// platformSupport family) rather than error.
		BuiltinArity: LintSeverityWarning,
		// Passing a kind a builtin's parameter cannot accept is likewise a
		// guaranteed runtime error that still compiles.
		BuiltinArgType: LintSeverityWarning,
		// Binding two names from a builtin that returns one value is not a
		// runtime error at all, which is what makes it worth reporting: the
		// program runs and quietly does the wrong thing.
		BuiltinSingleReturn: LintSeverityWarning,
		// And binding one name from a builtin that returns a (value, err) pair
		// is the same mistake from the other side: the name holds the pair, so
		// the program keeps running with a MULTI_VALUE where it meant a value.
		BuiltinPairReturn: LintSeverityWarning,
		// A deprecated builtin still works -- that is the only reason it is
		// still registered -- so this is a hint, not a warning. It is the one
		// builtin rule that reports something the program does correctly.
		BuiltinDeprecated: LintSeverityHint,
		// Both shapes this reports are compile errors, so error is what the
		// build will say too. It is the one lint rule that reports something
		// the compiler refuses outright rather than something it accepts and
		// runs badly -- which is why it exists: without it, the first anyone
		// hears of either is a failed build.
		AssignmentTarget: LintSeverityError,
		// Writing a global from a spawned callback is the same shape: the write
		// lands in that worker's copy of the globals and is gone when it
		// finishes, and nothing at all reports it.
		SpawnGlobalWrite: LintSeverityWarning,
		// An unclosed handle is invisible in exactly the same way: the
		// program runs, reports nothing, and holds an OS resource for the
		// life of the process. The rule only fires where it can see the
		// whole lifetime, so a report is about this code rather than a
		// guess about the rest of the program.
		UnclosedResource: LintSeverityWarning,
		// A bound-and-ignored error is the same failure one step earlier:
		// the call failed, the value beside it is null, and the program
		// keeps going as though it had succeeded. Warning rather than
		// error because the code compiles and runs -- which is the whole
		// problem with it.
		UncheckedError: LintSeverityWarning,
		// A match over an enum that misses a variant runs correctly until the
		// subject is that variant, and then it raises. Warning rather than
		// error because the miss is usually a variant added since -- the code
		// was right when it was written, which is exactly why nobody looks.
		MatchExhaustiveness: LintSeverityWarning,
		// Turning off certificate verification, or accepting a TLS version
		// deprecated in 2021, is a decision the code states outright. The rule
		// reads the literal the runtime will read, so a report here is not a
		// guess about intent -- it is what the connection will do.
		TlsVerificationDisabled: LintSeverityWarning,
		// A range or CIDR larger than the builtin will expand raises at run
		// time. Warning rather than error for the reason the whole builtin
		// family is: it parses, it compiles, and it fails only when reached.
		UnboundedResource: LintSeverityWarning,
		// A digest compared against one written into the program is deciding
		// authenticity. Warning rather than error because the code is correct
		// in every mechanical sense -- it runs, it compares, it is simply
		// trusting an algorithm that can be made to agree.
		WeakCrypto: LintSeverityWarning,
		// A credential in source is in every copy of the source, including the
		// history after it is deleted. Warning, because the program works
		// perfectly and that is the problem.
		HardcodedSecret: LintSeverityWarning,
		// A value spliced into a string a shell will parse is syntax, not an
		// argument. Warning rather than error because whether it is reachable
		// by anyone hostile is a question about the whole program.
		CommandInjection: LintSeverityWarning,
		// Writing to a path the program opened as evidence is the one finding
		// in this family that cannot be undone once it has run. It is still a
		// warning, because the code does exactly what it says and only the
		// author knows whether that path is an exhibit or a working copy.
		EvidenceMutation: LintSeverityWarning,
		// A path built from a value the program did not write, with nothing
		// looking at it in between. Warning, because whether the value is
		// really hostile depends on who can reach this program -- which is the
		// one thing a single document cannot answer.
		PathTraversal: LintSeverityWarning,
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
	case "builtinArity":
		severityName = c.BuiltinArity
	case "builtinArgType":
		severityName = c.BuiltinArgType
	case "builtinSingleReturn":
		severityName = c.BuiltinSingleReturn
	case "builtinPairReturn":
		severityName = c.BuiltinPairReturn
	case "builtinDeprecated":
		severityName = c.BuiltinDeprecated
	case "spawnGlobalWrite":
		severityName = c.SpawnGlobalWrite
	case "unclosedResource":
		severityName = c.UnclosedResource
	case "uncheckedError":
		severityName = c.UncheckedError
	case "matchExhaustiveness":
		severityName = c.MatchExhaustiveness
	case "tlsVerificationDisabled":
		severityName = c.TlsVerificationDisabled
	case "unboundedResource":
		severityName = c.UnboundedResource
	case "weakCrypto":
		severityName = c.WeakCrypto
	case "hardcodedSecret":
		severityName = c.HardcodedSecret
	case "commandInjection":
		severityName = c.CommandInjection
	case "assignmentTarget":
		severityName = c.AssignmentTarget
	case "evidenceMutation":
		severityName = c.EvidenceMutation
	case "pathTraversal":
		severityName = c.PathTraversal
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

	// A reach into another module the compiler will refuse. These are not
	// lints and take no LintConfig: the underscore export rule and "that
	// module declares no such name" are the language, not a matter of taste,
	// and the sentence shown is the compiler's own.
	//
	// Without a workspace this yields nothing, which is exactly right for
	// api.Lint and the REPL: they are handed a string with no file context,
	// so they cannot know what an import names and must not guess.
	diagnostics = append(diagnostics, snapshot.ModuleMemberDiagnostics()...)

	duplicateDiagnostics := lintDuplicateTopLevelDeclarations(snapshot, lintConfig)
	diagnostics = append(diagnostics, duplicateDiagnostics...)
	diagnostics = append(diagnostics, lintUnusedDeclarations(snapshot, lintConfig, duplicateNamesFromDiagnostics(duplicateDiagnostics))...)
	diagnostics = append(diagnostics, lintUndefinedDeclarations(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintNestingComplexity(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintSemicolons(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintUnreachableCode(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintPlatformSupport(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintBuiltinCalls(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintSpawnGlobalWrites(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintUnclosedResources(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintUncheckedErrors(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintMatchExhaustiveness(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintTlsVerificationDisabled(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintUnboundedResource(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintWeakCrypto(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintHardcodedSecret(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintCommandInjection(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintAssignmentTargets(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintEvidenceMutation(snapshot, lintConfig)...)
	diagnostics = append(diagnostics, lintPathTraversal(snapshot, lintConfig)...)

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
		// What the file has bound where the call is written. This rule used to
		// see only the file's imports, so a local `let ntfs = ...` slipped
		// through and `ntfs.close(h)` was reported as a call to a builtin
		// unavailable on this machine -- a warning about a function the program
		// does not call, on code that runs everywhere. The note here used to
		// say that bolting a scope walk on was more than the rule was worth,
		// and it was: a scope walk meant building one. Asking the graph is a
		// call.
		name, anchor, ok := builtinCalleeIn(call.Function, snapshot.localScopeAtNode(call.Function))
		if !ok || !builtin.UnsupportedOn(name, hostGOOS) {
			continue
		}
		rng, ok := snapshot.Program.RangeOf(anchor)
		if !ok {
			continue
		}
		platforms, _ := builtin.PlatformSupport(name)
		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message: fmt.Sprintf("builtin `%s` is not supported on %s (supported: %s)",
				name, hostGOOS, strings.Join(platforms, ", ")),
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
		// An arm after `_` is the same defect one construct over: `_` matches
		// anything, so the compare-and-jump chain never reaches what follows
		// it. This belongs here rather than in a rule of its own -- it is
		// literally code that cannot run, and one knob should govern one idea.
		if match, ok := node.(*mast.MatchExpression); ok && match != nil {
			for i, arm := range match.Arms {
				if arm == nil || !arm.IsWildcard() || i+1 >= len(match.Arms) {
					continue
				}
				next := match.Arms[i+1]
				if next == nil {
					break
				}
				rng, ok := snapshot.Program.RangeOf(next)
				if !ok {
					break
				}
				result = append(result, lsp.Diagnostic{
					Range:    localprotocol.ToLSPRange(rng),
					Severity: severity,
					Source:   &source,
					Message:  "unreachable arm after `_`, which matches anything",
				})
				break
			}
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

// lintDuplicateTopLevelDeclarations reports a name declared twice in ONE scope.
//
// In one scope, which is the whole of what this rule had wrong. It used to walk
// the file with a scope chain of its own and report a name found anywhere up
// that chain, so every shadow was a duplicate:
//
//	let x = 1;
//	let f = fn(x) { return x * 10; };
//	f(2);
//
// returns 20, and the parameter -- the thing that made it 20 -- was reported as
// a duplicate declaration of a top-level x that is still 1 afterwards. Struct
// and enum names were filed in the same table as values, so
//
//	struct Point { x };
//	let Point = 1;
//	let p = Point{x: 5};
//	p.x + Point;
//
// returns 6, with both declarations doing work in the last line, and was
// reported as well -- carrying a preferred quick fix that offers to delete one
// of the two lines.
//
// The rule's premise is that one of the two declarations is pointless. A shadow
// is not that: both are live, and which one a use means depends on where the
// use is written. A type name is not that either: it never enters the
// compiler's symbol table, so it takes nothing from the value of the same name.
// The graph already draws both lines where the compiler draws them, so the rule
// asks it rather than deriving scope a second time.
func lintDuplicateTopLevelDeclarations(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("duplicateTopLevelDeclaration")
	if !ok {
		return nil
	}

	graph := snapshot.Graph()
	if graph == nil {
		return nil
	}

	source := "mutant-lint"
	topLevelTypes := topLevelTypeNames(snapshot.Program.Statements)
	first := make(map[declarationKey]*sema.Node, 8)
	result := make([]lsp.Diagnostic, 0, 2)

	for _, node := range graph.Declarations() {
		if !isRedeclarable(node) {
			continue
		}

		key := declarationKey{scope: node.Scope, name: node.Name}
		previous, seen := first[key]
		if !seen {
			first[key] = node
			continue
		}

		// previous stays the FIRST declaration rather than the one last
		// reported: `let x = 1; let x = 2; let x = 3;` is two mistakes against
		// one original, and the suppression below asks about the original.
		if rebindsAConsumedName(graph, previous) {
			continue
		}

		rng := node.Anchor()
		if !rng.IsValid() {
			continue
		}

		message := fmt.Sprintf("duplicate declaration `%s`", node.Name)
		if declaredAtTopLevel(node, graph, topLevelTypes) {
			message = fmt.Sprintf("duplicate top-level declaration `%s`", node.Name)
		}

		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message:  message,
		})
	}

	return result
}

// declarationKey is a scope and a name: two declarations sharing one are the
// same binding declared twice. The scope is the pointer the graph built, so
// nothing has to decide what a scope is a second time.
type declarationKey struct {
	scope *sema.Scope
	name  string
}

// isRedeclarable reports whether a second declaration of this node's name in
// its own scope is worth saying anything about.
//
// `_` is the discard: `let a, _ = gets(); let b, _ = gets();` binds it twice on
// purpose. A loop binding is excluded because two loops over one name in one
// scope -- `for (item in a) {...} for (item in b) {...}` -- is how the language
// is written, and the walk this replaced never recorded one at all. An import
// namespace is excluded because `import util` and `let util` are different
// bindings under Mutant's rules and the compiler tries the namespace first
// rather than refusing. Fields and variants belong to a type rather than to a
// scope anyone declares in.
func isRedeclarable(node *sema.Node) bool {
	if node == nil || node.Name == "" || node.Name == "_" {
		return false
	}
	switch node.Kind {
	case sema.KindValue, sema.KindFunction, sema.KindParam, sema.KindStruct, sema.KindEnum:
		return true
	}
	return false
}

// declaredAtTopLevel reports whether the declaration is one of the file's own
// top-level statements.
//
// That is what the two messages distinguish, and the distinction is load
// bearing rather than cosmetic: the "Remove duplicate top-level declaration"
// quick fix is offered for one wording and not the other, and it deletes a
// whole line.
//
// A value is top level exactly when it is in the root scope, because a block
// opens no scope in Mutant and so there is nothing in between. A type name is
// in no scope chain at all -- struct and enum names are program-global -- so
// for one of those the question is put to the statement list instead.
func declaredAtTopLevel(node *sema.Node, graph *sema.Graph, topLevelTypes map[*mast.Identifier]struct{}) bool {
	if node == nil || graph == nil {
		return false
	}
	if node.Kind == sema.KindStruct || node.Kind == sema.KindEnum {
		_, top := topLevelTypes[node.Ident]
		return top
	}
	return node.Scope == graph.Root
}

// topLevelTypeNames returns the identifiers naming the structs and enums a
// file's top-level statements declare. It is a scan of one slice rather than a
// walk: a struct written inside a function is deliberately absent, which is
// what keeps the quick fix away from a line it cannot safely delete.
func topLevelTypeNames(statements []mast.Statement) map[*mast.Identifier]struct{} {
	named := make(map[*mast.Identifier]struct{}, 4)
	for _, stmt := range statements {
		switch node := stmt.(type) {
		case *mast.StructStatement:
			if node.Name != nil {
				named[node.Name] = struct{}{}
			}
		case *mast.EnumStatement:
			if node.Name != nil {
				named[node.Name] = struct{}{}
			}
		}
	}
	return named
}

type declarationScope struct {
	parent *declarationScope
	depth  int
	decls  map[string]declInfo
}

type declInfo struct {
	ident            *mast.Identifier
	fromMultiNameLet bool
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

// rebindsAConsumedName reports whether the earlier declaration was part of a
// multiple binding that was read before it was replaced.
//
//	let text, err = read(path);
//	if (err != null) { return err; }
//	text;
//	let text = trim(text);
//
// is the error idiom rather than a mistake: the pair is bound, the error half
// decides whether to go on, the value half is used while it is known good, and
// the name is then rebound. The rule's premise is that one of two declarations
// of a name is pointless, and a binding that was read is not that.
//
// The question is asked of UsesOf, which is keyed by the declaration's own
// identity, so every use it returns belongs to THIS binding of the name and not
// to the one that replaced it -- after the rebinding, a use of the name resolves
// to the later declaration and is not in this list at all. That is what makes
// "was it read" a sufficient question.
//
// It was not sufficient before. The check used to ask ReferenceLocations for a
// POSITION, which cannot tell the two bindings apart, so it settled for a use on
// the line directly below the declaration -- where the second binding does not
// yet exist. The cost of that approximation was the idiom's own recommended
// shape: a program that checks err before touching the value never has the use
// on the line below, and was told it had declared the name twice.
func rebindsAConsumedName(graph *sema.Graph, previous *sema.Node) bool {
	if graph == nil || previous == nil || !previous.Grouped {
		return false
	}
	return len(graph.UsesOf(previous.ID)) > 0
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

	// A file whose top level declares things but never does anything cannot be
	// a whole program: its names exist for whatever imports it. This rule sees
	// one file, so it cannot find those uses, and reporting them unused would
	// put a warning on every module in a project -- on exactly the names the
	// module exists to provide.
	//
	// The narrow test is deliberate. A file that runs something at its top
	// level is a program this rule can see all of, and a top-level helper
	// nothing there calls is still reported, which is the case worth keeping.
	exports := map[*mast.Identifier]struct{}{}
	if !hasTopLevelAction(snapshot.Program.Statements) {
		exports = topLevelDeclaredIdentifiers(snapshot.Program.Statements)
	}

	for _, ident := range candidates {
		if ident == nil || ident.Value == "" || ident.Value == "_" {
			continue
		}
		if _, skip := skipNames[ident.Value]; skip {
			continue
		}
		if _, exported := exports[ident]; exported {
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
		snapshot:   snapshot,
		severity:   severity,
		source:     &source,
		builtins:   knownBuiltins,
		namespaces: importNamespaces(snapshot.Program.Statements),
		result:     make([]lsp.Diagnostic, 0, 4),
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
	case *mast.WhileStatement:
		// A while nests exactly as a for does: its body is one level deeper,
		// its condition is not.
		nextDepth := depth
		if inFunction {
			nextDepth = depth + 1
			c.maybeAddNestingDiagnostic(node, nextDepth)
		}

		if node.Condition != nil {
			c.collectExpression(node.Condition, inFunction, depth)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, inFunction, nextDepth)
		}
	case *mast.ForInStatement:
		nextDepth := depth
		if inFunction {
			nextDepth = depth + 1
			c.maybeAddNestingDiagnostic(node, nextDepth)
		}

		if node.Iterable != nil {
			c.collectExpression(node.Iterable, inFunction, depth)
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
	case *mast.MatchExpression:
		nextDepth := depth
		if inFunction {
			nextDepth = depth + 1
			c.maybeAddNestingDiagnostic(node, nextDepth)
		}

		if node.Subject != nil {
			c.collectExpression(node.Subject, inFunction, depth)
		}
		for _, arm := range node.Arms {
			if arm == nil || arm.Body == nil {
				continue
			}
			// All arms are siblings at one level, the way an if's two
			// branches are: a match with twenty arms is wide, not deep, and
			// counting it as deep would report nesting nobody wrote.
			c.collectStatement(arm.Body, inFunction, nextDepth)
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
	case *mast.TemplateLiteral:
		for _, element := range node.Parts {
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
	// namespaces holds the name each `import` binds. They are kept as a
	// file-wide set rather than entries in the scope chain for two reasons: an
	// import is legal only at the top level, so there is no inner scope for one
	// to belong to; and an unaliased import derives its namespace from the file
	// name, so there is no identifier node to hang a declaration on.
	namespaces map[string]struct{}
	result     []lsp.Diagnostic
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
	case *mast.WhileStatement:
		if node.Condition != nil {
			c.collectExpression(node.Condition, current)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, current)
		}
	case *mast.ForInStatement:
		// The loop's own bindings, before the body that reads them. Without
		// this every `for (v in xs)` body reported `undefined identifier v` at
		// error severity -- a red squiggle on correct code, and a non-zero exit
		// from `mutant lint` for any program that uses the loop.
		if node.Key != nil {
			c.defineDeclaration(node.Key, current, false)
		}
		if node.Value != nil {
			c.defineDeclaration(node.Value, current, false)
		}
		if node.Iterable != nil {
			c.collectExpression(node.Iterable, current)
		}
		if node.Body != nil {
			c.collectStatement(node.Body, current)
		}
	case *mast.StructStatement, *mast.EnumStatement:
		// A type name is deliberately NOT defined here.
		//
		// It never enters the compiler's symbol table, so
		//
		//	struct Point { x };
		//	Point;
		//
		// does not compile -- "undefined variable: Point" -- while this rule,
		// which used to file the name beside the file's lets, said nothing at
		// all. A clean file in the editor and a failed build is the worst
		// direction for this rule to be wrong in.
		//
		// The two positions a type name may legally appear in are handled
		// where they occur: the name of a struct literal, and the left of a
		// field access naming an enum. Both ask the graph, which keeps type
		// names out of the scope chain for exactly this reason.
	}
}

// declaresType reports whether the file declares a struct or an enum under the
// name. It is asked of the graph rather than of the scope chain above, because
// a type name is in no scope: struct names are program-global in Mutant and
// live in a table of their own.
func (c *undefinedCollector) declaresType(name string) bool {
	if c == nil || c.snapshot == nil || name == "" {
		return false
	}
	_, _, declared := c.snapshot.Graph().TypeNamed(name)
	return declared
}

// enumDeclared is declaresType narrowed to enums, in the shape ResolveField
// asks for.
func (c *undefinedCollector) enumDeclared(name string) bool {
	if c == nil || c.snapshot == nil {
		return false
	}
	return c.snapshot.Graph().EnumDeclared(name)
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
		if _, ok := c.namespaces[node.Value]; ok {
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
	case *mast.MatchExpression:
		if node.Subject != nil {
			c.collectExpression(node.Subject, current)
		}
		for _, arm := range node.Arms {
			if arm == nil {
				continue
			}
			// Patterns are walked because an enum variant pattern names its
			// enum: `Status.Ok` is a real use of `Status`, and skipping it
			// would make an enum matched but never otherwise mentioned look
			// unused. FieldExpression walks only its left, so the variant
			// name itself is never resolved as a standalone binding.
			for _, pattern := range arm.Patterns {
				c.collectExpression(pattern, current)
			}
			if arm.Body != nil {
				c.collectStatement(arm.Body, current)
			}
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
		if node.Left == nil {
			return
		}
		// The left of a field access is usually a value and has to be checked
		// like any other. Two shapes are not: a namespace an import bound, and
		// a builtin family -- `str.upper` is str_upper, so `str` names no
		// variable and reporting it undefined would be a hard error on a
		// correct program.
		if namespace, isIdent := node.Left.(*mast.Identifier); isIdent && namespace != nil && namespace.Value != "" {
			if _, imported := c.namespaces[namespace.Value]; imported {
				return
			}
			// Guarded on the name being unbound, so a local `let str = "x"`
			// followed by `str.upper` is still the field access it looks like.
			if _, shadowed := current.find(namespace.Value); !shadowed && node.Field != nil {
				// An enum is settled before a fold, which is the precedence
				// ResolveField fixes and not a choice made here: `Colour.Red`
				// was namespace-shaped before modules existed. The enum names
				// come from the graph because a type name is not in this
				// walk's scope chain at all -- and until they did, `Colour`
				// was silent only because the walk had filed it as a value.
				switch semaResolver.ResolveField(
					sema.ScopeCtx{Enums: c.enumDeclared}, namespace.Value, node.Field.Value,
				).Kind {
				case sema.FieldEnumValue, sema.FieldBuiltinFold:
					return
				}
				// The family exists and this member does not, which is a typo
				// in the member. Walking the left instead reported `undefined
				// identifier hash` for `hash.blake3(x)` -- true of the name it
				// checked and useless to the author, because `hash` is not what
				// they got wrong and the half they did get wrong never appears.
				// The flat spelling has always named it: `hash_blake3`.
				//
				// Gated on the family existing, which is the same gate
				// builtinCallee applies: a receiver that heads no family is
				// someone's value and its fields are not this rule's business.
				if len(builtinFamilyMembers(namespace.Value)) > 0 {
					c.reportUnknownFamilyMember(node, namespace.Value)
					return
				}
			}
		}
		c.collectExpression(node.Left, current)
	case *mast.StructLiteral:
		// The name of a struct literal is a TYPE, so it is checked against the
		// file's type declarations rather than against its bindings. A name
		// that declares no type is still walked, because `Nope{x: 1}` is as
		// undefined as a bare `Nope` -- what must not happen is reporting
		// `Point{x: 1}`, which is the one place the name is certainly right.
		if node.Name != nil && !c.declaresType(node.Name.Value) {
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
	case *mast.TemplateLiteral:
		for _, element := range node.Parts {
			c.collectExpression(element, current)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key, current)
			c.collectExpression(value, current)
		}
	}
}

// reportUnknownFamilyMember complains about `hash.blake3` by the name the
// author would search for -- the flat one, which is the name the registry
// keys on and the one the capability reference lists.
func (c *undefinedCollector) reportUnknownFamilyMember(node *mast.FieldExpression, namespace string) {
	rng, ok := c.snapshot.Program.RangeOf(node)
	if !ok {
		// Without a range for the whole expression the squiggle would cover
		// only the namespace, which is the half that is correct.
		return
	}
	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.severity,
		Source:   c.source,
		Message: fmt.Sprintf("undefined identifier `%s_%s`: %s is a builtin family, but it has no %s",
			namespace, node.Field.Value, namespace, node.Field.Value),
	})
}

func (c *undefinedCollector) defineDeclaration(ident *mast.Identifier, current *declarationScope, fromMultiNameLet bool) {
	if c == nil || c.snapshot == nil || current == nil || ident == nil || ident.Value == "" {
		return
	}
	current.define(ident.Value, declInfo{ident: ident, fromMultiNameLet: fromMultiNameLet})
}

// lintBuiltinCalls checks calls to builtins against the two contracts the
// metadata makes machine-readable: how many arguments a builtin takes
// (`builtinArity`, e.g. `abs(1, 2)` or `clamp(x)`) and what kinds each of its
// parameters accepts (`builtinArgType`, e.g. `str_upper(42)`).
//
// Both are deliberately conservative and share the guards that make them
// false-positive-free: the callee must not be shadowed by an in-scope binding,
// must be live in builtin.Builtins, and must carry a verified contract — an
// entry in builtinArities for the count, declared kinds in builtin/metadata.go
// for the types. Anything unverified is simply never checked.
//
// The third rule on this walk, builtinPairReturn, checks the other machine-
// readable contract: what a builtin gives back. It lives in
// builtin_pair_return.go because, unlike the other two, it cannot decide at the
// call site -- whether a single-name binding is a defect depends on what the
// rest of the program does with the name, so the walk collects candidates and
// they are resolved once it finishes.
//
// One walk serves all three rules; the severity of each is read independently,
// so any can be turned off without disturbing the others.
func lintBuiltinCalls(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	aritySeverity, arityEnabled := lintConfig.severityForRule("builtinArity")
	argTypeSeverity, argTypeEnabled := lintConfig.severityForRule("builtinArgType")
	returnSeverity, returnEnabled := lintConfig.severityForRule("builtinSingleReturn")
	pairSeverity, pairEnabled := lintConfig.severityForRule("builtinPairReturn")
	deprecatedSeverity, deprecatedEnabled := lintConfig.severityForRule("builtinDeprecated")
	if !arityEnabled && !argTypeEnabled && !returnEnabled && !pairEnabled && !deprecatedEnabled {
		return nil
	}
	if !arityEnabled {
		aritySeverity = nil
	}
	if !argTypeEnabled {
		argTypeSeverity = nil
	}
	if !returnEnabled {
		returnSeverity = nil
	}
	if !pairEnabled {
		pairSeverity = nil
	}
	if !deprecatedEnabled {
		deprecatedSeverity = nil
	}

	source := "mutant-lint"
	knownBuiltins := make(map[string]struct{}, len(builtin.Builtins))
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		knownBuiltins[def.Name] = struct{}{}
	}

	collector := &builtinCallCollector{
		snapshot:        snapshot,
		aritySeverity:   aritySeverity,
		argTypeSeverity: argTypeSeverity,
		returnSeverity:  returnSeverity,
		pairSeverity:    pairSeverity,
		deprecatedSev:   deprecatedSeverity,
		source:          &source,
		builtins:        knownBuiltins,
		reassigned:      reassignedNames(snapshot),
		result:          make([]lsp.Diagnostic, 0, 2),
	}

	for _, stmt := range snapshot.Program.Statements {
		collector.collectStatement(stmt)
	}

	// Appended rather than interleaved: a pair binding is only known to be a
	// defect once the whole program has been seen, and Diagnostics already
	// concatenates rules rather than sorting them into source order.
	return append(collector.result,
		pairBindingDiagnostics(snapshot, collector.pairSeverity, collector.source, collector.pairCandidates)...)
}

// builtinCallCollector walks the program looking for calls to builtins, in
// either spelling, and checks each one against the arity table and the declared
// parameter kinds. The only leaf action is checkCall at a call whose callee
// names a builtin.
//
// It keeps no scope of its own. Whether a call names a builtin at all is a
// question about what the file has bound at that point, and this used to answer
// it from a declarationScope threaded through every method here, filled in by a
// defineDeclaration case per AST node that binds a name. That is a second
// account of which nodes declare a name, and it did not match the compiler's:
// it wrote struct and enum names into the same table as lets and parameters, so
// `struct rand { x; }` made `rand.int(1, 5)` look like a field read on a value
// and this whole rule went quiet for the file -- while the program compiled and
// ran the builtin, returning 3. A type name is not a value binding. sema.Graph
// says so once, and localScopeAtNode is how this walk asks.
//
// A nil severity means that rule is switched off. The walk still runs, because
// the other rule may be on.
type builtinCallCollector struct {
	snapshot        *Snapshot
	aritySeverity   *lsp.DiagnosticSeverity
	argTypeSeverity *lsp.DiagnosticSeverity
	returnSeverity  *lsp.DiagnosticSeverity
	pairSeverity    *lsp.DiagnosticSeverity
	deprecatedSev   *lsp.DiagnosticSeverity
	source          *string
	builtins        map[string]struct{}
	reassigned      map[string]struct{}

	result         []lsp.Diagnostic
	pairCandidates []pairBindingCandidate
}

// calleeAt resolves the builtin a call names, at the call's own position.
//
// An import namespace is handled by the same lookup rather than by a set kept
// beside it: an imported `fs` is a module, so `fs.read(...)` is that module's
// function and not the builtin fs_read, and the alias is a declaration in the
// graph like any other. So is an enum, which is why the whole LocalScope goes
// in and not just its Bound.
func (c *builtinCallCollector) calleeAt(fn mast.Expression) (name string, anchor mast.Node, ok bool) {
	if c == nil || c.snapshot == nil || fn == nil {
		return "", nil, false
	}
	return builtinCalleeIn(fn, c.snapshot.localScopeAtNode(fn))
}

func (c *builtinCallCollector) collectStatement(stmt mast.Statement) {
	if c == nil || c.snapshot == nil || stmt == nil {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}

		if len(names) == 1 {
			c.checkSingleNameBinding(names[0], node.Value)
		}

		if node.Value != nil {
			c.collectExpression(node.Value)
		}

		if len(names) > 1 {
			c.checkMultiNameBinding(names, node.Value)
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			c.collectExpression(expr)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			c.collectExpression(node.ReturnValue)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			c.collectExpression(node.Expression)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			c.collectStatement(inner)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			c.collectStatement(node.Init)
		}
		if node.Condition != nil {
			c.collectExpression(node.Condition)
		}
		if node.Post != nil {
			c.collectExpression(node.Post)
		}
		if node.Body != nil {
			c.collectStatement(node.Body)
		}
	case *mast.WhileStatement:
		if node.Condition != nil {
			c.collectExpression(node.Condition)
		}
		if node.Body != nil {
			c.collectStatement(node.Body)
		}
	case *mast.ForInStatement:
		// The loop's bindings used to be recorded here, so that `for (max in
		// xs) { max(1, 2); }` was not held to the builtin's contract. The graph
		// holds them -- in the enclosing scope, which is where the VM puts them
		// -- so this walk has nothing to do but descend.
		if node.Iterable != nil {
			c.collectExpression(node.Iterable)
		}
		if node.Body != nil {
			c.collectStatement(node.Body)
		}
	}
}

func (c *builtinCallCollector) collectExpression(expr mast.Expression) {
	if c == nil || c.snapshot == nil || expr == nil {
		return
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		if node.Body != nil {
			c.collectStatement(node.Body)
		}
	case *mast.MacroLiteral:
		if node.Body != nil {
			c.collectStatement(node.Body)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			c.collectExpression(node.Condition)
		}
		if node.Consequence != nil {
			c.collectStatement(node.Consequence)
		}
		if node.Alternative != nil {
			c.collectStatement(node.Alternative)
		}
	case *mast.MatchExpression:
		if node.Subject != nil {
			c.collectExpression(node.Subject)
		}
		for _, arm := range node.Arms {
			if arm == nil {
				continue
			}
			for _, pattern := range arm.Patterns {
				c.collectExpression(pattern)
			}
			if arm.Body != nil {
				c.collectStatement(arm.Body)
			}
		}
	case *mast.CallExpression:
		if ident, ok := node.Function.(*mast.Identifier); ok && ident != nil {
			// Macro special forms (quote/unquote/...) are not builtin calls; do
			// not arity-check them, but still walk their arguments. Keyed on
			// the bare spelling only: there is no namespaced quote.
			if isMacroSpecialFormName(ident.Value) {
				for _, arg := range node.Arguments {
					c.collectExpression(arg)
				}
				return
			}
		}
		// Either spelling: fs_read(p) and fs.read(p) are one call, so both get
		// checked against one contract.
		if name, anchor, ok := c.calleeAt(node.Function); ok {
			c.checkCall(name, anchor, node.Arguments)
		}
		if node.Function != nil {
			c.collectExpression(node.Function)
		}
		for _, arg := range node.Arguments {
			c.collectExpression(arg)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			c.collectExpression(node.Right)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			c.collectExpression(node.Left)
		}
		if node.Right != nil {
			c.collectExpression(node.Right)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			c.collectExpression(node.Left)
		}
		if node.Index != nil {
			c.collectExpression(node.Index)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			c.collectExpression(node.Left)
		}
		if node.Value != nil {
			c.collectExpression(node.Value)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			c.collectExpression(node.Left)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			c.collectExpression(node.Name)
		}
		for _, field := range node.Fields {
			if field == nil || field.Value == nil {
				continue
			}
			c.collectExpression(field.Value)
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			c.collectExpression(element)
		}
	case *mast.TemplateLiteral:
		for _, element := range node.Parts {
			c.collectExpression(element)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			c.collectExpression(key)
			c.collectExpression(value)
		}
	}
}

// checkCall runs both builtin-call rules at one call site: the argument count
// against the curated arity table, then each argument's type against the
// parameter kinds declared in builtin/metadata.go.
//
// A call that fails the arity check is not type-checked. Its arguments cannot be
// mapped onto parameters with any confidence, and one clear complaint per call
// beats a cascade of consequential ones.
// checkMultiNameBinding flags `let a, b = f()` where f is a builtin that
// returns a single value rather than the (value, err) pair the fallible parts of
// the library use.
//
// Nothing fails when this is written: the extra names simply take whatever the
// binding hands them. If the single value is an ARRAY the binding takes it
// apart, so the first name receives the array's first element -- `let updated,
// err = push(items, x)` leaves `updated` as `items[0]`. If it is anything else
// the first name is correct and the rest are null, so an `if (err)` check
// silently never fires. Both shapes run to completion with the wrong value,
// which is exactly why a diagnostic is worth more here than a runtime error.
//
// The guards that keep it false-positive-free mirror checkCall's: the callee
// must be an unshadowed live builtin, and it must carry a declared return
// contract. A builtin whose contract says pair, or one with no contract at all,
// is never reported.
// checkDeprecated reports a call to a builtin that is kept only for
// compatibility, and names what replaced it.
//
// It is reported at the call and never suppressed by the arity or type rules:
// the call may be perfectly well-formed, and usually is. The tag is what makes
// editors strike the name through.
func (c *builtinCallCollector) checkDeprecated(name string, anchor mast.Node) {
	if c == nil || c.deprecatedSev == nil || name == "" || anchor == nil {
		return
	}
	replacement, deprecated := builtin.DeprecatedBy(name)
	if !deprecated {
		return
	}
	rng, ok := c.snapshot.Program.RangeOf(anchor)
	if !ok {
		return
	}

	message := fmt.Sprintf("%s is deprecated.", name)
	if replacement != "" {
		message = fmt.Sprintf("%s is deprecated -- use %s instead. The old name keeps working, so this is safe to change at your own pace.",
			name, replacement)
	}

	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.deprecatedSev,
		Source:   c.source,
		Tags:     []lsp.DiagnosticTag{lsp.DiagnosticTagDeprecated},
		Message:  message,
	})
}

func (c *builtinCallCollector) checkMultiNameBinding(names []*mast.Identifier, value mast.Expression) {
	if c == nil || c.returnSeverity == nil || len(names) < 2 || value == nil {
		return
	}

	call, ok := value.(*mast.CallExpression)
	if !ok || call.Function == nil {
		return
	}
	name, anchor, ok := c.calleeAt(call.Function)
	if !ok {
		return
	}
	if _, live := c.builtins[name]; !live {
		return
	}

	spec, declared := builtin.ReturnSpec(name)
	if !declared || spec.Pair {
		return
	}

	rng, ok := c.snapshot.Program.RangeOf(anchor)
	if !ok {
		return
	}

	kinds := spec.KindsText()
	consequence := fmt.Sprintf("the %d extra name(s) are always null", len(names)-1)
	if len(names) == 2 {
		consequence = "the second name is always null"
	}
	for _, kind := range spec.Kinds {
		if kind == builtin.ParamArray {
			consequence = fmt.Sprintf("binding %d names takes that array apart, so %s receives its first element",
				len(names), names[0].Value)
		}
	}

	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.returnSeverity,
		Source:   c.source,
		Message: fmt.Sprintf("%s returns a single %s, not a (value, err) pair: %s. Bind one name.",
			name, kinds, consequence),
	})
}

// checkCall checks one call against the builtin contract for name.
//
// name is the builtin's flat registry name whichever way the call was spelled,
// and anchor is the node the squiggle should cover -- the identifier for
// fs_read(p), the whole `fs.read` for the dotted form. Shadowing has already
// been decided by builtinCallee, which is what lets one predicate serve every
// rule instead of each one spelling it slightly differently.
func (c *builtinCallCollector) checkCall(name string, anchor mast.Node, args []mast.Expression) {
	if name == "" || anchor == nil {
		return
	}
	// Only real builtins; a stale table key is inert.
	if _, ok := c.builtins[name]; !ok {
		return
	}

	c.checkDeprecated(name, anchor)

	if arity, ok := builtinArityFor(name); ok && !arity.accepts(len(args)) {
		// The count is wrong whether or not the rule that reports it is on, so
		// the type check is suppressed either way.
		if c.aritySeverity != nil {
			if rng, ok := c.snapshot.Program.RangeOf(anchor); ok {
				c.result = append(c.result, lsp.Diagnostic{
					Range:    localprotocol.ToLSPRange(rng),
					Severity: c.aritySeverity,
					Source:   c.source,
					Message:  arity.message(name, len(args)),
				})
			}
		}
		return
	}

	c.checkArgumentTypes(name, args)
}

// checkArgumentTypes flags an argument whose kind the parameter in that position
// cannot accept.
//
// It fires only where every one of these holds, which together are what make the
// rule false-positive-free:
//
//  1. the builtin documents its parameters and the call's argument count fits
//     them, so positions map to parameters unambiguously;
//  2. the parameter declares a non-empty kind set — an undeclared parameter, or
//     one verified to accept anything, is never checked;
//  3. the argument's type is certain rather than merely inferred
//     (argumentTypeIsCertain);
//  4. that type is expressible as a kind — structs, enums, and errors have no
//     kind to compare against and are skipped.
func (c *builtinCallCollector) checkArgumentTypes(name string, args []mast.Expression) {
	if c.argTypeSeverity == nil || len(args) == 0 {
		return
	}

	params, ok := builtin.ParamSpecs(name)
	if !ok || len(params) == 0 || !argumentCountFitsParams(params, len(args)) {
		return
	}

	for i, arg := range args {
		if arg == nil {
			continue
		}
		param, ok := paramForArgument(params, i)
		if !ok || param.AcceptsAnyKind() {
			continue
		}
		if !argumentTypeIsCertain(arg, c.reassigned) {
			continue
		}
		argType, ok := c.snapshot.TypeOf(arg)
		if !ok || !argType.IsKnown() {
			continue
		}
		kind, ok := paramKindForType(argType)
		if !ok {
			continue
		}
		if param.Accepts(kind) {
			c.checkArrayElements(name, i, param, arg)
			continue
		}
		rng, ok := c.snapshot.Program.RangeOf(arg)
		if !ok {
			continue
		}
		c.result = append(c.result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: c.argTypeSeverity,
			Source:   c.source,
			Message:  argTypeMessage(name, i+1, param, kind),
			Data:     ArgTypeDiagnosticData(param, kind),
		})
	}
}

// checkArrayElements flags elements of an array literal that the parameter's
// element contract rejects — `str_join([1, 2], ",")`, where every element has to
// be a STRING.
//
// It only ever looks at an array *literal*. A name bound to an array would take
// its element types from inference, and inference widens a mixed or unknown
// element to Any rather than tracking it, so the literal is the only place the
// elements are read straight off the syntax. Each element is then held to the
// same certainty rule as a top-level argument, so an element that is itself a
// call or an arithmetic expression is skipped rather than guessed at.
func (c *builtinCallCollector) checkArrayElements(name string, argIndex int, param builtin.BuiltinParamDoc, arg mast.Expression) {
	if len(param.Elem) == 0 {
		return
	}
	literal, ok := arg.(*mast.ArrayLiteral)
	if !ok || literal == nil {
		return
	}

	for _, element := range literal.Elements {
		if element == nil || !argumentTypeIsCertain(element, c.reassigned) {
			continue
		}
		elementType, ok := c.snapshot.TypeOf(element)
		if !ok || !elementType.IsKnown() {
			continue
		}
		elementKind, ok := paramKindForType(elementType)
		if !ok || param.AcceptsElement(elementKind) {
			continue
		}
		rng, ok := c.snapshot.Program.RangeOf(element)
		if !ok {
			continue
		}
		c.result = append(c.result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: c.argTypeSeverity,
			Source:   c.source,
			Message:  elementTypeMessage(name, argIndex+1, param, elementKind),
			Data:     ElementTypeDiagnosticData(param, elementKind),
		})
	}
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

// hasTopLevelAction reports whether the file's top level does anything beyond
// declaring names -- a call, a loop, a conditional, a bare expression.
//
// `import` counts as a declaration: a file that only imports and declares is
// still a module, and treating the import as action would put the warnings
// straight back on the module that imports another one.
func hasTopLevelAction(statements []mast.Statement) bool {
	for _, stmt := range statements {
		switch stmt.(type) {
		case *mast.LetStatement, *mast.StructStatement, *mast.EnumStatement, *mast.ImportStatement:
			continue
		case nil:
			continue
		default:
			return true
		}
	}
	return false
}

// topLevelDeclaredIdentifiers returns the identifier nodes a file's top-level
// `let` statements bind. Nodes rather than names: an inner declaration that
// happens to share a name with a top-level one is a different binding and is
// still reportable.
func topLevelDeclaredIdentifiers(statements []mast.Statement) map[*mast.Identifier]struct{} {
	declared := make(map[*mast.Identifier]struct{}, len(statements))
	for _, stmt := range statements {
		let, ok := stmt.(*mast.LetStatement)
		if !ok || let == nil {
			continue
		}
		names := let.Names
		if len(names) == 0 && let.Name != nil {
			names = []*mast.Identifier{let.Name}
		}
		for _, ident := range names {
			if ident != nil {
				declared[ident] = struct{}{}
			}
		}
	}
	return declared
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
	case *mast.ForInStatement:
		// The iterable is a read like any other, and the body may read names
		// from outside the loop.
		if node.Iterable != nil {
			collectUnusedCandidatesFromExpression(node.Iterable, out)
		}
		if node.Body != nil {
			collectUnusedCandidatesFromStatement(node.Body, out)
		}
	case *mast.WhileStatement:
		// A name read only by a while condition is used. Without this arm the
		// unused-declaration rule reports it, which is the false-positive class
		// every walker here exists to avoid.
		if node.Condition != nil {
			collectUnusedCandidatesFromExpression(node.Condition, out)
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
	case *mast.MatchExpression:
		// Patterns are skipped: this gathers declarations that might be
		// unused, and a pattern declares nothing.
		if node.Subject != nil {
			collectUnusedCandidatesFromExpression(node.Subject, out)
		}
		for _, arm := range node.Arms {
			if arm != nil && arm.Body != nil {
				collectUnusedCandidatesFromStatement(arm.Body, out)
			}
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
	// A name used only inside a ${...} hole is used. Without this arm the
	// unused-declaration rule reports every variable an interpolated string
	// reads, which is a warning on correct code -- the one thing these rules
	// promise never to produce.
	case *mast.TemplateLiteral:
		for _, part := range node.Parts {
			collectUnusedCandidatesFromExpression(part, out)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			collectUnusedCandidatesFromExpression(key, out)
			collectUnusedCandidatesFromExpression(value, out)
		}
	}
}
