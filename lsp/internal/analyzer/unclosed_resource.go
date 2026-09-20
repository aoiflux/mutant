package analyzer

// Twenty builtin families open a handle that lives in a package-level map with
// no cap, no eviction and no cleanup at exit. An unclosed handle holds its OS
// resource for the life of the process. For a script that opens one image and
// exits, the OS reclaims everything and this is theoretical; for the two shapes
// the language explicitly supports -- a loop over a corpus, and a long-running
// server -- it is descriptor exhaustion.
//
// This is Tier 1 of L-6 §7: it cannot prove every path, but it turns an
// invisible leak into a squiggle at edit time, for no language change and no
// runtime cost. Tier 2, with_resource, is the guarantee; this rule is what
// finds the places that have not been given one.
//
// The rule declines wherever it cannot be certain, and the reason is the usual
// one: a false positive here tells someone their correct code leaks. It stays
// quiet when
//
//   - the opener's result is not bound to a name, which is what
//     `with_resource(ntfs_open(p), ...)` looks like;
//   - the closer's name appears anywhere in the enclosing scope -- called,
//     passed by name, or spelled in the string with_resource takes;
//   - the bound name is used anywhere the rule does not understand. Only
//     arguments to the family's own builtins count as understood. A handle
//     returned to a caller, handed to a helper, stored in a list, or printed is
//     a handle whose lifetime is decided somewhere this rule cannot see.
//
// Together those mean the rule reports one shape: a resource opened, used
// through its own family, and abandoned. That is the shape the corpus workaround
// exists to avoid, and it is the shape a straight-line script gets wrong.

import (
	"fmt"
	"reflect"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// resourceFamily pairs the builtins that open a resource with the one that
// closes it, and names the prefixes of the builtins that legitimately consume
// the handle in between.
//
// The prefixes exist for the escape check, not for classification: a mention of
// the handle outside them is a use the rule cannot follow, so it stays quiet.
// They are deliberately loose (the whole `net_` surface for a connection rather
// than the exact consumers), because a prefix that is too wide only suppresses
// reports, while one that is too narrow would invent them.
type resourceFamily struct {
	openers  []string
	closer   string
	prefixes []string
}

// resourceFamilies is curated rather than derived from the names, because the
// derivation is not regular: hashset opens with `_load`, chan with `_new`, a
// connection is closed by net_conn_close rather than net_connect_close, and
// net_dial looks like an opener but returns a reachability report and no
// handle. TestResourceFamiliesCoverEveryCloser pins it against the registry so
// a new close family cannot be added without being accounted for here.
var resourceFamilies = []resourceFamily{
	{openers: []string{builtin.BuiltinNameNtfsOpen}, closer: builtin.BuiltinNameNtfsClose, prefixes: []string{"ntfs_"}},
	{openers: []string{builtin.BuiltinNameFatOpen}, closer: builtin.BuiltinNameFatClose, prefixes: []string{"fat_"}},
	{openers: []string{builtin.BuiltinNameXfatOpen}, closer: builtin.BuiltinNameXfatClose, prefixes: []string{"xfat_"}},
	{openers: []string{builtin.BuiltinNameExtOpen}, closer: builtin.BuiltinNameExtClose, prefixes: []string{"ext_"}},
	{openers: []string{builtin.BuiltinNameHfsOpen}, closer: builtin.BuiltinNameHfsClose, prefixes: []string{"hfs_"}},
	{openers: []string{builtin.BuiltinNameXfsOpen}, closer: builtin.BuiltinNameXfsClose, prefixes: []string{"xfs_"}},
	{openers: []string{builtin.BuiltinNameVhdiOpen}, closer: builtin.BuiltinNameVhdiClose, prefixes: []string{"vhdi_"}},
	{openers: []string{builtin.BuiltinNameEwfOpen}, closer: builtin.BuiltinNameEwfClose, prefixes: []string{"ewf_"}},
	{openers: []string{builtin.BuiltinNameRawOpen}, closer: builtin.BuiltinNameRawClose, prefixes: []string{"raw_"}},
	{openers: []string{builtin.BuiltinNameTableOpen}, closer: builtin.BuiltinNameTableClose, prefixes: []string{"table_"}},
	{openers: []string{builtin.BuiltinNameRegOpen}, closer: builtin.BuiltinNameRegClose, prefixes: []string{"reg_"}},
	{openers: []string{builtin.BuiltinNameHiveOpen}, closer: builtin.BuiltinNameHiveClose, prefixes: []string{"hive_"}},
	{openers: []string{builtin.BuiltinNameZipOpen}, closer: builtin.BuiltinNameZipClose, prefixes: []string{"zip_"}},
	{openers: []string{builtin.BuiltinNameTarOpen}, closer: builtin.BuiltinNameTarClose, prefixes: []string{"tar_"}},
	{openers: []string{builtin.BuiltinNameDbOpen, builtin.BuiltinNameDbOpenDisk}, closer: builtin.BuiltinNameDbClose, prefixes: []string{"db_"}},
	// The ledger is its own family rather than part of db_: the handle spaces
	// are separate, so a ledger_ call on a db_ handle is a bug the rule should
	// not be taught to read as a use.
	{openers: []string{builtin.BuiltinNameLedgerOpen}, closer: builtin.BuiltinNameLedgerClose, prefixes: []string{"ledger_"}},
	{openers: []string{builtin.BuiltinNameHashsetLoad}, closer: builtin.BuiltinNameHashsetClose, prefixes: []string{"hashset_"}},
	{openers: []string{builtin.BuiltinNameCacheOpen}, closer: builtin.BuiltinNameCacheClose, prefixes: []string{"cache_"}},
	{openers: []string{builtin.BuiltinNameChanNew}, closer: builtin.BuiltinNameChanClose, prefixes: []string{"chan_"}},
	{
		openers:  []string{builtin.BuiltinNameNetConnect, builtin.BuiltinNameNetTlsConnect},
		closer:   builtin.BuiltinNameNetConnClose,
		prefixes: []string{"net_", "http_conn_"},
	},
	{
		openers:  []string{builtin.BuiltinNameNetListen, builtin.BuiltinNameNetTlsListen},
		closer:   builtin.BuiltinNameNetListenClose,
		prefixes: []string{"net_", "http_conn_"},
	},
}

// nonResourceClosers are builtins whose name ends in `_close` but which close
// nothing a name can hold, with the reason for each.
//
// This is an allowlist rather than a silence: TestResourceFamiliesCoverEveryCloser
// requires every `*_close` in the registry to be either a family above or an
// entry here, so a genuinely new resource cannot slip past the rule by being
// forgotten.
var nonResourceClosers = map[string]string{
	builtin.BuiltinNameCaseClose: "`case_close` ends the chain-of-custody session (F-1), which is " +
		"process-wide rather than a handle: `case_open` returns no handle to hold and `case_close` " +
		"takes no arguments, so there is nothing for this rule to follow from one to the other. Nor " +
		"is a case left open a leak -- `case_write` seals the manifest without it, and the manifest " +
		"of an open case says `\"status\": \"open\"` rather than pretending otherwise.",
}

// openerFamilies indexes the table by opener name, which is how the walker asks
// about a call it just found.
var openerFamilies = func() map[string]resourceFamily {
	index := make(map[string]resourceFamily, len(resourceFamilies)*2)
	for _, family := range resourceFamilies {
		for _, opener := range family.openers {
			index[opener] = family
		}
	}
	return index
}()

func lintUnclosedResources(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("unclosedResource")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	collector := &unclosedResourceCollector{
		snapshot: snapshot,
		severity: severity,
		source:   &source,
		shadowed: namesBoundAnywhere(snapshot.Program.Statements),
	}
	collector.checkScope(snapshot.Program.Statements)
	return collector.result
}

type unclosedResourceCollector struct {
	snapshot *Snapshot
	severity *lsp.DiagnosticSeverity
	source   *string
	shadowed map[string]struct{}
	result   []lsp.Diagnostic
}

// namesBoundAnywhere collects every name the file binds -- top-level and local
// `let`s, and every function parameter.
//
// It is deliberately file-wide rather than scope-accurate. The only thing it is
// used for is deciding that `ntfs_open` in this file might not be the builtin,
// and over-suppressing on a program that happens to bind the name somewhere is
// the harmless direction.
func namesBoundAnywhere(statements []mast.Statement) map[string]struct{} {
	bound := make(map[string]struct{})

	var walk func(mast.Statement)
	walk = func(stmt mast.Statement) {
		if isNilStatement(stmt) {
			return
		}
		if let, ok := stmt.(*mast.LetStatement); ok {
			for _, name := range letNames(let) {
				if name != nil && name.Value != "" {
					bound[name.Value] = struct{}{}
				}
			}
		}
		visitExpressions(stmt, func(expr mast.Expression) {
			literal, ok := expr.(*mast.FunctionLiteral)
			if !ok || literal == nil {
				return
			}
			for _, param := range literal.Parameters {
				if param != nil && param.Value != "" {
					bound[param.Value] = struct{}{}
				}
			}
			if literal.Body != nil {
				for _, inner := range literal.Body.Statements {
					walk(inner)
				}
			}
		})

		switch n := stmt.(type) {
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walk(inner)
			}
		case *mast.ForStatement:
			if !isNilStatement(n.Init) {
				walk(n.Init)
			}
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.WhileStatement:
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.ForInStatement:
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.ExpressionStatement:
			forEachNestedBlockExpression(n.Expression, walk)
		case *mast.LetStatement:
			forEachNestedBlockExpression(n.Value, walk)
		}
	}

	for _, stmt := range statements {
		walk(stmt)
	}
	return bound
}

// checkScope examines one function body -- or the top level -- and then each
// function literal written inside it as a scope of its own.
//
// A scope rather than the whole file, because "opened here and closed in some
// other function" is exactly the arrangement the escape check is there to
// notice: if the handle never leaves this scope, this scope is the only place
// that could have closed it.
func (c *unclosedResourceCollector) checkScope(statements []mast.Statement) {
	bindings := c.openerBindings(statements)
	if len(bindings) > 0 {
		mentioned := identifiersMentionedIn(statements)
		safe := identifiersInFamilyArguments(statements)
		spelled := namesSpelledIn(statements)
		lifelong := identifiersHeldForTheProgramsLife(statements)

		for _, binding := range bindings {
			c.report(binding, mentioned, safe, spelled, lifelong)
		}
	}

	for _, nested := range nestedFunctionBodies(statements) {
		c.checkScope(nested)
	}
}

// openerBinding is one `let` whose value is a call to a resource opener.
type openerBinding struct {
	family resourceFamily
	opener string
	name   string

	// anchor is the node the diagnostic points at: the callee identifier for
	// `ntfs_open(...)`, the whole `ntfs.open` for the dotted spelling, so the
	// squiggle covers what the author wrote either way.
	anchor mast.Node
}

func (c *unclosedResourceCollector) openerBindings(statements []mast.Statement) []openerBinding {
	var found []openerBinding

	forEachStatementInScope(statements, func(stmt mast.Statement) {
		let, ok := stmt.(*mast.LetStatement)
		if !ok || let.Value == nil {
			return
		}
		call, ok := let.Value.(*mast.CallExpression)
		if !ok {
			return
		}
		calleeName, anchor, ok := builtinCallee(call.Function, c.isShadowed)
		if !ok {
			return
		}
		family, isOpener := openerFamilies[calleeName]
		if !isOpener {
			return
		}
		// builtinCallee already rejected a shadowed opener; the closer is a
		// different name and still has to be checked here.
		if _, shadowed := c.shadowed[family.closer]; shadowed {
			return
		}

		names := letNames(let)
		if len(names) == 0 || names[0] == nil || names[0].Value == "" || names[0].Value == "_" {
			return
		}

		found = append(found, openerBinding{
			family: family,
			opener: calleeName,
			name:   names[0].Value,
			anchor: anchor,
		})
	})

	return found
}

func (c *unclosedResourceCollector) report(
	binding openerBinding,
	mentioned map[string][]*mast.Identifier,
	safe map[*mast.Identifier]struct{},
	spelled map[string]struct{},
	lifelong map[*mast.Identifier]struct{},
) {
	// The closer named anywhere in this scope -- called, passed by name, or
	// written in the string with_resource takes -- is enough to stay quiet.
	if _, closed := spelled[binding.family.closer]; closed {
		return
	}

	for _, mention := range mentioned[binding.name] {
		if mention == binding.anchor {
			continue
		}
		if _, forever := lifelong[mention]; forever {
			// The resource is held by something with no reachable end, so its
			// lifetime is the program's on purpose and there is no "after" in
			// which to close it.
			return
		}
		if _, understood := safe[mention]; !understood {
			// The handle goes somewhere this rule cannot follow, so its
			// lifetime is decided somewhere else.
			return
		}
	}

	rng, ok := c.snapshot.Program.RangeOf(binding.anchor)
	if !ok {
		return
	}

	c.result = append(c.result, lsp.Diagnostic{
		Range:    localprotocol.ToLSPRange(rng),
		Severity: c.severity,
		Source:   c.source,
		Message: fmt.Sprintf(
			"`%s` opens a resource that nothing closes here. Handles live in a package-level store with no eviction, so an unclosed one is held for the life of the process. Call `%s` when you are done, or wrap the work in `with_resource(%s(...), \"%s\", fn(%s) { ... })`, which closes it even if the body fails.",
			binding.opener, binding.family.closer, binding.opener, binding.family.closer, binding.name),
	})
}

// forEachStatementInScope visits every statement belonging to this scope,
// through blocks, `if` arms and `for` bodies, but never into a function literal
// -- whose statements are their own scope.
func forEachStatementInScope(statements []mast.Statement, visit func(mast.Statement)) {
	var walk func(mast.Statement)
	walk = func(stmt mast.Statement) {
		if isNilStatement(stmt) {
			return
		}
		visit(stmt)

		switch n := stmt.(type) {
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walk(inner)
			}
		case *mast.ForStatement:
			if !isNilStatement(n.Init) {
				walk(n.Init)
			}
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.WhileStatement:
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.ForInStatement:
			if !isNilStatement(n.Body) {
				walk(n.Body)
			}
		case *mast.ExpressionStatement:
			forEachNestedBlockExpression(n.Expression, walk)
		case *mast.LetStatement:
			forEachNestedBlockExpression(n.Value, walk)
		case *mast.ReturnStatement:
			forEachNestedBlockExpression(n.ReturnValue, walk)
			for _, value := range n.ReturnValues {
				forEachNestedBlockExpression(value, walk)
			}
		}
	}

	for _, stmt := range statements {
		walk(stmt)
	}
}

// forEachNestedBlockExpression reaches the statements inside the two
// expressions that hold blocks -- `if` and `match`. Both are expressions in
// this language and so can appear anywhere a value can, which is why a
// statement walker has to look inside expressions at all.
func forEachNestedBlockExpression(expr mast.Expression, walk func(mast.Statement)) {
	switch node := expr.(type) {
	case *mast.IfExpression:
		if node == nil {
			return
		}
		if !isNilStatement(node.Consequence) {
			walk(node.Consequence)
		}
		if !isNilStatement(node.Alternative) {
			walk(node.Alternative)
		}
	case *mast.MatchExpression:
		if node == nil {
			return
		}
		for _, arm := range node.Arms {
			if arm != nil && !isNilStatement(arm.Body) {
				walk(arm.Body)
			}
		}
	}
}

// isNilStatement reports whether a statement slot is empty.
//
// The parser records an absent arm as a typed nil -- an `if` with no `else`
// holds a nil *BlockStatement, a `for` with no init a nil *LetStatement -- and
// an interface carrying a nil pointer is not itself nil, so the ordinary check
// walks straight into it. The shared expression walker dereferences without
// asking, and a panic there takes the language server down over a file that
// merely has an `if` in it.
//
// reflect rather than a type switch on purpose: a switch would have to list
// every statement type, and the cost of forgetting one is the crash this
// exists to prevent.
func isNilStatement(stmt mast.Statement) bool {
	if stmt == nil {
		return true
	}
	value := reflect.ValueOf(stmt)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

// nestedFunctionBodies collects the body of every function literal written
// directly in this scope. Each is a scope of its own: a resource opened inside
// a callback is closed inside that callback or not at all.
func nestedFunctionBodies(statements []mast.Statement) [][]mast.Statement {
	var bodies [][]mast.Statement
	for _, stmt := range statements {
		walkExpressions(stmt, false, func(expr mast.Expression) {
			literal, ok := expr.(*mast.FunctionLiteral)
			if !ok || literal == nil || literal.Body == nil {
				return
			}
			bodies = append(bodies, literal.Body.Statements)
		})
	}
	return bodies
}

// identifiersMentionedIn indexes every identifier in the scope by name,
// function literals included: a handle captured by a nested closure is still a
// mention this rule has to account for.
func identifiersMentionedIn(statements []mast.Statement) map[string][]*mast.Identifier {
	mentions := make(map[string][]*mast.Identifier)
	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			if ident, ok := expr.(*mast.Identifier); ok && ident != nil && ident.Value != "" {
				mentions[ident.Value] = append(mentions[ident.Value], ident)
			}
		})
	}
	return mentions
}

// identifiersInFamilyArguments collects the identifiers the rule understands:
// those reachable from an argument to a builtin of a family the table names.
// Anything else is a use whose consequences this rule cannot see.
func identifiersInFamilyArguments(statements []mast.Statement) map[*mast.Identifier]struct{} {
	safe := make(map[*mast.Identifier]struct{})
	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			call, ok := expr.(*mast.CallExpression)
			if !ok {
				return
			}
			calleeName, _, ok := builtinCallee(call.Function, nil)
			if !ok || !isFamilyConsumer(calleeName) {
				return
			}
			for _, arg := range call.Arguments {
				visitExpressions(arg, func(inner mast.Expression) {
					if ident, ok := inner.(*mast.Identifier); ok && ident != nil {
						safe[ident] = struct{}{}
					}
				})
			}
		})
	}
	return safe
}

// serveForever names the builtins that hold a resource until the process is
// interrupted. net_serve is the only one: it takes a listener and runs an
// accept loop that has no ordinary return, which is why a program that calls it
// never reaches a close and is not wrong for that.
var serveForever = map[string]struct{}{
	builtin.BuiltinNameNetServe: {},
}

// identifiersHeldForTheProgramsLife collects the mentions that put a resource
// beyond the reach of a close: those inside a loop with no exit, and those
// handed to a builtin that serves until interrupted.
//
// This is the server shape, and it is the one place where "held for the life of
// the process" is the intent rather than the defect. A listener bound at
// startup and served from until Ctrl-C has no reachable point at which to close
// it; reporting one would be telling every server in the corpus that it leaks.
func identifiersHeldForTheProgramsLife(statements []mast.Statement) map[*mast.Identifier]struct{} {
	held := make(map[*mast.Identifier]struct{})

	collect := func(node mast.Node) {
		visitExpressions(node, func(expr mast.Expression) {
			if ident, ok := expr.(*mast.Identifier); ok && ident != nil {
				held[ident] = struct{}{}
			}
		})
	}

	for _, stmt := range statements {
		forEachStatementInScope([]mast.Statement{stmt}, func(inner mast.Statement) {
			body, endless := endlessLoopBody(inner)
			if endless && !isNilStatement(body) {
				collect(body)
			}
		})

		visitExpressions(stmt, func(expr mast.Expression) {
			call, ok := expr.(*mast.CallExpression)
			if !ok {
				return
			}
			calleeName, _, ok := builtinCallee(call.Function, nil)
			if !ok {
				return
			}
			if _, serves := serveForever[calleeName]; !serves {
				return
			}
			for _, arg := range call.Arguments {
				collect(arg)
			}
		})
	}

	return held
}

// isEndlessLoop reports whether a `for` has no way out through its condition:
// `for (;;)` writes no condition at all, and `for (let i = 0; true; i = i + 1)`
// writes one that is always taken.
//
// A `break` inside is not looked for, which means a loop the program can in
// fact leave is treated as endless and its resource excused. That is the
// direction this rule always errs in: missing a report costs a squiggle, and
// inventing one costs someone's trust in the rule.
func isEndlessLoop(loop *mast.ForStatement) bool {
	if loop.Condition == nil {
		return true
	}
	return isAlwaysTrue(loop.Condition)
}

// endlessLoopBody reports the body of stmt when stmt is a loop that never ends.
//
// `while (true)` is the spelling a server loop actually uses, so leaving it out
// would have excused exactly the resources this rule is about -- while the
// equivalent `for (;;)` was still recognised.
func endlessLoopBody(stmt mast.Statement) (mast.Statement, bool) {
	switch loop := stmt.(type) {
	case *mast.ForStatement:
		if loop == nil {
			return nil, false
		}
		return loop.Body, isEndlessLoop(loop)
	case *mast.WhileStatement:
		if loop == nil {
			return nil, false
		}
		return loop.Body, isAlwaysTrue(loop.Condition)
	}
	return nil, false
}

// isAlwaysTrue reports whether a condition is the literal `true`. It is
// deliberately syntactic: anything cleverer would start excusing loops whose
// exit this rule cannot actually prove.
func isAlwaysTrue(cond mast.Expression) bool {
	literal, ok := cond.(*mast.Boolean)
	return ok && literal != nil && literal.Value
}

func isFamilyConsumer(name string) bool {
	for _, family := range resourceFamilies {
		for _, prefix := range family.prefixes {
			if len(name) > len(prefix) && name[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// namesSpelledIn collects every identifier and every string literal in the
// scope. A closer reaches its handle by any of its spellings -- `ntfs_close(h)`,
// `ntfs.close(h)`, or `with_resource(h, "ntfs_close", ...)` -- and one is as
// good as another for deciding to stay quiet.
//
// The dotted form has to be derived here rather than left to the walker:
// visitExpressions never visits a FieldExpression's Field, so `ntfs.close`
// would otherwise contribute only `ntfs` and the rule would report a handle
// that is correctly closed. This rule promises never to do that.
func namesSpelledIn(statements []mast.Statement) map[string]struct{} {
	spelled := make(map[string]struct{})
	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			switch n := expr.(type) {
			case *mast.Identifier:
				if n != nil {
					spelled[n.Value] = struct{}{}
				}
			case *mast.StringLiteral:
				if n != nil {
					spelled[n.Value] = struct{}{}
				}
			case *mast.FieldExpression:
				if n == nil || n.Field == nil || n.Field.Value == "" {
					return
				}
				namespace, isIdent := n.Left.(*mast.Identifier)
				if !isIdent || namespace == nil || namespace.Value == "" {
					return
				}
				spelled[namespace.Value+"_"+n.Field.Value] = struct{}{}
			}
		})
	}
	return spelled
}

// isShadowed reports whether the file binds name for itself somewhere. It is
// the shadow predicate builtinCallee needs, and it is the same set the rule
// already consults directly for closer names.
func (c *unclosedResourceCollector) isShadowed(name string) bool {
	if c == nil {
		return false
	}
	_, shadowed := c.shadowed[name]
	return shadowed
}
