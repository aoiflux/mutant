package analyzer

// pathTraversal reports a filesystem path built from something the program did
// not write.
//
// The other six security rules read one call site. This one has to relate three
// things that are usually lines apart -- where a value came from, what was done
// to it, and where it ended up -- which is why it was built last and why it
// carries the only machinery in the family that resembles taint tracking.
//
// The three questions are the same shape as everywhere else in this file:
//
//  1. **Where did it come from?** A source is a builtin that hands back
//     something nobody in this program chose: `gets` reads a line from whoever
//     is at the terminal, `serve_arg` hands a request's own argument to a
//     handler, `net_conn_read` and the http builtins return what the other end
//     sent. A value from any other origin is not tracked, so a program that
//     reads its input some other way is a program this says nothing about.
//  2. **What was done to it?** The taint follows one hop of `let`, through
//     concatenation and interpolation, which is how a path gets built:
//     `let file = root + "/" + name;`. It does not follow into arrays, hashes,
//     function calls or across a function boundary.
//  3. **Was it checked?** Any mention of the name -- or of any name it was
//     derived from -- as an argument to a text-inspecting builtin is taken as
//     the check. `text_contains(name, "..")`, a `regex_match`, a
//     `str_starts_with` against the intended root: all of them silence the
//     report, and so does `text_replace`, which is how the characters get
//     stripped. The rule cannot read which characters were looked for, so it
//     takes the author's word. That over-suppresses on purpose.
//
// What it reports, then, is the shape with nothing in between: a value arrives
// from outside, becomes a path, and reaches the filesystem without the program
// ever having looked at it. `..%2f..%2fetc%2fpasswd` is a request path, and
// `root + "/" + it` is a file outside root.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// untrustedSources are the builtins that return something the program did not
// choose, with the words to describe where it came from.
var untrustedSources = map[string]string{
	builtin.BuiltinNameGets:                    "typed at the terminal",
	builtin.BuiltinNameServeArg:                "taken from a request",
	builtin.BuiltinNameNetConnRead:             "read from a network connection",
	builtin.BuiltinNameNetConnReadBytes:        "read from a network connection",
	builtin.BuiltinNameHttpParseRequest:        "parsed out of an HTTP request",
	builtin.BuiltinNameHttpConnReadRequest:     "read from an HTTP client",
	builtin.BuiltinNameHttpGet:                 "fetched over HTTP",
	builtin.BuiltinNameHttpPost:                "fetched over HTTP",
	builtin.BuiltinNameHttpRequest:             "fetched over HTTP",
	builtin.BuiltinNameHttpConnReadRequestHead: "read from an HTTP client",
}

// pathGuards are the builtins that look inside a string. Any of them applied to
// a value is taken as the program having checked it.
//
// Deliberately wide, and deliberately blind to what was checked for: there is
// no way from here to tell `text_contains(p, "..")` from
// `text_contains(p, ".log")`, and a rule that guessed would report a program
// that is already careful. §1 keeps `policy_*` off this list -- the lint says
// what the code does, and a capability policy is a different layer's answer.
var pathGuards = map[string]struct{}{
	builtin.BuiltinNameTextContains:    {},
	builtin.BuiltinNameTextIndex:       {},
	builtin.BuiltinNameTextReplace:     {},
	builtin.BuiltinNameRegexMatch:      {},
	builtin.BuiltinNameRegexFind:       {},
	builtin.BuiltinNameRegexReplace:    {},
	builtin.BuiltinNameStrStartsWith:   {},
	builtin.BuiltinNameStrEndsWith:     {},
	builtin.BuiltinNameStrTrimPrefix:   {},
	builtin.BuiltinNameContains:        {},
	builtin.BuiltinNameIndexOf:         {},
	builtin.BuiltinNameURLDecode:       {},
	builtin.BuiltinNameBase64Encode:    {},
	builtin.BuiltinNameHexEncode:       {},
	builtin.BuiltinNameToInt:           {},
	builtin.BuiltinNameParseInt:        {},
	builtin.BuiltinNameDomainExtract:   {},
	builtin.BuiltinNameTLDExtract:      {},
	builtin.BuiltinNameIsValidDomain:   {},
	builtin.BuiltinNameIPInCIDR:        {},
	builtin.BuiltinNameHashsetContains: {},
}

// pathSinks maps a builtin to the argument that names a file it will touch.
var pathSinks = map[string]int{
	builtin.BuiltinNameFsRead:            0,
	builtin.BuiltinNameFsReadBytes:       0,
	builtin.BuiltinNameFsWrite:           0,
	builtin.BuiltinNameFsAppend:          0,
	builtin.BuiltinNameFsDelete:          0,
	builtin.BuiltinNameFsExists:          0,
	builtin.BuiltinNameFsStat:            0,
	builtin.BuiltinNameFsList:            0,
	builtin.BuiltinNameFsMkdir:           0,
	builtin.BuiltinNameFsHash:            0,
	builtin.BuiltinNameFsWalk:            0,
	builtin.BuiltinNameFsMetadata:        0,
	builtin.BuiltinNameFsMagic:           0,
	builtin.BuiltinNameFsExtractStrings:  0,
	builtin.BuiltinNameFsCarve:           0,
	builtin.BuiltinNameFsEntropy:         0,
	builtin.BuiltinNameFsCopy:            0,
	builtin.BuiltinNameFsMove:            0,
	builtin.BuiltinNameNtfsReadFile:      1,
	builtin.BuiltinNameFatReadFile:       1,
	builtin.BuiltinNameXfatReadFile:      1,
	builtin.BuiltinNameExtReadFile:       1,
	builtin.BuiltinNameHfsReadFile:       1,
	builtin.BuiltinNameXfsReadFile:       1,
	builtin.BuiltinNameZipRead:           1,
	builtin.BuiltinNameTarRead:           1,
	builtin.BuiltinNameNtfsReadFileBytes: 1,
	builtin.BuiltinNameZipReadBytes:      1,
	builtin.BuiltinNameTarReadBytes:      1,
}

func lintPathTraversal(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("pathTraversal")
	if !ok {
		return nil
	}

	statements := snapshot.Program.Statements
	shadowed := namesBoundAnywhere(statements)
	isShadowed := func(candidate string) bool {
		_, taken := shadowed[candidate]
		return taken
	}
	// File-wide, because a value checked in a helper is still a value that was
	// checked, and over-excusing is this family's direction.
	guarded := namesGivenToAGuard(statements, isShadowed)

	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachScope(statements, func(scope []mast.Statement) {
		origins := untrustedNames(scope, isShadowed)
		if len(origins) == 0 {
			return
		}

		forEachStatementInScope(scope, func(stmt mast.Statement) {
			walkExpressions(stmt, false, func(expr mast.Expression) {
				call, ok := expr.(*mast.CallExpression)
				if !ok || call == nil {
					return
				}
				name, _, ok := builtinCallee(call.Function, isShadowed)
				if !ok {
					return
				}
				index, isSink := pathSinks[name]
				if !isSink {
					return
				}
				argument := argumentAt(call, index)
				if argument == nil {
					return
				}

				tainted, origin := taintedNameIn(argument, origins, guarded)
				if tainted == "" {
					return
				}

				rng, ok := snapshot.Program.RangeOf(argument)
				if !ok {
					return
				}
				result = append(result, lsp.Diagnostic{
					Range:    localprotocol.ToLSPRange(rng),
					Severity: severity,
					Source:   &source,
					Message: fmt.Sprintf(
						"`%s` is given a path built from `%s`, which was %s, and nothing in this file looks at that value first. A `..` segment walks out of whatever directory the rest of the path names, so the file this reads or writes is chosen by whoever supplied the value rather than by the program. Check it before using it -- reject a path containing `..`, or confirm the resolved path still starts with the directory you meant -- and this rule will stay quiet.",
						name, tainted, origin),
				})
			})
		})
	})

	return result
}

// untrustedOrigin is a name and where its value came from.
type untrustedOrigin struct {
	source string
	from   string
}

// untrustedNames maps each name in this scope that holds an untrusted value to
// where it came from, following one hop of `let` and as many hops of
// concatenation and interpolation as the scope contains.
//
// The repetition is a fixed point rather than a single pass, because the
// statements can be in any order the author liked and `let b = a + "/";` may
// well appear before `let a = gets();` inside a function that runs later. It
// terminates because each round can only add names and there are finitely many.
func untrustedNames(scope []mast.Statement, isShadowed func(string) bool) map[string]untrustedOrigin {
	origins := make(map[string]untrustedOrigin)
	bindings := singleBindings(scope)

	for {
		grew := false
		for name, value := range bindings {
			if _, known := origins[name]; known {
				continue
			}
			if source, from, ok := untrustedValue(value, origins, isShadowed); ok {
				origins[name] = untrustedOrigin{source: source, from: from}
				grew = true
			}
		}
		if !grew {
			return origins
		}
	}
}

// untrustedValue reports whether an expression produces an untrusted value:
// a call to a source, a name already known to hold one, or a string built from
// either.
func untrustedValue(
	expr mast.Expression,
	origins map[string]untrustedOrigin,
	isShadowed func(string) bool,
) (source string, from string, ok bool) {
	switch node := expr.(type) {
	case *mast.Identifier:
		if node == nil {
			return "", "", false
		}
		if origin, known := origins[node.Value]; known {
			return node.Value, origin.from, true
		}

	case *mast.CallExpression:
		if node == nil {
			return "", "", false
		}
		name, _, valid := builtinCallee(node.Function, isShadowed)
		if !valid {
			return "", "", false
		}
		if from, untrusted := untrustedSources[name]; untrusted && isLiveBuiltin(name) {
			return name, from, true
		}

	case *mast.IndexExpression:
		// `request["path"]` is the field of a parsed request, and carries the
		// request's provenance.
		if node == nil {
			return "", "", false
		}
		return untrustedValue(node.Left, origins, isShadowed)

	case *mast.InfixExpression:
		if node == nil || node.Operator != "+" {
			return "", "", false
		}
		for _, side := range []mast.Expression{node.Left, node.Right} {
			if source, from, ok := untrustedValue(side, origins, isShadowed); ok {
				return source, from, true
			}
		}

	case *mast.TemplateLiteral:
		if node == nil {
			return "", "", false
		}
		for _, part := range node.Parts {
			if source, from, ok := untrustedValue(part, origins, isShadowed); ok {
				return source, from, true
			}
		}
	}

	return "", "", false
}

// taintedNameIn finds the untrusted, unchecked name a path expression is built
// from, and says where it came from.
func taintedNameIn(
	expr mast.Expression,
	origins map[string]untrustedOrigin,
	guarded map[string]struct{},
) (name string, from string) {
	var found, provenance string

	var walk func(mast.Expression)
	walk = func(e mast.Expression) {
		if found != "" || e == nil {
			return
		}
		switch node := e.(type) {
		case *mast.Identifier:
			if node == nil {
				return
			}
			origin, untrusted := origins[node.Value]
			if !untrusted {
				return
			}
			if _, checked := guarded[node.Value]; checked {
				return
			}
			// A name derived from a checked one is checked: the program looked
			// at the value before it became this.
			if _, checked := guarded[origin.source]; checked {
				return
			}
			found, provenance = node.Value, origin.from
		case *mast.InfixExpression:
			if node != nil && node.Operator == "+" {
				walk(node.Left)
				walk(node.Right)
			}
		case *mast.TemplateLiteral:
			if node == nil {
				return
			}
			for _, part := range node.Parts {
				walk(part)
			}
		}
	}
	walk(expr)

	return found, provenance
}

// namesGivenToAGuard collects every name the document hands to a builtin that
// inspects a string.
func namesGivenToAGuard(statements []mast.Statement, isShadowed func(string) bool) map[string]struct{} {
	guarded := make(map[string]struct{})

	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			call, ok := expr.(*mast.CallExpression)
			if !ok || call == nil {
				return
			}
			name, _, valid := builtinCallee(call.Function, isShadowed)
			if !valid {
				return
			}
			if _, guard := pathGuards[name]; !guard {
				return
			}
			for _, argument := range call.Arguments {
				if ident, ok := argument.(*mast.Identifier); ok && ident != nil && ident.Value != "" {
					guarded[ident.Value] = struct{}{}
				}
			}
		})
	}

	return guarded
}
