package analyzer

// commandInjection reports a value spliced into a string that an interpreter
// will then parse.
//
// `exec_string` does not run a program with arguments -- it hands a whole
// string to a shell (`security.ExecuteCommand(shell, commandArg.Value, ...)`,
// builtin/command_exec.go:29), and the shell decides where one word ends and
// the next begins. A value placed inside that string is therefore not data: a
// space, a `;`, a `|` or a `$(...)` in it becomes syntax. `cmd_add` is the same
// hazard one step earlier, because `cmd_run` joins the builder's lines with
// newlines and passes them to the same shell -- which is why the report belongs
// on `cmd_add`, where the string is assembled, rather than on `cmd_run`, where
// it is already too late. `lua_run_string` is the same shape with a different
// interpreter.
//
// The rule fires on the shape the word "injection" actually names: a value
// placed *inside* a larger command. An interpolation with a hole, or a
// concatenation with a non-literal piece -- those and nothing else.
//
// It says nothing about `exec_string(command)` where the whole string arrives
// as one value. That is a real hazard too, but it is a question about where the
// value came from rather than about what this line does with it, and answering
// it needs the taint tracking pathTraversal carries.
//
// And nothing else guards these builtins: there is no runtime capability policy
// for them, and none is planned -- SEC-017 in docs/SECURITY_LLD_TRACEABILITY.md
// records that decision --
// so this warning is the only thing between a spliced value and a shell, which
// is a reason to keep it quiet enough to stay switched on.

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// commandSink is a builtin that hands a string to an interpreter, and which of
// its arguments that string is.
type commandSink struct {
	index       int
	interpreter string
}

// commandSanitizers are the builtins that make a value safe to put inside a
// command string, either by removing what could be syntax or by turning the
// value into something that has no syntax at all.
//
// The list matters as much as the rule does. A rule with no way to comply is a
// rule people switch off, and the four contract rules that came before this one
// each have an explicit way for the program to say "I have handled this" -- `_`
// for a deliberately ignored error, `with_resource` for a handle. This is that
// escape: a spliced value that has been through one of these is a value the
// author has done something about.
//
// The encoders and the integer conversions are safe by construction: a
// percent-encoded, base64, hex or integer value cannot contain a quote, a
// semicolon or a space. `text_replace` and `regex_replace` are taken at the
// author's word -- they are how you strip a delimiter in this language, and
// there is no way to tell from here which characters were removed. That is a
// deliberate over-suppression, in the direction every rule in this family errs.
var commandSanitizers = map[string]struct{}{
	builtin.BuiltinNameURLEncode:       {},
	builtin.BuiltinNameBase64Encode:    {},
	builtin.BuiltinNameBase64URLEncode: {},
	builtin.BuiltinNameHexEncode:       {},
	builtin.BuiltinNameToInt:           {},
	builtin.BuiltinNameParseInt:        {},
	builtin.BuiltinNameTextReplace:     {},
	builtin.BuiltinNameRegexReplace:    {},
}

var commandSinks = map[string]commandSink{
	// exec_string(command, shell?)
	builtin.BuiltinNameExecString: {index: 0, interpreter: "a shell"},
	// cmd_add(builder, line) -- cmd_run joins the lines and runs them.
	builtin.BuiltinNameCmdAdd: {index: 1, interpreter: "a shell, once `cmd_run` is called"},
	// lua_run_string(code)
	builtin.BuiltinNameLuaRunString: {index: 0, interpreter: "the Lua interpreter"},
}

// commandArgvSinks are the builtins that hand a program its arguments directly
// rather than handing a whole string to a shell, and so need the other half of
// this rule: the one that reports a spliced element only where something will
// parse it.
var commandArgvSinks = map[string]string{
	// exec_argv(argv)
	builtin.BuiltinNameExecArgv: "a shell",
}

// commandIntroducingFlags are the argv elements after which the next element is
// a command for an interpreter to read, rather than an argument for a program
// to receive.
//
// The list is short deliberately, and every entry is a flag a shell documents:
// -c for the POSIX shells and fish, its clustered forms for a login or
// interactive one, /C and /K for cmd.exe, and -Command for PowerShell. A flag
// that is not here is read as an ordinary argument, which is the direction
// every rule in this family errs in. `-xvzc` ending in a c does not make tar's
// next argument a command, and reporting it would teach the reader to ignore
// the rule.
var commandIntroducingFlags = map[string]struct{}{
	"-c":       {},
	"-lc":      {},
	"-ic":      {},
	"-ec":      {},
	"-lic":     {},
	"-command": {},
	"/c":       {},
	"/k":       {},
}

func lintCommandInjection(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("commandInjection")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	var result []lsp.Diagnostic

	shadowed := namesBoundAnywhere(snapshot.Program.Statements)
	forEachBuiltinCall(snapshot.Program.Statements, shadowed,
		func(name string, _ mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if interpreter, isArgvSink := commandArgvSinks[name]; isArgvSink {
				if diagnostic, found := argvInjectionDiagnostic(
					snapshot, call, bindings, shadowed, name, interpreter, severity, &source); found {
					result = append(result, diagnostic)
				}
				return
			}

			sink, isSink := commandSinks[name]
			if !isSink {
				return
			}
			argument := argumentAt(call, sink.index)
			if argument == nil {
				return
			}

			spliced, how, found := splicedValue(resolveOneHop(argument, bindings))
			if !found {
				return
			}
			if isSanitized(spliced, bindings, shadowed) {
				return
			}

			rng, ok := snapshot.Program.RangeOf(spliced)
			if !ok {
				return
			}

			result = append(result, lsp.Diagnostic{
				Range:    snapshot.Range(rng),
				Severity: severity,
				Source:   &source,
				Message: fmt.Sprintf(
					"This value is %s the command `%s` gives to %s. The interpreter parses the finished string, so whatever is here is syntax and not an argument: a space adds a word, and `;`, `|`, `&&` or `$(...)` start a command of their own. Build the command from fixed text only -- with `cmd_builder` and one `cmd_add` per fixed line -- and if a value genuinely has to reach the command, check it against a list of the values you allow first.",
					how, name, sink.interpreter),
			})
		})

	return result
}

// argvInjectionDiagnostic reports a value spliced into an argv element that an
// interpreter is going to parse, and reports nothing else.
//
// exec_argv hands a program its arguments directly, so an element is one
// argument whatever it holds, and a value spliced into one is ordinarily
// nothing to report -- that is the reason the builtin exists. It stops being
// nothing when an earlier element is a flag telling the program to read a
// command from the next one, because from there the element is syntax again.
//
// So this looks at the flags and not at argv[0]. exec_string gives any bare
// name the command with -c now, so there is no closed set of shells left to
// recognise, and a program nobody here has heard of, given -c, parses its
// argument exactly as bash does.
func argvInjectionDiagnostic(
	snapshot *Snapshot,
	call *mast.CallExpression,
	bindings map[string]mast.Expression,
	shadowed map[string]struct{},
	name string,
	interpreter string,
	severity *lsp.DiagnosticSeverity,
	source *string,
) (lsp.Diagnostic, bool) {
	argument := argumentAt(call, 0)
	if argument == nil {
		return lsp.Diagnostic{}, false
	}
	array, isArray := resolveOneHop(argument, bindings).(*mast.ArrayLiteral)
	if !isArray || array == nil {
		return lsp.Diagnostic{}, false
	}

	flag := ""
	for _, element := range array.Elements {
		if element == nil {
			continue
		}
		resolved := resolveOneHop(element, bindings)

		if flag == "" {
			text, fixed := literalString(resolved)
			if !fixed {
				continue
			}
			if _, introduces := commandIntroducingFlags[strings.ToLower(strings.TrimSpace(text))]; introduces {
				flag = strings.TrimSpace(text)
			}
			continue
		}

		spliced, how, found := splicedValue(resolved)
		if !found || isSanitized(spliced, bindings, shadowed) {
			continue
		}
		rng, hasRange := snapshot.Program.RangeOf(spliced)
		if !hasRange {
			continue
		}

		return lsp.Diagnostic{
			Range:    snapshot.Range(rng),
			Severity: severity,
			Source:   source,
			Message: fmt.Sprintf(
				"This value is %s a command `%s` gives to %s, because an earlier element of the argv is `%s`, which tells it to read a command from the next one. From there the value is syntax and not an argument: a space adds a word, and `;`, `|`, `&&` or `$(...)` start a command of their own. Give the value its own argv element so the program receives it as one argument, and if it genuinely has to reach a command, check it against a list of the values you allow first.",
				how, name, interpreter, flag),
		}, true
	}

	return lsp.Diagnostic{}, false
}

// splicedValue finds the first piece of a command string that is not fixed
// text, and says how it got there.
//
// A template whose every hole is a string literal, or a concatenation of
// literals, is a constant that happens to be written in pieces: there is
// nothing in it the author did not put there, so there is nothing to report.
func splicedValue(expr mast.Expression) (spliced mast.Expression, how string, found bool) {
	switch node := expr.(type) {
	case *mast.TemplateLiteral:
		if node == nil {
			return nil, "", false
		}
		for _, part := range node.Parts {
			if part == nil {
				continue
			}
			if _, fixed := literalString(part); fixed {
				continue
			}
			return part, "interpolated into", true
		}

	case *mast.InfixExpression:
		if node == nil || node.Operator != "+" {
			return nil, "", false
		}
		for _, side := range []mast.Expression{node.Left, node.Right} {
			if side == nil {
				continue
			}
			if _, fixed := literalString(side); fixed {
				continue
			}
			// A nested `+` is the rest of the same chain; anything else is
			// the spliced value itself.
			if inner, innerHow, ok := splicedValue(side); ok {
				return inner, innerHow, true
			}
			if nested, isInfix := side.(*mast.InfixExpression); isInfix && nested != nil && nested.Operator == "+" {
				continue
			}
			return side, "concatenated into", true
		}
	}

	return nil, "", false
}

// isSanitized reports whether a spliced value has been through a builtin that
// makes it safe to put inside a command string -- written in the splice itself,
// or bound once to a name in the same scope.
func isSanitized(expr mast.Expression, bindings map[string]mast.Expression, shadowed map[string]struct{}) bool {
	call, ok := resolveOneHop(expr, bindings).(*mast.CallExpression)
	if !ok || call == nil {
		return false
	}
	name, _, ok := builtinCallee(call.Function, func(candidate string) bool {
		_, taken := shadowed[candidate]
		return taken
	})
	if !ok {
		return false
	}
	if _, sanitizer := commandSanitizers[name]; !sanitizer {
		return false
	}
	return isLiveBuiltin(name)
}
