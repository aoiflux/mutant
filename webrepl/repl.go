// Package webrepl hosts the browser (js/wasm) REPL session.
//
// It runs the SAME compiler and VM the CLI runs. It used to be a third,
// hand-written tree-walking interpreter -- roughly 1,300 lines with its own
// evalInfix/evalIndex/evalForStatement and its own copies of len/first/push --
// which meant every language feature had to be implemented three times and the
// browser silently disagreed with the CLI: macros were unsupported, (value,
// err) pairs were flattened into runtime failures, `a[i] = v` and string
// indexing did not work, and struct literals were never validated.
//
// Sharing the real pipeline (parse -> expand macros -> compile -> encrypt ->
// VM) removes that whole class of divergence: what the browser does is what
// `mutant` does, because it is the same code.
package webrepl

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"mutant/ast"
	"mutant/builtin"
	"mutant/compiler"
	"mutant/evaluator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/vm"
)

// replPassword keys the in-memory bytecode/VM encryption. It never touches
// disk; any consistent value works, exactly as the CLI REPL and net_serve do.
const replPassword = "mutant-webrepl-inproc-v1"

// REPL is one persistent browser session. Constants, globals, the symbol table
// and the macro environment carry across Eval calls so bindings entered on one
// line are visible on the next -- the same state-threading the CLI REPL does.
type REPL struct {
	constants   []object.Object
	globals     []object.Object
	symbolTable *compiler.SymbolTable
	macroEnv    *object.Environment

	// Struct and enum declarations accumulate across lines: each Eval compiles
	// on its own, so a type declared earlier has to be handed back to the
	// compiler or it reads as undefined on the next line.
	structDefs map[string][]*ast.Identifier
	enumDefs   map[string][]string
}

func New() *REPL {
	symbolTable := compiler.NewSymbolTable()
	// Define only browser-safe builtins. A host-bound name is then simply not a
	// symbol, so calling it fails at compile time with "undefined variable"
	// rather than reaching a filesystem or socket that does not exist in a
	// browser. Indexes stay the true builtin.Builtins indexes, which is what
	// OpGetBuiltin resolves against.
	for i, b := range builtin.Builtins {
		if BrowserSafe(b.Name) {
			symbolTable.DefineBuiltin(i, b.Name)
		}
	}

	return &REPL{
		constants:   []object.Object{},
		globals:     make([]object.Object, global.GlobalSize),
		symbolTable: symbolTable,
		macroEnv:    object.NewEnvironment(),
		structDefs:  make(map[string][]*ast.Identifier),
		enumDefs:    make(map[string][]string),
	}
}

// Eval compiles and runs one line in the session, returning whatever the
// program printed plus the value of its final expression.
func (r *REPL) Eval(input string) (string, error) {
	if helpOutput, handled := r.handleMetaHelp(input); handled {
		return helpOutput, nil
	}

	p := parser.New(lexer.New(input))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "\n"))
	}

	// Macros expand before compilation, exactly as the CLI pipeline does, so
	// quote/unquote work in the browser instead of being unsupported.
	evaluator.DefineMacros(program, r.macroEnv)
	expanded := evaluator.ExpandMacros(program, r.macroEnv)

	comp := compiler.NewWithState(r.symbolTable, r.constants)
	comp.SeedTypeDefinitions(r.structDefs, r.enumDefs)
	if err := comp.Compile(expanded); err != nil {
		return "", err
	}

	byteCode := mutil.EncryptByteCode(comp.ByteCode(), replPassword)
	r.constants = byteCode.Constants
	for name, fields := range byteCode.StructDefs {
		r.structDefs[name] = fields
	}
	for name, variants := range byteCode.EnumDefs {
		r.enumDefs[name] = variants
	}

	// putln/putf print through builtin.Output(); capture that so the browser
	// gets the text back as a string rather than losing it to the wasm console.
	var printed bytes.Buffer
	restoreOutput := builtin.SetOutput(&printed)
	machine := vm.NewWithGlobalStoreAndPassword(byteCode, r.globals, replPassword)
	runErr := machine.Run()
	restoreOutput()

	// Keep globals even on failure so a later line still sees earlier bindings.
	r.globals = machine.GlobalStore()

	// Deliberately no CleanupRuntimeSensitiveData: its stack sweep zeroes
	// objects that alias the constants this session reuses on the next Eval.
	// serve.go documents the same hazard for concurrent handler VMs.

	if runErr != nil {
		return "", runErr
	}

	return renderResult(printed.String(), machine.LastPoppedStackElement(), endsWithExpression(expanded))
}

// endsWithExpression reports whether the program's last statement was an
// expression -- the only kind with a value worth echoing back. After a `for`,
// `let`, or type declaration the VM's last-popped slot still holds an interior
// value (a loop condition, say); echoing it would print a stray "false" after
// every loop.
func endsWithExpression(node ast.Node) bool {
	program, ok := node.(*ast.Program)
	if !ok || len(program.Statements) == 0 {
		return false
	}
	_, isExpression := program.Statements[len(program.Statements)-1].(*ast.ExpressionStatement)
	return isExpression
}

// renderResult joins what the program printed with the value of its last
// expression, matching how the REPL has always presented a line.
func renderResult(printed string, last object.Object, echo bool) (string, error) {
	trimmed := strings.TrimRight(printed, "\n")

	if last == nil {
		return trimmed, nil
	}
	// Surface an error even when the value would not be echoed -- a failure is
	// worth reporting wherever it happened.
	if errObj, ok := last.(*object.Error); ok {
		return "", errors.New(errObj.Inspect())
	}
	if !echo {
		return trimmed, nil
	}

	// A void multi-value (a builtin that reported no result and no error) and a
	// null both mean "nothing worth echoing"; show only what was printed.
	if multi, ok := last.(*object.MultiValue); ok && multi.IsVoid() {
		return trimmed, nil
	}
	if _, isNull := last.(*object.Null); isNull {
		return trimmed, nil
	}

	if printed == "" {
		return last.Inspect(), nil
	}
	return printed + last.Inspect(), nil
}

func (r *REPL) CompletionCandidates(prefix string, mode string) []string {
	return builtin.ReplCompletionCandidates(prefix, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: supportedBuiltinSet(),
		Symbols:           r.symbolTable.GlobalNames(),
	})
}

func (r *REPL) CompletionCandidatesForLine(line string, mode string) []string {
	return builtin.ReplCompletionCandidatesForLine(line, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: supportedBuiltinSet(),
		Symbols:           r.symbolTable.GlobalNames(),
	})
}

func (r *REPL) handleMetaHelp(input string) (string, bool) {
	trimmed := trimCommandLine(input)
	if !strings.HasPrefix(strings.ToLower(trimmed), ":help") {
		return "", false
	}

	args := strings.Fields(trimmed)
	topic := ""
	mode := ""
	if len(args) > 1 {
		topic = args[1]
	}
	if len(args) > 2 {
		mode = args[2]
	}

	return builtin.RenderReplHelp(topic, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: supportedBuiltinSet(),
	}), true
}

func trimCommandLine(line string) string {
	trimmed := strings.TrimSpace(line)
	for strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	}
	return trimmed
}

// SupportedSyntaxSummary returns a short summary for browser clients.
func SupportedSyntaxSummary() string {
	return strings.Join([]string{
		"integers, booleans, strings",
		"float literals and numeric expressions",
		"arrays, hashes, indexing",
		"let bindings and identifiers",
		"multi-value returns and (value, err) destructuring",
		"function literals and user-defined function calls",
		"closures and higher-order builtins (map/filter/reduce/each/sort_by)",
		"struct/enum declarations, struct literals, and field access",
		"for loops with init/condition/post",
		"assignment expressions",
		"compound assignment (+= -= *= /= %=) and ++/--",
		"index and field assignment (a[i] = v, s.f = v)",
		"break and continue in loops",
		"macros with quote/unquote",
		"function calls for browser-safe builtins",
		"if/else expressions",
		"prefix ! and -",
		"infix + - * / % < > <= >= == != && ||",
		"builtins: len, first, last, rest, push, pop, putf, putln, bytes_* core (read/write + cursor), json_*, regex_*, text_* core set",
		"return statements",
	}, ", ")
}

// ParseInt helper for lightweight client bridges.
func ParseInt(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
