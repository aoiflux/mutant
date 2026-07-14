package webrepl

import (
	"errors"
	"fmt"
	"mutant/ast"
	"mutant/builtin"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
	"sort"
	"strconv"
	"strings"
)

var (
	trueObj  = &object.Boolean{Value: true}
	falseObj = &object.Boolean{Value: false}
	nullObj  = &object.Null{}
)

// REPL is a lightweight browser-safe evaluator used for js/wasm builds.
// It intentionally supports a focused subset of Mutant syntax.
type REPL struct {
	env    *object.Environment
	output strings.Builder
}

type webBuiltin func(repl *REPL, args ...object.Object) object.Object

var webSupportedBuiltinNames = []string{
	"help",
	"len",
	"first",
	"last",
	"rest",
	"push",
	"pop",
	"putf",
	"putln",
	"json_parse",
	"json_stringify",
	"bytes_len",
	"bytes_get",
	"bytes_slice",
	"bytes_read_u16_le",
	"bytes_read_u16_be",
	"bytes_read_u32_le",
	"bytes_read_u32_be",
	"bytes_read_u64_le",
	"bytes_read_u64_be",
	"bytes_write_u16_le",
	"bytes_write_u16_be",
	"bytes_write_u32_le",
	"bytes_write_u32_be",
	"bytes_write_u64_le",
	"bytes_write_u64_be",
	"bytes_cstr_at",
	"bytes_hex",
	"bytes_char_from_int",
	"bytes_int_from_char",
	"bytes_cursor_new",
	"bytes_cursor_tell",
	"bytes_cursor_seek",
	"bytes_cursor_eof",
	"bytes_cursor_read_u8",
	"bytes_cursor_read_u16_le",
	"bytes_cursor_read_u16_be",
	"bytes_cursor_read_u32_le",
	"bytes_cursor_read_u32_be",
	"bytes_cursor_read_u64_le",
	"bytes_cursor_read_u64_be",
	"regex_match",
	"regex_find",
	"regex_find_all",
	"regex_replace",
	"regex_capture_groups",
	"text_contains",
	"text_index",
	"text_count",
	"text_split",
	"text_replace",
	"text_levenshtein",
	"text_similarity",
	"text_fuzzy_find",
	"text_jaro_winkler",
}

var webBuiltins = map[string]webBuiltin{
	"help":                     webHelp,
	"len":                      webLen,
	"first":                    webFirst,
	"last":                     webLast,
	"rest":                     webRest,
	"push":                     webPush,
	"pop":                      webPop,
	"putf":                     webPutf,
	"putln":                    webPutln,
	"json_parse":               webJsonParse,
	"json_stringify":           webJsonStringify,
	"bytes_len":                webBytesLen,
	"bytes_get":                webBytesGet,
	"bytes_slice":              webBytesSlice,
	"bytes_read_u16_le":        webBytesReadU16LE,
	"bytes_read_u16_be":        webBytesReadU16BE,
	"bytes_read_u32_le":        webBytesReadU32LE,
	"bytes_read_u32_be":        webBytesReadU32BE,
	"bytes_read_u64_le":        webBytesReadU64LE,
	"bytes_read_u64_be":        webBytesReadU64BE,
	"bytes_write_u16_le":       webBytesWriteU16LE,
	"bytes_write_u16_be":       webBytesWriteU16BE,
	"bytes_write_u32_le":       webBytesWriteU32LE,
	"bytes_write_u32_be":       webBytesWriteU32BE,
	"bytes_write_u64_le":       webBytesWriteU64LE,
	"bytes_write_u64_be":       webBytesWriteU64BE,
	"bytes_cstr_at":            webBytesCStrAt,
	"bytes_hex":                webBytesHex,
	"bytes_char_from_int":      webBytesCharFromInt,
	"bytes_int_from_char":      webBytesIntFromChar,
	"bytes_cursor_new":         webBytesCursorNew,
	"bytes_cursor_tell":        webBytesCursorTell,
	"bytes_cursor_seek":        webBytesCursorSeek,
	"bytes_cursor_eof":         webBytesCursorEOF,
	"bytes_cursor_read_u8":     webBytesCursorReadU8,
	"bytes_cursor_read_u16_le": webBytesCursorReadU16LE,
	"bytes_cursor_read_u16_be": webBytesCursorReadU16BE,
	"bytes_cursor_read_u32_le": webBytesCursorReadU32LE,
	"bytes_cursor_read_u32_be": webBytesCursorReadU32BE,
	"bytes_cursor_read_u64_le": webBytesCursorReadU64LE,
	"bytes_cursor_read_u64_be": webBytesCursorReadU64BE,
	"regex_match":              webRegexMatch,
	"regex_find":               webRegexFind,
	"regex_find_all":           webRegexFindAll,
	"regex_replace":            webRegexReplace,
	"regex_capture_groups":     webRegexCaptureGroups,
	"text_contains":            webTextContains,
	"text_index":               webTextIndex,
	"text_count":               webTextCount,
	"text_split":               webTextSplit,
	"text_replace":             webTextReplace,
	"text_levenshtein":         webTextLevenshtein,
	"text_similarity":          webTextSimilarity,
	"text_fuzzy_find":          webTextFuzzyFind,
	"text_jaro_winkler":        webTextJaroWinkler,
}

func New() *REPL {
	return &REPL{env: object.NewEnvironment()}
}

func (r *REPL) Eval(input string) (string, error) {
	r.output.Reset()

	if helpOutput, handled := r.handleMetaHelp(input); handled {
		return helpOutput, nil
	}

	l := lexer.New(input)
	p := parser.New(l)
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "\n"))
	}

	result := evalNode(r, program, r.env)
	if result == nil {
		return "", nil
	}
	if errObj, ok := result.(*object.Error); ok {
		return "", errors.New(errObj.Inspect())
	}
	if _, isNull := result.(*object.Null); isNull {
		return strings.TrimRight(r.output.String(), "\n"), nil
	}
	if r.output.Len() == 0 {
		return result.Inspect(), nil
	}

	return r.output.String() + result.Inspect(), nil
}

func (r *REPL) CompletionCandidates(prefix string, mode string) []string {
	return builtin.ReplCompletionCandidates(prefix, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: webBuiltinsSet(),
		Symbols:           r.env.Keys(),
	})
}

func (r *REPL) CompletionCandidatesForLine(line string, mode string) []string {
	return builtin.ReplCompletionCandidatesForLine(line, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: webBuiltinsSet(),
		Symbols:           r.env.Keys(),
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
		SupportedBuiltins: webBuiltinsSet(),
	}), true
}

func evalNode(repl *REPL, node ast.Node, env *object.Environment) object.Object {
	switch n := node.(type) {
	case *ast.Program:
		return evalProgram(repl, n, env)
	case *ast.ExpressionStatement:
		return evalNode(repl, n.Expression, env)
	case *ast.LetStatement:
		value := evalNode(repl, n.Value, env)
		if isError(value) {
			return value
		}
		names := n.Names
		if len(names) == 0 && n.Name != nil {
			names = []*ast.Identifier{n.Name}
		}
		if len(names) <= 1 {
			if n.Name != nil {
				env.Set(n.Name.Value, value)
			}
			return nullObj
		}
		values := destructureValues(value, len(names))
		for i, ident := range names {
			if ident == nil {
				continue
			}
			env.Set(ident.Value, values[i])
		}
		return nullObj
	case *ast.ReturnStatement:
		if n.ReturnValue != nil {
			return evalNode(repl, n.ReturnValue, env)
		}
		if len(n.ReturnValues) > 0 {
			vals := make([]object.Object, 0, len(n.ReturnValues))
			for _, expr := range n.ReturnValues {
				v := evalNode(repl, expr, env)
				if isError(v) {
					return v
				}
				vals = append(vals, v)
			}
			if len(vals) == 0 {
				return nullObj
			}
			if len(vals) == 1 {
				return vals[0]
			}
			return &object.MultiValue{Values: vals}
		}
		return nullObj
	case *ast.BlockStatement:
		return evalBlock(repl, n, env)
	case *ast.IntegerLiteral:
		return &object.Integer{Value: n.Value}
	case *ast.Boolean:
		return nativeBool(n.Value)
	case *ast.StringLiteral:
		return &object.String{Value: n.Value}
	case *ast.ArrayLiteral:
		elements := evalExpressions(repl, n.Elements, env)
		if len(elements) == 1 && isError(elements[0]) {
			return elements[0]
		}
		return &object.Array{Elements: elements}
	case *ast.HashLiteral:
		return evalHash(repl, n, env)
	case *ast.IndexExpression:
		left := evalNode(repl, n.Left, env)
		if isError(left) {
			return left
		}
		index := evalNode(repl, n.Index, env)
		if isError(index) {
			return index
		}
		return evalIndex(left, index)
	case *ast.CallExpression:
		return evalCall(repl, n, env)
	case *ast.Identifier:
		if val, ok := env.Get(n.Value); ok {
			return val
		}
		if _, ok := webBuiltins[n.Value]; ok {
			return &object.String{Value: n.Value}
		}
		return newError("identifier not found: %s", n.Value)
	case *ast.PrefixExpression:
		right := evalNode(repl, n.Right, env)
		if isError(right) {
			return right
		}
		return evalPrefix(n.Operator, right)
	case *ast.InfixExpression:
		left := evalNode(repl, n.Left, env)
		if isError(left) {
			return left
		}
		right := evalNode(repl, n.Right, env)
		if isError(right) {
			return right
		}
		return evalInfix(n.Operator, left, right)
	case *ast.IfExpression:
		return evalIf(repl, n, env)
	default:
		return newError("unsupported syntax in browser REPL: %T", node)
	}
}

func evalProgram(repl *REPL, program *ast.Program, env *object.Environment) object.Object {
	var result object.Object = nullObj
	for _, stmt := range program.Statements {
		result = evalNode(repl, stmt, env)
		if isError(result) {
			return result
		}
	}
	return result
}

func evalBlock(repl *REPL, block *ast.BlockStatement, env *object.Environment) object.Object {
	var result object.Object = nullObj
	for _, stmt := range block.Statements {
		result = evalNode(repl, stmt, env)
		if isError(result) {
			return result
		}
	}
	return result
}

func evalIf(repl *REPL, exp *ast.IfExpression, env *object.Environment) object.Object {
	condition := evalNode(repl, exp.Condition, env)
	if isError(condition) {
		return condition
	}
	if isTruthy(condition) {
		return evalNode(repl, exp.Consequence, env)
	}
	if exp.Alternative != nil {
		return evalNode(repl, exp.Alternative, env)
	}
	return nullObj
}

func evalPrefix(op string, right object.Object) object.Object {
	switch op {
	case "!":
		return nativeBool(!isTruthy(right))
	case "-":
		intObj, ok := right.(*object.Integer)
		if !ok {
			return newError("unknown operator: -%s", right.Type())
		}
		return &object.Integer{Value: -intObj.Value}
	default:
		return newError("unknown operator: %s%s", op, right.Type())
	}
}

func evalInfix(op string, left, right object.Object) object.Object {
	switch {
	case left.Type() == object.INTEGER_OBJ && right.Type() == object.INTEGER_OBJ:
		return evalIntInfix(op, left.(*object.Integer).Value, right.(*object.Integer).Value)
	case left.Type() == object.STRING_OBJ && right.Type() == object.STRING_OBJ:
		if op == "+" {
			return &object.String{Value: left.(*object.String).Value + right.(*object.String).Value}
		}
		if op == "==" {
			return nativeBool(left.(*object.String).Value == right.(*object.String).Value)
		}
		if op == "!=" {
			return nativeBool(left.(*object.String).Value != right.(*object.String).Value)
		}
		return newError("unknown operator: %s %s %s", left.Type(), op, right.Type())
	case op == "==":
		return nativeBool(left.Inspect() == right.Inspect())
	case op == "!=":
		return nativeBool(left.Inspect() != right.Inspect())
	case left.Type() != right.Type():
		return newError("type mismatch: %s %s %s", left.Type(), op, right.Type())
	default:
		return newError("unknown operator: %s %s %s", left.Type(), op, right.Type())
	}
}

func evalIntInfix(op string, left, right int64) object.Object {
	switch op {
	case "+":
		return &object.Integer{Value: left + right}
	case "-":
		return &object.Integer{Value: left - right}
	case "*":
		return &object.Integer{Value: left * right}
	case "/":
		if right == 0 {
			return newError("division by zero")
		}
		return &object.Integer{Value: left / right}
	case "<":
		return nativeBool(left < right)
	case ">":
		return nativeBool(left > right)
	case "==":
		return nativeBool(left == right)
	case "!=":
		return nativeBool(left != right)
	default:
		return newError("unknown operator: INTEGER %s INTEGER", op)
	}
}

func evalExpressions(repl *REPL, expressions []ast.Expression, env *object.Environment) []object.Object {
	out := make([]object.Object, 0, len(expressions))
	for _, expression := range expressions {
		evaluated := evalNode(repl, expression, env)
		if isError(evaluated) {
			return []object.Object{evaluated}
		}
		out = append(out, evaluated)
	}
	return out
}

func evalHash(repl *REPL, hash *ast.HashLiteral, env *object.Environment) object.Object {
	pairs := make(map[object.HashKey]object.HashPair)
	for keyNode, valueNode := range hash.Pairs {
		keyObj := evalNode(repl, keyNode, env)
		if isError(keyObj) {
			return keyObj
		}
		hashable, ok := keyObj.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", keyObj.Type())
		}
		valueObj := evalNode(repl, valueNode, env)
		if isError(valueObj) {
			return valueObj
		}
		hashed := hashable.HashKey()
		pairs[hashed] = object.HashPair{Key: keyObj, Value: valueObj}
	}
	return &object.Hash{Pairs: pairs}
}

func evalIndex(left, index object.Object) object.Object {
	switch {
	case left.Type() == object.ARRAY_OBJ && index.Type() == object.INTEGER_OBJ:
		arr := left.(*object.Array)
		i := index.(*object.Integer).Value
		if i < 0 || i >= int64(len(arr.Elements)) {
			return nullObj
		}
		return arr.Elements[i]
	case left.Type() == object.HASH_OBJ:
		hashObj := left.(*object.Hash)
		hashKey, ok := index.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", index.Type())
		}
		pair, ok := hashObj.Pairs[hashKey.HashKey()]
		if !ok {
			return nullObj
		}
		return pair.Value
	default:
		return newError("index operator not supported: %s[%s]", left.Type(), index.Type())
	}
}

func evalCall(repl *REPL, call *ast.CallExpression, env *object.Environment) object.Object {
	ident, ok := call.Function.(*ast.Identifier)
	if !ok {
		return newError("unsupported call target in browser REPL")
	}

	if ident.Value == "help" {
		args := evalExpressions(repl, call.Arguments, env)
		if len(args) == 1 && isError(args[0]) {
			return args[0]
		}
		return webHelp(repl, args...)
	}

	builtinFn, ok := webBuiltins[ident.Value]
	if !ok {
		return newError("unknown function: %s", ident.Value)
	}
	args := evalExpressions(repl, call.Arguments, env)
	if len(args) == 1 && isError(args[0]) {
		return args[0]
	}
	return builtinFn(repl, args...)
}

func webLen(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	switch value := args[0].(type) {
	case *object.String:
		return &object.Integer{Value: int64(len(value.Value))}
	case *object.Array:
		return &object.Integer{Value: int64(len(value.Elements))}
	default:
		return newError("argument to len not supported, got %s", args[0].Type())
	}
}

func webFirst(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument to first must be ARRAY, got %s", args[0].Type())
	}
	if len(arr.Elements) == 0 {
		return nullObj
	}
	return arr.Elements[0]
}

func webLast(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument to last must be ARRAY, got %s", args[0].Type())
	}
	if len(arr.Elements) == 0 {
		return nullObj
	}
	return arr.Elements[len(arr.Elements)-1]
}

func webRest(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument to rest must be ARRAY, got %s", args[0].Type())
	}
	if len(arr.Elements) <= 1 {
		return nullObj
	}
	newElements := make([]object.Object, len(arr.Elements)-1)
	copy(newElements, arr.Elements[1:])
	return &object.Array{Elements: newElements}
}

func webPush(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	arr, ok := args[0].(*object.Array)
	if !ok {
		return newError("argument 1 to push must be ARRAY, got %s", args[0].Type())
	}
	newElements := make([]object.Object, len(arr.Elements)+1)
	copy(newElements, arr.Elements)
	newElements[len(arr.Elements)] = args[1]
	return &object.Array{Elements: newElements}
}

func webPop(_ *REPL, args ...object.Object) object.Object {
	return builtin.Pop(args...)
}

func webTextContains(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	haystack, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to text_contains must be STRING, got %s", args[0].Type())
	}
	needle, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to text_contains must be STRING, got %s", args[1].Type())
	}
	return nativeBool(strings.Contains(haystack.Value, needle.Value))
}

func webTextIndex(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	haystack, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to text_index must be STRING, got %s", args[0].Type())
	}
	needle, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to text_index must be STRING, got %s", args[1].Type())
	}
	return &object.Integer{Value: int64(strings.Index(haystack.Value, needle.Value))}
}

func webTextCount(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	haystack, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to text_count must be STRING, got %s", args[0].Type())
	}
	needle, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to text_count must be STRING, got %s", args[1].Type())
	}
	return &object.Integer{Value: int64(strings.Count(haystack.Value, needle.Value))}
}

func webTextSplit(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	value, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to text_split must be STRING, got %s", args[0].Type())
	}
	sep, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to text_split must be STRING, got %s", args[1].Type())
	}
	parts := strings.Split(value.Value, sep.Value)
	out := make([]object.Object, len(parts))
	for i, part := range parts {
		out[i] = &object.String{Value: part}
	}
	return &object.Array{Elements: out}
}

func webTextReplace(_ *REPL, args ...object.Object) object.Object {
	if len(args) != 3 {
		return newError("wrong number of arguments. got=%d, want=3", len(args))
	}
	value, ok := args[0].(*object.String)
	if !ok {
		return newError("argument 1 to text_replace must be STRING, got %s", args[0].Type())
	}
	oldPart, ok := args[1].(*object.String)
	if !ok {
		return newError("argument 2 to text_replace must be STRING, got %s", args[1].Type())
	}
	newPart, ok := args[2].(*object.String)
	if !ok {
		return newError("argument 3 to text_replace must be STRING, got %s", args[2].Type())
	}
	return &object.String{Value: strings.ReplaceAll(value.Value, oldPart.Value, newPart.Value)}
}

func webTextLevenshtein(_ *REPL, args ...object.Object) object.Object {
	return builtin.TextLevenshtein(args...)
}

func webTextSimilarity(_ *REPL, args ...object.Object) object.Object {
	return builtin.TextSimilarity(args...)
}

func webTextFuzzyFind(_ *REPL, args ...object.Object) object.Object {
	return builtin.TextFuzzyFind(args...)
}

func webTextJaroWinkler(_ *REPL, args ...object.Object) object.Object {
	return builtin.TextJaroWinkler(args...)
}

func webJsonParse(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.JsonParse(args...))
}

func webJsonStringify(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.JsonStringify(args...))
}

func webBytesLen(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesLen(args...))
}

func webBytesGet(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesGet(args...))
}

func webBytesSlice(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesSlice(args...))
}

func webBytesReadU16LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU16LE(args...))
}

func webBytesReadU16BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU16BE(args...))
}

func webBytesReadU32LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU32LE(args...))
}

func webBytesReadU32BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU32BE(args...))
}

func webBytesReadU64LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU64LE(args...))
}

func webBytesReadU64BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesReadU64BE(args...))
}

func webBytesWriteU16LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU16LE(args...))
}

func webBytesWriteU16BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU16BE(args...))
}

func webBytesWriteU32LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU32LE(args...))
}

func webBytesWriteU32BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU32BE(args...))
}

func webBytesWriteU64LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU64LE(args...))
}

func webBytesWriteU64BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesWriteU64BE(args...))
}

func webBytesCStrAt(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCStrAt(args...))
}

func webBytesHex(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesHex(args...))
}

func webBytesCharFromInt(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCharFromInt(args...))
}

func webBytesIntFromChar(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesIntFromChar(args...))
}

func webBytesCursorNew(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorNew(args...))
}

func webBytesCursorTell(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorTell(args...))
}

func webBytesCursorSeek(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorSeek(args...))
}

func webBytesCursorEOF(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorEOF(args...))
}

func webBytesCursorReadU8(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU8(args...))
}

func webBytesCursorReadU16LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU16LE(args...))
}

func webBytesCursorReadU16BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU16BE(args...))
}

func webBytesCursorReadU32LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU32LE(args...))
}

func webBytesCursorReadU32BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU32BE(args...))
}

func webBytesCursorReadU64LE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU64LE(args...))
}

func webBytesCursorReadU64BE(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.BytesCursorReadU64BE(args...))
}

func webRegexMatch(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.RegexMatch(args...))
}

func webRegexFind(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.RegexFind(args...))
}

func webRegexFindAll(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.RegexFindAll(args...))
}

func webRegexReplace(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.RegexReplace(args...))
}

func webRegexCaptureGroups(_ *REPL, args ...object.Object) object.Object {
	return unwrapBuiltinPair(builtin.RegexCaptureGroups(args...))
}

func webHelp(_ *REPL, args ...object.Object) object.Object {
	if len(args) > 2 {
		return newError("wrong number of arguments. got=%d, want=0..2", len(args))
	}

	topic := ""
	mode := "supported"
	if len(args) >= 1 {
		topicValue, ok := args[0].(*object.String)
		if !ok {
			return newError("argument 1 to help must be STRING, got %s", args[0].Type())
		}
		topic = topicValue.Value
	}
	if len(args) == 2 {
		modeValue, ok := args[1].(*object.String)
		if !ok {
			return newError("argument 2 to help must be STRING, got %s", args[1].Type())
		}
		mode = modeValue.Value
	}

	output := builtin.RenderReplHelp(topic, builtin.ReplHelpOptions{
		Mode:              mode,
		SupportedBuiltins: webBuiltinsSet(),
	})
	return &object.String{Value: output}
}

func webPutf(repl *REPL, args ...object.Object) object.Object {
	for _, arg := range args {
		repl.output.WriteString(arg.Inspect())
	}
	return nullObj
}

func webPutln(repl *REPL, args ...object.Object) object.Object {
	line := buildPutlnLine(args)
	repl.output.WriteString(line)
	repl.output.WriteByte('\n')
	return nullObj
}

func unwrapBuiltinPair(result object.Object) object.Object {
	if result == nil {
		return nullObj
	}

	multi, ok := result.(*object.MultiValue)
	if !ok {
		return result
	}

	if len(multi.Values) == 0 || multi.Values[0] == nil {
		return nullObj
	}
	if len(multi.Values) > 1 && multi.Values[1] != nil {
		if errObj, ok := multi.Values[1].(*object.Error); ok {
			return errObj
		}
	}

	return multi.Values[0]
}

func destructureValues(value object.Object, want int) []object.Object {
	result := make([]object.Object, want)
	for i := range result {
		result[i] = nullObj
	}
	if value == nil {
		return result
	}
	if multi, ok := value.(*object.MultiValue); ok {
		for i := 0; i < want && i < len(multi.Values); i++ {
			if multi.Values[i] != nil {
				result[i] = multi.Values[i]
			}
		}
		return result
	}
	result[0] = value
	return result
}

func isTruthy(obj object.Object) bool {
	switch v := obj.(type) {
	case *object.Boolean:
		return v.Value
	case *object.Null:
		return false
	case *object.Integer:
		return v.Value != 0
	case *object.String:
		return strings.TrimSpace(v.Value) != ""
	default:
		return obj != nil
	}
}

func isError(obj object.Object) bool {
	if obj == nil {
		return false
	}
	return obj.Type() == object.ERROR_OBJ
}

func nativeBool(v bool) *object.Boolean {
	if v {
		return trueObj
	}
	return falseObj
}

func newError(format string, args ...any) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, args...), Context: "webrepl"}
}

func buildPutlnLine(args []object.Object) string {
	var b strings.Builder
	for i, arg := range args {
		part := arg.Inspect()
		if i == 0 {
			b.WriteString(part)
			continue
		}

		if shouldInsertSpaceBefore(part, b.String()) {
			b.WriteByte(' ')
		}
		b.WriteString(part)
	}
	return b.String()
}

func shouldInsertSpaceBefore(next, current string) bool {
	if strings.TrimSpace(next) == "" || current == "" {
		return false
	}

	trimmedNext := strings.TrimLeft(next, " \t")
	if trimmedNext == "" {
		return false
	}

	if strings.HasPrefix(trimmedNext, ",") ||
		strings.HasPrefix(trimmedNext, ".") ||
		strings.HasPrefix(trimmedNext, ";") ||
		strings.HasPrefix(trimmedNext, ":") ||
		strings.HasPrefix(trimmedNext, ")") ||
		strings.HasPrefix(trimmedNext, "]") ||
		strings.HasPrefix(trimmedNext, "}") {
		return false
	}

	trimmedCurrent := strings.TrimRight(current, " \t")
	if trimmedCurrent == "" {
		return false
	}

	if strings.HasSuffix(trimmedCurrent, "=") ||
		strings.HasSuffix(trimmedCurrent, "(") ||
		strings.HasSuffix(trimmedCurrent, "[") ||
		strings.HasSuffix(trimmedCurrent, "{") {
		return false
	}

	return true
}

func trimCommandLine(line string) string {
	trimmed := strings.TrimSpace(line)
	for strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	}
	return trimmed
}

func webBuiltinsSet() map[string]struct{} {
	set := make(map[string]struct{}, len(webSupportedBuiltinNames))
	for _, name := range webSupportedBuiltinNames {
		set[name] = struct{}{}
	}
	return set
}

func SupportedBuiltinNames() []string {
	names := make([]string, len(webSupportedBuiltinNames))
	copy(names, webSupportedBuiltinNames)
	sort.Strings(names)
	return names
}

// SupportedSyntaxSummary returns a short summary for browser clients.
func SupportedSyntaxSummary() string {
	return strings.Join([]string{
		"integers, booleans, strings",
		"arrays, hashes, indexing",
		"let bindings and identifiers",
		"function calls for browser-safe builtins",
		"if/else expressions",
		"prefix ! and -",
		"infix + - * / < > == !=",
		"builtins: len, first, last, rest, push, pop, putf, putln, bytes_* core (read/write + cursor), json_*, regex_*, text_* core set",
		"return statements",
	}, ", ")
}

// ParseInt helper for lightweight client bridges.
func ParseInt(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
