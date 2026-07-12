package webrepl

import (
	"errors"
	"fmt"
	"mutant/ast"
	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
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
	env *object.Environment
}

type webBuiltin func(args ...object.Object) object.Object

var webBuiltins = map[string]webBuiltin{
	"len":           webLen,
	"first":         webFirst,
	"last":          webLast,
	"rest":          webRest,
	"push":          webPush,
	"text_contains": webTextContains,
	"text_index":    webTextIndex,
	"text_count":    webTextCount,
	"text_split":    webTextSplit,
	"text_replace":  webTextReplace,
}

func New() *REPL {
	return &REPL{env: object.NewEnvironment()}
}

func (r *REPL) Eval(input string) (string, error) {
	l := lexer.New(input)
	p := parser.New(l)
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "\n"))
	}

	result := evalNode(program, r.env)
	if result == nil {
		return "", nil
	}
	if errObj, ok := result.(*object.Error); ok {
		return "", errors.New(errObj.Inspect())
	}
	if _, isNull := result.(*object.Null); isNull {
		return "", nil
	}

	return result.Inspect(), nil
}

func evalNode(node ast.Node, env *object.Environment) object.Object {
	switch n := node.(type) {
	case *ast.Program:
		return evalProgram(n, env)
	case *ast.ExpressionStatement:
		return evalNode(n.Expression, env)
	case *ast.LetStatement:
		value := evalNode(n.Value, env)
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
			return evalNode(n.ReturnValue, env)
		}
		if len(n.ReturnValues) > 0 {
			vals := make([]object.Object, 0, len(n.ReturnValues))
			for _, expr := range n.ReturnValues {
				v := evalNode(expr, env)
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
		return evalBlock(n, env)
	case *ast.IntegerLiteral:
		return &object.Integer{Value: n.Value}
	case *ast.Boolean:
		return nativeBool(n.Value)
	case *ast.StringLiteral:
		return &object.String{Value: n.Value}
	case *ast.ArrayLiteral:
		elements := evalExpressions(n.Elements, env)
		if len(elements) == 1 && isError(elements[0]) {
			return elements[0]
		}
		return &object.Array{Elements: elements}
	case *ast.HashLiteral:
		return evalHash(n, env)
	case *ast.IndexExpression:
		left := evalNode(n.Left, env)
		if isError(left) {
			return left
		}
		index := evalNode(n.Index, env)
		if isError(index) {
			return index
		}
		return evalIndex(left, index)
	case *ast.CallExpression:
		return evalCall(n, env)
	case *ast.Identifier:
		if val, ok := env.Get(n.Value); ok {
			return val
		}
		if _, ok := webBuiltins[n.Value]; ok {
			return &object.String{Value: n.Value}
		}
		return newError("identifier not found: %s", n.Value)
	case *ast.PrefixExpression:
		right := evalNode(n.Right, env)
		if isError(right) {
			return right
		}
		return evalPrefix(n.Operator, right)
	case *ast.InfixExpression:
		left := evalNode(n.Left, env)
		if isError(left) {
			return left
		}
		right := evalNode(n.Right, env)
		if isError(right) {
			return right
		}
		return evalInfix(n.Operator, left, right)
	case *ast.IfExpression:
		return evalIf(n, env)
	default:
		return newError("unsupported syntax in browser REPL: %T", node)
	}
}

func evalProgram(program *ast.Program, env *object.Environment) object.Object {
	var result object.Object = nullObj
	for _, stmt := range program.Statements {
		result = evalNode(stmt, env)
		if isError(result) {
			return result
		}
	}
	return result
}

func evalBlock(block *ast.BlockStatement, env *object.Environment) object.Object {
	var result object.Object = nullObj
	for _, stmt := range block.Statements {
		result = evalNode(stmt, env)
		if isError(result) {
			return result
		}
	}
	return result
}

func evalIf(exp *ast.IfExpression, env *object.Environment) object.Object {
	condition := evalNode(exp.Condition, env)
	if isError(condition) {
		return condition
	}
	if isTruthy(condition) {
		return evalNode(exp.Consequence, env)
	}
	if exp.Alternative != nil {
		return evalNode(exp.Alternative, env)
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

func evalExpressions(expressions []ast.Expression, env *object.Environment) []object.Object {
	out := make([]object.Object, 0, len(expressions))
	for _, expression := range expressions {
		evaluated := evalNode(expression, env)
		if isError(evaluated) {
			return []object.Object{evaluated}
		}
		out = append(out, evaluated)
	}
	return out
}

func evalHash(hash *ast.HashLiteral, env *object.Environment) object.Object {
	pairs := make(map[object.HashKey]object.HashPair)
	for keyNode, valueNode := range hash.Pairs {
		keyObj := evalNode(keyNode, env)
		if isError(keyObj) {
			return keyObj
		}
		hashable, ok := keyObj.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", keyObj.Type())
		}
		valueObj := evalNode(valueNode, env)
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

func evalCall(call *ast.CallExpression, env *object.Environment) object.Object {
	ident, ok := call.Function.(*ast.Identifier)
	if !ok {
		return newError("unsupported call target in browser REPL")
	}
	builtinFn, ok := webBuiltins[ident.Value]
	if !ok {
		return newError("unknown function: %s", ident.Value)
	}
	args := evalExpressions(call.Arguments, env)
	if len(args) == 1 && isError(args[0]) {
		return args[0]
	}
	return builtinFn(args...)
}

func webLen(args ...object.Object) object.Object {
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

func webFirst(args ...object.Object) object.Object {
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

func webLast(args ...object.Object) object.Object {
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

func webRest(args ...object.Object) object.Object {
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

func webPush(args ...object.Object) object.Object {
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

func webTextContains(args ...object.Object) object.Object {
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

func webTextIndex(args ...object.Object) object.Object {
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

func webTextCount(args ...object.Object) object.Object {
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

func webTextSplit(args ...object.Object) object.Object {
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

func webTextReplace(args ...object.Object) object.Object {
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
		"builtins: len, first, last, rest, push, text_* core set",
		"return statements",
	}, ", ")
}

// ParseInt helper for lightweight client bridges.
func ParseInt(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
