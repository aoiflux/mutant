// Package evaluator expands macros.
//
// It contains a tree-walking interpreter because macro expansion needs one:
// expanding a macro means evaluating its body, and quote/unquote evaluates the
// unquoted expressions, both before any bytecode exists. That is now its only
// role -- no production path executes a user program through Eval. Programs are
// compiled and run on the VM in every mode, including the REPL's
// --enable-macros mode, so the language cannot behave one way here and another
// way there.
package evaluator

import (
	"mutant/ast"
	"mutant/builtin"
	"mutant/object"
)

var (
	NULL  = &object.Null{}
	TRUE  = &object.Boolean{Value: true}
	FALSE = &object.Boolean{Value: false}
)

// Eval evaluates a node and is the package boundary.
//
// The tree-walker signals "this expression cannot produce a value" with a
// fault, an unexported type that must not escape: outside this package an error
// is a value, and a caller that received a fault would have to know the
// difference to do anything with it. So the fault is unwrapped here and every
// caller sees the plain *object.Error it always did.
func Eval(n ast.Node, env *object.Environment) object.Object {
	result := eval(n, env)
	if f, raised := result.(*fault); raised {
		return f.err
	}
	return result
}

func eval(n ast.Node, env *object.Environment) object.Object {
	switch node := n.(type) {

	/// ---------- expressions ---------- ///
	case *ast.IntegerLiteral:
		return &object.Integer{Value: node.Value}

	case *ast.FloatLiteral:
		return &object.Float{Value: node.Value}

	case *ast.Boolean:
		return nativeBoolToBoolObject(node.Value)

	case *ast.PrefixExpression:
		right := eval(node.Right, env)
		if isError(right) {
			return right
		}
		return evalPrefixExpression(node.Operator, right)

	case *ast.InfixExpression:
		// Logical && / || short-circuit: the right operand is only evaluated when
		// the left operand does not already decide the result.
		if node.Operator == "&&" || node.Operator == "||" {
			return evalLogicalExpression(node, env)
		}
		left := eval(node.Left, env)
		if isError(left) {
			return left
		}
		right := eval(node.Right, env)
		if isError(right) {
			return right
		}
		return evalInfixExpression(node.Operator, left, right)

	case *ast.IfExpression:
		return evalIfExpression(node, env)

	case *ast.Identifier:
		return evalIdentifier(node, env)

	case *ast.FunctionLiteral:
		params := node.Parameters
		body := node.Body
		return &object.Function{Parameters: params, Env: env, Body: body}
	case *ast.StringLiteral:
		return &object.String{Value: node.Value}
	case *ast.CallExpression:
		if node.Function.TokenLiteral() == "quote" {
			// Arity is checked here rather than assumed: a bare `quote()` in
			// source used to index an empty argument slice and panic.
			if len(node.Arguments) != 1 {
				return newError("quote takes exactly one expression, got %d", len(node.Arguments))
			}
			return quote(node.Arguments[0], env)
		}
		function := eval(node.Function, env)
		if isError(function) {
			return function
		}
		args := evalExpressions(node.Arguments, env)
		if len(args) == 1 && isError(args[0]) {
			return args[0]
		}
		return applyFunction(function, args)
	case *ast.ArrayLiteral:
		elements := evalExpressions(node.Elements, env)
		if len(elements) == 1 && isError(elements[0]) {
			return elements[0]
		}
		return &object.Array{Elements: elements}
	case *ast.IndexExpression:
		left := eval(node.Left, env)
		if isError(left) {
			return left
		}
		index := eval(node.Index, env)
		if isError(index) {
			return index
		}
		return evalIndexExpression(left, index)
	case *ast.HashLiteral:
		return evalHashLiteral(node, env)

	/// ---------- statements ---------- ///
	case *ast.Program:
		return evalProgram(node.Statements, env)

	case *ast.BlockStatement:
		return evalBlockStatement(node, env)

	case *ast.ExpressionStatement:
		return eval(node.Expression, env)

	case *ast.ReturnStatement:
		values, errObj := evalReturnValues(node, env)
		if errObj != nil {
			return errObj
		}

		switch len(values) {
		case 0:
			return &object.ReturnValue{Value: NULL}
		case 1:
			return &object.ReturnValue{Value: values[0]}
		default:
			return &object.ReturnValue{Value: &object.MultiValue{Values: values}}
		}

	case *ast.LetStatement:
		val := eval(node.Value, env)
		if isError(val) {
			return val
		}
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*ast.Identifier{node.Name}
		}
		if len(names) <= 1 {
			env.Set(node.Name.Value, val)
			break
		}

		values := destructureValues(val, len(names))
		for i, ident := range names {
			if ident == nil {
				continue
			}
			env.Set(ident.Value, values[i])
		}

	case *ast.ForStatement:
		return evalForStatement(node, env)

	case *ast.BreakStatement:
		return &object.Break{}

	case *ast.ContinueStatement:
		return &object.Continue{}

	case *ast.StructStatement:
		return evalStructStatement(node, env)

	case *ast.EnumStatement:
		return evalEnumStatement(node, env)

	case *ast.AssignExpression:
		return evalAssignExpression(node, env)

	case *ast.FieldExpression:
		return evalFieldExpression(node, env)

	case *ast.StructLiteral:
		return evalStructLiteral(node, env)
	}
	return nil
}

func evalProgram(stmts []ast.Statement, env *object.Environment) object.Object {
	var res object.Object
	for _, s := range stmts {
		res = eval(s, env)

		switch res := res.(type) {
		case *object.ReturnValue:
			return res.Value
		case *fault:
			return res
		}
	}
	return res
}

func evalBlockStatement(block *ast.BlockStatement, env *object.Environment) object.Object {
	var res object.Object
	for _, stmt := range block.Statements {
		res = eval(stmt, env)
		if res != nil {
			// A fault ends the block; an error *value* does not. The two used to
			// be one test on ERROR_OBJ, which meant a statement that merely
			// evaluated to an error -- error("x") on its own line -- would end
			// the block as though it had failed.
			if isError(res) {
				return res
			}
			rt := res.Type()
			if rt == object.RETURN_VALUE_OBJ || rt == object.BREAK_OBJ || rt == object.CONTINUE_OBJ {
				return res
			}
		}
	}
	return res
}

func nativeBoolToBoolObject(input bool) *object.Boolean {
	if input {
		return TRUE
	}
	return FALSE
}

func evalIdentifier(node *ast.Identifier, env *object.Environment) object.Object {
	if val, ok := env.Get(node.Value); ok {
		return val
	}
	if builtin, ok := builtins[node.Value]; ok {
		return builtin
	}
	return newError("%s", "identifier not found: "+node.Value)
}

func applyFunction(fn object.Object, args []object.Object) object.Object {
	switch fun := fn.(type) {
	case *object.Function:
		// Check arity before binding parameters. extendFunctionEnv indexes
		// args positionally, so an under-applied call used to panic with an
		// index-out-of-range instead of reporting the mistake. The message
		// matches the VM's so both paths read the same.
		if len(args) != len(fun.Parameters) {
			return newError("wrong number of arguments. want=%d, got=%d", len(fun.Parameters), len(args))
		}
		extendedEnv := extendFunctionEnv(fun, args)
		evaluated := eval(fun.Body, extendedEnv)
		return unwrapReturnValue(evaluated)
	case *builtin.BuiltIn:
		// Some builtins need something the builtin itself does not have: the
		// ability to call a user function, or the running program's context. The
		// evaluator handles those natively, mirroring the VM.
		if kind := builtin.ExecutorNativeKind(fun); kind != "" {
			return applyExecutorNative(kind, args)
		}
		result := fun.Fn(args...)
		if result == nil {
			return NULL
		}
		// A bare error coming back from a builtin means the call failed, and
		// failure stops the tree-walker -- unless the builtin's contract says an
		// error is what it returns, which is what error() declares. Asking the
		// contract rather than the name means a second such builtin needs no
		// change here.
		//
		// The VM needs none of this: it keeps fatal errors in a separate Go
		// error channel, so an *object.Error reaching its stack is a value by
		// construction. This arm is what makes the two engines agree.
		if errObj, failed := result.(*object.Error); failed && !builtin.ReturnsErrorValue(fun) {
			return &fault{err: errObj}
		}
		return result
	default:
		return newError("not a function: %s", fn.Type())
	}
}

func extendFunctionEnv(fn *object.Function, args []object.Object) *object.Environment {
	env := object.NewEnclosedEnvironement(fn.Env)
	for paramIdx, param := range fn.Parameters {
		env.Set(param.Value, args[paramIdx])
	}
	return env
}

func unwrapReturnValue(obj object.Object) object.Object {
	if returnValue, ok := obj.(*object.ReturnValue); ok {
		return returnValue.Value
	}
	return obj
}

func evalReturnValues(node *ast.ReturnStatement, env *object.Environment) ([]object.Object, object.Object) {
	expressions := node.ReturnValues
	if len(expressions) == 0 && node.ReturnValue != nil {
		expressions = []ast.Expression{node.ReturnValue}
	}

	values := make([]object.Object, 0, len(expressions))
	for _, expr := range expressions {
		if expr == nil {
			continue
		}

		value := eval(expr, env)
		if isError(value) {
			return nil, value
		}
		values = append(values, value)
	}

	return values, nil
}

func destructureValues(source object.Object, arity int) []object.Object {
	values := make([]object.Object, arity)
	for i := range values {
		values[i] = NULL
	}

	switch obj := source.(type) {
	case *object.MultiValue:
		for i := 0; i < arity && i < len(obj.Values); i++ {
			if obj.Values[i] != nil {
				values[i] = obj.Values[i]
			}
		}
	case *object.Array:
		for i := 0; i < arity && i < len(obj.Elements); i++ {
			if obj.Elements[i] != nil {
				values[i] = obj.Elements[i]
			}
		}
	default:
		if arity > 0 && source != nil {
			values[0] = source
		}
	}

	return values
}

// evalLogicalExpression evaluates && / || with short-circuit semantics and a
// strict BOOLEAN result. For &&, the right operand is skipped when the left is
// falsy; for ||, it is skipped when the left is truthy.
func evalLogicalExpression(node *ast.InfixExpression, env *object.Environment) object.Object {
	left := eval(node.Left, env)
	if isError(left) {
		return left
	}
	leftTruthy := isTruthy(left)

	if node.Operator == "&&" {
		if !leftTruthy {
			return FALSE
		}
	} else { // "||"
		if leftTruthy {
			return TRUE
		}
	}

	right := eval(node.Right, env)
	if isError(right) {
		return right
	}
	if isTruthy(right) {
		return TRUE
	}
	return FALSE
}

func isTruthy(obj object.Object) bool {
	// Conventional truthiness (dev-sec-platform-upgrades): false, null, empty
	// string, 0 and 0.0 are falsy; everything else is truthy.
	switch o := obj.(type) {
	case *object.Boolean:
		return o.Value
	case *object.Null:
		return false
	case *object.String:
		return len(o.Value) != 0
	case *object.Bytes:
		return len(o.Value) != 0
	case *object.Integer:
		return o.Value != 0
	case *object.Float:
		return o.Value != 0
	default:
		return true
	}
}

func evalHashLiteral(node *ast.HashLiteral, env *object.Environment) object.Object {
	pairs := make(map[object.HashKey]object.HashPair)
	for keyNode, valueNode := range node.Pairs {
		key := eval(keyNode, env)
		if isError(key) {
			return key
		}
		hashKey, ok := key.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", key.Type())
		}
		value := eval(valueNode, env)
		if isError(value) {
			return value
		}
		hashed := hashKey.HashKey()
		pairs[hashed] = object.HashPair{Key: key, Value: value}
	}
	return &object.Hash{Pairs: pairs}
}

func evalForStatement(node *ast.ForStatement, env *object.Environment) object.Object {
	// Create a new scope for the loop to isolate init variable
	loopEnv := object.NewEnclosedEnvironement(env)

	// Execute init statement once
	if node.Init != nil {
		eval(node.Init, loopEnv)
	}

	var result object.Object

	// Loop: check condition, execute body, execute post
	for {
		if node.Condition != nil {
			condition := eval(node.Condition, loopEnv)
			if isError(condition) {
				return condition
			}
			if !isTruthy(condition) {
				break
			}
		}

		result = eval(node.Body, loopEnv)

		// Handle break: unwrap and return NULL
		if result != nil && result.Type() == object.BREAK_OBJ {
			return NULL
		}

		// Handle continue: skip post and go to next iteration
		if result != nil && result.Type() == object.CONTINUE_OBJ {
			// Continue with post execution
		} else if result != nil {
			// Handle return or error
			if result.Type() == object.RETURN_VALUE_OBJ || result.Type() == object.ERROR_OBJ {
				return result
			}
		}

		// Execute post expression
		if node.Post != nil {
			postResult := eval(node.Post, loopEnv)
			if isError(postResult) {
				return postResult
			}
		}
	}

	return NULL
}

func evalStructStatement(node *ast.StructStatement, env *object.Environment) object.Object {
	// Store struct definition as a special marker object in environment
	// We'll use a simple approach: store field names in environment with prefix
	structDefKey := "__struct_" + node.Name.Value
	fieldNames := []string{}
	for _, field := range node.Fields {
		fieldNames = append(fieldNames, field.Value)
	}

	// Create a simple marker to track this is a struct definition
	defMarker := &object.String{Value: "struct:" + node.Name.Value}
	env.Set(structDefKey, defMarker)

	// Store field list
	for i, fieldName := range fieldNames {
		fieldKey := structDefKey + "_field_" + string(rune(i))
		env.Set(fieldKey, &object.String{Value: fieldName})
	}

	return NULL
}

func evalEnumStatement(node *ast.EnumStatement, env *object.Environment) object.Object {
	// Store enum definition in environment
	enumDefKey := "__enum_" + node.Name.Value
	defMarker := &object.String{Value: "enum:" + node.Name.Value}
	env.Set(enumDefKey, defMarker)

	// Store each variant as accessible through enum name
	for i, variant := range node.Variants {
		variantKey := enumDefKey + "_variant_" + string(rune(i))
		env.Set(variantKey, &object.String{Value: variant.Value})

		// Also create enum value accessible as EnumName.VariantName
		enumValKey := node.Name.Value + "." + variant.Value
		env.Set(enumValKey, &object.EnumValue{
			TypeName: node.Name.Value,
			Tag:      variant.Value,
			Value:    &object.Integer{Value: int64(i)},
		})
	}

	return NULL
}

func evalAssignExpression(node *ast.AssignExpression, env *object.Environment) object.Object {
	value := eval(node.Value, env)
	if isError(value) {
		return value
	}

	// Compound assignment (x += v, x++): fold the current value of the target
	// with the right-hand side using the base operator before storing.
	if node.Operator != "" {
		current := eval(node.Left, env)
		if isError(current) {
			return current
		}
		value = evalInfixExpression(node.Operator, current, value)
		if isError(value) {
			return value
		}
	}

	// Handle simple identifier assignment: x = value
	if ident, ok := node.Left.(*ast.Identifier); ok {
		if _, updated := env.Update(ident.Value, value); !updated {
			env.Set(ident.Value, value)
		}
		return value
	}

	// Handle field assignment: struct.field = value
	if fieldExpr, ok := node.Left.(*ast.FieldExpression); ok {
		// Evaluate the left side (should be a struct)
		obj := eval(fieldExpr.Left, env)
		if isError(obj) {
			return obj
		}

		// Check if it's a struct
		structObj, ok := obj.(*object.Struct)
		if !ok {
			return newError("cannot assign field on non-struct: %s", obj.Type())
		}

		// Assign the field
		structObj.Fields[fieldExpr.Field.Value] = value
		return value
	}

	// Handle index assignment: a[i] = value / h[k] = value. Arrays, buffers and
	// hashes are all pointers, so mutating one in place is what the enclosing
	// environment sees; no write-back is needed, which is why the VM emits a
	// store after OpSetIndex and this does not.
	if idxExpr, ok := node.Left.(*ast.IndexExpression); ok {
		container := eval(idxExpr.Left, env)
		if isError(container) {
			return container
		}

		index := eval(idxExpr.Index, env)
		if isError(index) {
			return index
		}

		if err := evalSetIndex(container, index, value); err != nil {
			return err
		}
		return value
	}

	return newError("invalid assignment target")
}

// evalSetIndex stores value at index inside container, mirroring the VM's
// execSetIndex arm for arm. It returns an error object, or nil on success.
// The two implementations exist separately -- one works on the stack, one on
// evaluated objects -- so the messages are kept identical deliberately: the
// parity harness compares what a program prints, and a divergence in wording
// is a divergence.
func evalSetIndex(container, index, value object.Object) object.Object {
	switch c := container.(type) {
	case *object.Array:
		idx, ok := index.(*object.Integer)
		if !ok {
			return newError("array index must be INTEGER, got %s", index.Type())
		}
		if idx.Value < 0 || idx.Value >= int64(len(c.Elements)) {
			return newError("array index out of bounds: %d (len %d)", idx.Value, len(c.Elements))
		}
		c.Elements[idx.Value] = value
		return nil
	case *object.Bytes:
		idx, ok := index.(*object.Integer)
		if !ok {
			return newError("bytes index must be INTEGER, got %s", index.Type())
		}
		if idx.Value < 0 || idx.Value >= int64(len(c.Value)) {
			return newError("bytes index out of bounds: %d (len %d)", idx.Value, len(c.Value))
		}
		val, ok := value.(*object.Integer)
		if !ok {
			return newError("bytes element must be INTEGER, got %s", value.Type())
		}
		if val.Value < 0 || val.Value > 255 {
			return newError("bytes element out of range: %d (want 0-255)", val.Value)
		}
		c.Value[idx.Value] = byte(val.Value)
		return nil
	case *object.Hash:
		hashKey, ok := index.(object.Hashable)
		if !ok {
			return newError("unusable as a hashkey: %s", index.Type())
		}
		if c.Pairs == nil {
			c.Pairs = make(map[object.HashKey]object.HashPair)
		}
		c.Pairs[hashKey.HashKey()] = object.HashPair{Key: index, Value: value}
		return nil
	default:
		return newError("index assignment not supported on %s", container.Type())
	}
}

func evalFieldExpression(node *ast.FieldExpression, env *object.Environment) object.Object {
	// Handle enum variant access without evaluating the left identifier first.
	if ident, ok := node.Left.(*ast.Identifier); ok {
		enumValKey := ident.Value + "." + node.Field.Value
		if val, ok := env.Get(enumValKey); ok {
			return val
		}
	}

	// Evaluate the left side
	left := eval(node.Left, env)
	if isError(left) {
		return left
	}

	// Handle struct field access
	if structObj, ok := left.(*object.Struct); ok {
		if val, ok := structObj.Fields[node.Field.Value]; ok {
			return val
		}
		return NULL
	}

	// Errors read like structs, mirroring the VM's OpGetField. Both engines go
	// through object.Error.Field, which is the only way the two can be trusted
	// to agree about a field set that will grow.
	if errObj, ok := left.(*object.Error); ok {
		if val, ok := errObj.Field(node.Field.Value); ok {
			return val
		}
		return NULL
	}

	return newError("cannot access field %s on type %s", node.Field.Value, left.Type())
}

func evalStructLiteral(node *ast.StructLiteral, env *object.Environment) object.Object {
	// Evaluate all field values
	fields := make(map[string]object.Object)
	for _, fieldVal := range node.Fields {
		val := eval(fieldVal.Value, env)
		if isError(val) {
			return val
		}
		fields[fieldVal.Name.Value] = val
	}

	return &object.Struct{
		TypeName: node.Name.Value,
		Fields:   fields,
	}
}
