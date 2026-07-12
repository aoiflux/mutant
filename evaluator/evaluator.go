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

func Eval(n ast.Node, env *object.Environment) object.Object {
	switch node := n.(type) {

	/// ---------- expressions ---------- ///
	case *ast.IntegerLiteral:
		return &object.Integer{Value: node.Value}

	case *ast.Boolean:
		return nativeBoolToBoolObject(node.Value)

	case *ast.PrefixExpression:
		right := Eval(node.Right, env)
		if isError(right) {
			return right
		}
		return evalPrefixExpression(node.Operator, right)

	case *ast.InfixExpression:
		left := Eval(node.Left, env)
		if isError(left) {
			return left
		}
		right := Eval(node.Right, env)
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
			return quote(node.Arguments[0], env)
		}
		function := Eval(node.Function, env)
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
		left := Eval(node.Left, env)
		if isError(left) {
			return left
		}
		index := Eval(node.Index, env)
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
		return Eval(node.Expression, env)

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
		val := Eval(node.Value, env)
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
		res = Eval(s, env)

		switch res := res.(type) {
		case *object.ReturnValue:
			return res.Value
		case *object.Error:
			return res
		}
	}
	return res
}

func evalBlockStatement(block *ast.BlockStatement, env *object.Environment) object.Object {
	var res object.Object
	for _, stmt := range block.Statements {
		res = Eval(stmt, env)
		if res != nil {
			rt := res.Type()
			if rt == object.RETURN_VALUE_OBJ || rt == object.ERROR_OBJ ||
				rt == object.BREAK_OBJ || rt == object.CONTINUE_OBJ {
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
		extendedEnv := extendFunctionEnv(fun, args)
		evaluated := Eval(fun.Body, extendedEnv)
		return unwrapReturnValue(evaluated)
	case *builtin.BuiltIn:
		result := fun.Fn(args...)
		if result == nil {
			return NULL
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

		value := Eval(expr, env)
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

func isTruthy(obj object.Object) bool {
	switch obj {
	case NULL:
		return false
	case TRUE:
		return true
	case FALSE:
		return false
	default:
		return true
	}
}

func evalHashLiteral(node *ast.HashLiteral, env *object.Environment) object.Object {
	pairs := make(map[object.HashKey]object.HashPair)
	for keyNode, valueNode := range node.Pairs {
		key := Eval(keyNode, env)
		if isError(key) {
			return key
		}
		hashKey, ok := key.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", key.Type())
		}
		value := Eval(valueNode, env)
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
		Eval(node.Init, loopEnv)
	}

	var result object.Object

	// Loop: check condition, execute body, execute post
	for {
		if node.Condition != nil {
			condition := Eval(node.Condition, loopEnv)
			if isError(condition) {
				return condition
			}
			if !isTruthy(condition) {
				break
			}
		}

		result = Eval(node.Body, loopEnv)

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
			postResult := Eval(node.Post, loopEnv)
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
	value := Eval(node.Value, env)
	if isError(value) {
		return value
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
		obj := Eval(fieldExpr.Left, env)
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

	return newError("invalid assignment target")
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
	left := Eval(node.Left, env)
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

	return newError("cannot access field %s on type %s", node.Field.Value, left.Type())
}

func evalStructLiteral(node *ast.StructLiteral, env *object.Environment) object.Object {
	// Evaluate all field values
	fields := make(map[string]object.Object)
	for _, fieldVal := range node.Fields {
		val := Eval(fieldVal.Value, env)
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
