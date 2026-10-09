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
	"mutant/sema"
	"strings"
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
		if isSignal(right) {
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
		if isSignal(left) {
			return left
		}
		right := eval(node.Right, env)
		if isSignal(right) {
			return right
		}
		return evalInfixExpression(node.Operator, left, right)

	case *ast.IfExpression:
		return evalIfExpression(node, env)

	case *ast.MatchExpression:
		return evalMatchExpression(node, env)

	case *ast.Identifier:
		return evalIdentifier(node, env)

	case *ast.FunctionLiteral:
		params := node.Parameters
		body := node.Body
		return &object.Function{Parameters: params, Env: env, Body: body}
	case *ast.StringLiteral:
		return &object.String{Value: node.Value}
	case *ast.TemplateLiteral:
		return evalTemplateLiteral(node, env)
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
		if isSignal(function) {
			return function
		}
		args := evalExpressions(node.Arguments, env)
		if len(args) == 1 && isSignal(args[0]) {
			return args[0]
		}
		return applyFunction(function, args)
	case *ast.ArrayLiteral:
		elements := evalExpressions(node.Elements, env)
		if len(elements) == 1 && isSignal(elements[0]) {
			return elements[0]
		}
		return &object.Array{Elements: elements}
	case *ast.IndexExpression:
		left := eval(node.Left, env)
		if isSignal(left) {
			return left
		}
		index := eval(node.Index, env)
		if isSignal(index) {
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
			// Either a fault or an abrupt completion reached while evaluating
			// one of the returned expressions. It is handed up as it stands and
			// NOT wrapped: `return 1 + (if (c) { return 99; } else { x })` has
			// already decided what the function answers, and wrapping a
			// ReturnValue in a second one would make the function answer a
			// ReturnValue object.
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
		if isSignal(val) {
			// Nothing is bound. The initialiser never produced a value, so
			// there is no value to bind, and binding the signal object instead
			// is how `let w = if (v == 2) { break; } else { v };` came to read
			// `type mismatch: INTEGER+BREAK` one line later.
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

	case *ast.WhileStatement:
		return evalWhileStatement(node, env)

	case *ast.ForInStatement:
		return evalForInStatement(node, env)

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

	case *ast.ImportStatement:
		// Imports are resolved and linked before evaluation begins: by the
		// time a tree reaches here, every imported module's statements are
		// already part of the program. The node survives only as a marker,
		// so evaluating it is a no-op rather than an error.
		return nil
	}
	return nil
}

// evalTemplateLiteral joins the pieces of an interpolated string, matching the
// VM's OpConcat: a string piece contributes its own text, anything else
// contributes what it would print.
//
// The tree-walking evaluator only runs macro bodies now, but a macro that
// builds a message out of its arguments is exactly the kind anybody writes, so
// the two engines have to agree on what a hole produces.
func evalTemplateLiteral(node *ast.TemplateLiteral, env *object.Environment) object.Object {
	var out strings.Builder
	for i, text := range node.Texts {
		out.WriteString(text)
		if i >= len(node.Parts) {
			continue
		}
		// Inside a macro body the unexported eval is used, so a hole that gives
		// up ends the literal. The exported Eval unwraps the fatal signal into
		// an ordinary error value, and isError tests only for the signal -- so a
		// refusal raised in a hole used to be written into the string and
		// expansion SUCCEEDED, carrying the refusal's own text into the program
		// as a literal. A gate that reports itself that way reads as working.
		//
		// The run time keeps Eval, deliberately. There the two engines agree:
		// the VM pushes a builtin's error onto the stack as an ordinary value
		// and OpConcat prints it, so switching this unconditionally would make
		// the evaluator diverge from the VM rather than match it.
		var piece object.Object
		if env.InMacroExpansion() {
			piece = eval(node.Parts[i], env)
		} else {
			piece = Eval(node.Parts[i], env)
		}
		if isSignal(piece) {
			// A hole that breaks abandons the whole literal rather than
			// printing "BREAK" into it, which is what Inspect below would
			// otherwise do.
			return piece
		}
		if str, isString := piece.(*object.String); isString {
			out.WriteString(str.Value)
			continue
		}
		if piece != nil {
			out.WriteString(piece.Inspect())
		}
	}
	return &object.String{Value: out.String()}
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

		// A break or a continue that reached the top level has no loop to act
		// on, and the compiler refuses such a program outright. This is the
		// second boundary loopControlEscaped guards -- the first is a function
		// body -- and it has to be a refusal here for the same reason: a
		// program that falls off the end of a `break` carries on with an
		// answer nobody can tell from a deliberate one. `let n = 1; break; n;`
		// answered 1.
		if escaped := loopControlEscaped(res); escaped != nil {
			return escaped
		}
	}
	return res
}

// evalBlockStatement runs a block in a scope of its own.
//
// The two engines have to agree about this, and until they were made to they
// did not: the compiler gave a block no scope at all and the evaluator gave one
// only to a call, a loop and a match arm, so `let z = 1; if (c) { let z = 2; }`
// left z as 2 in both and Go leaves it as 1. Neither engine was right, and the
// disagreements between them were worse than either -- a `for` whose body
// redeclared the counter hung in the VM and terminated with the wrong answer in
// the tree-walker, from one program.
//
// Assignment is unaffected and that is what makes this safe: `x = 5` inside a
// block goes through Environment.Update, which walks outward and writes to the
// binding that already exists. Only a `let` writes here, through Set.
//
// A function body does NOT come through here -- see evalBlockBody.
func evalBlockStatement(block *ast.BlockStatement, env *object.Environment) object.Object {
	return evalBlockBody(block, object.NewEnclosedEnvironement(env))
}

// evalBlockBody runs a block's statements in the environment it is given,
// opening no scope.
//
// It is the path for the blocks that are not scopes of their own because
// something else has already opened theirs: a function body, which shares one
// scope with its parameters, and a macro body, which shares one with its. The
// compiler draws the boundary in the same place, and Go draws it there too --
// `func f(a int) { a := 1 }` is `a redeclared in this block`.
func evalBlockBody(block *ast.BlockStatement, env *object.Environment) object.Object {
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
	if resolved, registered := resolveBuiltin(node.Value, node.Value, env); registered {
		return resolved
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
		// evalBlockBody, not eval: the parameters are already bound in
		// extendedEnv and the body shares their scope rather than nesting
		// inside it, so a `let` of a parameter's name is the redeclaration the
		// compiler refuses rather than a silent shadow.
		evaluated := evalBlockBody(fun.Body, extendedEnv)
		// A body that produces no value produces a Go nil, not NULL, and the
		// builtin arm below already guards exactly this case with `if result ==
		// nil`. This arm did not, so the nil went to the program. evalBlockBody
		// returns nil for an empty body, and for a body whose last statement is
		// a `let` -- eval's LetStatement arm sets the name, breaks out of the
		// switch and falls through to `return nil`, and evalBlockBody hands back
		// the last statement's result. That second shape is how a function that
		// works by side effect is written, so it needs no unusual input to
		// reach. Whatever touched the value next dereferenced it:
		// builtin.TypeOf, evalInfixExpression, evalBangOperatorExpression. There
		// is no recover above this, and this engine is what computes
		// unquote(...) during macro expansion, so the result was `mutant
		// prog.mut` ending in a Go stack trace at compile time. The VM answers
		// NULL for every one of those shapes (M26-EVL-020).
		//
		// The guard sits here, ahead of the loop-control backstop below, so that
		// nothing inspects the nil at all. loopControlEscaped returns nil for a
		// nil today, so either order behaves the same -- but the row is that a
		// nil leaves this arm, and the fix for it should not rest on a detail of
		// another function.
		if evaluated == nil {
			return NULL
		}
		if escaped := loopControlEscaped(evaluated); escaped != nil {
			return escaped
		}
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
	case nil:
		// A callee that evaluated to nothing. fn.Type() on a nil interface
		// panics, and this arm is reachable from source: `eval` has no arm for
		// *ast.MacroLiteral, because DefineMacros is expected to have removed
		// the macro definitions first -- and it removes only the TOP-LEVEL
		// ones. A macro literal nested inside an `unquote` argument therefore
		// survives into code this engine runs, binds nil, and is then called.
		//
		// The message names the shape rather than the type, because there is no
		// type to name: that is the whole of what went wrong.
		return newError("call of a name that has no value: a macro definition " +
			"must appear at the top level, where it is expanded before anything runs")
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

// loopControlEscaped reports a `break` or a `continue` that reached a boundary
// with no loop on this side of it to act on.
//
// There are two such boundaries and it guards both: the end of a function body,
// which is where M26-EVL-023 needed it, and the end of the program, which is
// where M26-EVL-025 did. The compiler draws the same line in the same two
// places -- it clears loopContexts when it enters a function body and starts
// with it empty at the top level -- so these are the two places a signal can
// still be travelling with nothing left above it.
//
// It is the backstop half of M26-EVL-023, and it is a backstop rather than the
// fix: the compiler refuses the shape, so a program that reaches here has come
// through a path that does not compile first. Macro expansion is exactly such a
// path -- `mutant gen` runs DefineMacros and ExpandMacros for every module with
// no flag, so an `unquote` argument is user code this engine executes before
// anything is compiled. Without this, the signal left the call as its VALUE:
// unwrapReturnValue only unwraps *object.ReturnValue, so a *object.Break fell
// straight through, and the caller's loop obeyed a break written in a function
// it had merely called. `for (let i = 0; i < 3; i++) { let f = fn() { break; };
// f(); out = out + 1; }` answered 0, and a macro spliced that 0 into the
// program with no diagnostic.
//
// An error, not a silent null: the alternative is a value nobody can tell from
// a deliberate one, which is the whole defect. The words are sema's, so this
// says what the compiler says.
func loopControlEscaped(result object.Object) object.Object {
	if result == nil {
		return nil
	}
	switch result.Type() {
	case object.BREAK_OBJ:
		return newError("%s", sema.LoopControlRefusal("break").Message)
	case object.CONTINUE_OBJ:
		return newError("%s", sema.LoopControlRefusal("continue").Message)
	}
	return nil
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
		if isSignal(value) {
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
	if isSignal(left) {
		return left
	}
	// Before IsTruthy, which answers true for a Break -- so the short circuit
	// read a break as "keep going" and the operator produced a boolean.
	leftTruthy := object.IsTruthy(left)

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
	if isSignal(right) {
		return right
	}
	if object.IsTruthy(right) {
		return TRUE
	}
	return FALSE
}

func evalHashLiteral(node *ast.HashLiteral, env *object.Environment) object.Object {
	pairs := make(map[object.HashKey]object.HashPair, len(node.Pairs))
	// In the order the author wrote them, which is the order the compiler emits
	// them in. A key or a value may call something, and until M26-CMP-010 the
	// order those calls ran in was whatever Go map iteration chose, so one
	// program ran its own side effects in a different order on every run. A key
	// set twice is the later pair, here and in vm.buildHash; the parser refuses
	// one, so only a macro can produce one.
	for _, pair := range node.Pairs {
		keyNode, valueNode := pair.Key, pair.Value
		key := eval(keyNode, env)
		if isSignal(key) {
			return key
		}
		hashKey, ok := key.(object.Hashable)
		if !ok {
			return newError("unusable as hash key: %s", key.Type())
		}
		value := eval(valueNode, env)
		if isSignal(value) {
			// One of the three silent shapes of M26-EVL-025: a Break is not
			// Hashable, so it could only ever arrive as a VALUE, and it was
			// stored in the hash and the loop ran on.
			return value
		}
		hashed := hashKey.HashKey()
		pairs[hashed] = object.HashPair{Key: key, Value: value}
	}
	return &object.Hash{Pairs: pairs}
}

func evalForInStatement(node *ast.ForInStatement, env *object.Environment) object.Object {
	if node.Value == nil {
		return newError("for ... in has no name to bind")
	}

	iterable := eval(node.Iterable, env)
	if isSignal(iterable) {
		// Propagated OUTWARD, not acted on here. The compiler compiles the
		// iterable before pushing this loop's context
		// (compiler.compileForInStatement), so a break written in it belongs to
		// an enclosing loop, or to no loop at all -- and the signal has to
		// travel for either answer to be reachable.
		return iterable
	}

	// The same object.NewIterator the VM uses, so the two engines cannot drift
	// on what is iterable, on what a single binding yields, or on the order a
	// hash comes out in.
	iterator, ok := object.NewIterator(iterable)
	if !ok {
		return newError("cannot iterate over %s", iterable.Type())
	}

	loopEnv := object.NewEnclosedEnvironement(env)

	for {
		key, value, more := iterator.Next()
		if !more {
			break
		}

		if node.Key != nil {
			loopEnv.Set(node.Key.Value, key)
			loopEnv.Set(node.Value.Value, value)
		} else {
			loopEnv.Set(node.Value.Value, iterator.Primary(key, value))
		}

		result := eval(node.Body, loopEnv)
		if result == nil {
			continue
		}

		switch result.Type() {
		case object.BREAK_OBJ:
			return NULL
		case object.CONTINUE_OBJ:
			continue
		case object.RETURN_VALUE_OBJ, object.ERROR_OBJ:
			return result
		}
	}

	return NULL
}

func evalWhileStatement(node *ast.WhileStatement, env *object.Environment) object.Object {
	// A scope of its own, matching the for loop: a `let` in the body does not
	// leak out, and re-entering the body does not redeclare into the caller.
	loopEnv := object.NewEnclosedEnvironement(env)

	for {
		condition := eval(node.Condition, loopEnv)
		if isSignal(condition) {
			// Outward, for the reason given in evalForInStatement: the compiler
			// compiles a while condition before pushing the loop context.
			//
			// Without this the evaluator did not terminate. `while (if (i == 2)
			// { break; } else { true })` produced a Break object, IsTruthy
			// answered true for it, and the loop ran for ever on a program the
			// compiler refuses outright.
			return condition
		}
		if !object.IsTruthy(condition) {
			break
		}

		result := eval(node.Body, loopEnv)
		if result == nil {
			continue
		}

		switch result.Type() {
		case object.BREAK_OBJ:
			return NULL
		case object.CONTINUE_OBJ:
			continue
		case object.RETURN_VALUE_OBJ, object.ERROR_OBJ:
			return result
		}
	}

	return NULL
}

func evalForStatement(node *ast.ForStatement, env *object.Environment) object.Object {
	// Create a new scope for the loop to isolate init variable
	loopEnv := object.NewEnclosedEnvironement(env)

	// Execute init statement once. Its result was discarded, which meant a
	// failure in it was discarded too: `for (let i = (1 + "x"); i < 3; ...)`
	// swallowed the type error and the loop then ran with i unbound, reporting
	// `identifier not found: i` from the condition. A signal here is handed
	// outward for the same reason the condition's is -- the compiler compiles
	// the init section before pushing this loop's context.
	if node.Init != nil {
		if initResult := eval(node.Init, loopEnv); isSignal(initResult) {
			return initResult
		}
	}

	var result object.Object

	// Loop: check condition, execute body, execute post
	for {
		if node.Condition != nil {
			condition := eval(node.Condition, loopEnv)
			if isSignal(condition) {
				// Outward, as in evalWhileStatement.
				return condition
			}
			if !object.IsTruthy(condition) {
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

		// Execute post expression.
		//
		// The post section is the one part of a loop header that belongs to the
		// loop: the compiler compiles it INSIDE this loop's context, after the
		// body, so a break written there is this loop's break. The condition,
		// the init section and a for-in's iterable are all compiled outside it
		// and propagate instead. That asymmetry is the compiler's, and matching
		// it is the point -- it is not an asymmetry worth inventing twice.
		if node.Post != nil {
			postResult := eval(node.Post, loopEnv)
			if isError(postResult) {
				return postResult
			}
			if postResult != nil {
				switch postResult.Type() {
				case object.BREAK_OBJ:
					return NULL
				case object.CONTINUE_OBJ:
					// Refused, because neither reading of it terminates: going
					// on to the condition skips the advance, and re-running the
					// section -- which is where the compiler's jump points --
					// reaches the same continue again. Measured both ways
					// before it was refused; the first hangs.
					return newError("%s", sema.ContinueInLoopStepRefusal().Message)
				case object.RETURN_VALUE_OBJ:
					return postResult
				}
			}
		}
	}

	return NULL
}

// structDefinitionKey and structFieldsKey are the two spellings a struct
// occupies in the environment: one saying the type exists, one holding its
// field names in the order the declaration gave them.
//
// The order used to be stored one field per key, under a name built with
// string(rune(i)) -- so the first field's key held a NUL byte. Nothing ever
// read any of them, which is why evalStructLiteral had no order to hand a
// struct and Inspect was left ranging a Go map. One array under one key is
// something a reader can find.
func structDefinitionKey(name string) string {
	return "__struct_" + name
}

func structFieldsKey(name string) string {
	return structDefinitionKey(name) + "_fields"
}

func evalStructStatement(node *ast.StructStatement, env *object.Environment) object.Object {
	// A name declared twice is refused here as it is in the compiler: Fields is
	// a map, so one of the two could never hold a value of its own, and the
	// literal's refusal reports the field names that differ rather than the
	// count -- which is only equivalent while a repeat is impossible.
	seen := make(map[string]bool, len(node.Fields))
	fieldNames := make([]object.Object, 0, len(node.Fields))
	for _, field := range node.Fields {
		if seen[field.Value] {
			return newError("%s", object.DuplicateStructFieldDeclarationMessage(
				node.Name.Value, field.Value))
		}
		seen[field.Value] = true
		fieldNames = append(fieldNames, &object.String{Value: field.Value})
	}

	env.Set(structDefinitionKey(node.Name.Value), &object.String{Value: "struct:" + node.Name.Value})
	env.Set(structFieldsKey(node.Name.Value), &object.Array{Elements: fieldNames})

	return NULL
}

// enumDefinitionKey and enumValueKey are the two spellings an enum occupies in
// the environment: one saying the type exists, one holding each variant's
// value.
//
// They are functions rather than two string concatenations at each site because
// the sites drifted. evalFieldExpression used to build the second spelling by
// hand and treat a miss as "not an enum", which is not what a miss means -- it
// means the enum has no such variant. `enum str { x }; str.upper("a");` then
// fell through to the builtin fold and returned "A", while the VM refused the
// same program with "unknown enum tag str.upper".
func enumDefinitionKey(name string) string {
	return "__enum_" + name
}

func enumValueKey(enum, variant string) string {
	return enum + "." + variant
}

func evalEnumStatement(node *ast.EnumStatement, env *object.Environment) object.Object {
	// Store enum definition in environment
	enumDefKey := enumDefinitionKey(node.Name.Value)
	defMarker := &object.String{Value: "enum:" + node.Name.Value}
	env.Set(enumDefKey, defMarker)

	// Store each variant as accessible through enum name
	for i, variant := range node.Variants {
		variantKey := enumDefKey + "_variant_" + string(rune(i))
		env.Set(variantKey, &object.String{Value: variant.Value})

		// Also create enum value accessible as EnumName.VariantName
		env.Set(enumValueKey(node.Name.Value, variant.Value), &object.EnumValue{
			TypeName: node.Name.Value,
			Tag:      variant.Value,
			Value:    &object.Integer{Value: int64(i)},
		})
	}

	return NULL
}

// evalAssignExpression evaluates the target's parts before the value, because
// that is the order they are written in and the order the compiler emits.
//
// It used to evaluate the value first, which nothing reveals until both sides
// have side effects -- `a[note("index")] = note("value")` recorded them in
// opposite orders in the two engines. That matters beyond tidiness: this
// evaluator is what computes `unquote(...)` during macro expansion, so the same
// line meant two different things depending on whether it was written inside a
// macro or inline.
func evalAssignExpression(node *ast.AssignExpression, env *object.Environment) object.Object {
	// Handle simple identifier assignment: x = value
	if ident, ok := node.Left.(*ast.Identifier); ok {
		value := evalAssignedValue(node, env)
		if isSignal(value) {
			return value
		}
		if _, updated := env.Update(ident.Value, value); !updated {
			env.Set(ident.Value, value)
		}
		return value
	}

	// Handle field assignment: struct.field = value
	if fieldExpr, ok := node.Left.(*ast.FieldExpression); ok {
		// Evaluate the left side (should be a struct)
		obj := eval(fieldExpr.Left, env)
		if isSignal(obj) {
			return obj
		}

		// Check if it's a struct
		structObj, ok := obj.(*object.Struct)
		if !ok {
			return newError("cannot assign field on non-struct: %s", obj.Type())
		}

		value := evalAssignedValue(node, env)
		if isSignal(value) {
			return value
		}

		if _, declared := structObj.Fields[fieldExpr.Field.Value]; !declared {
			return newError("%s", object.UnknownStructFieldWriteMessage(
				structObj.TypeName, fieldExpr.Field.Value, structObj.FieldNames()))
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
		if isSignal(container) {
			return container
		}

		index := eval(idxExpr.Index, env)
		if isSignal(index) {
			return index
		}

		// A compound assignment folds the element THIS index names. Going
		// through evalAssignedValue would read the target back by evaluating
		// node.Left, which evaluates the index a second time: `a[f()] += 1`
		// called f() twice and folded the element at one index into the slot of
		// another. The compiler had the same defect in its own way, so the two
		// engines agreed about the wrong answer and a parity harness could not
		// be what found it.
		//
		// evalIndexExpression is the call the *ast.IndexExpression arm of eval
		// ends in, so an out-of-range or mistyped index answers here exactly as
		// it does where the target is merely read. The target is still read
		// before the right-hand side.
		var value object.Object
		if node.Operator == "" {
			value = eval(node.Value, env)
		} else {
			current := evalIndexExpression(container, index)
			if isError(current) {
				return current
			}
			right := eval(node.Value, env)
			if isSignal(right) {
				return right
			}
			value = evalInfixExpression(node.Operator, current, right)
		}
		if isSignal(value) {
			return value
		}

		if err := evalSetIndex(container, index, value); err != nil {
			return err
		}
		return value
	}

	return newError("invalid assignment target")
}

// evalAssignedValue is what the assignment stores: the right-hand side, or, for
// a compound assignment, the target's current value folded with it.
//
// The index-assignment branch of evalAssignExpression does NOT fold through
// here: it has already evaluated the index and has to fold the element that
// index names, and reading node.Left back here would evaluate the index a
// second time. An identifier or field target has no index to lose, so those
// branches still read the target through this.
//
// The target is read before the right-hand side because the compiler desugars
// `x += v` to `x = x <op> v` and then compiles that infix expression left to
// right. Reading them the other way round is a divergence nothing catches until
// both have side effects.
func evalAssignedValue(node *ast.AssignExpression, env *object.Environment) object.Object {
	if node.Operator == "" {
		return eval(node.Value, env)
	}

	current := eval(node.Left, env)
	if isSignal(current) {
		return current
	}

	value := eval(node.Value, env)
	if isSignal(value) {
		return value
	}

	return evalInfixExpression(node.Operator, current, value)
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
	// The left identifier is deliberately not evaluated first: `Colour.Red` is
	// an enum access and `str.upper` is a builtin, and neither is a field of
	// anything bound to that name.
	//
	// What it refers to is sema's decision, made once for every engine. This
	// one supplies only what is peculiar to it -- that a binding lives in an
	// environment rather than in a symbol table, and that an enum's variants
	// live under a second spelling in that same environment.
	//
	// Namespace stays nil deliberately: imports are resolved and linked before
	// evaluation begins, so there are no import namespaces here.
	if ident, ok := node.Left.(*ast.Identifier); ok {
		resolved := semaResolver.ResolveField(sema.ScopeCtx{
			Enums: func(name string) bool {
				_, declared := env.Get(enumDefinitionKey(name))
				return declared
			},
			Bound: func(name string) bool {
				_, bound := env.Get(name)
				return bound
			},
		}, ident.Value, node.Field.Value)

		switch resolved.Kind {
		case sema.FieldEnumValue:
			// Asked of the enum rather than of the variant, which is the whole
			// of the fix: a variant that is not there means the enum has no
			// such tag, and it used to mean "not an enum", which handed
			// `str.upper` to the fold under an `enum str`. The VM's words,
			// because they are the same refusal -- see vm.go, "unknown enum
			// tag %s.%s".
			if value, found := env.Get(enumValueKey(ident.Value, node.Field.Value)); found {
				return value
			}
			return newError("unknown enum tag %s.%s", ident.Value, node.Field.Value)

		case sema.FieldBuiltinFold:
			// Looked up in this engine's own table rather than taken on trust,
			// so a registry entry with no implementation falls through to field
			// access exactly as it did before.
			//
			// This is the second door into that table, and the one a fix aimed
			// at evalIdentifier leaves open: sema folded `fs.write` to
			// `fs_write` before we got here, so no identifier for the builtin
			// was ever built. Both doors go through resolveBuiltin for that
			// reason, keyed on the flat name and reporting the dotted spelling.
			if answer, registered := resolveBuiltin(
				resolved.Builtin, ident.Value+"."+node.Field.Value, env); registered {
				return answer
			}
		}
	}

	// Evaluate the left side
	left := eval(node.Left, env)
	if isSignal(left) {
		return left
	}

	// Handle struct field access
	if structObj, ok := left.(*object.Struct); ok {
		if val, ok := structObj.Fields[node.Field.Value]; ok {
			return val
		}
		return newError("%s", object.UnknownStructFieldMessage(
			structObj.TypeName, node.Field.Value, structObj.FieldNames()))
	}

	// An error's unknown field is still null, and a struct's is now a refusal:
	// the VM's OpGetField says why the two parted. Both engines still go through
	// object.Error.Field, which is the only way they can be trusted to agree
	// about a field set that will grow.
	if errObj, ok := left.(*object.Error); ok {
		if val, ok := errObj.Field(node.Field.Value); ok {
			return val
		}
		return NULL
	}

	return newError("cannot access field %s on type %s", node.Field.Value, left.Type())
}

// evalStructLiteral builds a struct, refusing the same four shapes the compiler
// refuses: an undeclared type, an unknown field name, a declared field nothing
// set, and a field initializer with no name.
//
// It used to check none of them, which made a struct literal mean something
// different in each engine -- the divergence parity/ exists to prevent. This
// engine is what computes `unquote(...)` during macro expansion, so it is not
// dead code, and it was the laxer of the two.
func evalStructLiteral(node *ast.StructLiteral, env *object.Environment) object.Object {
	declaredNames, isDeclared := declaredStructFields(node.Name.Value, env)
	if !isDeclared {
		// The compiler's words, because it is the same refusal.
		return newError("undefined struct type: %s", node.Name.Value)
	}

	declared := make(map[string]bool, len(declaredNames))
	for _, name := range declaredNames {
		declared[name] = true
	}

	// Evaluate all field values
	fields := make(map[string]object.Object, len(node.Fields))
	written := make([]string, 0, len(node.Fields))
	var unknown []string
	for _, fieldVal := range node.Fields {
		if fieldVal == nil || fieldVal.Name == nil {
			return newError("invalid field initializer in struct %s", node.Name.Value)
		}
		if _, twice := fields[fieldVal.Name.Value]; twice {
			return newError("%s", object.DuplicateStructFieldLiteralMessage(
				node.Name.Value, fieldVal.Name.Value))
		}
		val := eval(fieldVal.Value, env)
		if isSignal(val) {
			return val
		}
		fields[fieldVal.Name.Value] = val
		written = append(written, fieldVal.Name.Value)
		if !declared[fieldVal.Name.Value] {
			unknown = append(unknown, fieldVal.Name.Value)
		}
	}

	var missing []string
	for _, name := range declaredNames {
		if _, set := fields[name]; !set {
			missing = append(missing, name)
		}
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return newError("%s", object.StructLiteralRefusal(
			node.Name.Value, unknown, missing, declaredNames))
	}

	return &object.Struct{
		TypeName:   node.Name.Value,
		FieldOrder: structFieldOrder(node.Name.Value, written, env),
		Fields:     fields,
	}
}

// structFieldOrder answers the order Inspect should render a literal's fields
// in: the order the struct's own declaration gave them, however the literal was
// written.
//
// The literal's written order is the fallback. evalStructLiteral now refuses a
// literal whose type was never declared, so nothing a program can write reaches
// it; it stays because a printed record is a poor place to discover that a
// caller built a struct some other way.
func structFieldOrder(typeName string, written []string, env *object.Environment) []string {
	order, found := declaredStructFields(typeName, env)
	if !found {
		return written
	}
	return order
}

// declaredStructFields reads a struct's declared field names out of the
// environment, in declaration order, and reports whether the type is declared
// at all.
//
// It is the evaluator's whole view of a struct declaration, and the one place
// evalStructStatement's key is read, so a validation and a render order can
// never disagree about what a type declares.
func declaredStructFields(typeName string, env *object.Environment) ([]string, bool) {
	stored, found := env.Get(structFieldsKey(typeName))
	if !found {
		return nil, false
	}
	fields, isArray := stored.(*object.Array)
	if !isArray {
		return nil, false
	}

	names := make([]string, 0, len(fields.Elements))
	for _, element := range fields.Elements {
		name, isString := element.(*object.String)
		if !isString {
			return nil, false
		}
		names = append(names, name.Value)
	}
	return names, true
}
