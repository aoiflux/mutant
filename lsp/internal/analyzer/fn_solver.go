package analyzer

import (
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
)

// Parameter types for user-defined functions, solved from how the body uses
// them.
//
// Mutant has no type annotation syntax, so a user function's hover card can only
// say what its parameters accept if something works it out. Forward inference
// cannot: it walks a body once with every parameter as Any, which is why hover
// showed nothing but a list of names.
//
// This runs the other direction. Each parameter starts as "any kind", and every
// use of it in the body removes kinds it cannot be. `str_upper(host)` narrows
// host to STRING because that is what str_upper's verified contract demands;
// `a - b` narrows both to the numeric kinds because those are the only ones the
// VM's binary operation accepts. What survives is the parameter's type.
//
// The whole thing is display-only. It feeds hover, signature help, completion
// detail and inlay hints, and it must never feed a diagnostic: a constraint set
// is a deduction about a dynamically-typed program, and the bar for underlining
// someone's code is higher than the bar for describing it.

// kindSet is a set of ParamKinds, as a bitset so intersection is an AND and the
// fixpoint loop can compare rounds by value.
type kindSet uint16

const (
	ksString kindSet = 1 << iota
	ksInt
	ksFloat
	ksBool
	ksArray
	ksHash
	ksFn
	ksNull
)

// ksAny is the top of the lattice: a parameter nothing has constrained.
const ksAny = ksString | ksInt | ksFloat | ksBool | ksArray | ksHash | ksFn | ksNull

// The operand domains below are read off the VM, not assumed.
//
//   - execBinaryOperation (vm.go) accepts INTEGER×INTEGER, STRING×STRING, or
//     numeric×numeric, and execBinaryStringOperation rejects every operator but
//     OpAdd — so `+` admits strings and the rest do not.
//   - execComparison accepts INTEGER×INTEGER or numeric×numeric.
//   - execMinusOperation asserts INTEGER or FLOAT.
//
// `!`, `==` and `!=` accept anything, and so appear nowhere here: truthiness and
// equality are defined for every value, and a constraint that excludes nothing
// is worth no code.
const (
	ksNumeric    = ksInt | ksFloat
	ksAddable    = ksInt | ksFloat | ksString
	ksComparable = ksInt | ksFloat
)

var kindBits = map[builtin.ParamKind]kindSet{
	builtin.ParamString: ksString,
	builtin.ParamInt:    ksInt,
	builtin.ParamFloat:  ksFloat,
	builtin.ParamBool:   ksBool,
	builtin.ParamArray:  ksArray,
	builtin.ParamHash:   ksHash,
	builtin.ParamFn:     ksFn,
	builtin.ParamNull:   ksNull,
}

// kindSetFor converts a declared kind list into a set. An empty list, or one
// containing ANY, is the unconstrained top — the same rule the argument-type
// diagnostic follows, so the solver never narrows on a contract that says
// nothing.
func kindSetFor(kinds []builtin.ParamKind) kindSet {
	if len(kinds) == 0 {
		return ksAny
	}
	var set kindSet
	for _, kind := range kinds {
		if kind == builtin.ParamAny {
			return ksAny
		}
		set |= kindBits[kind]
	}
	if set == 0 {
		return ksAny
	}
	return set
}

// names renders a set in the runtime vocabulary the builtin cards use, so a user
// function's types read identically to a builtin's. The order is fixed rather
// than bit order, so `INTEGER|FLOAT` never comes out reversed between runs.
func (s kindSet) names() []string {
	ordered := []struct {
		bit  kindSet
		name string
	}{
		{ksString, "STRING"}, {ksInt, "INTEGER"}, {ksFloat, "FLOAT"},
		{ksBool, "BOOLEAN"}, {ksArray, "ARRAY"}, {ksHash, "HASH"},
		{ksFn, "FUNCTION"}, {ksNull, "NULL"},
	}
	out := make([]string, 0, len(ordered))
	for _, entry := range ordered {
		if s&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

// text renders the set for display, or "" when it says nothing worth showing.
//
// The empty set means the constraints contradict each other — a parameter passed
// to str_upper and also negated. That is a bug in the program, not a type, and
// it is not this code's job to report it, so it shows nothing rather than an
// impossible claim.
func (s kindSet) text() string {
	if s == ksAny || s == 0 {
		return ""
	}
	return strings.Join(s.names(), "|")
}

// asType collapses a solved set to a lattice type, but only when it names
// exactly one kind. A union is real information for a reader and no information
// for inference, which has no union to represent it.
func (s kindSet) asType() Type {
	if s == 0 || s == ksAny {
		return AnyType
	}
	if s&(s-1) != 0 {
		return AnyType // more than one bit set
	}
	switch s {
	case ksString:
		return tString
	case ksInt:
		return tInt
	case ksFloat:
		return tFloat
	case ksBool:
		return tBool
	case ksArray:
		return tArray
	case ksHash:
		return tHash
	case ksNull:
		return Type{Kind: TypeNull}
	}
	return AnyType
}

// solvedFunction is one user function's worked-out signature.
type solvedFunction struct {
	name    string
	literal *mast.FunctionLiteral
	params  []string
	// kinds is one set per parameter, positionally.
	kinds []kindSet
	// observed holds argument kinds seen at call sites in this document, used
	// only where the body constrained a parameter to nothing. It is evidence,
	// not a contract: one caller passing a string does not make the parameter a
	// string, so it is rendered as an observation and never as the type.
	observed []kindSet
}

// solveFunctionParams works out every user function's parameter kinds.
//
// Functions constrain each other — a parameter passed straight through to
// another function inherits that function's constraints — so this iterates to a
// fixpoint rather than making one pass. The iteration is bounded: sets only ever
// shrink, so it terminates on its own, and the cap is a guard against a bug
// rather than an expected exit.
func solveFunctionParams(program *mast.Program) map[*mast.FunctionLiteral]*solvedFunction {
	solved := map[*mast.FunctionLiteral]*solvedFunction{}
	if program == nil {
		return solved
	}

	byName := map[string]*solvedFunction{}
	for _, binding := range functionBindings(program) {
		fn := &solvedFunction{name: binding.name, literal: binding.literal}
		for _, p := range binding.literal.Parameters {
			if p == nil {
				continue
			}
			fn.params = append(fn.params, p.Value)
			fn.kinds = append(fn.kinds, ksAny)
			fn.observed = append(fn.observed, 0)
		}
		solved[binding.literal] = fn
		// A later binding of the same name shadows an earlier one; the last
		// wins, matching how a reader would resolve the call.
		byName[binding.name] = fn
	}

	for round := 0; round < 8; round++ {
		changed := false
		for _, fn := range solved {
			if fn.literal.Body == nil {
				continue
			}
			before := append([]kindSet(nil), fn.kinds...)
			constrainBody(fn, fn.literal.Body, byName)
			for i := range fn.kinds {
				if fn.kinds[i] != before[i] {
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	observeCallSites(program, byName)
	return solved
}

type functionBinding struct {
	name    string
	literal *mast.FunctionLiteral
}

// functionBindings collects every `let name = fn(...) {...}` in the document,
// including ones nested inside other functions.
func functionBindings(program *mast.Program) []functionBinding {
	var bindings []functionBinding
	var walkStatement func(mast.Statement)
	var walkExpression func(mast.Expression)

	walkExpression = func(e mast.Expression) {
		switch n := e.(type) {
		case *mast.FunctionLiteral:
			if n.Body != nil {
				for _, s := range n.Body.Statements {
					walkStatement(s)
				}
			}
		case *mast.CallExpression:
			walkExpression(n.Function)
			for _, arg := range n.Arguments {
				walkExpression(arg)
			}
		case *mast.InfixExpression:
			walkExpression(n.Left)
			walkExpression(n.Right)
		}
	}

	walkStatement = func(s mast.Statement) {
		switch n := s.(type) {
		case *mast.LetStatement:
			if literal, ok := n.Value.(*mast.FunctionLiteral); ok {
				name := ""
				if n.Name != nil {
					name = n.Name.Value
				}
				if literal.Name != "" {
					name = literal.Name
				}
				bindings = append(bindings, functionBinding{name: name, literal: literal})
			}
			walkExpression(n.Value)
		case *mast.ExpressionStatement:
			walkExpression(n.Expression)
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walkStatement(inner)
			}
		case *mast.ForStatement:
			if n.Body != nil {
				walkStatement(n.Body)
			}
		case *mast.ReturnStatement:
			for _, value := range n.ReturnValues {
				walkExpression(value)
			}
			if n.ReturnValue != nil {
				walkExpression(n.ReturnValue)
			}
		}
	}

	for _, stmt := range program.Statements {
		walkStatement(stmt)
	}
	return bindings
}

// constrainBody narrows fn's parameters by every use of them in one body.
func constrainBody(fn *solvedFunction, body *mast.BlockStatement, byName map[string]*solvedFunction) {
	narrow := func(e mast.Expression, allowed kindSet) {
		ident, ok := e.(*mast.Identifier)
		if !ok || ident == nil {
			return
		}
		for i, name := range fn.params {
			if name == ident.Value {
				fn.kinds[i] &= allowed
			}
		}
	}

	visit := func(e mast.Expression) {
		switch n := e.(type) {
		case *mast.CallExpression:
			constrainCall(n, narrow, byName)
		case *mast.InfixExpression:
			switch n.Operator {
			case "+":
				narrow(n.Left, ksAddable)
				narrow(n.Right, ksAddable)
			case "-", "*", "/", "%":
				narrow(n.Left, ksNumeric)
				narrow(n.Right, ksNumeric)
			case "<", ">", "<=", ">=":
				narrow(n.Left, ksComparable)
				narrow(n.Right, ksComparable)
			}
		case *mast.PrefixExpression:
			if n.Operator == "-" {
				narrow(n.Right, ksNumeric)
			}
		}
	}

	walkBodyExpressions(body, visit)
}

// walkBodyExpressions visits every expression in a function body, without
// descending into a nested function literal.
//
// A closure can capture an outer parameter, so its uses would be legitimate
// evidence — but its own parameters can shadow one by name, and this solver
// works by name. Rather than track scopes to tell the two apart, it declines to
// look: a missed constraint costs a less specific hover, a constraint taken from
// the wrong `x` would state a type the parameter does not have.
func walkBodyExpressions(body *mast.BlockStatement, visit func(mast.Expression)) {
	if body == nil {
		return
	}

	var walkStatement func(mast.Statement)
	var walkExpression func(mast.Expression)

	walkExpression = func(e mast.Expression) {
		if e == nil {
			return
		}
		visit(e)
		switch n := e.(type) {
		case *mast.CallExpression:
			walkExpression(n.Function)
			for _, arg := range n.Arguments {
				walkExpression(arg)
			}
		case *mast.InfixExpression:
			walkExpression(n.Left)
			walkExpression(n.Right)
		case *mast.PrefixExpression:
			walkExpression(n.Right)
		case *mast.IndexExpression:
			walkExpression(n.Left)
			walkExpression(n.Index)
		case *mast.AssignExpression:
			walkExpression(n.Left)
			walkExpression(n.Value)
		case *mast.FieldExpression:
			walkExpression(n.Left)
		case *mast.ArrayLiteral:
			for _, el := range n.Elements {
				walkExpression(el)
			}
		case *mast.HashLiteral:
			for key, value := range n.Pairs {
				walkExpression(key)
				walkExpression(value)
			}
		case *mast.IfExpression:
			walkExpression(n.Condition)
			if n.Consequence != nil {
				walkStatement(n.Consequence)
			}
			if n.Alternative != nil {
				walkStatement(n.Alternative)
			}
		}
	}

	walkStatement = func(s mast.Statement) {
		switch n := s.(type) {
		case *mast.LetStatement:
			walkExpression(n.Value)
		case *mast.ExpressionStatement:
			walkExpression(n.Expression)
		case *mast.ReturnStatement:
			for _, value := range n.ReturnValues {
				walkExpression(value)
			}
			walkExpression(n.ReturnValue)
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walkStatement(inner)
			}
		case *mast.ForStatement:
			if n.Init != nil {
				walkStatement(n.Init)
			}
			walkExpression(n.Condition)
			walkExpression(n.Post)
			if n.Body != nil {
				walkStatement(n.Body)
			}
		}
	}

	for _, stmt := range body.Statements {
		walkStatement(stmt)
	}
}

// constrainCall narrows the arguments of one call against whatever the callee
// demands — a builtin's declared contract, or another user function's solved
// parameters.
func constrainCall(call *mast.CallExpression, narrow func(mast.Expression, kindSet), byName map[string]*solvedFunction) {
	callee, ok := call.Function.(*mast.Identifier)
	if !ok || callee == nil {
		return
	}

	// Calling a parameter means that parameter is a function.
	narrow(call.Function, ksFn)

	if params, ok := builtin.ParamSpecs(callee.Value); ok {
		if !argumentCountFitsParams(params, len(call.Arguments)) {
			return // the arity rule's complaint, not this one's
		}
		for i, arg := range call.Arguments {
			param, ok := paramForArgument(params, i)
			if !ok {
				continue
			}
			narrow(arg, kindSetFor(param.Kinds))
		}
		return
	}

	target, ok := byName[callee.Value]
	if !ok || target == nil {
		return
	}
	for i, arg := range call.Arguments {
		if i >= len(target.kinds) {
			break
		}
		narrow(arg, target.kinds[i])
	}
}

// observeCallSites records the kinds actually passed at each call site in this
// document, for the parameters the body left unconstrained.
//
// This is deliberately weaker than a constraint and is presented as such. A
// function called once with a string is not a function that takes strings; it is
// a function nobody has yet called with anything else. Showing that as the type
// would be the one way this feature could actively mislead.
func observeCallSites(program *mast.Program, byName map[string]*solvedFunction) {
	if program.NodePositions == nil {
		return
	}
	for node := range program.NodePositions {
		call, ok := node.(*mast.CallExpression)
		if !ok || call == nil {
			continue
		}
		callee, ok := call.Function.(*mast.Identifier)
		if !ok || callee == nil {
			continue
		}
		target, ok := byName[callee.Value]
		if !ok || target == nil {
			continue
		}
		for i, arg := range call.Arguments {
			if i >= len(target.observed) {
				break
			}
			if set, ok := literalKindSet(arg); ok {
				target.observed[i] |= set
			}
		}
	}
}

// literalKindSet reads the kind of an argument whose type is visible in the
// syntax. Only literals count: anything else would need inference, and this
// runs before it.
func literalKindSet(e mast.Expression) (kindSet, bool) {
	switch n := e.(type) {
	case *mast.StringLiteral:
		return ksString, true
	case *mast.IntegerLiteral:
		return ksInt, true
	case *mast.FloatLiteral:
		return ksFloat, true
	case *mast.Boolean:
		return ksBool, true
	case *mast.ArrayLiteral:
		return ksArray, true
	case *mast.HashLiteral:
		return ksHash, true
	case *mast.FunctionLiteral:
		return ksFn, true
	case *mast.PrefixExpression:
		if n.Operator == "-" {
			return literalKindSet(n.Right)
		}
		if n.Operator == "!" {
			return ksBool, true
		}
	}
	return 0, false
}
