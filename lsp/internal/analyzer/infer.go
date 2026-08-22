package analyzer

import mast "mutant/ast"

// Best-effort, flow-insensitive type inference for editor smarts (hover,
// completion detail, inlay hints). It walks the AST once, tracking a lexical
// scope of name->Type, and records a Type for each node it can confidently type.
// Unknowns are simply omitted (treated as Any). This has ZERO runtime effect.

type typeEnv struct {
	parent *typeEnv
	vars   map[string]Type
}

func newTypeEnv(parent *typeEnv) *typeEnv {
	return &typeEnv{parent: parent, vars: make(map[string]Type)}
}

func (e *typeEnv) set(name string, t Type) {
	if name == "" || name == "_" {
		return
	}
	e.vars[name] = t
}

func (e *typeEnv) get(name string) (Type, bool) {
	for s := e; s != nil; s = s.parent {
		if t, ok := s.vars[name]; ok {
			return t, true
		}
	}
	return AnyType, false
}

type typeInferer struct {
	nodeTypes   map[mast.Node]Type
	structNames map[string]bool
	enumNames   map[string]bool
}

// inferTypes returns a map of AST node -> inferred Type. Only confidently-typed
// nodes are present; absence means Any.
func inferTypes(s *Snapshot) map[mast.Node]Type {
	if s == nil || s.Program == nil {
		return map[mast.Node]Type{}
	}
	inf := &typeInferer{
		nodeTypes:   make(map[mast.Node]Type),
		structNames: make(map[string]bool),
		enumNames:   make(map[string]bool),
	}
	// Struct/enum type names are file-global; collect them first so a reference
	// before the declaration still resolves.
	for _, stmt := range s.Program.Statements {
		switch n := stmt.(type) {
		case *mast.StructStatement:
			if n.Name != nil {
				inf.structNames[n.Name.Value] = true
			}
		case *mast.EnumStatement:
			if n.Name != nil {
				inf.enumNames[n.Name.Value] = true
			}
		}
	}

	root := newTypeEnv(nil)
	for _, stmt := range s.Program.Statements {
		inf.stmt(stmt, root)
	}
	return inf.nodeTypes
}

func (inf *typeInferer) record(node mast.Node, t Type) {
	if node == nil || !t.IsKnown() {
		return
	}
	inf.nodeTypes[node] = t
}

func (inf *typeInferer) stmt(stmt mast.Statement, env *typeEnv) {
	switch n := stmt.(type) {
	case *mast.LetStatement:
		names := n.Names
		if len(names) == 0 && n.Name != nil {
			names = []*mast.Identifier{n.Name}
		}
		if len(names) <= 1 {
			t := inf.expr(n.Value, env)
			if n.Name != nil {
				inf.record(n.Name, t)
				env.set(n.Name.Value, t)
			}
			return
		}
		inf.expr(n.Value, env) // record inner nodes
		types := inf.multiBindTypes(n.Value, len(names))
		for i, nm := range names {
			if nm == nil {
				continue
			}
			inf.record(nm, types[i])
			env.set(nm.Value, types[i])
		}
	case *mast.ExpressionStatement:
		inf.expr(n.Expression, env)
	case *mast.ReturnStatement:
		if len(n.ReturnValues) > 0 {
			for _, e := range n.ReturnValues {
				inf.expr(e, env)
			}
		} else if n.ReturnValue != nil {
			inf.expr(n.ReturnValue, env)
		}
	case *mast.BlockStatement:
		child := newTypeEnv(env)
		for _, s := range n.Statements {
			inf.stmt(s, child)
		}
	case *mast.ForStatement:
		child := newTypeEnv(env)
		if n.Init != nil {
			inf.stmt(n.Init, child)
		}
		if n.Condition != nil {
			inf.expr(n.Condition, child)
		}
		if n.Post != nil {
			inf.expr(n.Post, child)
		}
		if n.Body != nil {
			inf.stmt(n.Body, child)
		}
	}
}

// multiBindTypes distributes types across `let a, b = value` names. A fallible
// builtin call types the first name as the value and the last as error; anything
// else is Any.
func (inf *typeInferer) multiBindTypes(value mast.Expression, count int) []Type {
	types := make([]Type, count)
	for i := range types {
		types[i] = AnyType
	}
	call, ok := value.(*mast.CallExpression)
	if !ok {
		return types
	}
	id, ok := call.Function.(*mast.Identifier)
	if !ok {
		return types
	}
	if sig, ok := builtinReturnType(id.Value); ok && sig.fallible && count >= 2 {
		types[0] = sig.ret
		types[count-1] = Type{Kind: TypeError}
	}
	return types
}

func (inf *typeInferer) expr(e mast.Expression, env *typeEnv) Type {
	if e == nil {
		return AnyType
	}
	t := inf.exprKind(e, env)
	inf.record(e, t)
	return t
}

func (inf *typeInferer) exprKind(e mast.Expression, env *typeEnv) Type {
	switch n := e.(type) {
	case *mast.IntegerLiteral:
		return tInt
	case *mast.FloatLiteral:
		return tFloat
	case *mast.StringLiteral:
		return tString
	case *mast.Boolean:
		return tBool
	case *mast.ArrayLiteral:
		var elem Type = AnyType
		for i, el := range n.Elements {
			et := inf.expr(el, env)
			if i == 0 {
				elem = et
			} else {
				elem = joinTypes(elem, et)
			}
		}
		if len(n.Elements) == 0 {
			return tArray
		}
		return arrayOf(elem)
	case *mast.HashLiteral:
		for k, v := range n.Pairs {
			inf.expr(k, env)
			inf.expr(v, env)
		}
		return tHash
	case *mast.StructLiteral:
		for _, f := range n.Fields {
			if f != nil {
				inf.expr(f.Value, env)
			}
		}
		if n.Name != nil {
			return Type{Kind: TypeStruct, Name: n.Name.Value}
		}
		return Type{Kind: TypeStruct}
	case *mast.Identifier:
		if t, ok := env.get(n.Value); ok {
			return t
		}
		if inf.enumNames[n.Value] {
			return Type{Kind: TypeEnum, Name: n.Value}
		}
		if inf.structNames[n.Value] {
			return Type{Kind: TypeStruct, Name: n.Value}
		}
		return AnyType
	case *mast.PrefixExpression:
		rt := inf.expr(n.Right, env)
		if n.Operator == "!" {
			return tBool
		}
		if n.Operator == "-" && isNumericType(rt) {
			return rt
		}
		return AnyType
	case *mast.InfixExpression:
		lt := inf.expr(n.Left, env)
		rt := inf.expr(n.Right, env)
		return infixType(n.Operator, lt, rt)
	case *mast.IndexExpression:
		lt := inf.expr(n.Left, env)
		inf.expr(n.Index, env)
		if lt.Kind == TypeArray && lt.Elem != nil {
			return *lt.Elem
		}
		return AnyType
	case *mast.FieldExpression:
		lt := inf.expr(n.Left, env)
		if lt.Kind == TypeEnum {
			return lt // `Color.Red` is a value of the enum
		}
		return AnyType
	case *mast.CallExpression:
		inf.expr(n.Function, env)
		for _, a := range n.Arguments {
			inf.expr(a, env)
		}
		if id, ok := n.Function.(*mast.Identifier); ok {
			if sig, ok := builtinReturnType(id.Value); ok {
				return sig.ret
			}
		}
		return AnyType
	case *mast.AssignExpression:
		inf.expr(n.Left, env)
		return inf.expr(n.Value, env)
	case *mast.IfExpression:
		inf.expr(n.Condition, env)
		if n.Consequence != nil {
			inf.stmt(n.Consequence, env)
		}
		if n.Alternative != nil {
			inf.stmt(n.Alternative, env)
		}
		return AnyType
	case *mast.FunctionLiteral:
		child := newTypeEnv(env)
		for _, p := range n.Parameters {
			if p != nil {
				child.set(p.Value, AnyType)
			}
		}
		if n.Body != nil {
			inf.stmt(n.Body, child)
		}
		return Type{Kind: TypeFunction}
	default:
		return AnyType
	}
}

func isNumericType(t Type) bool {
	return t.Kind == TypeInt || t.Kind == TypeFloat
}

func joinTypes(a, b Type) Type {
	if a.Kind == b.Kind && a.Name == b.Name {
		return a
	}
	return AnyType
}

func infixType(operator string, lt, rt Type) Type {
	switch operator {
	case "<", ">", "<=", ">=", "==", "!=", "&&", "||":
		return tBool
	case "+":
		if lt.Kind == TypeString || rt.Kind == TypeString {
			return tString
		}
		return numericResultType(lt, rt)
	case "-", "*", "/", "%":
		return numericResultType(lt, rt)
	default:
		return AnyType
	}
}

func numericResultType(lt, rt Type) Type {
	if lt.Kind == TypeFloat || rt.Kind == TypeFloat {
		return tFloat
	}
	if lt.Kind == TypeInt && rt.Kind == TypeInt {
		return tInt
	}
	return AnyType
}
