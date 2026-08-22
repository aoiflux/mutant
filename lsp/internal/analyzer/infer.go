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
	// solved holds each function literal's parameter kinds, worked out by
	// fn_solver.go before this walk. Seeding them turns a body that could only
	// be typed as Any into one whose return type follows from its parameters.
	solved map[*mast.FunctionLiteral]*solvedFunction
	// structFields holds each struct's field types as seen in its initializers,
	// keyed structName -> fieldName -> Type. See observeStructField.
	structFields map[string]map[string]Type
}

// inferTypes returns a map of AST node -> inferred Type (only confidently-typed
// nodes are present; absence means Any) plus the struct field-type table keyed
// structName -> fieldName -> Type.
func inferTypes(s *Snapshot) (map[mast.Node]Type, map[string]map[string]Type) {
	if s == nil || s.Program == nil {
		return map[mast.Node]Type{}, map[string]map[string]Type{}
	}
	inf := &typeInferer{
		nodeTypes:    make(map[mast.Node]Type),
		structNames:  make(map[string]bool),
		enumNames:    make(map[string]bool),
		structFields: make(map[string]map[string]Type),
		solved:       s.solvedFunctions(),
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
	return inf.nodeTypes, inf.structFields
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
	if sig, ok := builtinReturnType(id.Value); ok && sig.pair && count >= 2 {
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
		var name string
		if n.Name != nil {
			name = n.Name.Value
		}
		for _, f := range n.Fields {
			if f == nil {
				continue
			}
			ft := inf.expr(f.Value, env)
			if name != "" && f.Name != nil {
				inf.observeStructField(name, f.Name.Value, ft)
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
		// A field access on a struct-typed value carries the field's type when it
		// was seen consistently across the struct's initializers.
		if lt.Kind == TypeStruct && lt.Name != "" && n.Field != nil {
			if ft, ok := inf.structFieldType(lt.Name, n.Field.Value); ok {
				// Record on the accessor identifier too, so hovering the field name
				// (the node under the cursor) shows its type.
				inf.record(n.Field, ft)
				return ft
			}
		}
		return AnyType
	case *mast.CallExpression:
		ft := inf.expr(n.Function, env)
		argTypes := make([]Type, len(n.Arguments))
		for i, a := range n.Arguments {
			argTypes[i] = inf.expr(a, env)
		}
		if id, ok := n.Function.(*mast.Identifier); ok {
			// Builtins whose result depends on their argument types
			// (element-preserving array ops, map's mapper return, numeric
			// kind-preservers) refine what the fixed builtinReturnTypes table —
			// which can only name a bare `array` — is able to express.
			if t, ok := argAwareCallType(id.Value, argTypes); ok {
				return t
			}
			if sig, ok := builtinReturnType(id.Value); ok {
				// A (value, err) builtin used as a single value is the whole
				// pair, not its first half. Saying `string` here would make
				// hover and the inlay hint on `let data = fs_read(p)` describe
				// a value the program never holds.
				if sig.pair {
					return multiOf(sig.ret)
				}
				return sig.ret
			}
		}
		// Calling a value with a known function type (a user function, or an
		// IIFE) yields that function's inferred return type.
		if ft.Kind == TypeFunction && ft.Ret != nil && ft.Ret.IsKnown() {
			return *ft.Ret
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
		solvedParams := inf.solved[n]
		for i, p := range n.Parameters {
			if p == nil {
				continue
			}
			// A solved parameter narrowed to exactly one kind is worth seeding;
			// a union collapses to Any, because the lattice has no union to
			// carry it and a guess would be worse than the gradual unknown.
			paramType := AnyType
			if solvedParams != nil && i < len(solvedParams.kinds) {
				paramType = solvedParams.kinds[i].asType()
			}
			child.set(p.Value, paramType)
			inf.record(p, paramType)
		}
		if n.Body != nil {
			inf.stmt(n.Body, child)
		}
		ret := inf.functionReturnType(n.Body)
		return Type{Kind: TypeFunction, Ret: &ret}
	default:
		return AnyType
	}
}

// functionReturnType infers a user function's return type by joining the types
// of everything it can yield: each explicit single-value `return`, plus the
// body's trailing expression (Mutant functions implicitly return their last
// expression). Any disagreement, a multi-value return, or an unknown collapses
// to Any. It reads types recorded by the preceding body walk, so it must run
// after inf.stmt has visited the body.
func (inf *typeInferer) functionReturnType(body *mast.BlockStatement) Type {
	if body == nil {
		return AnyType
	}

	var results []mast.Expression
	for _, s := range body.Statements {
		inf.collectReturnExprs(s, &results)
	}
	// Implicit trailing return: the last statement, when it is a bare value
	// expression. An `if` in tail position is control flow, not a value here — its
	// contribution already came from its branch returns above, and the `if` node
	// itself types as Any, so appending it would only poison the join.
	if n := len(body.Statements); n > 0 {
		if es, ok := body.Statements[n-1].(*mast.ExpressionStatement); ok && es.Expression != nil {
			if _, isIf := es.Expression.(*mast.IfExpression); !isIf {
				results = append(results, es.Expression)
			}
		}
	}
	if len(results) == 0 {
		return AnyType
	}

	joined := AnyType
	for i, e := range results {
		t := inf.recordedType(e)
		if i == 0 {
			joined = t
		} else {
			joined = joinTypes(joined, t)
		}
		if !joined.IsKnown() {
			return AnyType
		}
	}
	return joined
}

// collectReturnExprs gathers the value expressions of explicit `return`s reached
// from stmt without crossing into a nested function (whose returns belong to it).
// A multi-value return contributes a nil, which forces the join to Any.
func (inf *typeInferer) collectReturnExprs(stmt mast.Statement, out *[]mast.Expression) {
	switch n := stmt.(type) {
	case *mast.ReturnStatement:
		switch {
		case len(n.ReturnValues) == 1:
			*out = append(*out, n.ReturnValues[0])
		case len(n.ReturnValues) == 0 && n.ReturnValue != nil:
			*out = append(*out, n.ReturnValue)
		default:
			*out = append(*out, nil) // multi-value: ambiguous scalar type
		}
	case *mast.BlockStatement:
		for _, s := range n.Statements {
			inf.collectReturnExprs(s, out)
		}
	case *mast.ExpressionStatement:
		if ie, ok := n.Expression.(*mast.IfExpression); ok {
			if ie.Consequence != nil {
				inf.collectReturnExprs(ie.Consequence, out)
			}
			if ie.Alternative != nil {
				inf.collectReturnExprs(ie.Alternative, out)
			}
		}
	case *mast.ForStatement:
		if n.Body != nil {
			inf.collectReturnExprs(n.Body, out)
		}
	}
}

// recordedType returns the type recorded for an expression during the inference
// walk (nil or unrecorded expressions are Any).
func (inf *typeInferer) recordedType(e mast.Expression) Type {
	if e == nil {
		return AnyType
	}
	if t, ok := inf.nodeTypes[e]; ok {
		return t
	}
	return AnyType
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

// observeStructField folds a field's initializer type into the file-global struct
// field table. Types are joined across every initializer of the same struct, so a
// field keeps a concrete type only while every observed initializer agrees on it;
// any disagreement — or a single unknown initializer value — joins to Any and the
// field stops being typed. That conservative merge is what keeps struct-field
// types free of false positives.
func (inf *typeInferer) observeStructField(structName, field string, t Type) {
	if structName == "" || field == "" {
		return
	}
	m := inf.structFields[structName]
	if m == nil {
		m = make(map[string]Type)
		inf.structFields[structName] = m
	}
	if existing, ok := m[field]; ok {
		m[field] = joinTypes(existing, t)
	} else {
		m[field] = t
	}
}

// structFieldType returns a struct field's inferred type when every initializer
// seen so far agreed on a single known type for it (Any is treated as unknown).
func (inf *typeInferer) structFieldType(structName, field string) (Type, bool) {
	if m, ok := inf.structFields[structName]; ok {
		if t, ok := m[field]; ok && t.IsKnown() {
			return t, true
		}
	}
	return AnyType, false
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

// argAwareCallType types builtin calls whose result depends on the argument
// types — something the fixed builtinReturnTypes table, which can only name a
// bare `array`, cannot express. Element-preserving array ops carry the input's
// element type through; `map` takes the mapper's return type; `first`/`last`
// yield the element itself; and the numeric ops preserve int-vs-float. It returns
// (type, true) only when it produced something more precise than the table would;
// otherwise the caller falls back to the table. Every branch is conservative — an
// unknown element type or a disagreement yields (Any, false), never a wrong type,
// preserving the zero-false-positive contract.
func argAwareCallType(name string, argTypes []Type) (Type, bool) {
	arg := func(i int) Type {
		if i >= 0 && i < len(argTypes) {
			return argTypes[i]
		}
		return AnyType
	}
	// elemOf returns the known element type of an array-typed value.
	elemOf := func(t Type) (Type, bool) {
		if t.Kind == TypeArray && t.Elem != nil && t.Elem.IsKnown() {
			return *t.Elem, true
		}
		return AnyType, false
	}

	switch name {
	// first/last return an element, not an array.
	case "first", "last":
		if el, ok := elemOf(arg(0)); ok {
			return el, true
		}
	// Element-preserving array ops: the result's element type equals arg 0's.
	case "sort", "reverse", "unique", "rest", "pop", "slice", "sort_by", "filter":
		if el, ok := elemOf(arg(0)); ok {
			return arrayOf(el), true
		}
	case "push":
		// push(arr, elem): the element type survives only if the pushed value agrees.
		if el, ok := elemOf(arg(0)); ok {
			if j := joinTypes(el, arg(1)); j.IsKnown() {
				return arrayOf(j), true
			}
		}
	case "concat":
		// concat(a, b): survives only when both arrays share an element type.
		if ea, oka := elemOf(arg(0)); oka {
			if eb, okb := elemOf(arg(1)); okb {
				if j := joinTypes(ea, eb); j.IsKnown() {
					return arrayOf(j), true
				}
			}
		}
	case "map":
		// map(arr, fn): the result's element type is the mapper's return type.
		if fn := arg(1); fn.Kind == TypeFunction && fn.Ret != nil && fn.Ret.IsKnown() {
			return arrayOf(*fn.Ret), true
		}
	case "sum":
		// sum([]int) -> int, sum([]float) -> float.
		if el, ok := elemOf(arg(0)); ok && isNumericType(el) {
			return el, true
		}
	case "abs":
		// abs preserves its argument's numeric kind.
		if a := arg(0); isNumericType(a) {
			return a, true
		}
	case "min", "max", "clamp":
		// Preserve the numeric kind when every argument agrees (all int, all float).
		if len(argTypes) == 0 {
			return AnyType, false
		}
		j := arg(0)
		for i := 1; i < len(argTypes); i++ {
			j = joinTypes(j, arg(i))
		}
		if isNumericType(j) {
			return j, true
		}
	case "mod":
		if r := numericResultType(arg(0), arg(1)); isNumericType(r) {
			return r, true
		}
	}
	return AnyType, false
}
