package sema

import "mutant/ast"

// The walk. One switch per AST level, and the only one in the package.
//
// Its traversal order is the order the language server's five walks used,
// preserved deliberately rather than tidied: a name is bound at the point the
// walk reaches its declaration, so a use before a declaration resolves to
// nothing and a use after it resolves to that declaration. `let f = fn() {
// f(); };` recurses because a single-name `let` binds before its value is
// walked, and `let a, b = split();` does not, because a multi-name `let` binds
// after. Both are the compiler's rules, and changing either here would change
// what the editor says about a program without changing the program.

func (b *builder) statement(stmt ast.Statement) {
	switch node := stmt.(type) {
	case nil:
		return

	case *ast.LetStatement:
		b.letStatement(node)

	case *ast.ImportStatement:
		b.importStatement(node)

	case *ast.ReturnStatement:
		for _, value := range node.ReturnValues {
			b.expression(value, nil)
		}
		if len(node.ReturnValues) == 0 {
			b.expression(node.ReturnValue, nil)
		}

	case *ast.ExpressionStatement:
		b.expression(node.Expression, nil)

	case *ast.BlockStatement:
		// No scope is opened. A block does not introduce one in Mutant:
		// `{ let x = 1; }` leaves x bound after the closing brace.
		for _, inner := range node.Statements {
			b.statement(inner)
		}

	case *ast.WhileStatement:
		b.expression(node.Condition, nil)
		b.block(node.Body)

	case *ast.ForInStatement:
		// The bindings land in the enclosing scope, not the body, which is
		// what the VM does with either loop form.
		for _, name := range []*ast.Identifier{node.Key, node.Value} {
			if rng, ok := b.rangeOf(name); ok {
				b.declare(name.Value, name, rng, KindLoopBind)
			}
		}
		b.expression(node.Iterable, nil)
		b.block(node.Body)

	case *ast.ForStatement:
		b.statement(node.Init)
		b.expression(node.Condition, nil)
		b.expression(node.Post, nil)
		b.block(node.Body)

	case *ast.StructStatement:
		b.typeStatement(node.Name, node.Fields, KindStruct, KindField)

	case *ast.EnumStatement:
		b.typeStatement(node.Name, node.Variants, KindEnum, KindVariant)

	case *ast.BreakStatement, *ast.ContinueStatement:
		// No names, no children.
	}
}

func (b *builder) letStatement(node *ast.LetStatement) {
	names := node.Names
	if len(names) == 0 && node.Name != nil {
		names = []*ast.Identifier{node.Name}
	}

	if len(names) == 1 {
		name := names[0]
		var bound *Node
		if rng, ok := b.rangeOf(name); ok {
			bound = b.declare(name.Value, name, rng, kindForValue(node.Value))
		}
		// Bound before the value is walked, which is what makes a function
		// literal able to call itself.
		b.expression(node.Value, bound)
		return
	}

	b.expression(node.Value, nil)
	for _, name := range names {
		if rng, ok := b.rangeOf(name); ok {
			// Grouped: this let bound more than one name, which in Mutant means
			// the (value, err) idiom rather than a convenience.
			if declared := b.declare(name.Value, name, rng, KindValue); declared != nil {
				declared.Grouped = true
			}
		}
	}
}

// importStatement binds the namespace an import names.
//
// This is the case none of the walks this graph replaces had at all. The alias
// is an ordinary declaration in the file's top-level scope: it can be completed,
// it has a definition to go to, and it can be found by find-references, none of
// which was true before.
//
// The declaration has no name range when the namespace was derived rather than
// written -- `import "lib/report.mut";` binds `report` without the word
// `report` appearing anywhere. Go-to-definition still lands on the statement,
// because FullRange covers it; rename declines, because there is no text that
// spells the name and rewriting the path instead would break the import.
func (b *builder) importStatement(node *ast.ImportStatement) {
	alias := node.Namespace()
	if alias == "" {
		return
	}

	stmtRange, haveStatement := b.rangeOf(node)
	if !haveStatement {
		// Fall back to the path literal so the alias still has somewhere to
		// point, rather than dropping the binding entirely.
		stmtRange, haveStatement = b.rangeOf(node.Path)
	}
	declRange, _ := b.rangeOf(node.Alias)
	if !haveStatement && !declRange.IsValid() {
		return
	}

	var spelling string
	if node.Path != nil {
		spelling = node.Path.Value
	}
	target := b.targets[alias]

	bound := b.declareIn(b.g.Root, alias, node.Alias, declRange, stmtRange, KindNamespace)
	if bound != nil {
		bound.Target = target
	}
	b.g.imports = append(b.g.imports, ImportEdge{
		From:      b.g.Module,
		To:        target,
		Alias:     alias,
		Spelling:  spelling,
		Range:     stmtRange,
		Statement: node,
	})
}

// typeStatement declares a struct or enum and its members.
//
// Type names do not go in the scope chain. A struct or enum name never enters
// the compiler's symbol table -- it is claimed program-wide by claimTypeName
// and stored in a flat map -- so `struct Point { x }` and `let Point = 1` are
// two different bindings that do not shadow each other, and a bare `Point` in
// value position is the let. They live in their own table, under ScopeType.
func (b *builder) typeStatement(name *ast.Identifier, members []*ast.Identifier, typeKind, memberKind NodeKind) {
	rng, ok := b.rangeOf(name)
	if !ok {
		return
	}

	declared := b.declareIn(b.types(), name.Value, name, rng, rng, typeKind)
	memberScope := b.memberScope(segmentFor(declared, name.Value), declared)
	for _, member := range members {
		if memberRange, ok := b.rangeOf(member); ok {
			b.declareIn(memberScope, member.Value, member, memberRange, memberRange, memberKind)
		}
	}
}

func (b *builder) expression(expr ast.Expression, boundTo *Node) {
	switch node := expr.(type) {
	case nil:
		return

	case *ast.Identifier:
		b.reference(node, false)

	case *ast.FunctionLiteral:
		b.functionScope(node, node.Parameters, node.Body, boundTo, "fn")

	case *ast.MacroLiteral:
		b.functionScope(node, node.Parameters, node.Body, boundTo, "macro")

	case *ast.IfExpression:
		b.expression(node.Condition, nil)
		b.block(node.Consequence)
		b.block(node.Alternative)

	case *ast.MatchExpression:
		b.expression(node.Subject, nil)
		for _, arm := range node.Arms {
			if arm == nil {
				continue
			}
			// Patterns are walked so that go-to-definition on the `Status` of
			// a `Status.Ok` arm reaches the enum declaration.
			for _, pattern := range arm.Patterns {
				b.expression(pattern, nil)
			}
			b.block(arm.Body)
		}

	case *ast.CallExpression:
		if callee, isIdent := node.Function.(*ast.Identifier); isIdent {
			b.reference(callee, true)
		} else {
			b.expression(node.Function, nil)
		}
		for _, arg := range node.Arguments {
			b.expression(arg, nil)
		}

	case *ast.PrefixExpression:
		b.expression(node.Right, nil)

	case *ast.InfixExpression:
		b.expression(node.Left, nil)
		b.expression(node.Right, nil)

	case *ast.IndexExpression:
		b.expression(node.Left, nil)
		b.expression(node.Index, nil)

	case *ast.AssignExpression:
		b.expression(node.Left, nil)
		b.expression(node.Value, nil)

	case *ast.FieldExpression:
		b.fieldExpression(node)

	case *ast.StructLiteral:
		b.structLiteral(node)

	case *ast.ArrayLiteral:
		for _, element := range node.Elements {
			b.expression(element, nil)
		}

	case *ast.TemplateLiteral:
		for _, part := range node.Parts {
			b.expression(part, nil)
		}

	case *ast.HashLiteral:
		// Pairs is a map, so this reaches the entries in a different order on
		// every run. BuildFile sorts the references it produces for exactly
		// this reason.
		for key, value := range node.Pairs {
			b.expression(key, nil)
			b.expression(value, nil)
		}
	}
}

// fieldExpression records what `left.field` refers to.
//
// The left-hand side is resolved as an ordinary use, which is what gives an
// import alias and an enum name a reference. The field itself has three
// outcomes:
//
//   - `Colour.Red`, where the left names an enum declared here, is a reference
//     to the variant. It needs nothing but names, so the graph decides it.
//   - `p.x`, where the left holds a struct, is a reference to that struct's
//     field -- but only the caller's StructOf can say which struct, so the
//     graph asks and resolves the answer. Without an oracle it stays
//     unresolved.
//   - `stats.mean` is a declaration in another file and belongs to the
//     cross-module path, not here.
//
// The field name is recorded either way. Where it is written is a question
// about positions; what it means is not.
func (b *builder) fieldExpression(node *ast.FieldExpression) {
	b.noteField(node.Field)

	left, isIdent := node.Left.(*ast.Identifier)
	if !isIdent {
		b.expression(node.Left, nil)
		return
	}

	// Enum first, matching Resolver.ResolveField: `Colour.Red` is the enum
	// even where a `let Colour` also exists.
	if enum := b.lookupType(left.Value, KindEnum); enum != nil {
		if rng, ok := b.rangeOf(left); ok {
			b.record(left, rng, enum.ID, false)
		}
		if variant := b.lookupMember(enum, node.Field); variant != nil {
			if rng, ok := b.rangeOf(node.Field); ok {
				b.record(node.Field, rng, variant.ID, false)
			}
		}
		return
	}

	// The left is an ordinary use, which is what gives an import alias its
	// reference. Where it names nothing, the miss is recorded with the member
	// beside it rather than as a bare identifier: `str` alone is not a name in
	// any Mutant program, and `str.upper` is str_upper.
	if target := b.lookup(left.Value); target != nil {
		if rng, ok := b.rangeOf(left); ok {
			b.record(left, rng, target.ID, false)
		}
		b.structField(left, node.Field)
		return
	}
	b.unboundReceiver(left, node)
}

// structField resolves `p.x` by asking the caller what p holds.
func (b *builder) structField(left, field *ast.Identifier) {
	if b.structOf == nil || field == nil {
		return
	}
	holder := b.lookup(left.Value)
	if holder == nil || holder.Ident == nil {
		return
	}
	declared := b.lookupType(b.structOf(holder.Ident), KindStruct)
	if declared == nil {
		return
	}
	member := b.lookupMember(declared, field)
	if member == nil {
		return
	}
	if rng, ok := b.rangeOf(field); ok {
		b.record(field, rng, member.ID, false)
	}
}

func (b *builder) noteField(field *ast.Identifier) {
	if rng, ok := b.rangeOf(field); ok {
		b.g.fields = append(b.g.fields, fieldName{ident: field, rng: rng})
	}
}

// structLiteral records what `Point{x: 5}` refers to.
//
// The literal's name is a TYPE, so it is looked up in the type table and
// nowhere else. A file with `let Point = 1;` and no struct Point has the name
// bound and still cannot write the literal -- the compiler refuses it with
// "undefined struct type: Point" -- so a miss here is recorded as a miss, and
// the value table is not consulted to excuse it.
//
// A field name is not a use of anything until the struct is known, which is why
// the miss is recorded for the type name only. `Nope{x: 1}` is one mistake, not
// two, and reporting `x` as undefined as well would be reporting the half the
// author got right.
func (b *builder) structLiteral(node *ast.StructLiteral) {
	var declared *Node
	if node.Name != nil {
		declared = b.lookupType(node.Name.Value, KindStruct)
		if rng, ok := b.rangeOf(node.Name); ok {
			if declared != nil {
				b.record(node.Name, rng, declared.ID, false)
			} else {
				b.noteUnbound(node.Name, rng, UnboundType, false)
			}
		}
	}
	for _, field := range node.Fields {
		if field == nil {
			continue
		}
		if declared != nil {
			if member := b.lookupMember(declared, field.Name); member != nil {
				if rng, ok := b.rangeOf(field.Name); ok {
					b.record(field.Name, rng, member.ID, false)
				}
			}
		}
		b.expression(field.Value, nil)
	}
}

// functionScope opens the one kind of scope Mutant has, binds the parameters in
// it, and walks the body.
//
// The scope covers the whole literal rather than just its body, because the
// parameters are declared in the header: a cursor on a parameter name is inside
// the scope that parameter belongs to, and a scope stopping at the opening
// brace would place it in the enclosing one.
func (b *builder) functionScope(literal ast.Node, params []*ast.Identifier, body *ast.BlockStatement, boundTo *Node, anonPrefix string) {
	segment := segmentFor(boundTo, "")
	if segment == "" {
		segment = b.anonSegment(anonPrefix)
	}

	scopeRange, ok := b.rangeOf(literal)
	if !ok {
		scopeRange, _ = b.rangeOf(body)
	}
	b.push(segment, scopeRange, boundTo)
	for _, param := range params {
		if rng, ok := b.rangeOf(param); ok {
			b.declare(param.Value, param, rng, KindParam)
		}
	}
	b.block(body)
	b.pop()
}

// block walks a body.
//
// Every block in Mutant is a body -- of a function, a loop, an `if` arm, a
// match arm -- and every one of those fields is a *ast.BlockStatement rather
// than the Statement interface. An absent body is therefore a typed nil, which
// is not a nil interface and does not match `case nil`: it selects the
// *ast.BlockStatement arm with a nil receiver and reading Statements off it
// panics. `if (x) { }` has exactly that shape, and it panicked here until the
// coverage test ran.
//
// A block opens no scope. `{ let x = 1; }` leaves x bound after the closing
// brace, so the declarations inside one go to the enclosing scope.
func (b *builder) block(body *ast.BlockStatement) {
	if body == nil {
		return
	}
	for _, inner := range body.Statements {
		b.statement(inner)
	}
}

func kindForValue(value ast.Expression) NodeKind {
	if _, isFunction := value.(*ast.FunctionLiteral); isFunction {
		return KindFunction
	}
	return KindValue
}
