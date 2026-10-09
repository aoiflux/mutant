package compiler

import (
	"errors"

	"mutant/ast"
	"mutant/object"
)

// Which struct a value holds is not a question about names, so sema does not
// answer it -- lsp/internal/analyzer/struct_type.go says so for the editor's
// half, and says why: which field `x` names depends on what `p` contains, and
// that is inference.
//
// This is the compiler's half, and it is deliberately only the certain part of
// that inference: a name the program binds once, from a struct literal, and
// never binds or assigns again. For such a name the declaration is known, so a
// field the declaration does not contain is a mistake the compiler can refuse
// instead of leaving to run time (owner rule, 2026-10-02: an error that can be
// caught at compile time is caught at compile time).
//
// Everything else -- a parameter, a function's return, an element of an array --
// is refused one step later, by both engines' field access. That is not a
// weaker guarantee, only a later one: examples/binary/static_bin_analysis.mut
// reads every one of its fields through a parameter, so the later refusal is
// the one that covers most real code.
//
// Soundness is the whole of the design here, because being wrong means refusing
// a program that works. Two rules buy it:
//
//   - EVERY occurrence of the name in the program has to be a read or the one
//     `let` that bound it. A second binding, an assignment, a parameter or a
//     `for…in` variable of that name anywhere drops it -- including one that
//     appears after the read, which is what keeps
//     `let p = P{a:1}; let f = fn(){ return p.zzz; }; p = Q{zzz:1};`
//     compiling. An in-order tracker would have refused that program's third
//     line of meaning on its second line.
//   - A node type the walk does not know abandons the whole program's tracking
//     rather than skipping that subtree. A skipped subtree is how an unseen
//     assignment becomes a wrong refusal; abandoning makes it a missed refusal,
//     which both engines still catch. ast.Modify's doc comment records what the
//     other choice costs: a missing *CallExpression case meant macro expansion
//     never reached a macro used as an argument.
//
// The names are per module, like claimTypeName's: a value name belongs to the
// module that bound it, and only type names are program-global.

// refuseDuplicateFields refuses a declaration that names one field twice.
//
// `struct P { a; a; }` used to be caught by accident, two steps later: the
// literal `P { a: 1 }` was refused as "expects 2 fields, got 1", which named
// neither the real mistake nor the place it was made. That count check is gone
// now -- a literal reports the field names that differ instead -- so the repeat
// is refused here, where it was written, and the two changes have to land
// together.
//
// It is also incoherent on its own terms: Fields is a map, so one of the two
// declarations could never have a value of its own.
func refuseDuplicateFields(node *ast.StructStatement) error {
	seen := make(map[string]bool, len(node.Fields))
	for _, field := range node.Fields {
		if field == nil {
			continue
		}
		if seen[field.Value] {
			return errors.New(object.DuplicateStructFieldDeclarationMessage(
				node.Name.Value, field.Value))
		}
		seen[field.Value] = true
	}
	return nil
}

// structBindingScan is one program's worth of "which names certainly hold a
// struct".
type structBindingScan struct {
	// candidate maps a name to the struct type the single `let` gave it.
	candidate map[string]string

	// poisoned holds every name bound or written anywhere other than that one
	// `let`. A poisoned name is never tracked, whatever else the walk saw.
	poisoned map[string]bool

	// complete is false once the walk met a node type it has no case for.
	complete bool
}

func newStructBindingScan() *structBindingScan {
	return &structBindingScan{
		candidate: make(map[string]string),
		poisoned:  make(map[string]bool),
		complete:  true,
	}
}

// bind records a binding of name. structType is the struct type a `let` from a
// struct literal gave it, and "" for every other kind of binding.
//
// A name bound twice is poisoned however it was bound, because a read of it can
// then only be attributed by knowing where the read is, and where a read is is
// the scope question this deliberately does not ask.
func (s *structBindingScan) bind(name, structType string) {
	if name == "" {
		return
	}
	if _, already := s.candidate[name]; already || structType == "" {
		s.poisoned[name] = true
		return
	}
	s.candidate[name] = structType
}

// write records that name is bound or assigned somewhere that makes its value a
// question about where in the program you are.
func (s *structBindingScan) write(name string) {
	if name != "" {
		s.poisoned[name] = true
	}
}

func (s *structBindingScan) block(node *ast.BlockStatement) {
	if node == nil {
		return
	}
	for _, stmt := range node.Statements {
		s.statement(stmt)
	}
}

func (s *structBindingScan) statement(node ast.Statement) {
	switch node := node.(type) {
	case nil:
		return

	case *ast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*ast.Identifier{node.Name}
		}
		// Only a single-name `let` from a struct literal says anything about a
		// type. `let a, b = f()` spreads a multi-value or an array, and which
		// half each name gets is not a question answered here.
		structType := ""
		if literal, isLiteral := node.Value.(*ast.StructLiteral); isLiteral &&
			literal != nil && literal.Name != nil && len(names) == 1 {
			structType = literal.Name.Value
		}
		for _, name := range names {
			if name != nil {
				s.bind(name.Value, structType)
			}
		}
		s.expression(node.Value)

	case *ast.ReturnStatement:
		s.expression(node.ReturnValue)
		for _, expr := range node.ReturnValues {
			s.expression(expr)
		}

	case *ast.ExpressionStatement:
		s.expression(node.Expression)

	case *ast.BlockStatement:
		s.block(node)

	case *ast.ForStatement:
		// Init is a statement, and is where `for (let i = 0; …)` binds i.
		s.statement(node.Init)
		s.expression(node.Condition)
		s.expression(node.Post)
		s.block(node.Body)

	case *ast.ForInStatement:
		// A `for…in` variable is defined in the ENCLOSING scope, not the body
		// (sema.Scope's doc comment: mutant has fewer scopes than its syntax
		// suggests), so it is a second binding of the name wherever the name is
		// also let-bound.
		if node.Key != nil {
			s.write(node.Key.Value)
		}
		if node.Value != nil {
			s.write(node.Value.Value)
		}
		s.expression(node.Iterable)
		s.block(node.Body)

	case *ast.WhileStatement:
		s.expression(node.Condition)
		s.block(node.Body)

	case *ast.ImportStatement:
		// An import namespace is not a value, and sema resolves `ns.member`
		// before a field read is ever considered. The alias is poisoned anyway,
		// because the cost is nothing and the alternative is relying on that
		// ordering staying as it is.
		if node.Alias != nil {
			s.write(node.Alias.Value)
		}

	case *ast.StructStatement, *ast.EnumStatement,
		*ast.BreakStatement, *ast.ContinueStatement:
		// A type declaration binds no value name, and neither jump holds an
		// expression.

	default:
		s.complete = false
	}
}

func (s *structBindingScan) expression(node ast.Expression) {
	switch node := node.(type) {
	case nil:
		return

	case *ast.Identifier, *ast.IntegerLiteral, *ast.FloatLiteral,
		*ast.StringLiteral, *ast.Boolean:
		// Leaves. A bare read is the one occurrence that keeps a name tracked.

	case *ast.AssignExpression:
		// A bare name on the left is a write to the name. A field or an index
		// on the left is a write THROUGH the name, which reads it -- and is the
		// very thing this file exists to let the compiler check -- so the target
		// is walked instead.
		if base, isName := node.Left.(*ast.Identifier); isName {
			s.write(base.Value)
		} else {
			s.expression(node.Left)
		}
		s.expression(node.Value)

	case *ast.InfixExpression:
		s.expression(node.Left)
		s.expression(node.Right)

	case *ast.PrefixExpression:
		s.expression(node.Right)

	case *ast.IndexExpression:
		s.expression(node.Left)
		s.expression(node.Index)

	case *ast.FieldExpression:
		s.expression(node.Left)

	case *ast.CallExpression:
		s.expression(node.Function)
		for _, arg := range node.Arguments {
			s.expression(arg)
		}

	case *ast.ArrayLiteral:
		for _, element := range node.Elements {
			s.expression(element)
		}

	case *ast.HashLiteral:
		for _, pair := range node.Pairs {
			s.expression(pair.Key)
			s.expression(pair.Value)
		}

	case *ast.StructLiteral:
		for _, field := range node.Fields {
			if field != nil {
				s.expression(field.Value)
			}
		}

	case *ast.TemplateLiteral:
		for _, part := range node.Parts {
			s.expression(part)
		}

	case *ast.IfExpression:
		s.expression(node.Condition)
		s.block(node.Consequence)
		s.block(node.Alternative)

	case *ast.MatchExpression:
		// An arm's patterns are expressions, not bindings: match destructures
		// nothing, so there is no name here to poison.
		s.expression(node.Subject)
		for _, arm := range node.Arms {
			if arm == nil {
				continue
			}
			for _, pattern := range arm.Patterns {
				s.expression(pattern)
			}
			s.block(arm.Body)
		}

	case *ast.FunctionLiteral:
		// A parameter binds the name for the body, so a body reading `p` is not
		// reading whatever the top level bound. Name is the self-reference a
		// recursive function is compiled with, and is poisoned for the same
		// reason.
		for _, param := range node.Parameters {
			if param != nil {
				s.write(param.Value)
			}
		}
		s.write(node.Name)
		s.block(node.Body)

	case *ast.MacroLiteral:
		for _, param := range node.Parameters {
			if param != nil {
				s.write(param.Value)
			}
		}
		s.block(node.Body)

	default:
		s.complete = false
	}
}

// noteStructBindings folds one program's scan into the compiler's per-module
// table. It runs before the program's statements are compiled.
//
// Anything this program binds or writes is removed first, whatever the scan
// concluded. The REPL compiles one program per line against a symbol table that
// outlives them, so `let p = P{a:1}` on line 1 and `p = 5` on line 2 have to
// leave p untracked on line 3.
func (c *Compiler) noteStructBindings(program *ast.Program) {
	if program == nil {
		return
	}

	scan := newStructBindingScan()
	for _, stmt := range program.Statements {
		scan.statement(stmt)
	}

	for name := range scan.poisoned {
		delete(c.structBindings, c.structBindingKey(name))
	}
	for name := range scan.candidate {
		delete(c.structBindings, c.structBindingKey(name))
	}

	if !scan.complete {
		return
	}
	for name, structType := range scan.candidate {
		if !scan.poisoned[name] {
			c.structBindings[c.structBindingKey(name)] = structType
		}
	}
}

// structBindingKey scopes a value name to the module that bound it. claimTypeName
// takes the module key for the opposite reason -- a type name is shared and has
// to collide -- and the two together are the whole of the rule: types are
// program-global, values are not.
func (c *Compiler) structBindingKey(name string) string {
	return c.symbolTable.CurrentModule() + "\x00" + name
}

// structTypeOfBinding answers the struct type a name certainly holds.
func (c *Compiler) structTypeOfBinding(name string) (string, bool) {
	structType, tracked := c.structBindings[c.structBindingKey(name)]
	return structType, tracked
}

// checkFieldIsDeclared refuses a field the struct type does not declare.
//
// A type the compiler holds no declaration for answers nil: the literal that
// built the value is already refused with "undefined struct type", and one
// mistake should produce one error.
func (c *Compiler) checkFieldIsDeclared(structType, field string, isWrite bool) error {
	typeDef, declared := c.structDefinitions[structType]
	if !declared {
		return nil
	}

	names := make([]string, 0, len(typeDef))
	for _, name := range typeDef {
		if name == nil {
			continue
		}
		if name.Value == field {
			return nil
		}
		names = append(names, name.Value)
	}

	if isWrite {
		return errors.New(object.UnknownStructFieldWriteMessage(structType, field, names))
	}
	return errors.New(object.UnknownStructFieldMessage(structType, field, names))
}
