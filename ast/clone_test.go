package ast_test

import (
	"reflect"
	"testing"

	"mutant/ast"
	"mutant/lexer"
	"mutant/parser"
	"mutant/token"
)

// Clone exists so a template can be rewritten without damaging the template.
// The test that matters is therefore not "the copy looks the same" but "the
// original still looks the same after the copy has been rewritten".
//
// This is an external test package because it parses real source, and the
// parser imports ast.

func parseForClone(t *testing.T, source string) *ast.Program {
	t.Helper()

	p := parser.New(lexer.New(source))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("source did not parse: %s", errs[0])
	}
	return program
}

// A representative program: every node type Clone has a case for appears in it,
// so a missing case shows up as a shared subtree rather than as a silent gap.
const cloneSample = `struct Point { x; y; }
enum Colour { Red, Green }
let base = 1;
let items = [1, 2, 3];
let table = {"a": 1, "b": 2};
let point = Point{x: 1, y: 2};
let add = fn(a, b) { return a + b, null; };
for (let i = 0; i < 3; i = i + 1) {
	base = base + items[i];
	if (base > 1) { base = base - 1; } else { base = base + 1; };
}
putln(add(base, 1), point.x, table["a"], -base, !true, 1.5, "text");
`

func TestCloneProducesAnEqualTree(t *testing.T) {
	program := parseForClone(t, cloneSample)

	cloned, ok := ast.Clone(program).(*ast.Program)
	if !ok || cloned == nil {
		t.Fatal("cloning a program did not return a program")
	}

	if cloned.String() != program.String() {
		t.Fatalf("the clone does not print the same as the original:\noriginal %s\nclone    %s",
			program.String(), cloned.String())
	}
}

// The point of the whole exercise: rewriting the copy must be invisible through
// the original.
func TestCloneIsIndependentOfTheOriginal(t *testing.T) {
	program := parseForClone(t, cloneSample)
	before := program.String()

	cloned := ast.Clone(program)
	ast.Modify(cloned, func(node ast.Node) ast.Node {
		switch node := node.(type) {
		case *ast.IntegerLiteral:
			node.Value = 999
		case *ast.Identifier:
			node.Value = node.Value + "_rewritten"
		case *ast.StringLiteral:
			node.Value = "rewritten"
		}
		return node
	})

	if after := program.String(); after != before {
		t.Fatalf("rewriting the clone changed the original:\nbefore %s\nafter  %s", before, after)
	}
	if cloned.String() == before {
		t.Fatal("the rewrite did not change the clone either, so this proves nothing")
	}
}

// A clone must not share a single node pointer with its source; one shared node
// is one place a rewrite leaks back.
func TestCloneSharesNoNodesWithTheOriginal(t *testing.T) {
	program := parseForClone(t, cloneSample)
	cloned := ast.Clone(program)

	original := map[ast.Node]struct{}{}
	ast.Modify(program, func(node ast.Node) ast.Node {
		if node != nil {
			original[node] = struct{}{}
		}
		return node
	})
	if len(original) == 0 {
		t.Fatal("the walk found no nodes, so this proves nothing")
	}

	ast.Modify(cloned, func(node ast.Node) ast.Node {
		if node == nil {
			return node
		}
		if _, shared := original[node]; shared {
			t.Fatalf("the clone shares a %T with the original", node)
		}
		return node
	})
}

// Modify does not walk into macro bodies, so the shared-pointer sweep above
// cannot see them. A macro body is precisely the template Clone was written
// for, so it gets its own check.
func TestCloneCopiesMacroBodies(t *testing.T) {
	macro := &ast.MacroLiteral{
		Token:      token.Token{Literal: "macro"},
		Parameters: []*ast.Identifier{{Value: "x"}},
		Body: &ast.BlockStatement{
			Statements: []ast.Statement{&ast.ExpressionStatement{Expression: &ast.IntegerLiteral{Value: 1}}},
		},
	}

	cloned, ok := ast.Clone(macro).(*ast.MacroLiteral)
	if !ok || cloned == nil {
		t.Fatal("cloning a macro literal did not return one")
	}
	if cloned.Body == macro.Body {
		t.Fatal("the clone shares its body with the original macro")
	}
	if cloned.Parameters[0] == macro.Parameters[0] {
		t.Fatal("the clone shares a parameter identifier with the original macro")
	}

	cloned.Body.Statements[0].(*ast.ExpressionStatement).Expression.(*ast.IntegerLiteral).Value = 2
	if macro.Body.Statements[0].(*ast.ExpressionStatement).Expression.(*ast.IntegerLiteral).Value != 1 {
		t.Fatal("rewriting the cloned body changed the original macro")
	}
}

// The parser aliases Name to Names[0] and ReturnValue to ReturnValues[0]. The
// clone has to reproduce the aliasing, not two equal-but-separate identifiers,
// or a later rewrite through one of them stops being visible through the other.
func TestCloneKeepsFieldAliasing(t *testing.T) {
	program := parseForClone(t, "let value, err = fn() { return 1, null; }();\n")

	cloned, ok := ast.Clone(program).(*ast.Program)
	if !ok {
		t.Fatal("cloning a program did not return a program")
	}

	let, ok := cloned.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected a let statement, got %T", cloned.Statements[0])
	}
	if len(let.Names) == 0 {
		t.Fatal("the cloned let has no names")
	}
	if let.Name != let.Names[0] {
		t.Fatalf("cloned Name is not the same identifier as Names[0]: %p vs %p", let.Name, let.Names[0])
	}

	var found *ast.ReturnStatement
	ast.Modify(cloned, func(node ast.Node) ast.Node {
		if ret, ok := node.(*ast.ReturnStatement); ok && found == nil {
			found = ret
		}
		return node
	})
	if found == nil {
		t.Fatal("the cloned program has no return statement")
	}
	if len(found.ReturnValues) == 0 {
		t.Fatal("the cloned return statement has no values")
	}
	if found.ReturnValue != found.ReturnValues[0] {
		t.Fatalf("cloned ReturnValue is not the same expression as ReturnValues[0]: %p vs %p",
			found.ReturnValue, found.ReturnValues[0])
	}
}

// Nils are legal in these trees (a `for (;;)` header, an `if` with no else).
// Cloning must reproduce them rather than panic or invent nodes.
func TestCloneHandlesAbsentChildren(t *testing.T) {
	loop := &ast.ForStatement{Body: &ast.BlockStatement{}}

	cloned, ok := ast.Clone(loop).(*ast.ForStatement)
	if !ok || cloned == nil {
		t.Fatal("cloning a for statement did not return one")
	}
	if cloned.Init != nil || cloned.Condition != nil || cloned.Post != nil {
		t.Fatalf("clone invented a for-header part: init=%v condition=%v post=%v",
			cloned.Init, cloned.Condition, cloned.Post)
	}

	branch := &ast.IfExpression{Condition: &ast.Boolean{Value: true}, Consequence: &ast.BlockStatement{}}
	clonedBranch, ok := ast.Clone(branch).(*ast.IfExpression)
	if !ok || clonedBranch == nil {
		t.Fatal("cloning an if expression did not return one")
	}
	if clonedBranch.Alternative != nil {
		t.Fatal("clone invented an else branch")
	}

	if ast.Clone(nil) != nil {
		t.Fatal("cloning nil did not return nil")
	}
}

// A cloned Program carries no NodePositions on purpose: the map is keyed by the
// original node pointers, which the clone is not. Returning the original map
// would be worse than returning none, because every lookup would answer for a
// different node.
func TestClonedProgramDropsNodePositions(t *testing.T) {
	program := parseForClone(t, "let a = 1;\n")
	if len(program.NodePositions) == 0 {
		t.Fatal("the parser produced no positions, so this proves nothing")
	}

	cloned, ok := ast.Clone(program).(*ast.Program)
	if !ok {
		t.Fatal("cloning a program did not return a program")
	}
	if len(cloned.NodePositions) != 0 {
		t.Fatalf("the clone carried %d stale positions", len(cloned.NodePositions))
	}
}

// Every node type in the package needs a Clone case. Without this, a new node
// type falls through to the "return the node as-is" default and is silently
// shared between the original and the copy.
func TestCloneCoversEveryNodeType(t *testing.T) {
	samples := []ast.Node{
		&ast.Program{},
		&ast.BlockStatement{},
		&ast.ExpressionStatement{},
		&ast.LetStatement{},
		&ast.ReturnStatement{},
		&ast.ForStatement{},
		&ast.BreakStatement{},
		&ast.ContinueStatement{},
		&ast.StructStatement{},
		&ast.EnumStatement{},
		&ast.Identifier{},
		&ast.IntegerLiteral{},
		&ast.FloatLiteral{},
		&ast.StringLiteral{},
		&ast.Boolean{},
		&ast.PrefixExpression{},
		&ast.InfixExpression{},
		&ast.IndexExpression{},
		&ast.CallExpression{},
		&ast.AssignExpression{},
		&ast.FieldExpression{},
		&ast.IfExpression{},
		&ast.FunctionLiteral{},
		&ast.MacroLiteral{},
		&ast.ArrayLiteral{},
		&ast.HashLiteral{},
		&ast.StructLiteral{},
	}

	covered := map[reflect.Type]struct{}{}
	for _, sample := range samples {
		typ := reflect.TypeOf(sample)
		if cloned := ast.Clone(sample); cloned == sample {
			t.Fatalf("Clone returned the same %s pointer, so it has no case for it", typ)
		}
		covered[typ] = struct{}{}
	}

	if len(covered) != len(samples) {
		t.Fatalf("the sample list has duplicates: %d types for %d samples", len(covered), len(samples))
	}
}
