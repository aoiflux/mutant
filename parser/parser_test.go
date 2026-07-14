package parser

import (
	"mutant/ast"
	"mutant/lexer"
	"testing"
)

func TestLetStatements(t *testing.T) {
	tests := []struct {
		input              string
		expectedIdentifier string
		expectedValue      interface{}
	}{
		{"let x = 5;", "x", 5}, {"let y = true;", "y", true}, {"let foobar = y;", "foobar", "y"},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l) // new parser

		program := p.ParseProgram()
		checkParserErrors(t, p)

		if program == nil {
			t.Fatalf("ParseProgram() returned nil")
		}

		if len(program.Statements) != 1 {
			t.Fatalf("program.Statements does not contain 3 statements. Got = %d", len(program.Statements))
		}

		stmt := program.Statements[0]
		if !testLetStmt(t, stmt, tt.expectedIdentifier) {
			return
		}

		val := stmt.(*ast.LetStatement).Value
		if !testLiteralExpression(t, val, tt.expectedValue) {
			return
		}
	}
}

func TestLetDestructuringStatements(t *testing.T) {
	input := "let data, err = fs_read(\"a.txt\");"

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("stmt not *ast.LetStatement. Got = %T", program.Statements[0])
	}

	if len(stmt.Names) != 2 {
		t.Fatalf("let destructuring target count wrong. got=%d", len(stmt.Names))
	}
	if stmt.Names[0].Value != "data" || stmt.Names[1].Value != "err" {
		t.Fatalf("unexpected let destructuring names: got=%s,%s", stmt.Names[0].Value, stmt.Names[1].Value)
	}
	if stmt.Name == nil || stmt.Name.Value != "data" {
		t.Fatalf("compatibility Name field not set correctly")
	}
}

func TestReturnStatements(t *testing.T) {
	input :=
		`
			return 5;
			return 151050;
			return 10;
		`

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	checkParserErrors(t, p)

	if program == nil {
		t.Fatalf("ParseProgram() returned nil")
	}

	if len(program.Statements) != 3 {
		t.Fatalf("program.Statements does not contain 3 statements. Got = %d", len(program.Statements))
	}

	for _, stmt := range program.Statements {
		returnStatement, ok := stmt.(*ast.ReturnStatement)
		if !ok {
			t.Errorf("stmt not *ast.ReturnStatement.Got = %T", stmt)
			continue
		}

		if len(returnStatement.ReturnValues) != 1 {
			t.Errorf("returnStmt.ReturnValues length not 1, got %d", len(returnStatement.ReturnValues))
			continue
		}

		if returnStatement.TokenLiteral() != "return" {
			t.Errorf("returnStmt.TokenLiteral not 'return', got %q", returnStatement.TokenLiteral())
		}
	}
}

func TestMultipleReturnStatements(t *testing.T) {
	input := "return 1, 2, 3;"

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ReturnStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ReturnStatement. got=%T", program.Statements[0])
	}

	if len(stmt.ReturnValues) != 3 {
		t.Fatalf("return statement has wrong number of values. got=%d", len(stmt.ReturnValues))
	}

	testIntegerLiteral(t, stmt.ReturnValues[0], 1)
	testIntegerLiteral(t, stmt.ReturnValues[1], 2)
	testIntegerLiteral(t, stmt.ReturnValues[2], 3)

	if stmt.ReturnValue == nil {
		t.Fatalf("ReturnValue compatibility field should not be nil")
	}
	testIntegerLiteral(t, stmt.ReturnValue, 1)
}

func TestIdentifierExpression(t *testing.T) {
	input := "foobar;"
	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	checkParserErrors(t, p)

	if program == nil {
		t.Fatalf("ParseProgram() returned nil")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	ident, ok := stmt.Expression.(*ast.Identifier)
	if !ok {
		t.Fatalf("exp not *ast.Identifier. got=%T", stmt.Expression)
	}
	if ident.Value != "foobar" {
		t.Errorf("ident.Value not %s. got=%s", "foobar", ident.Value)
	}
	if ident.TokenLiteral() != "foobar" {
		t.Errorf("ident.TokenLiteral not %s. got=%s", "foobar",
			ident.TokenLiteral())
	}
}

func TestIntegerLiteralExpression(t *testing.T) {
	input := "5;"
	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	checkParserErrors(t, p)

	if program == nil {
		t.Fatalf("ParseProgram() returned nil")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	literal, ok := stmt.Expression.(*ast.IntegerLiteral)
	if !ok {
		t.Fatalf("exp not *ast.Identifier. got=%T", stmt.Expression)
	}
	if literal.Value != 5 {
		t.Errorf("integer.Value not %d. got=%d", 5, literal.Value)
	}
	if literal.TokenLiteral() != "5" {
		t.Errorf("literal.TokenLiteral not %s. got=%s", "5", literal.TokenLiteral())
	}
}

func TestParsingPrefixExpressions(t *testing.T) {
	prefixTests := []struct {
		input    string
		operator string
		value    interface{}
	}{
		{"!5;", "!", 5},
		{"-15;", "-", 15},
		{"!true", "!", true},
		{"!false", "!", false},
	}

	for _, tt := range prefixTests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		if program == nil {
			t.Fatalf("ParseProgram() returned nil")
		}

		if len(program.Statements) != 1 {
			t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
		}

		stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
		if !ok {
			t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
				program.Statements[0])
		}

		exp, ok := stmt.Expression.(*ast.PrefixExpression)
		if !ok {
			t.Fatalf("exp is not ast.PrefixExpression, got = %T", stmt.Expression)
		}

		if exp.Operator != tt.operator {
			t.Fatalf("exp.Operator is not '%s'. got=%s", tt.operator, exp.Operator)
		}

		if !testLiteralExpression(t, exp.Right, tt.value) {
			return
		}
	}
}

func TestParsingInfixExpressions(t *testing.T) {
	infixTests := []struct {
		input      string
		leftValue  interface{}
		operator   string
		rightValue interface{}
	}{
		{"5 + 5;", 5, "+", 5},
		{"5 - 5;", 5, "-", 5},
		{"5 * 5;", 5, "*", 5},
		{"5 / 5;", 5, "/", 5},

		{"5 > 5;", 5, ">", 5},
		{"5 < 5;", 5, "<", 5},
		{"5 == 5;", 5, "==", 5},
		{"5 != 5;", 5, "!=", 5},
		{"true == true", true, "==", true},
		{"true != false", true, "!=", false},
		{"false != false", false, "!=", false},
	}

	for _, tt := range infixTests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		if program == nil {
			t.Fatalf("ParseProgram() returned nil")
		}

		if len(program.Statements) != 1 {
			t.Fatalf("program.Statements does not contain 1 statement. Got = %d", len(program.Statements))
		}

		stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
		if !ok {
			t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T", program.Statements[0])
		}

		if !testInfixExpression(t, stmt.Expression, tt.leftValue, tt.operator, tt.rightValue) {
			return
		}

	}
}

func TestOperatorPrecedenceParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"-a * b", "((-a) * b)"},
		{"!-a", "(!(-a))"},
		{"a + b + c", "((a + b) + c)"},
		{"a + b - c", "((a + b) - c)"},
		{"a * b * c", "((a * b) * c)"},
		{"a * b / c", "((a * b) / c)"},
		{"5 > 4 == 3 < 4", "((5 > 4) == (3 < 4))"},
		{"5 < 4 != 3 > 4", "((5 < 4) != (3 > 4))"},
		{"3 + 4 * 5 == 3 * 1 + 4 * 5", "((3 + (4 * 5)) == ((3 * 1) + (4 * 5)))"},
		{"true", "true"},
		{"false", "false"},
		{"3 > 5 ==  false", "((3 > 5) == false)"},
		{"3 < 5 == true", "((3 < 5) == true)"},
		{"1 + (2 + 3 ) + 4", "((1 + (2 + 3)) + 4)"},
		{"(5 + 5) * 2", "((5 + 5) * 2)"},
		{"2 / (5 + 5)", "(2 / (5 + 5))"},
		{"-(5 + 5)", "(-(5 + 5))"},
		{"!(true == true)", "(!(true == true))"},
		{"a + add(b * c) + d", "((a + add((b * c))) + d)"},
		{"add(a, b, 1, 2 * 3, 4 + 5, add(6, 7 * 8))", "add(a, b, 1, (2 * 3), (4 + 5), add(6, (7 * 8)))"},
		{"add(a + b + c * d / f + g)", "add((((a + b) + ((c * d) / f)) + g))"},
		{"a * [1, 2, 3, 4][b * c] * d", "((a * ([1, 2, 3, 4][(b * c)])) * d)"},
		{"add(a * b[2], b[1], 2 * [1, 2][1])", "add((a * (b[2])), (b[1]), (2 * ([1, 2][1])))"},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		actual := program.String()
		if actual != tt.expected {
			t.Errorf("expected=%q, got=%q", tt.expected, actual)
		}
	}
}

func TestMalformedCallInNestedBlockDoesNotPanic(t *testing.T) {
	input := "let handler = fn() { if (true) { run(,); } };"

	l := lexer.New(input)
	p := New(l)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseProgram panicked for malformed nested call: %v", r)
		}
	}()

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}

	if len(p.Errors()) == 0 {
		t.Fatal("expected parser errors for malformed call, got none")
	}

	_ = program.String()
}

func TestParserRecoversAndCollectsMultipleStatementErrors(t *testing.T) {
	input := "let first = ;\nlet second = ;\nlet ok = 1;\n"

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}

	if len(p.Errors()) < 2 {
		t.Fatalf("expected at least 2 parser errors, got=%d (%v)", len(p.Errors()), p.Errors())
	}

	foundRecovered := false
	for _, stmt := range program.Statements {
		letStmt, ok := stmt.(*ast.LetStatement)
		if !ok || letStmt.Name == nil {
			continue
		}
		if letStmt.Name.Value == "ok" {
			foundRecovered = true
			break
		}
	}
	if !foundRecovered {
		t.Fatalf("expected parser recovery to include valid trailing let `ok`, statements=%d", len(program.Statements))
	}
}

func TestParserRecoversInsideBlockAndCollectsMultipleErrors(t *testing.T) {
	input := "let run = fn() {\nlet a = ;\nlet b = ;\nlet c = 3;\n};\n"

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}

	if len(p.Errors()) < 2 {
		t.Fatalf("expected at least 2 parser errors, got=%d (%v)", len(p.Errors()), p.Errors())
	}

	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 top-level statement, got=%d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected top-level let statement, got=%T", program.Statements[0])
	}

	fn, ok := stmt.Value.(*ast.FunctionLiteral)
	if !ok || fn == nil || fn.Body == nil {
		t.Fatalf("expected function literal body, got=%T", stmt.Value)
	}

	foundRecovered := false
	for _, bodyStmt := range fn.Body.Statements {
		recoveredLet, ok := bodyStmt.(*ast.LetStatement)
		if !ok || recoveredLet.Name == nil {
			continue
		}
		if recoveredLet.Name.Value == "c" {
			foundRecovered = true
			break
		}
	}
	if !foundRecovered {
		t.Fatalf("expected block recovery to include valid trailing let `c`, body statements=%d", len(fn.Body.Statements))
	}
}

func TestParserRecoversWithinCallArguments(t *testing.T) {
	input := "let out = add(1, , 3);"

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}
	if len(p.Errors()) == 0 {
		t.Fatal("expected parser errors for malformed call argument, got none")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement, got=%d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected let statement, got=%T", program.Statements[0])
	}

	call, ok := stmt.Value.(*ast.CallExpression)
	if !ok {
		t.Fatalf("expected call expression value, got=%T", stmt.Value)
	}

	if len(call.Arguments) != 2 {
		t.Fatalf("expected recovered call args length=2, got=%d", len(call.Arguments))
	}
	testIntegerLiteral(t, call.Arguments[0], 1)
	testIntegerLiteral(t, call.Arguments[1], 3)
}

func TestParserRecoversWithinHashLiteralPairs(t *testing.T) {
	input := "let h = {\"a\": 1, : 2, \"c\": 3};"

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}
	if len(p.Errors()) == 0 {
		t.Fatal("expected parser errors for malformed hash pair, got none")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement, got=%d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected let statement, got=%T", program.Statements[0])
	}

	hash, ok := stmt.Value.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("expected hash literal value, got=%T", stmt.Value)
	}

	if len(hash.Pairs) != 2 {
		t.Fatalf("expected recovered hash pair count=2, got=%d", len(hash.Pairs))
	}
}

func TestParserRecoversWithinStructLiteralFields(t *testing.T) {
	input := "let p = Point{a: 1, : 2, c: 3};"

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatal("ParseProgram() returned nil")
	}
	if len(p.Errors()) == 0 {
		t.Fatal("expected parser errors for malformed struct field, got none")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("expected 1 statement, got=%d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("expected let statement, got=%T", program.Statements[0])
	}

	strct, ok := stmt.Value.(*ast.StructLiteral)
	if !ok {
		t.Fatalf("expected struct literal value, got=%T", stmt.Value)
	}

	if len(strct.Fields) != 2 {
		t.Fatalf("expected recovered struct field count=2, got=%d", len(strct.Fields))
	}
	if strct.Fields[0].Name == nil || strct.Fields[0].Name.Value != "a" {
		t.Fatalf("expected first recovered field to be a, got=%#v", strct.Fields[0].Name)
	}
	if strct.Fields[1].Name == nil || strct.Fields[1].Name.Value != "c" {
		t.Fatalf("expected second recovered field to be c, got=%#v", strct.Fields[1].Name)
	}
}

func TestBooleanExpression(t *testing.T) {
	tests := []struct {
		input           string
		expectedBoolean bool
	}{
		{"true;", true},
		{"false;", false},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		if len(program.Statements) != 1 {
			t.Fatalf("program has not enough statements. got=%d",
				len(program.Statements))
		}

		stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
		if !ok {
			t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
				program.Statements[0])
		}

		boolean, ok := stmt.Expression.(*ast.Boolean)
		if !ok {
			t.Fatalf("exp not *ast.Boolean. got=%T", stmt.Expression)
		}
		if boolean.Value != tt.expectedBoolean {
			t.Errorf("boolean.Value not %t. got=%t", tt.expectedBoolean,
				boolean.Value)
		}
	}
}

func TestIfElseExpression(t *testing.T) {
	input := `if (x < y) { x } else { y }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	exp, ok := stmt.Expression.(*ast.IfExpression)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.IfExpression. got=%T", stmt.Expression)
	}

	if !testInfixExpression(t, exp.Condition, "x", "<", "y") {
		return
	}

	if len(exp.Consequence.Statements) != 1 {
		t.Errorf("consequence is not 1 statements. got=%d\n",
			len(exp.Consequence.Statements))
	}

	consequence, ok := exp.Consequence.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("Statements[0] is not ast.ExpressionStatement. got=%T",
			exp.Consequence.Statements[0])
	}

	if !testIdentifier(t, consequence.Expression, "x") {
		return
	}

	if len(exp.Alternative.Statements) != 1 {
		t.Errorf("exp.Alternative.Statements does not contain 1 statements. got=%d\n",
			len(exp.Alternative.Statements))
	}

	alternative, ok := exp.Alternative.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("Statements[0] is not ast.ExpressionStatement. got=%T",
			exp.Alternative.Statements[0])
	}

	if !testIdentifier(t, alternative.Expression, "y") {
		return
	}
}

func TestIfElseIfExpression(t *testing.T) {
	input := `if (x < y) { x } else if (x > y) { z } else { y }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	exp, ok := stmt.Expression.(*ast.IfExpression)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.IfExpression. got=%T", stmt.Expression)
	}

	if !testInfixExpression(t, exp.Condition, "x", "<", "y") {
		return
	}

	if len(exp.Consequence.Statements) != 1 {
		t.Fatalf("consequence is not 1 statements. got=%d\n", len(exp.Consequence.Statements))
	}

	if exp.Alternative == nil || len(exp.Alternative.Statements) != 1 {
		t.Fatalf("exp.Alternative.Statements does not contain 1 statements. got=%d\n", len(exp.Alternative.Statements))
	}

	elseIfStmt, ok := exp.Alternative.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("exp.Alternative.Statements[0] is not ast.ExpressionStatement. got=%T", exp.Alternative.Statements[0])
	}

	elseIf, ok := elseIfStmt.Expression.(*ast.IfExpression)
	if !ok {
		t.Fatalf("else-if expression is not ast.IfExpression. got=%T", elseIfStmt.Expression)
	}

	if !testInfixExpression(t, elseIf.Condition, "x", ">", "y") {
		return
	}

	if len(elseIf.Consequence.Statements) != 1 {
		t.Fatalf("else-if consequence is not 1 statements. got=%d\n", len(elseIf.Consequence.Statements))
	}

	elseIfConsequence, ok := elseIf.Consequence.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("else-if consequence statement is not ast.ExpressionStatement. got=%T", elseIf.Consequence.Statements[0])
	}
	if !testIdentifier(t, elseIfConsequence.Expression, "z") {
		return
	}

	if elseIf.Alternative == nil || len(elseIf.Alternative.Statements) != 1 {
		t.Fatalf("else-if alternative is not 1 statements. got=%d\n", len(elseIf.Alternative.Statements))
	}

	finalElseStmt, ok := elseIf.Alternative.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("else-if alternative statement is not ast.ExpressionStatement. got=%T", elseIf.Alternative.Statements[0])
	}
	if !testIdentifier(t, finalElseStmt.Expression, "y") {
		return
	}
}

func TestIfElseIfExpressionWithoutFinalElse(t *testing.T) {
	input := `if (x < y) { x } else if (x > y) { z }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	exp, ok := stmt.Expression.(*ast.IfExpression)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.IfExpression. got=%T", stmt.Expression)
	}

	if exp.Alternative == nil || len(exp.Alternative.Statements) != 1 {
		t.Fatalf("exp.Alternative.Statements does not contain 1 statements. got=%d\n", len(exp.Alternative.Statements))
	}

	elseIfStmt, ok := exp.Alternative.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("exp.Alternative.Statements[0] is not ast.ExpressionStatement. got=%T", exp.Alternative.Statements[0])
	}

	elseIf, ok := elseIfStmt.Expression.(*ast.IfExpression)
	if !ok {
		t.Fatalf("else-if expression is not ast.IfExpression. got=%T", elseIfStmt.Expression)
	}

	if elseIf.Alternative != nil {
		t.Fatalf("else-if should not have final alternative, got=%#v", elseIf.Alternative)
	}
}

func TestFunctionLiteralParsing(t *testing.T) {
	input := `fn(x, y) { x + y; }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	function, ok := stmt.Expression.(*ast.FunctionLiteral)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.FunctionLiteral. got=%T",
			stmt.Expression)
	}

	if len(function.Parameters) != 2 {
		t.Fatalf("function literal parameters wrong. want 2, got=%d\n",
			len(function.Parameters))
	}

	testLiteralExpression(t, function.Parameters[0], "x")
	testLiteralExpression(t, function.Parameters[1], "y")

	if len(function.Body.Statements) != 1 {
		t.Fatalf("function.Body.Statements has not 1 statements. got=%d\n",
			len(function.Body.Statements))
	}

	bodyStmt, ok := function.Body.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("function body stmt is not ast.ExpressionStatement. got=%T",
			function.Body.Statements[0])
	}

	testInfixExpression(t, bodyStmt.Expression, "x", "+", "y")
}

func TestFunctionParameterParsing(t *testing.T) {
	tests := []struct {
		input          string
		expectedParams []string
	}{
		{input: "fn() {};", expectedParams: []string{}},
		{input: "fn(x) {};", expectedParams: []string{"x"}},
		{input: "fn(x, y, z) {};", expectedParams: []string{"x", "y", "z"}},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		stmt := program.Statements[0].(*ast.ExpressionStatement)
		function := stmt.Expression.(*ast.FunctionLiteral)

		if len(function.Parameters) != len(tt.expectedParams) {
			t.Errorf("length parameters wrong. want %d, got=%d\n",
				len(tt.expectedParams), len(function.Parameters))
		}

		for i, ident := range tt.expectedParams {
			testLiteralExpression(t, function.Parameters[i], ident)
		}
	}
}

func TestCallExpressionParsing(t *testing.T) {
	input := "add(1, 2 * 3, 4 + 5);"

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("stmt is not ast.ExpressionStatement. got=%T",
			program.Statements[0])
	}

	exp, ok := stmt.Expression.(*ast.CallExpression)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.CallExpression. got=%T",
			stmt.Expression)
	}

	if !testIdentifier(t, exp.Function, "add") {
		return
	}

	if len(exp.Arguments) != 3 {
		t.Fatalf("wrong length of arguments. got=%d", len(exp.Arguments))
	}

	testLiteralExpression(t, exp.Arguments[0], 1)
	testInfixExpression(t, exp.Arguments[1], 2, "*", 3)
	testInfixExpression(t, exp.Arguments[2], 4, "+", 5)
}

func TestCallExpressionParameterParsing(t *testing.T) {
	tests := []struct {
		input         string
		expectedIdent string
		expectedArgs  []string
	}{
		{
			input:         "add();",
			expectedIdent: "add",
			expectedArgs:  []string{},
		},
		{
			input:         "add(1);",
			expectedIdent: "add",
			expectedArgs:  []string{"1"},
		},
		{
			input:         "add(1, 2 * 3, 4 + 5);",
			expectedIdent: "add",
			expectedArgs:  []string{"1", "(2 * 3)", "(4 + 5)"},
		},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)
		program := p.ParseProgram()
		checkParserErrors(t, p)

		stmt := program.Statements[0].(*ast.ExpressionStatement)
		exp, ok := stmt.Expression.(*ast.CallExpression)
		if !ok {
			t.Fatalf("stmt.Expression is not ast.CallExpression. got=%T",
				stmt.Expression)
		}

		if !testIdentifier(t, exp.Function, tt.expectedIdent) {
			return
		}

		if len(exp.Arguments) != len(tt.expectedArgs) {
			t.Fatalf("wrong number of arguments. want=%d, got=%d",
				len(tt.expectedArgs), len(exp.Arguments))
		}

		for i, arg := range tt.expectedArgs {
			if exp.Arguments[i].String() != arg {
				t.Errorf("argument %d wrong. want=%q, got=%q", i,
					arg, exp.Arguments[i].String())
			}
		}
	}
}

func TestLiteralStringExpression(t *testing.T) {
	input := `"hello world";`
	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	literal, ok := stmt.Expression.(*ast.StringLiteral)

	if !ok {
		t.Fatalf("exp not *ast.StringLiteral. got=%T", stmt.Expression)
	}
	if literal.Value != "hello world" {
		t.Errorf("literal.Value not %q. got=%q", "hello world", literal.Value)
	}
}

func TestParsingArrayLiterals(t *testing.T) {
	input := "[1, 2 * 2, 3 + 3]"
	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	array, ok := stmt.Expression.(*ast.ArrayLiteral)

	if !ok {
		t.Fatalf("exp not ast.ArrayLiteral. got=%T", stmt.Expression)
	}
	if len(array.Elements) != 3 {
		t.Fatalf("len(array.Elements) not 3. got=%d", len(array.Elements))
	}

	testIntegerLiteral(t, array.Elements[0], 1)
	testInfixExpression(t, array.Elements[1], 2, "*", 2)
	testInfixExpression(t, array.Elements[2], 3, "+", 3)
}

func TestParsingIndexExpressions(t *testing.T) {
	input := "myArray[1 + 1]"
	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)
	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	indexExp, ok := stmt.Expression.(*ast.IndexExpression)
	if !ok {
		t.Fatalf("exp not *ast.IndexExpression. got=%T", stmt.Expression)
	}
	if !testIdentifier(t, indexExp.Left, "myArray") {
		return
	}
	if !testInfixExpression(t, indexExp.Index, 1, "+", 1) {
		return
	}
}

func TestParsingHashLiteralsStringKeys(t *testing.T) {
	input := `{"one": 1, "two": 2, "three": 3}`
	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()

	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	hash, ok := stmt.Expression.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("exp is not ast.HashLiteral. got=%T", stmt.Expression)
	}
	if len(hash.Pairs) != 3 {
		t.Errorf("hash.Pairs has wrong length. got=%d", len(hash.Pairs))
	}

	expected := map[string]int64{"one": 1, "two": 2, "three": 3}
	for key, value := range hash.Pairs {
		literal, ok := key.(*ast.StringLiteral)
		if !ok {
			t.Errorf("key is not ast.StringLiteral. got=%T", key)
		}
		expectedValue := expected[literal.String()]
		testIntegerLiteral(t, value, expectedValue)
	}
}

func TestParsingHashLiteralsFloatVals(t *testing.T) {
	input := `{"a": 1.5, "b": 2.4141, "c": 355.25511}`
	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()

	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	hash, ok := stmt.Expression.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("exp is not ast.HashLiteral. got=%T", stmt.Expression)
	}
	if len(hash.Pairs) != 3 {
		t.Errorf("hash.Pairs has wrong length. got=%d", len(hash.Pairs))
	}

	epxected := map[string]float64{"a": 1.500000, "b": 2.4141, "c": 355.25511}
	for key, value := range hash.Pairs {
		literal, ok := key.(*ast.StringLiteral)
		if !ok {
			t.Errorf("key is not ast.StringLiteral. got=%T", key)
		}
		expectedValue := epxected[literal.String()]
		testFloatLiteral(t, value, expectedValue)
	}
}

func TestParsingEmptyHashLiteral(t *testing.T) {
	input := "{}"
	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	hash, ok := stmt.Expression.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("exp is not ast.HashLiteral. got=%T", stmt.Expression)
	}
	if len(hash.Pairs) != 0 {
		t.Errorf("hash.Pairs has wrong length. got=%d", len(hash.Pairs))
	}
}

func TestParsingHashLiteralsWithExpressions(t *testing.T) {
	input := `{"one": 0 + 1, "two": 10 - 8, "three": 15 / 5}`
	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()

	checkParserErrors(t, p)
	stmt := program.Statements[0].(*ast.ExpressionStatement)
	hash, ok := stmt.Expression.(*ast.HashLiteral)
	if !ok {
		t.Fatalf("exp is not ast.HashLiteral. got=%T", stmt.Expression)
	}
	if len(hash.Pairs) != 3 {
		t.Errorf("hash.Pairs has wrong length. got=%d", len(hash.Pairs))
	}

	tests := map[string]func(ast.Expression){
		"one":   func(e ast.Expression) { testInfixExpression(t, e, 0, "+", 1) },
		"two":   func(e ast.Expression) { testInfixExpression(t, e, 10, "-", 8) },
		"three": func(e ast.Expression) { testInfixExpression(t, e, 15, "/", 5) },
	}

	for key, value := range hash.Pairs {
		literal, ok := key.(*ast.StringLiteral)
		if !ok {
			t.Errorf("key is not ast.StringLiteral. got=%T", key)
			continue
		}

		testFunc, ok := tests[literal.String()]
		if !ok {
			t.Errorf("No test function for key %q found", literal.String())
			continue
		}

		testFunc(value)
	}
}

// parser/parser_test.go

func TestMacroLiteralParsing(t *testing.T) {
	input := `macro(x, y) { x + y; }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain %d statements. got=%d\n", 1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("statement is not ast.ExpressionStatement. got=%T", program.Statements[0])
	}

	macro, ok := stmt.Expression.(*ast.MacroLiteral)
	if !ok {
		t.Fatalf("stmt.Expression is not ast.MacroLiteral. got=%T", stmt.Expression)
	}

	if len(macro.Parameters) != 2 {
		t.Fatalf("macro literal parameters wrong. want 2, got=%d\n", len(macro.Parameters))
	}

	testLiteralExpression(t, macro.Parameters[0], "x")
	testLiteralExpression(t, macro.Parameters[1], "y")

	if len(macro.Body.Statements) != 1 {
		t.Fatalf("macro.Body.Statements has not 1 statements. got=%d\n", len(macro.Body.Statements))
	}

	bodyStmt, ok := macro.Body.Statements[0].(*ast.ExpressionStatement)
	if !ok {
		t.Fatalf("macro body stmt is not ast.ExpressionStatement. got=%T", macro.Body.Statements[0])
	}

	testInfixExpression(t, bodyStmt.Expression, "x", "+", "y")
}

func TestFunctionLiteralWithName(t *testing.T) {
	input := `let myFunction = fn() { };`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Body does not contain %d statements. got=%d\n",
			1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.LetStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.LetStatement. got=%T",
			program.Statements[0])
	}

	function, ok := stmt.Value.(*ast.FunctionLiteral)
	if !ok {
		t.Fatalf("stmt.Value is not ast.FunctionLiteral. got=%T",
			stmt.Value)
	}

	if function.Name != "myFunction" {
		t.Fatalf("function literal name wrong. want 'myFunction', got=%q\n",
			function.Name)
	}
}

func TestForStatementParsing(t *testing.T) {
	input := `for (let i = 0; i < 5; i = i + 1) { i; }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statement. got=%d", len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.ForStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.ForStatement. got=%T", program.Statements[0])
	}

	if stmt.Init == nil {
		t.Fatalf("for init should not be nil")
	}
	if stmt.Condition == nil {
		t.Fatalf("for condition should not be nil")
	}
	if stmt.Post == nil {
		t.Fatalf("for post should not be nil")
	}
	if len(stmt.Body.Statements) != 1 {
		t.Fatalf("for body should have 1 statement. got=%d", len(stmt.Body.Statements))
	}
}

func TestBreakAndContinueParsing(t *testing.T) {
	input := `for (; true; ) { continue; break; }`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ForStatement)
	if len(stmt.Body.Statements) != 2 {
		t.Fatalf("for body should have 2 statements. got=%d", len(stmt.Body.Statements))
	}

	if _, ok := stmt.Body.Statements[0].(*ast.ContinueStatement); !ok {
		t.Fatalf("body statement[0] is not ast.ContinueStatement. got=%T", stmt.Body.Statements[0])
	}
	if _, ok := stmt.Body.Statements[1].(*ast.BreakStatement); !ok {
		t.Fatalf("body statement[1] is not ast.BreakStatement. got=%T", stmt.Body.Statements[1])
	}
}

func TestStructStatementParsing(t *testing.T) {
	input := `struct Point { x; y; };`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt, ok := program.Statements[0].(*ast.StructStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.StructStatement. got=%T", program.Statements[0])
	}

	if stmt.Name.Value != "Point" {
		t.Fatalf("expected struct name Point, got=%s", stmt.Name.Value)
	}
	if len(stmt.Fields) != 2 {
		t.Fatalf("expected 2 struct fields, got=%d", len(stmt.Fields))
	}
	if stmt.Fields[0].Value != "x" || stmt.Fields[1].Value != "y" {
		t.Fatalf("unexpected struct fields: %s, %s", stmt.Fields[0].Value, stmt.Fields[1].Value)
	}
}

func TestEnumStatementParsing(t *testing.T) {
	input := `enum Color { Red, Green, Blue };`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt, ok := program.Statements[0].(*ast.EnumStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.EnumStatement. got=%T", program.Statements[0])
	}

	if stmt.Name.Value != "Color" {
		t.Fatalf("expected enum name Color, got=%s", stmt.Name.Value)
	}
	if len(stmt.Variants) != 3 {
		t.Fatalf("expected 3 enum variants, got=%d", len(stmt.Variants))
	}
}

func TestFieldExpressionParsing(t *testing.T) {
	input := `Color.Red;`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	field, ok := stmt.Expression.(*ast.FieldExpression)
	if !ok {
		t.Fatalf("expression is not ast.FieldExpression. got=%T", stmt.Expression)
	}

	if !testIdentifier(t, field.Left, "Color") {
		return
	}
	if field.Field.Value != "Red" {
		t.Fatalf("expected field Red, got=%s", field.Field.Value)
	}
}

func TestStructLiteralParsing(t *testing.T) {
	input := `Point { x: 1, y: 2 };`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	stmt := program.Statements[0].(*ast.ExpressionStatement)
	lit, ok := stmt.Expression.(*ast.StructLiteral)
	if !ok {
		t.Fatalf("expression is not ast.StructLiteral. got=%T", stmt.Expression)
	}

	if lit.Name.Value != "Point" {
		t.Fatalf("expected struct literal name Point, got=%s", lit.Name.Value)
	}
	if len(lit.Fields) != 2 {
		t.Fatalf("expected 2 struct literal fields, got=%d", len(lit.Fields))
	}
}

func TestAssignmentExpressionParsing(t *testing.T) {
	input := `x = y + 1; point.x = 3;`

	l := lexer.New(input)
	p := New(l)
	program := p.ParseProgram()
	checkParserErrors(t, p)

	if len(program.Statements) != 2 {
		t.Fatalf("expected 2 statements, got=%d", len(program.Statements))
	}

	first := program.Statements[0].(*ast.ExpressionStatement)
	if _, ok := first.Expression.(*ast.AssignExpression); !ok {
		t.Fatalf("first expression is not ast.AssignExpression. got=%T", first.Expression)
	}

	second := program.Statements[1].(*ast.ExpressionStatement)
	assign, ok := second.Expression.(*ast.AssignExpression)
	if !ok {
		t.Fatalf("second expression is not ast.AssignExpression. got=%T", second.Expression)
	}
	if _, ok := assign.Left.(*ast.FieldExpression); !ok {
		t.Fatalf("assignment target should be ast.FieldExpression. got=%T", assign.Left)
	}
}
