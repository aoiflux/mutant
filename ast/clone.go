package ast

// Clone returns a deep copy of node: every node reachable from it is a new
// value, so rewriting the copy cannot be observed through the original.
//
// This exists because Modify rewrites in place. That is what its callers want
// when they are rewriting a program, but it is wrong for a template that gets
// used more than once -- and a macro body is exactly that. Expanding a macro
// evaluates the body's quote(...), which runs Modify over the body to
// substitute the unquoted arguments. Without a copy the substitution is written
// back into the macro itself, so a second call re-uses the first call's
// arguments: add_expr(3, 9) followed by add_expr(x, 5) both produced 12.
//
// Tokens are copied by value; they carry position information from the original
// source, which is the honest answer for a node the macro expander produced. A
// cloned Program deliberately carries no NodePositions: those keys are the
// original node pointers, and a clone is by definition not those nodes. Only
// the LSP reads that side-table, and it works on parsed source rather than on
// expanded macros.
func Clone(node Node) Node {
	switch node := node.(type) {
	case nil:
		return nil

	/// ---------- leaves ---------- ///
	case *Identifier:
		return cloneIdentifier(node)
	case *IntegerLiteral:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied
	case *FloatLiteral:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied
	case *StringLiteral:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied
	case *Boolean:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied
	case *BreakStatement:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied
	case *ContinueStatement:
		if node == nil {
			return nil
		}
		copied := *node
		return &copied

	/// ---------- expressions ---------- ///
	case *PrefixExpression:
		if node == nil {
			return nil
		}
		return &PrefixExpression{
			Token:    node.Token,
			Operator: node.Operator,
			Right:    cloneExpression(node.Right),
		}
	case *InfixExpression:
		if node == nil {
			return nil
		}
		return &InfixExpression{
			Token:    node.Token,
			Left:     cloneExpression(node.Left),
			Operator: node.Operator,
			Right:    cloneExpression(node.Right),
		}
	case *IndexExpression:
		if node == nil {
			return nil
		}
		return &IndexExpression{
			Token: node.Token,
			Left:  cloneExpression(node.Left),
			Index: cloneExpression(node.Index),
		}
	case *CallExpression:
		if node == nil {
			return nil
		}
		return &CallExpression{
			Token:     node.Token,
			Function:  cloneExpression(node.Function),
			Arguments: cloneExpressions(node.Arguments),
		}
	case *AssignExpression:
		if node == nil {
			return nil
		}
		return &AssignExpression{
			Token:    node.Token,
			Left:     cloneExpression(node.Left),
			Value:    cloneExpression(node.Value),
			Operator: node.Operator,
			Postfix:  node.Postfix,
		}
	case *FieldExpression:
		if node == nil {
			return nil
		}
		return &FieldExpression{
			Token: node.Token,
			Left:  cloneExpression(node.Left),
			Field: cloneIdentifier(node.Field),
		}
	case *IfExpression:
		if node == nil {
			return nil
		}
		return &IfExpression{
			Token:       node.Token,
			Condition:   cloneExpression(node.Condition),
			Consequence: cloneBlock(node.Consequence),
			Alternative: cloneBlock(node.Alternative),
		}
	case *FunctionLiteral:
		if node == nil {
			return nil
		}
		return &FunctionLiteral{
			Token:      node.Token,
			Parameters: cloneIdentifiers(node.Parameters),
			Body:       cloneBlock(node.Body),
			Name:       node.Name,
		}
	case *MacroLiteral:
		if node == nil {
			return nil
		}
		return &MacroLiteral{
			Token:      node.Token,
			Parameters: cloneIdentifiers(node.Parameters),
			Body:       cloneBlock(node.Body),
		}
	case *ArrayLiteral:
		if node == nil {
			return nil
		}
		return &ArrayLiteral{
			Token:    node.Token,
			Elements: cloneExpressions(node.Elements),
		}
	case *HashLiteral:
		if node == nil {
			return nil
		}
		pairs := make(map[Expression]Expression, len(node.Pairs))
		for key, value := range node.Pairs {
			pairs[cloneExpression(key)] = cloneExpression(value)
		}
		return &HashLiteral{Token: node.Token, Pairs: pairs}
	case *StructLiteral:
		if node == nil {
			return nil
		}
		fields := make([]*StructFieldValue, 0, len(node.Fields))
		for _, field := range node.Fields {
			if field == nil {
				fields = append(fields, nil)
				continue
			}
			fields = append(fields, &StructFieldValue{
				Name:  cloneIdentifier(field.Name),
				Value: cloneExpression(field.Value),
			})
		}
		return &StructLiteral{
			Token:  node.Token,
			Name:   cloneIdentifier(node.Name),
			Fields: fields,
		}

	/// ---------- statements ---------- ///
	case *Program:
		if node == nil {
			return nil
		}
		copied := &Program{Statements: cloneStatements(node.Statements)}
		if node.Comments != nil {
			copied.Comments = append(copied.Comments, node.Comments...)
		}
		return copied
	case *BlockStatement:
		return cloneBlock(node)
	case *ExpressionStatement:
		if node == nil {
			return nil
		}
		return &ExpressionStatement{
			Token:      node.Token,
			Expression: cloneExpression(node.Expression),
		}
	case *LetStatement:
		if node == nil {
			return nil
		}
		copied := &LetStatement{
			Token: node.Token,
			Names: cloneIdentifiers(node.Names),
			Value: cloneExpression(node.Value),
		}
		// Name aliases Names[0] in a parsed tree and the compiler reads both, so
		// keep them the same pointer rather than two equal copies.
		if len(copied.Names) > 0 {
			copied.Name = copied.Names[0]
		} else {
			copied.Name = cloneIdentifier(node.Name)
		}
		return copied
	case *ReturnStatement:
		if node == nil {
			return nil
		}
		copied := &ReturnStatement{
			Token:        node.Token,
			ReturnValues: cloneExpressions(node.ReturnValues),
		}
		// Same aliasing rule as LetStatement.Name.
		if len(copied.ReturnValues) > 0 {
			copied.ReturnValue = copied.ReturnValues[0]
		} else {
			copied.ReturnValue = cloneExpression(node.ReturnValue)
		}
		return copied
	case *ForStatement:
		if node == nil {
			return nil
		}
		copied := &ForStatement{
			Token:     node.Token,
			Condition: cloneExpression(node.Condition),
			Post:      cloneExpression(node.Post),
			Body:      cloneBlock(node.Body),
		}
		if node.Init != nil {
			copied.Init, _ = Clone(node.Init).(Statement)
		}
		return copied
	case *StructStatement:
		if node == nil {
			return nil
		}
		return &StructStatement{
			Token:  node.Token,
			Name:   cloneIdentifier(node.Name),
			Fields: cloneIdentifiers(node.Fields),
		}
	case *EnumStatement:
		if node == nil {
			return nil
		}
		return &EnumStatement{
			Token:    node.Token,
			Name:     cloneIdentifier(node.Name),
			Variants: cloneIdentifiers(node.Variants),
		}
	}

	// An unknown node type is returned as-is rather than dropped: sharing it is
	// wrong, but losing it is worse, and a new node type failing the clone
	// coverage test is how this is meant to be noticed.
	return node
}

func cloneExpression(expression Expression) Expression {
	if expression == nil {
		return nil
	}
	cloned, _ := Clone(expression).(Expression)
	return cloned
}

func cloneExpressions(expressions []Expression) []Expression {
	if expressions == nil {
		return nil
	}
	cloned := make([]Expression, 0, len(expressions))
	for _, expression := range expressions {
		cloned = append(cloned, cloneExpression(expression))
	}
	return cloned
}

func cloneStatements(statements []Statement) []Statement {
	if statements == nil {
		return nil
	}
	cloned := make([]Statement, 0, len(statements))
	for _, statement := range statements {
		if statement == nil {
			cloned = append(cloned, nil)
			continue
		}
		copied, _ := Clone(statement).(Statement)
		cloned = append(cloned, copied)
	}
	return cloned
}

func cloneIdentifier(identifier *Identifier) *Identifier {
	if identifier == nil {
		return nil
	}
	copied := *identifier
	return &copied
}

func cloneIdentifiers(identifiers []*Identifier) []*Identifier {
	if identifiers == nil {
		return nil
	}
	cloned := make([]*Identifier, 0, len(identifiers))
	for _, identifier := range identifiers {
		cloned = append(cloned, cloneIdentifier(identifier))
	}
	return cloned
}

func cloneBlock(block *BlockStatement) *BlockStatement {
	if block == nil {
		return nil
	}
	return &BlockStatement{
		Token:      block.Token,
		Statements: cloneStatements(block.Statements),
	}
}
