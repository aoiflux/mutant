package evaluator

import (
	"fmt"

	"mutant/ast"
	"mutant/object"
)

func DefineMacros(program *ast.Program, env *object.Environment) {
	definitions := []int{}

	for i, statement := range program.Statements {
		if isMacroDefinition(statement) {
			addMacro(statement, env)
			definitions = append(definitions, i)
		}
	}

	for i := len(definitions) - 1; i >= 0; i = i - 1 {
		definitionIndex := definitions[i]
		program.Statements = append(
			program.Statements[:definitionIndex],
			program.Statements[definitionIndex+1:]...,
		)
	}
}

func isMacroDefinition(node ast.Statement) bool {
	letStatement, ok := node.(*ast.LetStatement)
	if !ok {
		return false
	}
	_, ok = letStatement.Value.(*ast.MacroLiteral)
	return ok
}

func addMacro(stmt ast.Statement, env *object.Environment) {
	letStatement, _ := stmt.(*ast.LetStatement)
	macroLiteral, _ := letStatement.Value.(*ast.MacroLiteral)

	macro := &object.Macro{
		Parameters: macroLiteral.Parameters,
		Env:        env,
		Body:       macroLiteral.Body,
	}

	env.Set(letStatement.Name.Value, macro)
}

// ExpandMacros replaces every macro call in the program with the source the
// macro produced.
//
// It reports a bad macro rather than panicking. A macro body that does not end
// in a quote, one called with the wrong number of arguments, and an unquote of
// a value with no source form are all things a program can be written to do,
// and each used to take the whole compiler down with a Go stack trace.
// maxExpansionPasses bounds the expand-until-settled loop. A macro that emits a
// call to itself never settles, and 100 passes is far past anything a real
// program needs -- macros here nest by a handful at most.
const maxExpansionPasses = 100

func ExpandMacros(program ast.Node, env *object.Environment) (ast.Node, error) {
	node := program

	// Expansion repeats until nothing changes, because a macro may produce a
	// call to another macro. ast.Modify does not walk into what it just
	// substituted, so a single pass left that call in the tree and the compiler
	// reported it as an undefined variable.
	for pass := 0; ; pass++ {
		expanded, changed, err := expandMacrosOnce(node, env)
		if err != nil {
			return nil, err
		}
		node = expanded
		if !changed {
			return node, nil
		}
		if pass+1 >= maxExpansionPasses {
			return nil, fmt.Errorf(
				"macro expansion did not settle after %d passes: a macro expands into a call to itself",
				maxExpansionPasses)
		}
	}
}

func expandMacrosOnce(program ast.Node, env *object.Environment) (ast.Node, bool, error) {
	var failure error
	changed := false

	expanded := ast.Modify(program, func(node ast.Node) ast.Node {
		if failure != nil {
			return node
		}

		callExpression, ok := node.(*ast.CallExpression)
		if !ok {
			return node
		}

		macro, ok := isMacroCall(callExpression, env)
		if !ok {
			return node
		}

		name := callExpression.Function.String()
		args := quoteArgs(callExpression)
		if len(args) != len(macro.Parameters) {
			failure = fmt.Errorf("macro %s: wrong number of arguments. want=%d, got=%d",
				name, len(macro.Parameters), len(args))
			return node
		}

		evaluated := Eval(macro.Body, extendMacroEnv(macro, args))

		if errObj, isErr := evaluated.(*object.Error); isErr {
			failure = fmt.Errorf("macro %s: %s", name, errObj.Message)
			return node
		}

		quote, ok := evaluated.(*object.Quote)
		if !ok {
			// The macro ran, but produced a value instead of source. Naming what
			// it produced is the difference between a usable message and
			// "we only support returning AST-nodes from macros".
			produced := "nothing"
			if evaluated != nil {
				produced = string(evaluated.Type())
			}
			failure = fmt.Errorf("macro %s must return quote(...), got %s", name, produced)
			return node
		}

		changed = true
		return quote.Node
	})

	if failure != nil {
		return nil, false, failure
	}
	return expanded, changed, nil
}

func isMacroCall(exp *ast.CallExpression, env *object.Environment) (*object.Macro, bool) {
	identifier, ok := exp.Function.(*ast.Identifier)
	if !ok {
		return nil, false
	}

	obj, ok := env.Get(identifier.Value)
	if !ok {
		return nil, false
	}

	macro, ok := obj.(*object.Macro)
	if !ok {
		return nil, false
	}

	return macro, true
}

func quoteArgs(exp *ast.CallExpression) []*object.Quote {
	args := []*object.Quote{}

	for _, a := range exp.Arguments {
		args = append(args, &object.Quote{Node: a})
	}

	return args
}

// extendMacroEnv binds the call's arguments to the macro's parameters. The
// caller checks arity first: this indexes positionally and would otherwise
// panic on an under-applied macro.
func extendMacroEnv(macro *object.Macro, args []*object.Quote) *object.Environment {
	extended := object.NewEnclosedEnvironement(macro.Env)

	for paramIdx, param := range macro.Parameters {
		if paramIdx >= len(args) {
			break
		}
		extended.Set(param.Value, args[paramIdx])
	}

	return extended
}
