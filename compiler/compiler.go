package compiler

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"mutant/ast"
	"mutant/builtin"
	"mutant/code"
	"mutant/object"
	"sort"
)

type Compiler struct {
	constants         []object.Object
	symbolTable       *SymbolTable
	scopes            []CompilationScope
	scopeIndex        int
	structDefinitions map[string][]*ast.Identifier // Maps struct name to field names
	enumDefinitions   map[string][]string          // Maps enum name to tag names
	loopContexts      []LoopContext

	injectSecurityChecks bool
	hasChkDbg            bool
	hasChkSnd            bool

	polymorphicEngine *PolymorphicEngine // Optional bytecode mutation engine
}

type ByteCode struct {
	Instructions code.Instructions
	Constants    []object.Object
	StructDefs   map[string][]*ast.Identifier
	EnumDefs     map[string][]string
	LuaPatches   map[string]*object.LuaPatch
}

type EmittedInstruction struct {
	Opcode   code.Opcode
	Position int
}

type CompilationScope struct {
	instructions    code.Instructions
	lastInstruction EmittedInstruction
	prevInstruction EmittedInstruction
}

type LoopContext struct {
	breakPositions    []int
	continuePositions []int
}

func New() *Compiler {
	mainScope := CompilationScope{
		instructions:    code.Instructions{},
		lastInstruction: EmittedInstruction{},
		prevInstruction: EmittedInstruction{},
	}

	table := NewSymbolTable()
	for i, v := range builtin.Builtins {
		table.DefineBuiltin(i, v.Name)
	}

	return &Compiler{
		constants:         []object.Object{},
		symbolTable:       table,
		scopes:            []CompilationScope{mainScope},
		scopeIndex:        0,
		structDefinitions: make(map[string][]*ast.Identifier),
		enumDefinitions:   make(map[string][]string),
		loopContexts:      []LoopContext{},
	}
}

func NewWithState(st *SymbolTable, constants []object.Object) *Compiler {
	compiler := New()
	compiler.symbolTable = st
	compiler.constants = constants
	compiler.structDefinitions = make(map[string][]*ast.Identifier)
	compiler.enumDefinitions = make(map[string][]string)
	return compiler
}

func (c *Compiler) EnableSecurityOpcodeInjection() {
	c.injectSecurityChecks = true
}

// EnablePolymorphism enables bytecode polymorphism at the specified mutation level
func (c *Compiler) EnablePolymorphism(level int) {
	if level > 0 {
		// Generate a random seed using crypto/rand
		seedBytes := make([]byte, 8)
		if _, err := rand.Read(seedBytes); err != nil {
			// Fallback to a deterministic seed if random generation fails
			seedBytes = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		}
		seed := int64(binary.BigEndian.Uint64(seedBytes))
		c.polymorphicEngine = NewPolymorphicEngine(level, seed)
	}
}

// EnablePolymorphismWithSeed enables bytecode polymorphism with a specific seed for reproducibility
func (c *Compiler) EnablePolymorphismWithSeed(level int, seed int64) {
	if level > 0 {
		c.polymorphicEngine = NewPolymorphicEngine(level, seed)
	}
}

func (c *Compiler) Compile(node ast.Node) error {
	switch node := node.(type) {
	case *ast.Program:
		for _, s := range node.Statements {
			if err := c.Compile(s); err != nil {
				return err
			}
			c.maybeEmitRandomSecurityCheckOpcodes()
		}
	case *ast.BlockStatement:
		for _, s := range node.Statements {
			if err := c.Compile(s); err != nil {
				return err
			}
		}
	case *ast.ExpressionStatement:
		if err := c.Compile(node.Expression); err != nil {
			return err
		}
		c.emit(code.OpPop)
	case *ast.PrefixExpression:
		if err := c.Compile(node.Right); err != nil {
			return err
		}
		switch node.Operator {
		case "-":
			c.emit(code.OpMinus)
		case "!":
			c.emit(code.OpBang)
		default:
			return fmt.Errorf("unknown operator %s", node.Operator)
		}
	case *ast.InfixExpression:
		if node.Operator == "<" {
			if err := c.Compile(node.Right); err != nil {
				return err
			}
			if err := c.Compile(node.Left); err != nil {
				return err
			}
			c.emit(code.OpGreater)
			return nil
		}
		if err := c.Compile(node.Left); err != nil {
			return err
		}
		if err := c.Compile(node.Right); err != nil {
			return err
		}
		switch node.Operator {
		case "+":
			c.emit(code.OpAdd)
		case "-":
			c.emit(code.OpSub)
		case "*":
			c.emit(code.OpMul)
		case "/":
			c.emit(code.OpDiv)
		case ">":
			c.emit(code.OpGreater)
		case "==":
			c.emit(code.OpEqual)
		case "!=":
			c.emit(code.OpUnEqual)
		default:
			return fmt.Errorf("unknown operator %s", node.Operator)
		}
	case *ast.IfExpression:
		if err := c.Compile(node.Condition); err != nil {
			return err
		}

		// emit bogus jumpFalse location
		jumpFalsePosition := c.emit(code.OpJumpFalse, 9999)

		if err := c.Compile(node.Consequence); err != nil {
			return err
		}

		if c.lastInstructionIs(code.OpPop) {
			c.removeLastPop()
		}

		// emit bogus jump location
		jumpPos := c.emit(code.OpJump, 9999)

		afterConsequencePosition := len(c.currentInstructions())
		c.changeOperand(jumpFalsePosition, afterConsequencePosition)

		if node.Alternative == nil {
			c.emit(code.OpNull)
		} else {
			if err := c.Compile(node.Alternative); err != nil {
				return err
			}

			if c.lastInstructionIs(code.OpPop) {
				c.removeLastPop()
			}
		}

		afterAlternativePosition := len(c.currentInstructions())
		c.changeOperand(jumpPos, afterAlternativePosition)
	case *ast.IndexExpression:
		if err := c.Compile(node.Left); err != nil {
			return err
		}
		if err := c.Compile(node.Index); err != nil {
			return err
		}
		c.emit(code.OpIndex)
	case *ast.FloatLiteral:
		float := &object.Float{Value: node.Value}
		c.emit(code.OpConstant, c.addConstant(float))
	case *ast.IntegerLiteral:
		integer := &object.Integer{Value: node.Value}
		c.emit(code.OpConstant, c.addConstant(integer))
	case *ast.StringLiteral:
		str := &object.String{Value: node.Value}
		c.emit(code.OpConstant, c.addConstant(str))
	case *ast.Boolean:
		if node.Value {
			c.emit(code.OpTrue)
		} else {
			c.emit(code.OpFalse)
		}
	case *ast.ArrayLiteral:
		for _, element := range node.Elements {
			if err := c.Compile(element); err != nil {
				return err
			}
		}
		c.emit(code.OpArray, len(node.Elements))
	case *ast.HashLiteral:
		keys := []ast.Expression{}
		for k := range node.Pairs {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

		for _, k := range keys {
			if err := c.Compile(k); err != nil {
				return err
			}
			if err := c.Compile(node.Pairs[k]); err != nil {
				return err
			}
		}

		c.emit(code.OpHash, len(node.Pairs)*2)

	case *ast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*ast.Identifier{node.Name}
		}

		if len(names) <= 1 {
			symbol := c.symbolTable.Define(node.Name.Value)
			if err := c.Compile(node.Value); err != nil {
				return err
			}
			if symbol.Scope == GlobalScope {
				c.emit(code.OpSetGlobal, symbol.Index)
			} else {
				c.emit(code.OpSetLocal, symbol.Index)
			}
			break
		}

		if err := c.Compile(node.Value); err != nil {
			return err
		}
		c.emit(code.OpDestructure, len(names))

		for i := len(names) - 1; i >= 0; i-- {
			ident := names[i]
			if ident == nil {
				continue
			}
			symbol := c.symbolTable.Define(ident.Value)
			if symbol.Scope == GlobalScope {
				c.emit(code.OpSetGlobal, symbol.Index)
			} else {
				c.emit(code.OpSetLocal, symbol.Index)
			}
		}

	case *ast.Identifier:
		symbol, ok := c.symbolTable.Resolve(node.Value)
		if !ok {
			return fmt.Errorf("undefined variable: %s", node.Value)
		}
		c.loadSymbol(symbol)

	case *ast.FunctionLiteral:
		c.enterScope()
		if node.Name != "" {
			c.symbolTable.DefineFunctionName(node.Name)
		}
		for _, param := range node.Parameters {
			c.symbolTable.Define(param.Value)
		}
		if err := c.Compile(node.Body); err != nil {
			return err
		}
		if c.lastInstructionIs(code.OpPop) {
			c.replaceLastPopWithReturn()
		}
		if !c.lastInstructionIs(code.OpReturnValue) {
			c.emit(code.OpReturn)
		}

		freeSymbols := c.symbolTable.FreeSymbols
		numLocals := c.symbolTable.numDefinitions
		insts := c.leaveScope()

		for _, sym := range freeSymbols {
			c.loadSymbol(sym)
		}

		compiledFun := &object.CompiledFunction{
			Instructions: insts,
			NumLocals:    numLocals,
			NumParams:    len(node.Parameters),
		}

		fnIndex := c.addConstant(compiledFun)
		c.emit(code.OpClosure, fnIndex, len(freeSymbols))
	case *ast.ReturnStatement:
		returnExprs := node.ReturnValues
		if len(returnExprs) == 0 && node.ReturnValue != nil {
			returnExprs = []ast.Expression{node.ReturnValue}
		}

		if len(returnExprs) == 0 {
			c.emit(code.OpReturn)
			return nil
		}

		if len(returnExprs) == 1 {
			if err := c.Compile(returnExprs[0]); err != nil {
				return err
			}
			c.emit(code.OpReturnValue)
			return nil
		}

		for _, expr := range returnExprs {
			if err := c.Compile(expr); err != nil {
				return err
			}
		}

		c.emit(code.OpMultiValue, len(returnExprs))
		c.emit(code.OpReturnValue)

	case *ast.ForStatement:
		return c.compileForStatement(node)

	case *ast.BreakStatement:
		if len(c.loopContexts) == 0 {
			return fmt.Errorf("break used outside of for loop")
		}
		jumpPos := c.emit(code.OpJump, 9999)
		ctx := &c.loopContexts[len(c.loopContexts)-1]
		ctx.breakPositions = append(ctx.breakPositions, jumpPos)

	case *ast.ContinueStatement:
		if len(c.loopContexts) == 0 {
			return fmt.Errorf("continue used outside of for loop")
		}
		jumpPos := c.emit(code.OpJump, 9999)
		ctx := &c.loopContexts[len(c.loopContexts)-1]
		ctx.continuePositions = append(ctx.continuePositions, jumpPos)

	case *ast.StructStatement:
		// Store struct definition
		c.structDefinitions[node.Name.Value] = node.Fields
		return nil

	case *ast.EnumStatement:
		// Store enum definition
		tags := []string{}
		for _, variant := range node.Variants {
			tags = append(tags, variant.Value)
		}
		c.enumDefinitions[node.Name.Value] = tags
		return nil

	case *ast.AssignExpression:
		return c.compileAssignExpression(node)

	case *ast.FieldExpression:
		return c.compileFieldExpression(node)

	case *ast.StructLiteral:
		return c.compileStructLiteral(node)

	case *ast.CallExpression:
		if err := c.Compile(node.Function); err != nil {
			return err
		}
		for _, arg := range node.Arguments {
			if err := c.Compile(arg); err != nil {
				return err
			}
		}
		c.emit(code.OpCall, len(node.Arguments))
	}

	return nil
}

func (c *Compiler) ByteCode() *ByteCode {
	if c.injectSecurityChecks {
		c.ensureRequiredSecurityCheckOpcodes()
	}

	bytecode := &ByteCode{
		Instructions: c.currentInstructions(),
		Constants:    c.constants,
		StructDefs:   c.structDefinitions,
		EnumDefs:     c.enumDefinitions,
		LuaPatches:   make(map[string]*object.LuaPatch),
	}

	// Apply polymorphic mutations if engine is enabled
	if c.polymorphicEngine != nil {
		bytecode = c.polymorphicEngine.Mutate(bytecode)
	}

	return bytecode
}

func (c *Compiler) maybeEmitRandomSecurityCheckOpcodes() {
	if !c.injectSecurityChecks {
		return
	}

	if randomChance(3) {
		c.emit(code.OpChkDbg)
		c.hasChkDbg = true
	}

	if randomChance(3) {
		c.emit(code.OpChkSnd)
		c.hasChkSnd = true
	}
}

func (c *Compiler) ensureRequiredSecurityCheckOpcodes() {
	if !c.hasChkDbg {
		c.emit(code.OpChkDbg)
		c.hasChkDbg = true
	}

	if !c.hasChkSnd {
		c.emit(code.OpChkSnd)
		c.hasChkSnd = true
	}
}

func randomChance(mod uint32) bool {
	if mod == 0 {
		return false
	}

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return false
	}

	return binary.BigEndian.Uint32(b)%mod == 0
}

func (c *Compiler) addConstant(obj object.Object) int {
	c.constants = append(c.constants, obj)
	return len(c.constants) - 1
}

func (c *Compiler) emit(op code.Opcode, operands ...int) int {
	ins := code.Make(op, operands...)
	pos := c.addInstruction(ins)
	c.setLastInstruction(op, pos)
	return pos
}

func (c *Compiler) addInstruction(ins []byte) int {
	posNewInstruction := len(c.currentInstructions())
	c.scopes[c.scopeIndex].instructions = append(c.currentInstructions(), ins...)
	return posNewInstruction
}

func (c *Compiler) setLastInstruction(op code.Opcode, pos int) {
	prev := c.scopes[c.scopeIndex].lastInstruction
	last := EmittedInstruction{Opcode: op, Position: pos}
	c.scopes[c.scopeIndex].prevInstruction = prev
	c.scopes[c.scopeIndex].lastInstruction = last
}

func (c *Compiler) lastInstructionIs(op code.Opcode) bool {
	if len(c.currentInstructions()) == 0 {
		return false
	}
	return c.scopes[c.scopeIndex].lastInstruction.Opcode == op
}
func (c *Compiler) removeLastPop() {
	c.scopes[c.scopeIndex].instructions = c.currentInstructions()[:c.scopes[c.scopeIndex].lastInstruction.Position]
	c.scopes[c.scopeIndex].lastInstruction = c.scopes[c.scopeIndex].prevInstruction
}
func (c *Compiler) replaceLastPopWithReturn() {
	lastPos := c.scopes[c.scopeIndex].lastInstruction.Position
	c.replaceInstruction(lastPos, code.Make(code.OpReturnValue))
	c.scopes[c.scopeIndex].lastInstruction.Opcode = code.OpReturnValue
}

func (c *Compiler) replaceInstruction(pos int, newInstruction []byte) {
	for i := 0; i < len(newInstruction); i++ {
		c.currentInstructions()[pos+i] = newInstruction[i]
	}
}

func (c *Compiler) changeOperand(pos int, operand int) {
	op := code.Opcode(c.currentInstructions()[pos])
	newInstruction := code.Make(op, operand)
	c.replaceInstruction(pos, newInstruction)
}

func (c *Compiler) currentInstructions() code.Instructions {
	return c.scopes[c.scopeIndex].instructions
}

func (c *Compiler) enterScope() {
	scope := CompilationScope{
		instructions:    code.Instructions{},
		lastInstruction: EmittedInstruction{},
		prevInstruction: EmittedInstruction{},
	}

	c.scopes = append(c.scopes, scope)
	c.scopeIndex++

	c.symbolTable = NewEnclosedSymbolTable(c.symbolTable)
}

func (c *Compiler) leaveScope() code.Instructions {
	instructions := c.currentInstructions()
	c.scopes = c.scopes[:len(c.scopes)-1]
	c.scopeIndex--
	c.symbolTable = c.symbolTable.Outer
	return instructions
}

func (c *Compiler) loadSymbol(s Symbol) {
	switch s.Scope {
	case GlobalScope:
		c.emit(code.OpGetGlobal, s.Index)
	case LocalScope:
		c.emit(code.OpGetLocal, s.Index)
	case BuiltinScope:
		c.emit(code.OpGetBuiltin, s.Index)
	case FreeScope:
		c.emit(code.OpGetFree, s.Index)
	case FunctionScope:
		c.emit(code.OpCurrentClosure)
	}
}

func (c *Compiler) compileForStatement(node *ast.ForStatement) error {
	initStart := len(c.currentInstructions())
	if node.Init != nil {
		if err := c.Compile(node.Init); err != nil {
			return err
		}
		if c.lastInstructionIs(code.OpPop) && c.scopes[c.scopeIndex].lastInstruction.Position >= initStart {
			c.removeLastPop()
		}
	}

	conditionStartPosition := len(c.currentInstructions())
	if node.Condition != nil {
		if err := c.Compile(node.Condition); err != nil {
			return err
		}
	} else {
		c.emit(code.OpTrue)
	}

	jumpFalsePosition := c.emit(code.OpJumpFalse, 9999)

	c.loopContexts = append(c.loopContexts, LoopContext{})
	if err := c.Compile(node.Body); err != nil {
		c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]
		return err
	}

	if c.lastInstructionIs(code.OpPop) {
		c.removeLastPop()
	}

	postStartPosition := len(c.currentInstructions())
	ctx := &c.loopContexts[len(c.loopContexts)-1]
	for _, pos := range ctx.continuePositions {
		c.changeOperand(pos, postStartPosition)
	}

	if node.Post != nil {
		if err := c.Compile(node.Post); err != nil {
			c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]
			return err
		}
		if c.lastInstructionIs(code.OpPop) {
			c.removeLastPop()
		}
	}

	c.emit(code.OpJump, conditionStartPosition)
	loopEndPosition := len(c.currentInstructions())
	c.changeOperand(jumpFalsePosition, loopEndPosition)

	for _, pos := range ctx.breakPositions {
		c.changeOperand(pos, loopEndPosition)
	}

	c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]

	return nil
}

func (c *Compiler) compileAssignExpression(node *ast.AssignExpression) error {
	// Handle identifier assignment: x = value
	if ident, ok := node.Left.(*ast.Identifier); ok {
		if err := c.Compile(node.Value); err != nil {
			return err
		}

		symbol, ok := c.symbolTable.Resolve(ident.Value)
		if !ok {
			// If not found, define it as global
			symbol = c.symbolTable.Define(ident.Value)
		}

		if symbol.Scope == GlobalScope {
			c.emit(code.OpSetGlobal, symbol.Index)
			c.emit(code.OpGetGlobal, symbol.Index)
		} else {
			c.emit(code.OpSetLocal, symbol.Index)
			c.emit(code.OpGetLocal, symbol.Index)
		}
		return nil
	}

	// Handle field assignment: struct.field = value
	if fieldExpr, ok := node.Left.(*ast.FieldExpression); ok {
		if err := c.Compile(fieldExpr.Left); err != nil {
			return err
		}

		fieldNameIndex := c.addConstant(&object.String{Value: fieldExpr.Field.Value})

		if err := c.Compile(node.Value); err != nil {
			return err
		}

		c.emit(code.OpSetField, fieldNameIndex)

		// If assigning to a named variable field (e.g., p.x = 1), persist the updated struct.
		if ident, ok := fieldExpr.Left.(*ast.Identifier); ok {
			symbol, resolved := c.symbolTable.Resolve(ident.Value)
			if !resolved {
				return fmt.Errorf("undefined variable: %s", ident.Value)
			}

			if symbol.Scope == GlobalScope {
				c.emit(code.OpSetGlobal, symbol.Index)
				c.emit(code.OpGetGlobal, symbol.Index)
			} else {
				c.emit(code.OpSetLocal, symbol.Index)
				c.emit(code.OpGetLocal, symbol.Index)
			}
			c.emit(code.OpGetField, fieldNameIndex)
		}
		return nil
	}

	return fmt.Errorf("invalid assignment target")
}

func (c *Compiler) compileFieldExpression(node *ast.FieldExpression) error {
	if ident, ok := node.Left.(*ast.Identifier); ok {
		if _, exists := c.enumDefinitions[ident.Value]; exists {
			typeNameIndex := c.addConstant(&object.String{Value: ident.Value})
			tagNameIndex := c.addConstant(&object.String{Value: node.Field.Value})
			c.emit(code.OpEnumValue, typeNameIndex, tagNameIndex)
			return nil
		}
	}

	if err := c.Compile(node.Left); err != nil {
		return err
	}

	fieldNameIndex := c.addConstant(&object.String{Value: node.Field.Value})
	c.emit(code.OpGetField, fieldNameIndex)
	return nil
}

func (c *Compiler) compileStructLiteral(node *ast.StructLiteral) error {
	structName := node.Name.Value
	typeDef, ok := c.structDefinitions[structName]
	if !ok {
		return fmt.Errorf("undefined struct type: %s", structName)
	}
	if len(typeDef) != len(node.Fields) {
		return fmt.Errorf("struct %s expects %d fields, got %d", structName, len(typeDef), len(node.Fields))
	}

	fieldExprByName := make(map[string]ast.Expression, len(node.Fields))
	for _, field := range node.Fields {
		if field == nil || field.Name == nil {
			return fmt.Errorf("invalid field initializer in struct %s", structName)
		}
		fieldExprByName[field.Name.Value] = field.Value
	}

	typeNameIndex := c.addConstant(&object.String{Value: structName})
	for _, field := range typeDef {
		expr, exists := fieldExprByName[field.Value]
		if !exists {
			return fmt.Errorf("missing field %s for struct %s", field.Value, structName)
		}
		if err := c.Compile(expr); err != nil {
			return err
		}
	}

	c.emit(code.OpMakeStruct, typeNameIndex, len(typeDef))
	return nil
}
