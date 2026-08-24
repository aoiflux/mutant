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

	// OpcodeMap undoes the polymorphic engine's opcode permutation: it is
	// indexed by the byte found in the instruction stream and yields the real
	// opcode. 256 entries, or nil when the program was not remapped.
	//
	// It has to travel with the program rather than be re-derived from the seed,
	// because nothing that runs a .mu file knows the seed -- and a VM that
	// guesses wrong does not fail cleanly. Every opcode maps to another *defined*
	// opcode, so a stream read without this table still decodes, just as a
	// different instruction of a different width.
	//
	// The field is gob-encoded with the rest of ByteCode. An older .mu simply has
	// no entry for it and decodes to nil, which is the unmutated case.
	OpcodeMap []byte
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

// SeedTypeDefinitions pre-loads struct and enum declarations recorded by an
// earlier compilation. A REPL session compiles each line separately, so without
// this a type declared on one line is "undefined" on the next; seeding the
// definitions carried out of the previous ByteCode keeps a session coherent.
func (c *Compiler) SeedTypeDefinitions(structs map[string][]*ast.Identifier, enums map[string][]string) {
	for name, fields := range structs {
		if _, exists := c.structDefinitions[name]; !exists {
			c.structDefinitions[name] = fields
		}
	}
	for name, variants := range enums {
		if _, exists := c.enumDefinitions[name]; !exists {
			c.enumDefinitions[name] = variants
		}
	}
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
		// Logical && / || short-circuit and produce a strict boolean. They compile
		// to conditional jumps (like `if`) rather than an arithmetic opcode, so the
		// right operand's instructions only run when the left doesn't decide it.
		if node.Operator == "&&" || node.Operator == "||" {
			return c.compileLogicalExpression(node)
		}
		// a < b  ==  b > a ;  a <= b  ==  b >= a. Compile with swapped operands
		// so we need only the "greater" family of opcodes.
		if node.Operator == "<" || node.Operator == "<=" {
			if err := c.Compile(node.Right); err != nil {
				return err
			}
			if err := c.Compile(node.Left); err != nil {
				return err
			}
			if node.Operator == "<" {
				c.emit(code.OpGreater)
			} else {
				c.emit(code.OpGreaterEqual)
			}
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
		case "%":
			c.emit(code.OpMod)
		case ">":
			c.emit(code.OpGreater)
		case ">=":
			c.emit(code.OpGreaterEqual)
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

	case *ast.MacroLiteral:
		// Macros are collected and expanded into ordinary AST before
		// compilation (evaluator.DefineMacros/ExpandMacros). DefineMacros only
		// scans top-level statements, so the usual way one reaches codegen is a
		// macro declared inside a function or a block -- which is never
		// collected, and so is never expanded or removed. Emitting nothing for
		// it would leave the stack unbalanced and the VM would later pop past
		// the bottom and panic, so say plainly what went wrong instead.
		return fmt.Errorf("macro definitions must appear at the top level, and are expanded before compilation")

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

	case nil:
		// A missing node is not nothing: the caller expected this to leave a
		// value on the stack. Emitting nothing balances the compile and breaks
		// the VM instead, several phases later, with a pop past the bottom of
		// the stack. Macro expansion used to produce these -- unquoting a value
		// with no source form put a nil in the tree -- and the resulting .mu
		// compiled cleanly and then crashed when it was run.
		return fmt.Errorf("internal: nothing to compile where an expression was expected")

	default:
		// Every AST node type has a case above. A new one landing here would
		// otherwise compile to nothing at all, silently.
		return fmt.Errorf("internal: no code generation for %T", node)
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

// PolymorphicLevel reports the mutation level this compiler applied, or 0 if
// polymorphism was never enabled.
//
// Callers that need to know whether ByteCode() appended a polymorphic marker
// must ask this rather than inspecting the trailing bytes. The marker is
// [0xFF, level], and ordinary bytecode reaches those values on its own: an
// OpConstant whose operand ends in 0xFF followed by a one-byte opcode looks
// exactly like a marker. Deciding to truncate on that guess silently cut two
// real bytes off roughly a third of the programs large enough to have 256
// constants.
func (c *Compiler) PolymorphicLevel() int {
	if c.polymorphicEngine == nil {
		return 0
	}
	return c.polymorphicEngine.mutationLevel
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

// compileLogicalExpression emits short-circuit code for && / || that leaves a
// strict boolean on the stack. OpJumpFalse pops its condition and jumps when it
// is falsy, so we branch on the operands and only evaluate the right side when
// the left doesn't already decide the result.
func (c *Compiler) compileLogicalExpression(node *ast.InfixExpression) error {
	if err := c.Compile(node.Left); err != nil {
		return err
	}

	if node.Operator == "&&" {
		leftFalse := c.emit(code.OpJumpFalse, 9999) // left falsy -> result is false
		if err := c.Compile(node.Right); err != nil {
			return err
		}
		rightFalse := c.emit(code.OpJumpFalse, 9999) // right falsy -> result is false
		c.emit(code.OpTrue)
		toEnd := c.emit(code.OpJump, 9999)
		falsePos := len(c.currentInstructions())
		c.changeOperand(leftFalse, falsePos)
		c.changeOperand(rightFalse, falsePos)
		c.emit(code.OpFalse)
		c.changeOperand(toEnd, len(c.currentInstructions()))
		return nil
	}

	// "||": OpJumpFalse falls through when the left is truthy -> result is true.
	leftFalse := c.emit(code.OpJumpFalse, 9999)
	c.emit(code.OpTrue)
	trueEnd1 := c.emit(code.OpJump, 9999)
	c.changeOperand(leftFalse, len(c.currentInstructions())) // left falsy -> test right
	if err := c.Compile(node.Right); err != nil {
		return err
	}
	rightFalse := c.emit(code.OpJumpFalse, 9999)
	c.emit(code.OpTrue)
	trueEnd2 := c.emit(code.OpJump, 9999)
	c.changeOperand(rightFalse, len(c.currentInstructions()))
	c.emit(code.OpFalse)
	endPos := len(c.currentInstructions())
	c.changeOperand(trueEnd1, endPos)
	c.changeOperand(trueEnd2, endPos)
	return nil
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
	// Compound assignment (x += v, x++) desugars to `x = x <op> v`: the value to
	// store is the base operator applied to the target's current value and the
	// right-hand side. Every store path below compiles valueExpr, so this is the
	// single point where the fold is introduced.
	valueExpr := node.Value
	if node.Operator != "" {
		valueExpr = &ast.InfixExpression{
			Token:    node.Token,
			Left:     node.Left,
			Operator: node.Operator,
			Right:    node.Value,
		}
	}

	// Handle identifier assignment: x = value
	if ident, ok := node.Left.(*ast.Identifier); ok {
		if err := c.Compile(valueExpr); err != nil {
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

		if err := c.Compile(valueExpr); err != nil {
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

	// Handle index assignment: a[i] = value / h[k] = value
	if idxExpr, ok := node.Left.(*ast.IndexExpression); ok {
		if err := c.Compile(idxExpr.Left); err != nil {
			return err
		}
		if err := c.Compile(idxExpr.Index); err != nil {
			return err
		}
		if err := c.Compile(valueExpr); err != nil {
			return err
		}
		c.emit(code.OpSetIndex)

		// If the container is a simple variable, persist the mutated container
		// back into its slot (mirrors field assignment) and leave it as the
		// expression's value.
		if ident, ok := idxExpr.Left.(*ast.Identifier); ok {
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
