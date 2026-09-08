package compiler

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
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
	// securityRNG decides where the optional security checks land. It is nil
	// unless a seed was supplied, in which case the placement becomes
	// reproducible -- see SetSecurityCheckSeed.
	securityRNG *mathrand.Rand

	polymorphicEngine *PolymorphicEngine // Optional bytecode mutation engine

	// positions is the parser's node-to-range side table, merged in from every
	// Program compiled. macroOrigins is its sibling for nodes a macro produced.
	// Both are keyed by node pointer, so they are accumulated rather than
	// replaced: the REPL compiles one Program per line against a symbol table
	// and constant pool that outlive it, and a closure compiled on line 1 is
	// still callable on line 3.
	positions    map[ast.Node]ast.Range
	macroOrigins map[ast.Node]ast.MacroOrigin

	// The position instructions are currently being attributed to, maintained
	// by Compile as it descends. macroLine/macroCol are the definition site of
	// the macro the current node was expanded from, and are zero outside one.
	posLine, posCol       int
	posEndLine, posEndCol int
	macroLine, macroCol   int

	sourceFile string
	sourceText string
}

type ByteCode struct {
	Instructions code.Instructions
	Constants    []object.Object
	StructDefs   map[string][]*ast.Identifier
	EnumDefs     map[string][]string
	LuaPatches   map[string]*object.LuaPatch

	// Version is the bytecode container version. It is absent from anything
	// compiled before versioning existed, which gob decodes to 0 -- so 0 means
	// BytecodeVersionOrdinalBuiltins and is normalised to it on load.
	Version int

	// BuiltinNames is what an OpGetBuiltin operand indexes: the builtins this
	// program referenced, in the order the compiler first saw them. Carrying the
	// names rather than registry ordinals is what lets a builtin be renamed,
	// retired or reordered without invalidating artifacts already compiled --
	// they name what they call, and the runtime resolves those names at load.
	//
	// Only referenced builtins are listed, not the whole registry. A program
	// that calls three builtins should not fail to load because an unrelated
	// four hundredth was retired.
	//
	// Empty for BytecodeVersionOrdinalBuiltins, where the operand is a registry
	// ordinal resolved through builtin.ResolveLegacyOrdinals instead.
	BuiltinNames []string

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

	// SourceFile, LineTable and MacroTable are what turn a failing instruction
	// pointer back into something an analyst can act on. LineTable annotates
	// Instructions; each CompiledFunction in Constants carries its own.
	//
	// These need no Version bump, unlike BuiltinNames above. gob omits zero
	// values and ignores fields it does not know, so a new runtime reading an
	// old artifact sees empty tables -- which is exactly true of it -- and an
	// old runtime reading a new artifact ignores them. Absence is already the
	// correct reading in both directions, so there is nothing for a version to
	// disambiguate.
	//
	// They are removed from artifacts that leave the machine: see
	// StripDebugInfo.
	SourceFile string
	LineTable  code.LineTable
	MacroTable code.LineTable

	// EndTable records where each attributed construct ends, so a report can
	// underline the span that failed rather than pointing at its first
	// character. Same encoding as LineTable, separately strippable.
	EndTable code.LineTable

	// SourceText is the program's own source, carried so a failing artifact
	// can quote the line it died on without reading anything off disk. A .mu
	// gets copied to the machine that runs it far more often than its .mut
	// does, and a VM that opens files at fault time to find out where it is
	// would be a worse idea than the bytes it saves.
	//
	// Stripped for release along with everything else here.
	SourceText string
}

// StripDebugInfo removes every source position from the program: the file name,
// both tables on the main stream, and the name and tables of every compiled
// function reachable through the constant pool.
//
// It is called for release artifacts: those are what leave the machine, and a
// map from an artifact's bytecode back to its source lines is a
// reverse-engineering aid worth withholding from them. A .mu compiled to run
// locally keeps its positions, because the machine running it already holds the
// source.
//
// Polymorphism does not strip. The engine moves every instruction, which would
// leave a table built at emit time describing the wrong lines, so it carries the
// tables through the same offset remap it uses to repoint jumps -- see
// PolymorphicEngine.spliceFillers. Dropping them there instead would have meant
// no ordinary run ever had positions, since mutation is on by default.
func (bc *ByteCode) StripDebugInfo() {
	if bc == nil {
		return
	}

	bc.SourceFile = ""
	bc.SourceText = ""
	bc.LineTable = nil
	bc.MacroTable = nil
	bc.EndTable = nil

	for _, constant := range bc.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			fn.Name = ""
			fn.Params = nil
			fn.LineTable = nil
			fn.MacroTable = nil
			fn.EndTable = nil
		}
	}
}

type EmittedInstruction struct {
	Opcode   code.Opcode
	Position int
}

type CompilationScope struct {
	instructions    code.Instructions
	lastInstruction EmittedInstruction
	prevInstruction EmittedInstruction

	// One line table per instruction stream, built as the stream is emitted.
	// Value types, so a zero CompilationScope is usable and the two existing
	// composite literals did not have to change.
	lines  code.LineTableBuilder
	ends   code.LineTableBuilder
	macros code.LineTableBuilder
}

// scopeDebug is everything a finished scope hands back besides its
// instructions. It exists so leaveScope stays a two-value call as the number of
// tables grows.
type scopeDebug struct {
	lines  code.LineTable
	ends   code.LineTable
	macros code.LineTable
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

// SetSecurityCheckSeed makes the placement of the injected OpChkDbg/OpChkSnd
// checks reproducible from a seed.
//
// Without it the placement is drawn from crypto/rand, which meant --seed did
// not actually reproduce a build: two compiles of the same source with the same
// seed produced instruction streams of different lengths, at every mutation
// level, including 0 where the polymorphic engine does not run at all. That is
// the same defect NOP insertion had, in the one part of the pipeline that was
// never looked at because it is not a mutation stage.
//
// What the seed reproduces is the bytecode, not the .mu file. The file is
// sealed with AES-GCM under a fresh salt and nonce and differs every build,
// which is correct -- repeating a GCM nonce under one key is a break.
//
// Leaving it unset keeps the old behaviour, which is what a build with no --seed
// wants: the checks land somewhere different every time.
func (c *Compiler) SetSecurityCheckSeed(seed int64) {
	c.securityRNG = mathrand.New(mathrand.NewSource(seed))
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

// Compile emits code for node, tracking the source position instructions are
// attributed to.
//
// The position bookkeeping lives here rather than inside the dispatch switch so
// that the switch -- which is the compiler -- stays about compiling. A node with
// no recorded range does not reset the current position, it inherits the
// enclosing one, which is the right answer for the nodes the compiler
// synthesises on its own behalf: they belong to whatever the user wrote that
// caused them.
func (c *Compiler) Compile(node ast.Node) error {
	if program, ok := node.(*ast.Program); ok {
		c.absorbPositions(program)
	}

	origin, fromMacro := c.macroOrigins[node]

	rng, ok := c.positions[node]
	if !ok || !rng.Start.IsValid() || (!fromMacro && !anchorsPosition(node)) {
		return c.compileNode(node)
	}

	savedLine, savedCol := c.posLine, c.posCol
	savedEndLine, savedEndCol := c.posEndLine, c.posEndCol
	savedMacroLine, savedMacroCol := c.macroLine, c.macroCol

	c.posLine, c.posCol = rng.Start.Line, rng.Start.Column

	// The end is optional: a node whose range the parser only half filled in
	// still gets a usable start, and the reporter falls back to a caret on the
	// start column rather than underlining a span it cannot trust.
	c.posEndLine, c.posEndCol = 0, 0
	if rng.End.IsValid() {
		c.posEndLine, c.posEndCol = rng.End.Line, rng.End.Column
	}

	if fromMacro && origin.Definition.Start.IsValid() {
		c.macroLine, c.macroCol = origin.Definition.Start.Line, origin.Definition.Start.Column
	}

	err := c.compileNode(node)

	c.posLine, c.posCol = savedLine, savedCol
	c.posEndLine, c.posEndCol = savedEndLine, savedEndCol
	c.macroLine, c.macroCol = savedMacroLine, savedMacroCol
	return err
}

// anchorsPosition reports whether a node should move the position instructions
// are attributed to, or leave it where its parent set it.
//
// Only statements and calls anchor. Attributing every expression node its own
// position sounds more precise and is not: it costs one table entry per
// instruction -- measured at parity with the instruction stream itself, against
// the single-digit percent this is supposed to cost -- and buys a column inside
// an expression that no traceback frame reports anyway. A frame is a call, and a
// fault is somewhere in a statement; those are the two granularities that get
// read, so those are the two that get recorded.
//
// Infix and index expressions anchor as well, and they are the exception that
// proves the rule: they are where a well-formed program actually fails at
// runtime -- division by zero, a type mismatch across an operator, an index
// past the end -- so they are the two places a caret under the sub-expression
// is worth more than the entries it costs. `total / count(xs)` names which
// division rather than which line.
//
// A node a macro produced anchors regardless, because it is the only place its
// origin can be attached.
func anchorsPosition(node ast.Node) bool {
	switch node.(type) {
	case ast.Statement, *ast.CallExpression, *ast.InfixExpression, *ast.IndexExpression:
		return true
	}
	return false
}

// absorbPositions merges a Program's position side-tables into the compiler's.
// Merging rather than assigning is what makes the REPL work: each line is its
// own Program, and code compiled from an earlier one is still live.
func (c *Compiler) absorbPositions(program *ast.Program) {
	if program == nil {
		return
	}

	if len(program.NodePositions) > 0 {
		if c.positions == nil {
			c.positions = make(map[ast.Node]ast.Range, len(program.NodePositions))
		}
		for node, rng := range program.NodePositions {
			c.positions[node] = rng
		}
	}

	if len(program.MacroExpansions) > 0 {
		if c.macroOrigins == nil {
			c.macroOrigins = make(map[ast.Node]ast.MacroOrigin, len(program.MacroExpansions))
		}
		for node, origin := range program.MacroExpansions {
			c.macroOrigins[node] = origin
		}
	}
}

// SetSourceFile records the path reported in tracebacks and on errors. It is
// stripped along with the line tables from anything built for distribution.
func (c *Compiler) SetSourceFile(path string) { c.sourceFile = path }

// SetSourceText embeds the program's source so a failing artifact can quote the
// line it died on. Stripped for release along with the position tables.
func (c *Compiler) SetSourceText(text string) { c.sourceText = text }

// parameterNames pulls the declared names out of a function literal so a
// traceback can label the arguments it finds on the stack. A nil parameter --
// which a hand-built AST in a test can produce -- becomes an empty name, and
// the renderer falls back to the position for that one argument.
func parameterNames(params []*ast.Identifier) []string {
	if len(params) == 0 {
		return nil
	}

	names := make([]string, len(params))
	for i, param := range params {
		if param != nil {
			names[i] = param.Value
		}
	}
	return names
}

func (c *Compiler) compileNode(node ast.Node) error {
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
		case "~":
			c.emit(code.OpBitNot)
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
		case "&":
			c.emit(code.OpBitAnd)
		case "|":
			c.emit(code.OpBitOr)
		case "^":
			c.emit(code.OpBitXor)
		case "<<":
			c.emit(code.OpShiftLeft)
		case ">>":
			c.emit(code.OpShiftRight)
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
		// Read before leaveScope drops the table. Every capture of one of this
		// function's locals has already been discovered, because a capture is
		// discovered while the inner literal is compiled and every inner literal
		// is inside the body just compiled.
		capturedLocals := c.symbolTable.CapturedLocals()
		insts, debug := c.leaveScope()

		// The reads and writes of a captured slot were emitted before anyone knew
		// it would be captured, so they are patched now rather than at emit time.
		// Only the opcode byte changes -- the cell forms take the same one-byte
		// operand -- so nothing moves and no jump target, line-table offset or
		// loop patch has to be recomputed.
		boxCapturedLocals(insts, capturedLocals)

		// The capture list OpClosure consumes is built in the *enclosing* scope,
		// and it pushes cells rather than values: that shared pointer is the
		// whole mechanism. loadSymbol is deliberately not used here -- it reads
		// through storage, and this list is the one place that wants the storage
		// itself.
		for _, sym := range freeSymbols {
			c.emitCapture(sym)
		}

		compiledFun := &object.CompiledFunction{
			Instructions:   insts,
			NumLocals:      numLocals,
			NumParams:      len(node.Parameters),
			CapturedLocals: capturedLocals,
			Name:           node.Name,
			Params:         parameterNames(node.Parameters),
			LineTable:      debug.lines,
			MacroTable:     debug.macros,
			EndTable:       debug.ends,
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
		Version:      BytecodeVersion,
		BuiltinNames: c.symbolTable.ReferencedBuiltins(),
		SourceFile:   c.sourceFile,
		SourceText:   c.sourceText,
		LineTable:    c.scopes[c.scopeIndex].lines.Build(),
		MacroTable:   c.scopes[c.scopeIndex].macros.Build(),
		EndTable:     c.scopes[c.scopeIndex].ends.Build(),
	}

	// Apply polymorphic mutations if engine is enabled. The engine carries the
	// line tables through its own offset remap, because mutation is on by
	// default -- `mutant prog.mut` compiles at level 5 -- and dropping
	// positions here would mean no ordinary run ever had them. What actually
	// removes them is building for release; see generator.compile.
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

	if c.randomChance(3) {
		c.emit(code.OpChkDbg)
		c.hasChkDbg = true
	}

	if c.randomChance(3) {
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

func (c *Compiler) randomChance(mod uint32) bool {
	if mod == 0 {
		return false
	}

	if c.securityRNG != nil {
		return uint32(c.securityRNG.Int63())%mod == 0
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
	c.recordPosition(pos)
	c.setLastInstruction(op, pos)
	return pos
}

// recordPosition notes where the instruction beginning at ip came from. Both
// builders drop the call when there is no position to record, so an instruction
// outside any macro costs nothing in the macro table.
func (c *Compiler) recordPosition(ip int) {
	scope := &c.scopes[c.scopeIndex]
	scope.lines.Add(ip, c.posLine, c.posCol)
	scope.ends.Add(ip, c.posEndLine, c.posEndCol)
	scope.macros.Add(ip, c.macroLine, c.macroCol)
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

func (c *Compiler) leaveScope() (code.Instructions, scopeDebug) {
	instructions := c.currentInstructions()
	debug := scopeDebug{
		lines:  c.scopes[c.scopeIndex].lines.Build(),
		ends:   c.scopes[c.scopeIndex].ends.Build(),
		macros: c.scopes[c.scopeIndex].macros.Build(),
	}

	c.scopes = c.scopes[:len(c.scopes)-1]
	c.scopeIndex--
	c.symbolTable = c.symbolTable.Outer
	return instructions, debug
}

func (c *Compiler) loadSymbol(s Symbol) {
	switch s.Scope {
	case GlobalScope:
		c.emit(code.OpGetGlobal, s.Index)
	case LocalScope:
		c.emit(code.OpGetLocal, s.Index)
	case BuiltinScope:
		// s.Index is the builtin's ordinal in the global registry, and that is
		// deliberately not what gets emitted. An ordinal in the instruction
		// stream makes the registry append-only forever: nothing can be renamed,
		// retired or reordered without rebinding every call in every .mu already
		// written. The operand indexes this program's own table of names
		// instead, which the runtime resolves by name at load.
		//
		// The high bit marks the operand as a name-table index. It costs nothing
		// here and makes a pre-v2.5 runtime handed this program stop on its own
		// bounds check rather than silently call whichever builtin sits at that
		// registry ordinal; see code.BuiltinNameTableFlag.
		c.emit(code.OpGetBuiltin, code.BuiltinNameTableFlag|c.symbolTable.ReferenceBuiltin(s.Name))
	case FreeScope:
		// OpGetFree reads through the cell. A free whose original is the
		// enclosing function's own name is captured by value instead and is not
		// a cell; the VM's arm handles both, which is also what keeps bytecode
		// compiled before boxing running unchanged.
		c.emit(code.OpGetFree, s.Index)
	case FunctionScope:
		c.emit(code.OpCurrentClosure)
	}
}

// emitCapture pushes the storage for symbol so OpClosure can put it in the new
// closure's Free list. It is loadSymbol's counterpart for the capture list: the
// same five scopes, but a boxed local yields its cell rather than its value.
//
// Only three of the five can appear, because Resolve returns globals and
// builtins without capturing them -- an inner function reaches those directly.
func (c *Compiler) emitCapture(s Symbol) {
	switch s.Scope {
	case LocalScope:
		c.emit(code.OpCaptureLocal, s.Index)
	case FreeScope:
		// A capture two functions deep. This frame's Free[i] already holds the
		// cell the owner boxed, so the inner closure is handed the same pointer
		// and all three levels share one location.
		c.emit(code.OpCaptureFree, s.Index)
	case FunctionScope:
		// The enclosing function's own name, for recursion. Not storage and not
		// assignable, so it is captured by value; emitAssignStore refuses to
		// write it.
		c.emit(code.OpCurrentClosure)
	default:
		// Unreachable for anything Resolve produces; emitting the read form
		// keeps a future scope from silently capturing nothing.
		c.loadSymbol(s)
	}
}

// boxCapturedLocals rewrites the plain local accessors for captured slots to
// their cell forms, in place.
//
// The pass exists because of an ordering problem with no cheaper answer: a
// capture is discovered when the *inner* function literal is compiled, and by
// then the enclosing function has already emitted OpGetLocal/OpSetLocal for the
// slot. Boxing every local instead would remove the pass and put a heap
// allocation and an indirection on the hottest path in the VM, for the small
// minority of locals anything captures.
//
// It walks by operand width rather than scanning for opcode bytes: an operand
// can hold any value, including one that equals OpGetLocal, and a scan would
// eventually rewrite a constant index or a jump target instead of an
// instruction.
func boxCapturedLocals(ins code.Instructions, captured []int) {
	if len(captured) == 0 {
		return
	}
	boxed := make(map[int]bool, len(captured))
	for _, index := range captured {
		boxed[index] = true
	}

	for ip := 0; ip < len(ins); {
		def, err := code.Lookup(ins[ip])
		if err != nil {
			// Not decodable, so neither is anything after it. Stopping is right:
			// this only ever runs on a stream this compiler just emitted, and
			// guessing where the next instruction starts would corrupt it.
			return
		}
		operands, read := code.ReadOperands(def, ins[ip+1:])
		switch code.Opcode(ins[ip]) {
		case code.OpGetLocal:
			if len(operands) == 1 && boxed[operands[0]] {
				ins[ip] = byte(code.OpGetLocalCell)
			}
		case code.OpSetLocal:
			if len(operands) == 1 && boxed[operands[0]] {
				ins[ip] = byte(code.OpSetLocalCell)
			}
		}
		ip += 1 + read
	}
}

// emitAssignStore writes the value on top of the stack back into symbol's
// storage and leaves it there as the assignment expression's value.
//
// It exists because SymbolScope has five values and assignment used to branch
// on two: everything that was not GlobalScope was written with OpSetLocal
// against symbol.Index, and that index only means a frame slot for LocalScope.
// A free variable's index is its position in the closure's capture list, so
// writing free 0 landed on local 0 -- usually the first parameter -- and the
// program carried on with a plausible wrong value. loadSymbol has always
// switched all five ways; this is the write side of the same switch.
//
// Four of the five scopes are storage and are written. The captured one writes
// through a cell -- the frame slot and every closure over the variable point at
// the same one -- which is what lets a closure accumulate into a variable its
// enclosing frame can still read. Builtins and the enclosing function's own name
// are not storage and never should have compiled; they are refused here.
func (c *Compiler) emitAssignStore(symbol Symbol) error {
	switch symbol.Scope {
	case GlobalScope:
		c.emit(code.OpSetGlobal, symbol.Index)
		c.emit(code.OpGetGlobal, symbol.Index)
	case LocalScope:
		// Rewritten to the cell forms by boxCapturedLocals if it turns out
		// something captures this slot, which is not known yet: the capture is
		// discovered when the inner literal is compiled, and that has not
		// happened at the point this runs.
		c.emit(code.OpSetLocal, symbol.Index)
		c.emit(code.OpGetLocal, symbol.Index)
	case FreeScope:
		// The write goes through the shared cell, so the enclosing frame and
		// every other closure over the same variable see it -- which is what
		// Environment.Update has always done in the tree-walking evaluator.
		//
		// The one free that is not a cell is the enclosing function's own name,
		// captured by value for recursion. Writing it is refused here rather
		// than at run time, where the failure would be an opaque type error
		// about a closure.
		if original, ok := c.symbolTable.freeOriginal(symbol.Index); ok && original.Scope == FunctionScope {
			return fmt.Errorf("cannot assign to the name of the function being defined: %s", symbol.Name)
		}
		c.emit(code.OpSetFree, symbol.Index)
		c.emit(code.OpGetFree, symbol.Index)
	case BuiltinScope:
		return fmt.Errorf("cannot assign to builtin: %s", symbol.Name)
	case FunctionScope:
		return fmt.Errorf("cannot assign to the name of the function being defined: %s", symbol.Name)
	default:
		return fmt.Errorf("internal: no assignment path for %s in scope %s", symbol.Name, symbol.Scope)
	}
	return nil
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

		if err := c.emitAssignStore(symbol); err != nil {
			return err
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

			if err := c.emitAssignStore(symbol); err != nil {
				return err
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
			if err := c.emitAssignStore(symbol); err != nil {
				return err
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
