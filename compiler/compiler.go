package compiler

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand"
	"mutant/ast"
	"mutant/builtin"
	"mutant/code"
	"mutant/object"
	"mutant/sema"
	"path/filepath"
	"strings"
)

type Compiler struct {
	constants         []object.Object
	symbolTable       *SymbolTable
	scopes            []CompilationScope
	scopeIndex        int
	structDefinitions map[string][]*ast.Identifier // Maps struct name to field names
	enumDefinitions   map[string][]string          // Maps enum name to tag names
	loopContexts      []LoopContext

	// structLiteralDepth is how many struct literals are having their
	// initialisers compiled inside one another right now. It is read only to
	// key the scratch slots emitStructFieldsInSourceOrder spills a literal's
	// initialisers into, so that a literal written inside another literal's
	// initialiser cannot claim a slot the outer one has written and not yet
	// read back.
	structLiteralDepth int

	// declScopes is a stack of the names each open scope has itself declared,
	// innermost last. It is what the one-declaration-per-scope rule is asked
	// about, and it is never consulted outward: a name declared further out is
	// visible here and may be shadowed here, which is the whole point of a
	// scope and is the case this stack exists to stop being an error.
	//
	// It is on the Compiler and not on the SymbolTable because a REPL keeps one
	// table across lines and builds a fresh Compiler for each, and `let x = 1`
	// on one line followed by `let x = 2` on the next has to go on working.
	// Each entry is pushed by openBlock or by enterScope and popped by its
	// pair, so the bottom entry is the top level of whatever unit is being
	// compiled -- a file, a module, or one REPL line.
	declScopes []map[string]bool

	// moduleDisplays maps a module key to the path a human should see for it,
	// so an error about another module can name the file rather than repeat
	// the absolute path the linker uses as a key. Filled by EnterModule, which
	// runs for every module in dependency order, so a module's imports are
	// always already in here by the time its own body is compiled.
	moduleDisplays map[string]string

	// structBindings records which of a module's value names certainly hold a
	// struct, and of what type, so that a field the declaration does not
	// contain is refused here rather than at run time. compiler/struct_fields.go
	// is the whole of the rule, including why it is keyed per module.
	structBindings map[string]string

	// typeOwners records which module declared each struct or enum name.
	// Unlike values, type names are one flat namespace for the whole program:
	// they travel in ByteCode.StructDefs/EnumDefs keyed by bare name and are
	// looked up there by the VM, so two modules cannot each have a `Point`.
	// Recording the owner is what turns that from a silent overwrite into an
	// error naming both files.
	typeOwners map[string]string

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
	// moduleSpans maps lines of sourceText back to the files they came from.
	// Empty for a single-file compile, where SourceFile already answers it.
	moduleSpans []ModuleSpan
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

	// ModuleSpans says which file each line of SourceText came from.
	//
	// Linking concatenates every module of a program into one source blob and
	// compiles that, so SourceFile and the single blob are no longer enough to
	// answer "where did this instruction come from": a fault in lib.mut would
	// otherwise be reported as main.mut at the blob's line number, and quoted
	// against main.mut's text -- a plausible-looking file, line and source
	// snippet, all three wrong. A wrong answer in the failure reporter is worse
	// than no answer, so the mapping travels with the program.
	//
	// Entries are sorted by StartLine and cover the blob without gaps,
	// beginning with the first module linked. A single-file program has exactly
	// one entry, so there is no special case to get wrong.
	//
	// The first module linked is not the entry module. The linker walks the
	// import graph in post-order, so every dependency is emitted before the
	// file that imported it and the entry -- the file SourceFile names -- is
	// the LAST span. Graph.Modules in module/graph.go is where that order comes
	// from, and entrySpan below is what reads it.
	//
	// Debug info, and stripped with the rest of it: it would otherwise hand a
	// release artifact the whole import graph and every absolute path in it.
	ModuleSpans []ModuleSpan

	// GlobalNames are the program's global slots, indexed by slot number, and
	// carry the same contract CompiledFunction.LocalNames does for a frame:
	// the name to show for a slot, empty where there is none to show.
	//
	// Bare names, not the module-qualified keys the symbol table files them
	// under -- the qualifier is a linker detail nobody typed. Two modules may
	// each declare `helper`; they hold different slots, so both are listed,
	// each against its own.
	//
	// Debug info, stripped with the rest: a release artifact would otherwise
	// name every top-level binding in the program.
	GlobalNames []string
}

// ModuleSpan marks where one module's source begins inside the linked blob.
//
// StartLine is 1-based and names the first line of the module in SourceText,
// so a blob line L belongs to the last span whose StartLine is <= L, and its
// line within that file is L - StartLine + 1.
type ModuleSpan struct {
	// Path is the module as it should be shown to a reader -- the same string
	// SourceFile would have carried had this module been compiled alone.
	Path string

	// StartLine is the 1-based line of SourceText at which this module begins.
	StartLine int
}

// ModuleAt resolves a line of the linked source blob back to the file it came
// from and its line within that file.
//
// It returns ok false when there are no spans -- an artifact compiled before
// linking existed, or one whose debug info has been stripped. Callers must
// treat that as "unknown" and fall back to SourceFile rather than guessing:
// the blob line is only a file line by coincidence when a program has one
// module.
func (bc *ByteCode) ModuleAt(line int) (path string, localLine int, ok bool) {
	if bc == nil || len(bc.ModuleSpans) == 0 || line <= 0 {
		return "", 0, false
	}

	// Spans are in link order, which is start-line order. Walking backwards
	// finds the last one that begins at or before the line.
	for i := len(bc.ModuleSpans) - 1; i >= 0; i-- {
		span := bc.ModuleSpans[i]
		if span.StartLine <= line {
			return span.Path, line - span.StartLine + 1, true
		}
	}

	return "", 0, false
}

// ModuleLine is the inverse of ModuleAt: it maps a file and a line within that
// file to the line of the linked source blob the tables are keyed by. It is
// what a breakpoint goes through -- an editor knows a path and a line number,
// and the line tables know neither.
//
// A program with no spans is one module, so the blob is the file and the line
// passes through unchanged. That is also the answer for an empty path, which is
// how a caller says "the program's own source" without having to know whether
// the program was linked. For a linked program the program's own source is the
// entry module, which entrySpan finds.
//
// Matching is by cleaned path first and by base name second. The second pass is
// there because the path an editor sends is the one the user opened, and the
// path a span carries is the one the linker resolved: the same file can reach
// here spelled two ways -- a symlinked checkout, a UNC share, a drive letter in
// the other case -- and refusing the breakpoint because the spellings differ
// would be a right answer to the wrong question. An ambiguous base name matches
// nothing rather than the first candidate: two modules named util.mut is
// exactly the case where guessing puts the breakpoint in the wrong file.
//
// A line past the end of the file named is refused rather than mapped. The
// arithmetic alone would run out of that module's span and into the next one,
// so an editor asking about line 40 of a thirty-line file would be told its
// breakpoint is verified at a line of some other module: an inverse of ModuleAt
// only within each span, which is not what being an inverse means.
// code.LineIndex.At refuses a line past the last one with code for the same
// reason, and this is the same judgement one step earlier.
func (bc *ByteCode) ModuleLine(path string, line int) (absLine int, ok bool) {
	if bc == nil || line <= 0 {
		return 0, false
	}
	if len(bc.ModuleSpans) == 0 {
		return line, true
	}

	index, found := bc.moduleSpanFor(path)
	if !found {
		return 0, false
	}

	absLine = bc.ModuleSpans[index].StartLine + line - 1
	if last, bounded := bc.spanLastLine(index); bounded && absLine > last {
		return 0, false
	}
	return absLine, true
}

// spanLastLine reports the last line of the blob belonging to span index, and
// whether anything bounds that span at all.
//
// Every span but the last is bounded by its successor: a module's source ends
// where the next module's begins, and the linker starts each module on a line
// of its own, so the successor's StartLine is always one past this module's
// end.
//
// The last span has no successor and is bounded only by the blob, which
// SourceText holds -- so the blob's line count is that module's last line. An
// artifact carrying the spans but not the text, assembled by hand or decoded
// from something older, leaves it unbounded, and saying so beats guessing: the
// alternative is refusing every breakpoint in the entry module of such an
// artifact, and an over-long line in the last span has no following module to
// be misfiled into anyway.
func (bc *ByteCode) spanLastLine(index int) (int, bool) {
	if index+1 < len(bc.ModuleSpans) {
		return bc.ModuleSpans[index+1].StartLine - 1, true
	}
	if lines := blobLineCount(bc.SourceText); lines > 0 {
		return lines, true
	}
	return 0, false
}

// blobLineCount is how many lines of source a linked blob holds.
//
// Every module the linker appends ends in a newline -- it adds one to any file
// that does not, so that two files' code can never share a line -- which makes
// the newline count the line count. Text ending mid-line holds one line more
// than it has newlines; the linker never produces that, but a ByteCode built by
// hand in a test can, and undercounting it would refuse a real line of a real
// file.
func blobLineCount(text string) int {
	if text == "" {
		return 0
	}

	count := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		count++
	}
	return count
}

// moduleSpanFor finds the span describing path, under the matching rule
// ModuleLine documents.
func (bc *ByteCode) moduleSpanFor(path string) (int, bool) {
	if path == "" {
		// No file named: the program's own source, which is the entry module.
		return bc.entrySpan()
	}

	want := filepath.Clean(path)
	for i, span := range bc.ModuleSpans {
		if filepath.Clean(span.Path) == want {
			return i, true
		}
	}

	base := filepath.Base(want)
	found := -1
	for i, span := range bc.ModuleSpans {
		if filepath.Base(span.Path) != base {
			continue
		}
		if found >= 0 {
			// Two modules share the base name. Picking one would put the
			// breakpoint in a file the user is not looking at.
			return 0, false
		}
		found = i
	}
	if found < 0 {
		return 0, false
	}
	return found, true
}

// entrySpan reports the index of the entry module's span -- the file SourceFile
// names, and what a caller naming no file at all is asking about.
//
// It is not span 0. Spans are in link order and the linker walks the import
// graph in post-order, so span 0 is the first module linked: the deepest
// dependency of the program, a file the reader may never have opened. The entry
// is appended only once its whole import graph is already in the slice, which
// puts it last.
//
// SourceFile is consulted before that invariant is leaned on, because it is the
// independent record of which file the entry is: the linker fills it from the
// same display path it writes into the entry's own span, so for anything the
// linker built the two agree string for string. The scan runs backwards, so an
// artifact somehow carrying one file twice resolves to the copy nearest the
// entry rather than to a dependency. Where SourceFile names no span -- it is
// empty, or the spans were assembled against another spelling -- link order is
// all there is, and the last span is the answer.
func (bc *ByteCode) entrySpan() (int, bool) {
	// ModuleAt and ModuleLine both guard the nil receiver, and moduleSpanFor is
	// reached only through ModuleLine, so nothing can arrive here on a nil
	// ByteCode today. The guard is here because moduleSpanFor answered an empty
	// path without reading the receiver at all before the entry span had to be
	// found, and a helper that panics where its only caller used to answer is a
	// worse thing to leave lying around than one redundant line.
	if bc == nil || len(bc.ModuleSpans) == 0 {
		return 0, false
	}

	if bc.SourceFile != "" {
		want := filepath.Clean(bc.SourceFile)
		for i := len(bc.ModuleSpans) - 1; i >= 0; i-- {
			if filepath.Clean(bc.ModuleSpans[i].Path) == want {
				return i, true
			}
		}
	}
	return len(bc.ModuleSpans) - 1, true
}

// ModulesNamed counts the program's modules whose path could be what a caller
// meant by path, under the same rule moduleSpanFor matches on: the cleaned path
// if that hits, and otherwise the base name.
//
// It exists so a refusal can tell "no such file" apart from "more than one file
// by that name", which moduleSpanFor deliberately conflates -- it returns no
// match for an ambiguous base name because picking one would arm a breakpoint
// in a file nobody is looking at. That is the right answer to give a caller and
// the wrong one to repeat to a person.
func (bc *ByteCode) ModulesNamed(path string) int {
	if bc == nil || path == "" {
		return 0
	}

	want := filepath.Clean(path)
	for _, span := range bc.ModuleSpans {
		if filepath.Clean(span.Path) == want {
			return 1
		}
	}

	base := filepath.Base(want)
	count := 0
	for _, span := range bc.ModuleSpans {
		if filepath.Base(span.Path) == base {
			count++
		}
	}
	return count
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
	bc.GlobalNames = nil
	// ModuleSpans is the most disclosing table of the set: it names every file
	// the program was built from, by absolute path, and lays out the whole
	// import graph. Dropping the line tables while shipping that would defeat
	// the point of stripping.
	bc.ModuleSpans = nil

	for _, constant := range bc.Constants {
		if fn, ok := constant.(*object.CompiledFunction); ok {
			fn.Name = ""
			fn.Params = nil
			fn.LocalNames = nil
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
		moduleDisplays:    make(map[string]string),
		structBindings:    make(map[string]string),
		typeOwners:        make(map[string]string),
		loopContexts:      []LoopContext{},
		declScopes:        []map[string]bool{{}},
	}
}

func NewWithState(st *SymbolTable, constants []object.Object) *Compiler {
	compiler := New()
	compiler.symbolTable = st
	compiler.constants = constants
	compiler.structDefinitions = make(map[string][]*ast.Identifier)
	compiler.enumDefinitions = make(map[string][]string)
	compiler.moduleDisplays = make(map[string]string)
	compiler.typeOwners = make(map[string]string)
	return compiler
}

// ModuleScope names the module a compilation is about to enter.
//
// It exists because linking drives every module through one Compiler: without
// it, the compiler could not tell whose top level it was filling in, and every
// module's globals would land in one flat namespace where the last `helper`
// declared won.
type ModuleScope struct {
	// Key identifies the module. It has to be stable and unique across the
	// program; the linker uses the file's canonical absolute path.
	Key string

	// Display is the module as a reader should see it -- the path relative to
	// the working directory. It appears in errors about this module, and
	// nowhere else.
	Display string

	// Namespaces maps every namespace this module's imports bound to the Key
	// of the module it names.
	Namespaces map[string]string
}

// EnterModule points the compiler at the next module: its top-level
// definitions are filed under scope.Key, and `ns.name` inside it resolves
// through scope.Namespaces.
//
// Call it before compiling each module, in dependency order. A compilation
// that never calls it -- the REPL, the playground, a single file -- keeps the
// one flat global scope it always had.
func (c *Compiler) EnterModule(scope ModuleScope) {
	// A module's top level is its own scope. Without this reset, linking --
	// which drives every module through one Compiler -- would read a `let
	// helper = ...` in the second module as a duplicate of the first module's,
	// which the symbol table already keeps apart by qualifying the store key.
	c.declScopes = []map[string]bool{{}}

	if scope.Display != "" {
		c.moduleDisplays[scope.Key] = scope.Display
	}
	c.symbolTable.SetCurrentModule(scope.Key)
	for namespace, key := range scope.Namespaces {
		c.symbolTable.BindNamespace(namespace, key)
	}
}

// moduleName renders a module key for a human. It falls back to the key
// itself, which is a real path, rather than to something evasive.
func (c *Compiler) moduleName(key string) string {
	if display, ok := c.moduleDisplays[key]; ok {
		return display
	}
	if key == "" {
		return "this program"
	}
	return key
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

		// Before any statement of it is compiled, because the scan's answer
		// depends on what the whole program does with a name -- an assignment
		// below a function that reads the name is what keeps that read from
		// being refused. See compiler/struct_fields.go.
		c.noteStructBindings(program)
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

// SetModuleSpans records which file each line of the linked source blob came
// from. The linker calls it once, with one span per module in link order; a
// single-file compile leaves it unset and the VM falls back to SourceFile.
//
// Spans must be sorted by StartLine, which link order already guarantees.
func (c *Compiler) SetModuleSpans(spans []ModuleSpan) {
	c.moduleSpans = append([]ModuleSpan(nil), spans...)
}

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
		// A block is a scope. Reaching this case means the block is not a
		// function body -- that path calls compileBlockBody directly, so that a
		// function's parameters and its body share one scope the way Go's do.
		return c.compileBlockScope(node)
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
		if err := c.Compile(node.Left); err != nil {
			return err
		}
		if err := c.Compile(node.Right); err != nil {
			return err
		}
		opcode, known := infixOpcode(node.Operator)
		if !known {
			return fmt.Errorf("unknown operator %s", node.Operator)
		}
		c.emit(opcode)
	case *ast.MatchExpression:
		return c.compileMatchExpression(node)
	case *ast.IfExpression:
		if err := c.Compile(node.Condition); err != nil {
			return err
		}

		// emit bogus jumpFalse location
		jumpFalsePosition := c.emit(code.OpJumpFalse, 9999)

		if err := c.Compile(node.Consequence); err != nil {
			return err
		}

		c.leaveOneValue(node.Consequence)

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

			c.leaveOneValue(node.Alternative)
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
	case *ast.TemplateLiteral:
		if err := c.compileTemplateLiteral(node); err != nil {
			return err
		}
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
		// In the order the author wrote them, key then value, pair by pair.
		//
		// The pairs used to be ordered by key.String() instead, which is
		// M26-CMP-010 and M26-LEX-004, and two things were wrong with it. The
		// sort ran over a Go map and was not stable, so two keys that render
		// alike -- a key written twice, or a string beside an identifier spelled
		// the same way, because ast.StringLiteral.String() renders a string
		// without its quotes -- came out in whichever order the map had handed
		// them over: `{"k": 1, "k": 2}["k"]` compiled to 2 on twenty of
		// twenty-four builds and to 1 on the other four, so one source had two
		// bytecodes and a .mu artifact was not reproducible. And with the keys
		// all distinct it still ran a key's and a value's side effects in
		// alphabetical order rather than written order, which the tree-walking
		// evaluator never did.
		for _, pair := range node.Pairs {
			if err := c.Compile(pair.Key); err != nil {
				return err
			}
			if err := c.Compile(pair.Value); err != nil {
				return err
			}
		}

		c.emit(code.OpHash, len(node.Pairs)*2)

	case *ast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*ast.Identifier{node.Name}
		}

		if err := c.refuseIfNothingIsNew(names); err != nil {
			return err
		}

		if len(names) <= 1 {
			// The value is compiled first and the name declared after, which is
			// M26-CMP-001 and is also Go's rule: a declared name's scope begins
			// after its declaration, not at it. Declaring first made every
			// mention of the name inside the initializer resolve to the slot
			// this very statement was about to fill and had not written yet --
			// null at the top level, and whatever an earlier call left in the
			// frame at that offset inside a function, which is why the wrong
			// answers were plausible numbers rather than obvious breakage.
			//
			// With block scoping it is also what makes `let x = 1; if (c) { let
			// x = x + 1; }` mean what it means in Go: the initializer's x is
			// the outer one, because the inner one does not exist yet.
			if err := c.Compile(node.Value); err != nil {
				return err
			}
			symbol := c.declare(node.Name.Value)
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
			symbol := c.declare(ident.Value)
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
			// Define runs for the blank too, and must: a parameter list is
			// positional, so `fn(_, b)` still has to give the discard slot 0 or
			// b would read the wrong argument. Only the RULE skips the blank.
			if param.Value != blankName && c.declaredHere(param.Value) {
				return sema.DuplicateParameterRefusal(param.Value)
			}
			c.declare(param.Value)
		}

		// A function body is a loop boundary. loopContexts hangs off the Compiler
		// rather than off the scope it belongs to, so without this a break or a
		// continue inside a closure finds the enclosing loop's context and records
		// a jump position that is an offset in the closure's stream. The loop then
		// back-patches that position in its own stream, overwriting operand 0 of
		// whatever instruction happens to sit there, while the closure keeps the
		// unpatched `OpJump 9999`. Nothing reports any of it: the program loads a
		// different constant and prints a plausible wrong number, or faults at an
		// unrelated ip, or -- when the offset lands past the end of the enclosing
		// stream -- takes the compiler down with it.
		//
		// Clearing it makes such a break what it always was: a break with no loop
		// to leave, reported as one. A loop *inside* the closure is unaffected,
		// because it pushes its own context onto this empty stack and patches the
		// stream the positions actually belong to.
		//
		// It also settles an aliasing hazard. The loop compilers hold a
		// &c.loopContexts[len-1] across compiling their post section; an append
		// from inside a nested function body could reallocate the backing array
		// and leave that pointer addressing the old one. Nothing inside a body
		// appends to this slice any more.
		enclosingLoops := c.loopContexts
		c.loopContexts = nil
		if err := c.compileBlockBody(node.Body); err != nil {
			c.loopContexts = enclosingLoops
			return err
		}
		c.loopContexts = enclosingLoops
		// Whether the body's last value becomes the return value is a question
		// about the last statement's syntax, not about the last instruction
		// emitted -- the distinction leaveOneValue documents. A body ending in
		// `for (v in xs)` also ends in an OpPop, the one dropping the loop
		// cursor, so converting that pop into a return hands the caller the
		// cursor where it expected null.
		if endsInExpressionStatement(node.Body) {
			c.replaceLastPopWithReturn()
		}
		if !c.lastInstructionIs(code.OpReturnValue) {
			c.emit(code.OpReturn)
		}

		freeSymbols := c.symbolTable.FreeSymbols
		numLocals := c.symbolTable.numDefinitions
		localNames := c.symbolTable.LocalSlotNames()
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
			LocalNames:     localNames,
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

	case *ast.WhileStatement:
		return c.compileWhileStatement(node)

	case *ast.ForInStatement:
		return c.compileForInStatement(node)

	case *ast.BreakStatement:
		if len(c.loopContexts) == 0 {
			return sema.LoopControlRefusal("break")
		}
		jumpPos := c.emit(code.OpJump, 9999)
		ctx := &c.loopContexts[len(c.loopContexts)-1]
		ctx.breakPositions = append(ctx.breakPositions, jumpPos)

	case *ast.ContinueStatement:
		if len(c.loopContexts) == 0 {
			return sema.LoopControlRefusal("continue")
		}
		jumpPos := c.emit(code.OpJump, 9999)
		ctx := &c.loopContexts[len(c.loopContexts)-1]
		ctx.continuePositions = append(ctx.continuePositions, jumpPos)

	case *ast.StructStatement:
		// Store struct definition
		if err := c.claimTypeName("struct", node.Name.Value); err != nil {
			return err
		}
		if err := refuseDuplicateFields(node); err != nil {
			return err
		}
		c.structDefinitions[node.Name.Value] = node.Fields
		return nil

	case *ast.EnumStatement:
		// Store enum definition
		tags := []string{}
		for _, variant := range node.Variants {
			tags = append(tags, variant.Value)
		}
		if err := c.claimTypeName("enum", node.Name.Value); err != nil {
			return err
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

	case *ast.ImportStatement:
		// Nothing to emit. An import is resolved and linked before compilation
		// begins, so by the time the compiler sees this node the imported
		// module's statements are already in the stream ahead of it. The node
		// survives only as the record of what the author wrote -- which is what
		// the formatter and the language server read it for.

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
		GlobalNames:  c.symbolTable.GlobalSlotNames(),
		ModuleSpans:  c.moduleSpans,
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

// recordPosition notes where the instruction beginning at ip came from, in all
// three of the current scope's tables.
//
// An instruction with no position of its own records nothing in any of them and
// so inherits the whole of the enclosing construct's entry -- its line, its end
// and its macro origin together. That is the inheritance Compile describes for
// the nodes the compiler synthesises on its own behalf, and the three tables
// have to inherit together: an instruction described by a line from one
// construct and an end from another is underlined across a span nobody wrote.
//
// An instruction that does carry a position belongs to a different construct
// and must not keep what the last one recorded. The line table needs no help
// with that, because a position it can record replaces the previous coverage.
// The end and macro tables are optional per construct -- a range the parser
// only half filled in has no end, and most code is not from a macro -- so for
// them "nothing to record" has to be written down, as the end of the previous
// entry's coverage. Dropping it is what made the first macro a program expanded
// the reported origin of every instruction compiled after it.
func (c *Compiler) recordPosition(ip int) {
	scope := &c.scopes[c.scopeIndex]
	scope.lines.Add(ip, c.posLine, c.posCol)

	if c.posLine <= 0 {
		scope.ends.Add(ip, c.posEndLine, c.posEndCol)
		scope.macros.Add(ip, c.macroLine, c.macroCol)
		return
	}

	scope.ends.AddOrReset(ip, c.posEndLine, c.posEndCol)
	scope.macros.AddOrReset(ip, c.macroLine, c.macroCol)
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

// changeOperand back-patches operand 0 of the instruction at pos, which is how
// every forward jump gets its real target once the target is known.
//
// The operands after the first are read back and re-emitted unchanged. Rebuilding
// the instruction from operand 0 alone would be right for every single-operand
// opcode and silently wrong for a wider one: code.Make would produce a shorter
// instruction, replaceInstruction would write only those bytes, and the tail of
// the original -- OpIterNext's binding count -- would survive as the first byte
// of whatever came next. That corrupts the stream from the patch point onward
// rather than failing at it.
func (c *Compiler) changeOperand(pos int, operand int) {
	ins := c.currentInstructions()
	op := code.Opcode(ins[pos])

	operands := []int{operand}
	if def, err := code.Lookup(byte(op)); err == nil && len(def.OperandWidths) > 1 {
		existing, _ := code.ReadOperands(def, ins[pos+1:])
		operands = append(operands, existing[1:]...)
	}

	c.replaceInstruction(pos, code.Make(op, operands...))
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

	// One scope for the parameters and the body together, not one each. Go
	// draws the boundary in the same place -- `func f(a int) { a := 1 }` is
	// `a redeclared in this block` -- and the reason is the same: the parameter
	// and the body's first statement are as close together as two declarations
	// can be, so a silent shadow between them is a mistake rather than an
	// intention. Compile of the body therefore uses compileBlockBody, which
	// opens no scope of its own.
	c.declScopes = append(c.declScopes, map[string]bool{})
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
	if len(c.declScopes) > 1 {
		c.declScopes = c.declScopes[:len(c.declScopes)-1]
	}
	return instructions, debug
}

// openBlock begins a scope that ends with the construct that opened it.
//
// Opened for every construct that is a block in Go, and for the two that have
// no Go equivalent in the place Go's nearest construct puts it:
//
//   - a brace-delimited block, an if body, an else body, a match arm: the block
//     itself, which is case *ast.BlockStatement;
//   - a loop header: openBlock at the top of the loop's compiler, so the name a
//     `for` or a `for ... in` declares belongs to the loop and the body nests
//     inside it. This is what fixes the hang -- a `for` compiles its post
//     section after its body, so once the body's scope has closed, `i++` means
//     the header's `i` again rather than the body's;
//   - a function's parameters and body: ONE scope, opened by enterScope, which
//     is why the body is compiled by compileBlockBody rather than by Compile.
//
// A while loop gets no header scope because a while header cannot declare
// anything; its body is an ordinary block.
func (c *Compiler) openBlock() {
	c.symbolTable.OpenBlock()
	c.declScopes = append(c.declScopes, map[string]bool{})
}

// closeBlock ends the innermost scope openBlock began. It is always run, error
// path included, because a compile that fails inside a block leaves the symbol
// table to be reused -- the REPL's table outlives the failed line -- and a
// block left open would go on hiding the names it shadowed.
func (c *Compiler) closeBlock() {
	c.symbolTable.CloseBlock()
	if len(c.declScopes) > 1 {
		c.declScopes = c.declScopes[:len(c.declScopes)-1]
	}
}

// blankName is the discard. It is exempt from the one-declaration rule, as it
// is in Go: `let _, err = first(); let _, written = second();` declares `_`
// twice and `let _, _ = chan_send(c, v);` declares it twice in one statement,
// and neither is a name anything can read back.
const blankName = "_"

// noteDeclared records that the innermost scope declared name.
func (c *Compiler) noteDeclared(name string) {
	if name == "" || name == blankName {
		return
	}
	c.declScopes[len(c.declScopes)-1][name] = true
}

// declaredHere reports whether the innermost scope has itself declared name.
func (c *Compiler) declaredHere(name string) bool {
	return c.declScopes[len(c.declScopes)-1][name]
}

// declare allocates a slot for name and records the declaration against the
// scope that made it. The two always happen together; splitting them is how a
// scope comes to allow a duplicate it should have refused.
func (c *Compiler) declare(name string) Symbol {
	symbol := c.symbolTable.Define(name)
	c.noteDeclared(name)
	return symbol
}

// refuseIfNothingIsNew applies the one-declaration-per-scope rule to a `let`.
//
// The rule is Go's rule for a short variable declaration, measured against the
// Go compiler rather than read off the spec: a declaration may reuse names the
// same scope already declared provided at least one non-blank name is new, and
// is refused when none is. `a, err := f(); b, err := g()` compiles in Go and
// `a, err := f(); a, err := g()` is `no new variables on left side of :=`.
//
// That is not a softening of the rule, it is the rule. The (value, err) idiom
// depends on it -- 53 of the 124 shipped example programs rebind one name that
// way, 633 times between them -- and a rule that refused it would be refusing
// the language's own convention rather than a mistake.
// There is one deviation from Go in it, and it is the blank. In Go, `_, err :=
// f()` with err already declared is `no new variables on left side of :=`, and
// the remedy is `_, err = f()`. Mutant has no multi-target assignment: `_, err =
// f()` is `no prefix parse function for , found`. So the strict rule would
// refuse "call it and keep the error" -- 27 lines of
// examples/forensics/record_disclosure.mut, and the same shape across the
// examples -- while offering no legal way to write what those lines mean. A
// refusal with no remedy makes the language worse rather than better, which is
// the opposite of why this rule exists.
//
// A blank on the left therefore satisfies the rule. Nothing unsafe gets through:
// the names are in ONE scope, so there is no question of which declaration a
// later mention means -- the later one always wins from where it is written --
// and shadowing, which is what block scoping exists to make correct, cannot
// arise without a scope boundary. What is still refused is every declaration
// that is wholly a redeclaration: `let x = 1; let x = 2;`, whose remedy is
// `x = 2`, and `let a, err = f(); let a, err = g();`, which renames nothing.
//
// Adding `_, err = f()` would remove the deviation and is the named follow-on.
func (c *Compiler) refuseIfNothingIsNew(names []*ast.Identifier) error {
	fresh := 0
	already := make([]string, 0, len(names))
	for _, ident := range names {
		if ident == nil {
			continue
		}
		if ident.Value == blankName {
			// The blank is the remedy Mutant has instead of multi-target
			// assignment: see above. It counts as new.
			fresh++
			continue
		}
		if c.declaredHere(ident.Value) {
			already = append(already, ident.Value)
			continue
		}
		fresh++
	}
	if fresh == 0 && len(already) > 0 {
		return sema.DuplicateDeclarationRefusal(already)
	}
	return nil
}

// compileBlockScope compiles a block as its own scope. Every block is one,
// except a function body -- see openBlock.
func (c *Compiler) compileBlockScope(block *ast.BlockStatement) error {
	c.openBlock()
	err := c.compileBlockBody(block)
	c.closeBlock()
	return err
}

// compileBlockBody compiles a block's statements into the scope already open.
// It is the function-body path, where the parameters and the body share one
// scope.
func (c *Compiler) compileBlockBody(block *ast.BlockStatement) error {
	for _, stmt := range block.Statements {
		if err := c.Compile(stmt); err != nil {
			return err
		}
	}
	return nil
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
	if err := c.emitStoreOnly(symbol); err != nil {
		return err
	}
	// Reloading is what makes an assignment evaluate to the value assigned,
	// which is what every other assignment form here does and what the
	// evaluator does. loadSymbol reads back through exactly the storage
	// emitStoreOnly wrote to, scope for scope.
	c.loadSymbol(symbol)
	return nil
}

// emitStoreOnly writes the value on top of the stack into symbol's storage and
// leaves nothing behind. Callers that want the assignment to have a value say
// so by reloading something afterwards.
func (c *Compiler) emitStoreOnly(symbol Symbol) error {
	switch symbol.Scope {
	case GlobalScope:
		c.emit(code.OpSetGlobal, symbol.Index)
	case LocalScope:
		// Rewritten to the cell forms by boxCapturedLocals if it turns out
		// something captures this slot, which is not known yet: the capture is
		// discovered when the inner literal is compiled, and that has not
		// happened at the point this runs.
		c.emit(code.OpSetLocal, symbol.Index)
	case FreeScope:
		// The write goes through the shared cell, so the enclosing frame and
		// every other closure over the same variable see it -- which is what
		// Environment.Update has always done in the tree-walking evaluator.
		//
		// The one free that is not a cell is the enclosing function's own name,
		// captured by value for recursion. Writing it is refused here rather
		// than at run time, where the failure would be an opaque type error
		// about a closure.
		//
		// Asked of the whole capture chain rather than of the first hop. Two
		// functions deep the first hop is the middle function's own capture of
		// the name, so the check saw FreeScope, concluded "an ordinary captured
		// variable" and emitted the write -- which then failed at run time with
		// precisely the opaque complaint about a closure that this refusal exists
		// to replace.
		if c.symbolTable.freeCapturesFunctionName(symbol.Index) {
			return fmt.Errorf("cannot assign to the name of the function being defined: %s", symbol.Name)
		}
		c.emit(code.OpSetFree, symbol.Index)
	case BuiltinScope:
		return fmt.Errorf("cannot assign to builtin: %s", symbol.Name)
	case FunctionScope:
		return fmt.Errorf("cannot assign to the name of the function being defined: %s", symbol.Name)
	default:
		return fmt.Errorf("internal: no assignment path for %s in scope %s", symbol.Name, symbol.Scope)
	}
	return nil
}

// compileForInStatement emits the iterator-driven loop shape.
//
//	<iterable>
//	OpIterInit          ; the iterable is replaced by a cursor over it
//	head:
//	OpIterNext end, n   ; push the next binding(s), or jump to end when spent
//	<store bindings>
//	<body>
//	OpJump head
//	end:
//	OpPop               ; drop the cursor
//
// The cursor is left on the stack for the whole loop and dropped at `end`,
// which is also where `break` is patched to -- so every way out of the loop
// goes through the same pop and none of them leaks a stack slot. `continue`
// is patched to `head`, where the advance lives: a for-in has no post section
// of its own, the advance *is* the post section.
func (c *Compiler) compileForInStatement(node *ast.ForInStatement) error {
	// The header is a scope, as in a counted for: the key and value names
	// belong to the loop, and the body nests inside so it may shadow them.
	c.openBlock()
	defer c.closeBlock()

	if node.Value == nil {
		return fmt.Errorf("for ... in has no name to bind")
	}
	if node.Key != nil && node.Key.Value == node.Value.Value {
		// Both halves would write the same slot, so the loop would silently
		// read the key and then overwrite it with the value.
		return fmt.Errorf("for ... in binds %s twice", node.Key.Value)
	}

	if err := c.Compile(node.Iterable); err != nil {
		return err
	}
	c.emit(code.OpIterInit)

	// Defined before the body is compiled, so the body can resolve them, and
	// once rather than per iteration, so the slot is stable across the loop.
	bindings := 1
	valueSymbol := c.symbolTable.Define(node.Value.Value)
	var keySymbol Symbol
	if node.Key != nil {
		bindings = 2
		keySymbol = c.symbolTable.Define(node.Key.Value)
	}

	headPosition := len(c.currentInstructions())
	nextPosition := c.emit(code.OpIterNext, 9999, bindings)

	// Stored in reverse of the push order: OpIterNext pushes the key first and
	// the value on top, so the value comes off first.
	c.emitBindingStore(valueSymbol)
	if node.Key != nil {
		c.emitBindingStore(keySymbol)
	}

	c.loopContexts = append(c.loopContexts, LoopContext{})
	if err := c.Compile(node.Body); err != nil {
		c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]
		return err
	}

	// Deliberately no removeLastPop here, unlike the two condition-driven
	// loops. Dropping the body's trailing pop leaves its last expression's
	// value on the stack once per iteration, and this loop keeps its cursor
	// underneath that -- so the second iteration reads the leftover value as
	// the cursor. The body has to be stack-neutral.

	ctx := &c.loopContexts[len(c.loopContexts)-1]
	for _, pos := range ctx.continuePositions {
		c.changeOperand(pos, headPosition)
	}

	c.emit(code.OpJump, headPosition)

	loopEndPosition := len(c.currentInstructions())
	c.changeOperand(nextPosition, loopEndPosition)
	for _, pos := range ctx.breakPositions {
		c.changeOperand(pos, loopEndPosition)
	}
	c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]

	// Drop the cursor. Reached by falling out of the loop and by every break.
	c.emit(code.OpPop)

	return nil
}

// emitBindingStore stores the top of the stack into a loop binding. The plain
// local form is right even when a closure in the body captures the binding:
// boxCapturedLocals rewrites it to the cell form afterwards, once the capture
// is known.
// compileMatchExpression emits the compare-and-jump chain a `match` is.
//
// The subject is compiled once and stays on the stack for the whole
// expression; each alternative duplicates it to test against, because OpEqual
// and OpJumpFalse both consume what they read. The shape per arm is:
//
//	<subject>                                  ; pushed once, before any arm
//	OpDup / <pattern> / OpEqual / OpJumpFalse  ; once per alternative
//	OpPop                                      ; this arm matched: drop subject
//	<arm body>                                 ; leaves exactly one value
//	OpJump end
//	...
//	OpMatchFail                                ; nothing matched
//	end:
//
// A scratch local holding the subject would work too, and was rejected:
// SymbolTable.Define never reuses a slot, so a match inside a large function
// would spend one of the 256 local slots per occurrence and eventually panic
// in code.Make. OpDup already existed and costs one byte.
func (c *Compiler) compileMatchExpression(node *ast.MatchExpression) error {
	if len(node.Arms) == 0 {
		return fmt.Errorf("match has no arms")
	}

	if err := c.Compile(node.Subject); err != nil {
		return err
	}

	endJumps := []int{}
	matchAlwaysSucceeds := false

	for _, arm := range node.Arms {
		if arm == nil || arm.Body == nil {
			return fmt.Errorf("match arm has no body")
		}

		// Jumps meaning "an alternative matched, run the body", and the one
		// test whose failure leaves the arm entirely.
		matchedJumps := []int{}
		missedJump := -1

		for i, pattern := range arm.Patterns {
			c.emit(code.OpDup)
			if err := c.Compile(pattern); err != nil {
				return err
			}
			c.emit(code.OpEqual)

			if i == len(arm.Patterns)-1 {
				missedJump = c.emit(code.OpJumpFalse, 9999)
				break
			}

			// Not the last alternative of `a | b | c`: failing this one only
			// rules out this one, so it falls through to the next test rather
			// than leaving the arm.
			nextAlternative := c.emit(code.OpJumpFalse, 9999)
			matchedJumps = append(matchedJumps, c.emit(code.OpJump, 9999))
			c.changeOperand(nextAlternative, len(c.currentInstructions()))
		}

		for _, pos := range matchedJumps {
			c.changeOperand(pos, len(c.currentInstructions()))
		}

		// The arm matched, so the subject has done its work.
		c.emit(code.OpPop)

		if err := c.Compile(arm.Body); err != nil {
			return err
		}
		c.leaveOneValue(arm.Body)

		endJumps = append(endJumps, c.emit(code.OpJump, 9999))

		if arm.IsWildcard() {
			// `_` is emitted with no test at all, so there is no jump to
			// patch and nothing after this arm can be reached.
			matchAlwaysSucceeds = true
			continue
		}
		c.changeOperand(missedJump, len(c.currentInstructions()))
	}

	// Falling off the end is an error naming the value, not a null. A match is
	// an expression, so a silent null would flow on as though an arm had
	// produced it -- and an enum gaining a variant later is exactly the case
	// where every existing match would start doing that.
	if !matchAlwaysSucceeds {
		c.emit(code.OpMatchFail)
	}

	endPosition := len(c.currentInstructions())
	for _, pos := range endJumps {
		c.changeOperand(pos, endPosition)
	}

	return nil
}

// leaveOneValue makes the block just compiled leave exactly one value on the
// stack, which is what every branch of a value-producing expression owes its
// caller.
//
// A block ending in an expression statement ends in an OpPop -- the statement
// pushed its value and threw it away -- so removing that pop turns the block
// back into the value it computed. A block ending in anything else (a `let`, a
// loop, a `return`, or nothing at all) computed no value, and a branch that
// pushed nothing while its siblings pushed one leaves everything after it
// reading one slot too deep.
//
// The question is asked of the syntax rather than of the last instruction
// emitted, and that is not a style choice. A `for (v in xs)` statement also
// ends in an OpPop -- the one that drops the loop cursor OpIterInit pushed --
// so a block ending in a loop looks exactly like a block ending in a value to
// anything that only inspects the instruction stream, and stripping that pop
// leaves the cursor on the stack as the arm's value.
func (c *Compiler) leaveOneValue(body *ast.BlockStatement) {
	if endsInExpressionStatement(body) {
		c.removeLastPop()
		return
	}
	c.emit(code.OpNull)
}

// endsInExpressionStatement reports whether the block just compiled computed a
// value and threw it away, which is to say whether its trailing OpPop is one
// that may be removed or rewritten.
//
// This is the syntactic question leaveOneValue's comment insists on, factored
// out so every caller asks it the same way: an expression statement emits its
// OpPop unconditionally, so a block ending in one always ends in that pop, and
// a block ending in anything else that happens to end in a pop ends in
// somebody else's.
func endsInExpressionStatement(body *ast.BlockStatement) bool {
	if body == nil || len(body.Statements) == 0 {
		return false
	}
	_, ok := body.Statements[len(body.Statements)-1].(*ast.ExpressionStatement)
	return ok
}

func (c *Compiler) emitBindingStore(symbol Symbol) {
	if symbol.Scope == GlobalScope {
		c.emit(code.OpSetGlobal, symbol.Index)
		return
	}
	c.emit(code.OpSetLocal, symbol.Index)
}

// compileWhileStatement emits the same loop shape as a for statement with no
// init and no post section.
//
// The one difference that matters is where `continue` lands: a for loop sends
// it to the post section so the increment still runs, but a while loop has no
// post section, so it goes straight back to the condition. Sending it to the
// loop end instead -- or forgetting to patch it at all -- turns `continue` into
// `break`, which is the kind of wrong that runs.
func (c *Compiler) compileWhileStatement(node *ast.WhileStatement) error {
	conditionStartPosition := len(c.currentInstructions())
	if node.Condition == nil {
		return fmt.Errorf("while statement has no condition")
	}
	if err := c.Compile(node.Condition); err != nil {
		return err
	}

	jumpFalsePosition := c.emit(code.OpJumpFalse, 9999)

	c.loopContexts = append(c.loopContexts, LoopContext{})
	if err := c.Compile(node.Body); err != nil {
		c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]
		return err
	}

	// Deliberately no removeLastPop here, and none after the body, init or
	// post section of a for statement either. A loop body is a statement: it
	// owes no value to anyone, and `while` is not an expression in this
	// language, so there is nobody for that value to be owed to. Stripping the
	// pop of a body ending in an expression statement leaves that value on the
	// stack once per iteration, which is invisible until the loop sits inside
	// a for-in -- whose cursor lives below the leak and gets read as whatever
	// piled up on top of it. See compileForInStatement.
	ctx := &c.loopContexts[len(c.loopContexts)-1]
	for _, pos := range ctx.continuePositions {
		c.changeOperand(pos, conditionStartPosition)
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

func (c *Compiler) compileForStatement(node *ast.ForStatement) error {
	// The header is a scope and the body nests inside it, which is how Go
	// arranges a for statement and is what makes the body free to shadow the
	// name the header declared. It is also the fix for the hang: the post
	// section is compiled after the body's scope has closed, so `i++` and the
	// condition both mean the header's `i` whatever the body declared.
	c.openBlock()
	defer c.closeBlock()

	if node.Init != nil {
		if err := c.Compile(node.Init); err != nil {
			return err
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

	// No removeLastPop after the body -- see compileWhileStatement for why the
	// leak this used to introduce is only ever visible under a for-in.
	postStartPosition := len(c.currentInstructions())
	ctx := &c.loopContexts[len(c.loopContexts)-1]
	for _, pos := range ctx.continuePositions {
		c.changeOperand(pos, postStartPosition)
	}

	// The post section is an Expression, not a Statement, so nothing else
	// discards its value -- and an assignment is an expression that yields the
	// value it stored, so the usual `i++` pushes one. The pop has to be
	// emitted here.
	//
	// This is the half of the leak that survived "write the body so it ends in
	// a `let`": a body can be spelled to leave nothing behind, but there is no
	// spelling of an increment that is not an expression.
	if node.Post != nil {
		if err := c.Compile(node.Post); err != nil {
			c.loopContexts = c.loopContexts[:len(c.loopContexts)-1]
			return err
		}
		c.emit(code.OpPop)
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

// infixOpcode maps a binary operator to the opcode that applies it to two
// operands already pushed in source order.
//
// It is a table rather than part of the InfixExpression arm because a compound
// assignment sometimes has to fold without an InfixExpression to compile at all
// -- see compileAssignExpression. Both callers read this one table, so the fold
// cannot drift from the expression it desugars to, which is the reason the fold
// is not hand-emitted with a switch of its own.
//
// The operators deliberately absent are the ones an opcode alone cannot
// express: `&&` and `||` short-circuit through jumps, and `<` and `<=` compile
// their operands in the opposite order. No compound assignment can ask for any
// of them -- compoundAssignBaseOperator in parser/parse_expressions.go maps only
// `+ - * / % & | ^ << >>` -- so this table is complete for the fold.
func infixOpcode(operator string) (code.Opcode, bool) {
	switch operator {
	case "+":
		return code.OpAdd, true
	case "-":
		return code.OpSub, true
	case "*":
		return code.OpMul, true
	case "/":
		return code.OpDiv, true
	case "%":
		return code.OpMod, true
	case "&":
		return code.OpBitAnd, true
	case "|":
		return code.OpBitOr, true
	case "^":
		return code.OpBitXor, true
	case "<<":
		return code.OpShiftLeft, true
	case ">>":
		return code.OpShiftRight, true
	case ">":
		return code.OpGreater, true
	case ">=":
		return code.OpGreaterEqual, true
	// `<` and `<=` have opcodes of their own rather than reusing the
	// greater family with the operands compiled in the other order. The
	// swap was invisible for two literals and decisive as soon as either
	// operand had a side effect: it ran the right one first, so one
	// expression meant one thing here and another thing inside a macro,
	// which the evaluator expands.
	case "<":
		return code.OpLess, true
	case "<=":
		return code.OpLessEqual, true
	case "==":
		return code.OpEqual, true
	case "!=":
		return code.OpUnEqual, true
	}
	return 0, false
}

func (c *Compiler) compileAssignExpression(node *ast.AssignExpression) error {
	base, steps, ok := flattenAssignTarget(node.Left)
	if !ok {
		return fmt.Errorf("invalid assignment target")
	}

	// Compound assignment (x += v, x++) desugars to `x = x <op> v`: the value to
	// store is the base operator applied to the target's current value and the
	// right-hand side. Every store path below compiles valueExpr, so this is the
	// single point where the fold is introduced.
	//
	// Rewriting the target into an InfixExpression is only correct while the
	// target can be compiled twice. `a[f()] += 1` cannot: the index is compiled
	// once as the store's operand and again inside the rewrite, so f() runs twice
	// and the element at one index is folded into the slot of another. Where the
	// last index is impure, no rewrite is built -- foldOperator carries the
	// operator down to the fold, which reads a spilled copy of that index.
	//
	// The spilled index is reached by passing the slot, never by looking the index
	// node up. A node pointer is not unique in an expanded program: a macro
	// argument used at two unquote sites is spliced in BY POINTER -- only the
	// macro template is cloned (evaluator/quote_unquote.go) -- so one node stands
	// at two places that have to compile to different things.
	// examples/modules/lib/stats.mut ships that shape.
	valueExpr := node.Value
	foldOperator := ""
	if node.Operator != "" {
		if last := len(steps) - 1; last >= 0 && steps[last].index != nil && !pureAssignIndex(steps[last].index) {
			foldOperator = node.Operator
		} else {
			valueExpr = &ast.InfixExpression{
				Token:    node.Token,
				Left:     node.Left,
				Operator: node.Operator,
				Right:    node.Value,
			}
		}
	}

	// Handle identifier assignment: x = value
	if len(steps) == 0 {
		if err := c.Compile(valueExpr); err != nil {
			return err
		}

		symbol, ok := c.symbolTable.Resolve(base.Value)
		if !ok {
			// If not found, define it as global
			symbol = c.symbolTable.Define(base.Value)
		}

		return c.emitAssignStore(symbol)
	}

	// Assigning through an import namespace would read as "give that module a
	// different value", which no module system here can honour: the target is
	// another file's global slot and the write would be invisible at its
	// declaration. Say so, rather than letting it fall through to "undefined
	// variable: <namespace>".
	if steps[0].field != "" {
		if key, bound := c.symbolTable.LookupNamespace(base.Value); bound {
			return fmt.Errorf(
				"cannot assign to %s.%s: %s belongs to %s, and a module owns its own top-level names",
				base.Value, steps[0].field, steps[0].field, c.moduleName(key),
			)
		}

		// A write to a field the declaration does not contain used to add one,
		// so the record stopped matching its type and the field the author
		// meant to change kept its old value. Only the first hop is checked:
		// `p.a.b = v` writes through p.a, whose type is not a question the
		// compiler can answer.
		if structType, tracked := c.structTypeOfBinding(base.Value); tracked {
			if err := c.checkFieldIsDeclared(structType, steps[0].field, true); err != nil {
				return err
			}
		}
	}

	symbol, resolved := c.symbolTable.Resolve(base.Value)
	if !resolved {
		return fmt.Errorf("undefined variable: %s", base.Value)
	}

	// Every hop but the last is loaded again on the way back out, so an index
	// that is a call would run more than once. Refuse that rather than emit it:
	// the workaround is one line (`let k = f(); a[k][j] = v`) and the failure it
	// replaces -- a side effect happening a number of times the source does not
	// say -- is not one anybody would find by reading the program.
	for _, step := range steps[:len(steps)-1] {
		if step.index != nil && !pureAssignIndex(step.index) {
			return fmt.Errorf(
				"cannot assign through %s: an index before the last one is evaluated more than once, "+
					"so it has to be a name or a literal -- bind it to a variable first",
				node.Left.String(),
			)
		}
	}

	// The value is compiled once, into a slot, and read back from there both as
	// the innermost store's operand and as what the whole expression evaluates
	// to. That is the only way the assigned value survives a chain: every store
	// on the way out consumes three stack slots and leaves one, so the value the
	// program wrote is gone by the time the outermost store finishes, and before
	// that it sits underneath intermediate containers with nothing to reach it.
	// Reading the target back instead would answer with what the container now
	// holds rather than with what was assigned, and would force the last index
	// to be re-evaluated -- so `counts[etld1(url)] = 1` would stop compiling.
	//
	// The spill happens where the value expression was already being compiled,
	// so the order a program's side effects run in does not change: container,
	// then index, then value, exactly as before.
	spill := c.internalSlot("assign")

	// The last index, for a compound assignment the rewrite above could not
	// express. One slot per scope is enough, for the same reason it is enough for
	// the value, but this window is wider and so worth writing out: the slot is
	// written where the index was already being evaluated, then read once as the
	// store's operand and once as the last hop of the fold's left operand -- and
	// BOTH reads are emitted before the right-hand side is. The right-hand side is
	// the only thing that can write the slot again (`a[f()] += (b[g()] += 1)`
	// reuses it), and by the time it runs both reads have already put their value
	// on the stack. Every hop before the last is a name or a literal, refused
	// above otherwise, so nothing else between the write and the reads runs any of
	// the program. Both shapes are regression rows.
	var indexSlot *Symbol
	if foldOperator != "" {
		slot := c.internalSlot("assignindex")
		indexSlot = &slot
	}

	if err := c.emitAssignChain(symbol, steps, len(steps), indexSlot, func() error {
		if foldOperator != "" {
			// The target's current value, read through the index already
			// spilled rather than by evaluating that index a second time.
			if err := c.emitPathLoad(symbol, steps, len(steps), indexSlot); err != nil {
				return err
			}
			if err := c.Compile(node.Value); err != nil {
				return err
			}
			opcode, known := infixOpcode(foldOperator)
			if !known {
				return fmt.Errorf("unknown operator %s", foldOperator)
			}
			c.emit(opcode)
		} else if err := c.Compile(valueExpr); err != nil {
			return err
		}
		if err := c.emitStoreOnly(spill); err != nil {
			return err
		}
		c.loadSymbol(spill)
		return nil
	}); err != nil {
		return err
	}

	// An assignment evaluates to the value assigned -- the same answer the
	// evaluator gives, the same answer `x = 1`, `p.x = 1` and `x += 1` give
	// here, and the same answer every language where assignment is an
	// expression gives. Index assignment used to be the one exception, yielding
	// whatever OpSetIndex happened to leave on the stack, which was the
	// container.
	c.loadSymbol(spill)
	return nil
}

// internalSlot hands back the compiler's own storage for kind in the scope being
// compiled, claiming it the first time it is asked for.
//
// One slot per scope is enough, and it is worth saying why, because the obvious
// worry is an assignment nested inside another one -- `r[q[0] = 1] = 77`, or
// `a[0] = (b[0] = 5)`. Nothing of the program's runs between this slot being
// written and being read: the value is spilled where the value expression was
// already being compiled, and everything between that point and the final read
// is the chain's own stores. An inner assignment is therefore always finished
// with the slot before an outer one writes it, and its result is already on the
// stack. A slot per nesting depth was written first and removed: it guarded
// against an ordering that spilling in source order had already ruled out, and
// a safety mechanism nothing can make fail is one that only looks like safety.
//
// The key is spelled with a space so no source line can collide with it, and
// DefineInternal leaves the symbol nameless so it stays out of the debugger and
// the REPL's completion.
func (c *Compiler) internalSlot(kind string) Symbol {
	key := " " + kind
	if symbol, ok := c.symbolTable.ResolveInternal(key); ok {
		return symbol
	}
	return c.symbolTable.DefineInternal(key)
}

// assignStep is one hop of an assignment target: `[i]` or `.f`. Every target is
// a base identifier followed by zero or more of them, and flattening it that way
// is what lets a write through more than one container be emitted at all --
// `grid[0][1] = 9` used to mutate a container nothing stored back, and the write
// disappeared with no error.
type assignStep struct {
	index ast.Expression // set for a[i]
	field string         // set for a.f
}

// flattenAssignTarget peels an assignment target down to the variable it
// ultimately writes, returning the hops in source order. It reports false for a
// target with no variable under it (`f()[0] = 1`, `[1, 2][0] = 1`), which the
// caller turns into a compile error: there is nowhere to store the result, and
// emitting a mutation of a temporary would be a write the program never sees.
func flattenAssignTarget(target ast.Expression) (*ast.Identifier, []assignStep, bool) {
	var steps []assignStep
	for {
		switch t := target.(type) {
		case *ast.Identifier:
			for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
				steps[i], steps[j] = steps[j], steps[i]
			}
			return t, steps, true
		case *ast.IndexExpression:
			if t.Index == nil {
				return nil, nil, false
			}
			steps = append(steps, assignStep{index: t.Index})
			target = t.Left
		case *ast.FieldExpression:
			if t.Field == nil {
				return nil, nil, false
			}
			steps = append(steps, assignStep{field: t.Field.Value})
			target = t.Left
		default:
			return nil, nil, false
		}
	}
}

// pureAssignIndex reports whether an index expression can be evaluated more than
// once without changing what the program does. Names and literals can; a call
// cannot, and neither can anything built out of one.
func pureAssignIndex(expr ast.Expression) bool {
	switch e := expr.(type) {
	case *ast.Identifier, *ast.IntegerLiteral, *ast.FloatLiteral, *ast.StringLiteral, *ast.Boolean:
		return true
	case *ast.IndexExpression:
		return pureAssignIndex(e.Left) && pureAssignIndex(e.Index)
	case *ast.FieldExpression:
		return pureAssignIndex(e.Left)
	default:
		return false
	}
}

// emitAssignChain writes emitValue into base + steps[:depth], storing every
// container it passed through back where it came from.
//
// Both stores leave the container they mutated on the stack, which is the whole
// trick: the new value of a container one level up is exactly "load that level,
// mutate it, and take what OpSetIndex hands back". So a nested write is the
// shallower write with a deeper one supplying its value, and the recursion
// bottoms out at the base variable, where emitAssignStore finally puts something
// somewhere that outlives the expression.
//
// The alternative -- mutating in place and trusting the containers to be shared
// -- is what the compiler used to do, and it is only true when a load hands back
// the same object the slot holds. Globals and locals are stored encrypted, so a
// load hands back a copy, and the write went into the copy.
// indexSlot, when set, is the compiler's own storage for the index of the step
// this level stores through: the index is compiled once into it and read back
// both as this store's operand and by the fold in emitValue. It is nil for
// every inner level of the chain, whose indexes the caller has already
// restricted to names and literals.
func (c *Compiler) emitAssignChain(symbol Symbol, steps []assignStep, depth int, indexSlot *Symbol, emitValue func() error) error {
	last := steps[depth-1]

	// store mutates the container already on the stack and leaves it there.
	store := func() error {
		if last.index != nil {
			if err := c.Compile(last.index); err != nil {
				return err
			}
			if indexSlot != nil {
				// Spilled where it was already being evaluated, so the
				// container-then-index order the program is written in is
				// the order that runs, and pushed straight back as this
				// store's operand.
				if err := c.emitStoreOnly(*indexSlot); err != nil {
					return err
				}
				c.loadSymbol(*indexSlot)
			}
			if err := emitValue(); err != nil {
				return err
			}
			c.emit(code.OpSetIndex)
			return nil
		}
		if err := emitValue(); err != nil {
			return err
		}
		c.emit(code.OpSetField, c.addConstant(&object.String{Value: last.field}))
		return nil
	}

	if depth == 1 {
		c.loadSymbol(symbol)
		if err := store(); err != nil {
			return err
		}
		// Nothing is reloaded here: the chain leaves the stack as it found it,
		// and the caller pushes the assigned value.
		return c.emitStoreOnly(symbol)
	}

	return c.emitAssignChain(symbol, steps, depth-1, nil, func() error {
		if err := c.emitPathLoad(symbol, steps, depth-1, nil); err != nil {
			return err
		}
		return store()
	})
}

// emitPathLoad pushes the value of base + steps[:depth].
//
// indexSlot, when set, holds the already-evaluated index of the LAST step being
// loaded, so a compound assignment can read the element it is about to fold
// without evaluating that index again.
func (c *Compiler) emitPathLoad(symbol Symbol, steps []assignStep, depth int, indexSlot *Symbol) error {
	c.loadSymbol(symbol)
	for i, step := range steps[:depth] {
		if step.index != nil {
			if indexSlot != nil && i == depth-1 {
				c.loadSymbol(*indexSlot)
			} else if err := c.Compile(step.index); err != nil {
				return err
			}
			c.emit(code.OpIndex)
			continue
		}
		c.emit(code.OpGetField, c.addConstant(&object.String{Value: step.field}))
	}
	return nil
}

// claimTypeName records that the module being compiled declares a struct or
// enum called name, and refuses the declaration if another module already did.
//
// Type names are program-wide, so this is the only thing standing between two
// modules that each declare `Point` and a program where one of them silently
// gets the other's fields. Outside a modular compile every key is "", so a
// REPL redeclaring a type on a later line is still free to do it.
func (c *Compiler) claimTypeName(kind, name string) error {
	key := c.symbolTable.CurrentModule()
	if owner, taken := c.typeOwners[name]; taken && owner != key {
		return fmt.Errorf(
			"%s %s is declared in both %s and %s: struct and enum names are shared across the whole program, so one of them has to be renamed",
			kind, name, c.moduleName(owner), c.moduleName(key),
		)
	}
	c.typeOwners[name] = key
	return nil
}

// compileTemplateLiteral compiles "a${b}c" as its pieces in source order
// followed by one OpConcat that joins them.
//
// The alternative -- desugaring to a call -- would have been fewer lines and
// one silent trap: whichever function it called could be shadowed by a module
// that declares that name, and every interpolated string in the program would
// then mean something else.
func (c *Compiler) compileTemplateLiteral(node *ast.TemplateLiteral) error {
	pieces := 0
	for i, text := range node.Texts {
		// An empty text slot contributes nothing and is not worth a constant:
		// "${a}${b}" has three of them.
		if text != "" {
			c.emit(code.OpConstant, c.addConstant(&object.String{Value: text}))
			pieces++
		}
		if i >= len(node.Parts) {
			continue
		}
		if err := c.Compile(node.Parts[i]); err != nil {
			return err
		}
		pieces++
	}

	if pieces == 0 {
		c.emit(code.OpConstant, c.addConstant(&object.String{Value: ""}))
		return nil
	}

	// A single piece still goes through OpConcat rather than being left on the
	// stack: "${n}" has to produce a string even when n is an integer.
	c.emit(code.OpConcat, pieces)
	return nil
}

// semaResolver is the one decision procedure for what a name refers to. It
// holds no state, so one instance serves every compilation in the process.
var semaResolver = sema.NewResolver()

// scopeCtx describes the name environment the compiler has reached, for sema to
// decide against.
//
// It is built per call rather than cached because every predicate closes over
// state that moves as compilation descends: the symbol table is swapped on
// entering a function scope, and the namespace map is rebound on entering a
// module. A cached context would answer for wherever it happened to be built.
func (c *Compiler) scopeCtx() sema.ScopeCtx {
	return sema.ScopeCtx{
		Module: c.symbolTable.CurrentModule(),

		Enums: func(name string) bool {
			_, declared := c.enumDefinitions[name]
			return declared
		},

		Namespace: c.symbolTable.LookupNamespace,

		Bound: func(name string) bool {
			symbol, found := c.symbolTable.Resolve(name)
			// A bare builtin is not a binding. DefineBuiltin writes every
			// builtin into the very store Resolve reads, so without this test
			// the four families whose own name is also a registered builtin --
			// rand, sort, assert, gunzip -- came back "taken" and never folded.
			// That was a901ce4. This is now the only place in the tree that
			// distinction is drawn, instead of the third of three.
			return found && symbol.Scope != BuiltinScope
		},

		Exports: func(key, name string) (sema.ExportFact, bool) {
			symbol, declared := c.symbolTable.ResolveIn(key, name)
			if !declared {
				return sema.ExportFact{}, false
			}
			return sema.ExportFact{
				Name:    symbol.Name,
				Private: sema.IsModulePrivate(symbol.Name),
			}, true
		},

		// ModuleKnown is deliberately nil. module.Load has already succeeded by
		// the time anything is compiled, so every module in the closure is
		// loaded by construction and sema never has to hedge here.

		ModuleName: c.moduleName,
	}
}

func (c *Compiler) compileFieldExpression(node *ast.FieldExpression) error {
	if ident, ok := node.Left.(*ast.Identifier); ok {
		resolution := semaResolver.ResolveField(c.scopeCtx(), ident.Value, node.Field.Value)

		// A hedged answer means sema was asked about a module it could not see,
		// which cannot happen behind a successful module.Load. Stopping beats
		// emitting code for a guess.
		if resolution.Confidence != sema.Certain {
			return fmt.Errorf("internal: sema hedged on %s.%s during compilation",
				ident.Value, node.Field.Value)
		}

		switch resolution.Kind {
		case sema.FieldEnumValue:
			typeNameIndex := c.addConstant(&object.String{Value: ident.Value})
			tagNameIndex := c.addConstant(&object.String{Value: node.Field.Value})
			c.emit(code.OpEnumValue, typeNameIndex, tagNameIndex)
			return nil

		case sema.FieldModuleMember:
			// sema vouched for this member against this very table, so a miss
			// is a disagreement between the two rather than a program error.
			symbol, declared := c.symbolTable.ResolveIn(resolution.ModuleKey, resolution.Member)
			if !declared {
				return fmt.Errorf("internal: sema resolved %s.%s to a member the symbol table does not hold",
					ident.Value, resolution.Member)
			}
			c.loadSymbol(symbol)
			return nil

		case sema.FieldBuiltinFold:
			c.loadSymbol(Symbol{Name: resolution.Builtin, Scope: BuiltinScope})
			return nil

		case sema.FieldRefused:
			return resolution.Refusal

		case sema.FieldValueAccess:
			// An ordinary field read on a value. Fall through to OpGetField,
			// which is also where a.b.c, f().x and arr[0].x arrive directly.
			//
			// A bare name is also the one receiver whose type the compiler can
			// be certain of, so it is the one place a field the declaration does
			// not contain is refused before the program runs. a.b.c arrives
			// here too, as its own inner node: `p.a` is checked, and `.c` on
			// whatever `p.a` holds is not a type anything here knows.
			if structType, tracked := c.structTypeOfBinding(ident.Value); tracked {
				if err := c.checkFieldIsDeclared(structType, node.Field.Value, false); err != nil {
					return err
				}
			}
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

	fieldExprByName := make(map[string]ast.Expression, len(node.Fields))
	written := make([]string, 0, len(node.Fields))
	for _, field := range node.Fields {
		if field == nil || field.Name == nil {
			return fmt.Errorf("invalid field initializer in struct %s", structName)
		}
		if _, twice := fieldExprByName[field.Name.Value]; twice {
			// Caught here rather than folded into the report below, because a
			// name written twice is not a name that disagrees with the
			// declaration -- and because one of the two values is silently
			// dropped, which is its own reason to refuse.
			return errors.New(object.DuplicateStructFieldLiteralMessage(structName, field.Name.Value))
		}
		fieldExprByName[field.Name.Value] = field.Value
		written = append(written, field.Name.Value)
	}

	// The field count is not checked separately any more: it is reported as the
	// field NAMES that differ, which is what the author has to change either
	// way. That is only equivalent because a repeated name is refused -- above
	// for a literal, and at the declaration by refuseDuplicateFields. A repeat
	// is the one way the counts can differ while the name sets agree, and it
	// used to be the count check that caught it.
	declaredNames := make([]string, 0, len(typeDef))
	declared := make(map[string]bool, len(typeDef))
	for _, field := range typeDef {
		declaredNames = append(declaredNames, field.Value)
		declared[field.Value] = true
	}

	var unknown, missing []string
	for _, name := range written {
		if !declared[name] {
			unknown = append(unknown, name)
		}
	}
	for _, field := range typeDef {
		if _, set := fieldExprByName[field.Value]; !set {
			missing = append(missing, field.Value)
		}
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return errors.New(object.StructLiteralRefusal(structName, unknown, missing, declaredNames))
	}

	typeNameIndex := c.addConstant(&object.String{Value: structName})

	// OpMakeStruct names the values it pops by the order the DECLARATION lists
	// the fields in, so the stack has to end up in that order however the
	// literal was written. Compiling the initialisers in that order is the
	// obvious way to get there, and it is M26-CMP-010:
	// `Header{magic: read_u32(h), size: read_u32(h)}` against
	// `struct Header { size, magic }` read the two numbers the other way round
	// and gave each field the other one's value, silently -- and the
	// tree-walking evaluator, which evaluates node.Fields as written, disagreed
	// with the compiler about that same literal.
	//
	// A literal that already lists its fields in declaration order, which is how
	// nearly all of them are written, emits exactly what it has always emitted.
	// Only one that does not pays for the reordering.
	if structLiteralIsInDeclarationOrder(node.Fields, typeDef) {
		for _, field := range typeDef {
			if err := c.Compile(fieldExprByName[field.Value]); err != nil {
				return err
			}
		}
	} else if err := c.emitStructFieldsInSourceOrder(structName, node.Fields, typeDef); err != nil {
		return err
	}

	c.emit(code.OpMakeStruct, typeNameIndex, len(typeDef))
	return nil
}

// structLiteralIsInDeclarationOrder reports whether the literal sets its fields
// in the order the declaration lists them, in which case the initialisers can
// go straight onto the stack in the order they are written.
//
// It is only ever asked after the refusals above have established that the
// literal sets exactly the declared fields, once each, so the two lengths agree
// and a position-by-position comparison is the whole question.
func structLiteralIsInDeclarationOrder(fields []*ast.StructFieldValue, typeDef []*ast.Identifier) bool {
	if len(fields) != len(typeDef) {
		return false
	}
	for i, field := range fields {
		if field == nil || field.Name == nil || typeDef[i] == nil {
			return false
		}
		if field.Name.Value != typeDef[i].Value {
			return false
		}
	}
	return true
}

// emitStructFieldsInSourceOrder compiles the initialisers where the author
// wrote them and leaves their values on the stack in declaration order.
//
// Each value is spilled into one of the compiler's own slots as soon as it is
// computed -- the same storage an assignment through a container uses to keep
// the assigned value alive across its stores, see internalSlot -- and the slots
// are read back in the order OpMakeStruct names them. That costs two extra
// instructions per field and no new opcode. An opcode that permutes the top of
// the stack would be the alternative, and adding one to an append-only
// instruction set for something the existing spill already does is a worse
// trade than two instructions on the literals that are written out of order.
//
// The slot keys carry the nesting depth and nothing else. Sibling literals
// share slots safely, because one finishes before the next begins. A literal
// written inside another literal's initialiser must not share them, because it
// runs between that initialiser's spill and the outer literal's read-back, so
// one key in common would overwrite a value the outer literal still needs --
// and it cannot, because a literal that spills holds the depth raised for the
// whole of its own field compilation, so anything nested inside it sees a
// strictly greater depth. The key is spelled with spaces, which no source line
// can produce, for the reason internalSlot gives.
func (c *Compiler) emitStructFieldsInSourceOrder(
	structName string, fields []*ast.StructFieldValue, typeDef []*ast.Identifier,
) error {
	depth := c.structLiteralDepth
	c.structLiteralDepth++
	defer func() { c.structLiteralDepth-- }()

	slots := make(map[string]Symbol, len(fields))
	for i, field := range fields {
		if err := c.Compile(field.Value); err != nil {
			return err
		}
		slot := c.internalSlot(fmt.Sprintf("struct %d %d", depth, i))
		if err := c.emitStoreOnly(slot); err != nil {
			return err
		}
		slots[field.Name.Value] = slot
	}

	for _, field := range typeDef {
		slot, spilled := slots[field.Value]
		if !spilled {
			// Unreachable: the refusals in compileStructLiteral have already
			// established that the literal sets every declared field. Saying so
			// beats loading slot zero, which holds something else entirely.
			return fmt.Errorf("internal: struct %s literal has no initializer for field %s",
				structName, field.Value)
		}
		c.loadSymbol(slot)
	}
	return nil
}
