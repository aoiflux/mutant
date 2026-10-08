package vm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"mutant/ast"
	"mutant/builtin"
	"mutant/code"
	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
	"os"
	"strings"
)

// VM structure defines virtual machine
type VM struct {
	// bytecode is kept so a worker VM can be built over the SAME compiled
	// program: pmap runs its callback on sibling VMs, and they must share the
	// constants pool, instruction length and password or the closure they call
	// would not decrypt.
	bytecode        *compiler.ByteCode
	constants       []object.Object
	stack           []object.Object
	stackPointer    int // top of stack is stack[stackPointer-1]
	globals         []object.Object
	secureGlobals   map[int]*object.SecureGlobal
	frames          []*Frame
	frameIndex      int
	inslen          int
	password        string // password for instruction decryption
	stepCount       uint64
	integrityEvery  uint64
	integrityJitter uint64
	nextIntegrityAt uint64
	nextSweepAt     uint64
	frameIntegrity  map[*object.CompiledFunction][32]byte
	frameBoundaries map[*object.CompiledFunction]map[int]struct{}
	secureMode      bool
	structDefs      map[string]any // Struct definitions (field names)
	enumDefs        map[string]any // Enum definitions (tag names)
	memoryMode      string

	// builtins is what an OpGetBuiltin operand indexes, resolved once at
	// construction: from the program's own name table, or -- for bytecode
	// predating names -- from the frozen ordinal snapshot. builtinsErr holds a
	// resolution failure until Run can return it, because the constructors
	// cannot.
	builtins        []*builtin.BuiltIn
	builtinsErr     error
	builtinsVersion int

	enforceSecurityCheckOpcodes bool

	// opcodeReverse undoes the polymorphic engine's opcode permutation, indexed
	// by the byte found in the stream. nil when the program was not remapped,
	// which is every program compiled outside `mutant gen`/`mutant release` and
	// every one built at --mutation 0.
	//
	// It must be consulted at every point an opcode byte is turned into a
	// code.Opcode, not just in the fetch loop: the boundary map and the
	// security-opcode scan decode the same streams, and a scan that missed the
	// remapping would report a program as missing its OpChkDbg/OpChkSnd checks.
	opcodeReverse []byte

	// xorStream caches the instruction-decryption key/nonce (seed=inslen and
	// password are constant per run) so decoding an opcode or its operands never
	// re-derives them. Reach for it through instructionStream, which builds it on
	// first use: the constructors map instruction boundaries before Run gets a
	// chance to prepare anything.
	xorStream *security.XORStream

	// constantBoundariesMapped records that every compiled function in the
	// constants pool has had its instruction boundaries mapped. The pool is
	// assigned once, in New, and never grows, so that is a one-time job -- and it
	// has to be tracked, because the integrity probes ask for the boundaries
	// before every opcode.
	constantBoundariesMapped bool

	// serveConn and serveArg are what serve_conn()/serve_arg() report. net_serve
	// sets them before running a handler; everywhere else they stay zero and the
	// builtins answer null, which is what lets one file both serve a connection
	// and run standalone. Worker VMs inherit them, so a handler that hands work
	// to spawn or pmap does not lose its connection along the way.
	// serveContextSet distinguishes "no context" from a context whose connection
	// handle is 0, which is what net_spawn dispatches with -- a handler with no
	// connection but a real shared arg. Without it, serve_conn() would answer
	// null there instead of the 0 that case has always reported.
	serveContextSet bool
	serveConn       int64
	serveArg        object.Object

	// debug is the attached debugger, or nil -- which is every run that is not
	// a debug session, and the state the fetch loop is written to cost nothing
	// in: one nil check per instruction, next to the integrity probe that is
	// already there.
	//
	// It is set by NewDebugger rather than by a constructor, because attaching
	// is a decision made after the VM exists and before it runs, and a
	// constructor parameter would have to be threaded through all nine of them.
	debug *Debugger

	// cover is the line-coverage recorder, non-nil only under
	// `mutant test --cover`. Like debug, it is one nil check per instruction on
	// a run that is not using it. coverMain is the program's own function,
	// captured before the run because it is the one function that is not in the
	// constant pool. See coverage.go.
	cover     *coverage
	coverMain *object.CompiledFunction

	// tests is the test-run ledger, created the first time the program calls
	// one of the testing builtins and nil in every run that calls none. It is
	// not on the instruction path: only the builtins themselves touch it, so a
	// program that never asserts never learns it exists. See testing.go.
	tests *testRun
}

var (
	isDebuggerPresent  = security.IsDebuggerPresent
	isSandboxed        = security.IsSandboxed
	logSecurityWarning = func(event, stage string) {
		fmt.Fprintf(os.Stderr, "[security] event=%s stage=%s action=warn\n", event, stage)
	}
)

const (
	initialStackCapacity   = global.StackSize
	initialGlobalsCapacity = global.GlobalSize
	integritySweepBase     = uint64(251)
	integritySweepSpread   = uint64(83)
	integrityProbeSpread   = uint64(31)

	vMMemoryModeRuntime = "runtime"
	vMMemoryModeWrapper = "wrapper"
)

func resolveVMGlobalMemoryMode() string {
	return vMMemoryModeRuntime
}

func deriveIntegritySeed(instructions []byte) uint64 {
	h := sha256.Sum256(instructions)
	seed := uint64(h[0]) |
		(uint64(h[1]) << 8) |
		(uint64(h[2]) << 16) |
		(uint64(h[3]) << 24) |
		(uint64(h[4]) << 32) |
		(uint64(h[5]) << 40) |
		(uint64(h[6]) << 48) |
		(uint64(h[7]) << 56)
	if seed == 0 {
		return 0x9e3779b97f4a7c15
	}
	return seed
}

func nextIntegrityJitter(state uint64) uint64 {
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	state ^= state << 13
	state ^= state >> 7
	state ^= state << 17
	return state
}

func (vm *VM) nextProbeInterval() uint64 {
	vm.integrityJitter = nextIntegrityJitter(vm.integrityJitter)
	if integrityProbeSpread == 0 {
		return vm.integrityEvery
	}
	return vm.integrityEvery + (vm.integrityJitter % integrityProbeSpread)
}

func (vm *VM) nextSweepInterval() uint64 {
	vm.integrityJitter = nextIntegrityJitter(vm.integrityJitter)
	if integritySweepSpread == 0 {
		return integritySweepBase
	}
	return integritySweepBase + (vm.integrityJitter % integritySweepSpread)
}

func New(bc *compiler.ByteCode) *VM {
	mainInstructions := bc.Instructions
	// Named and given the program's own line table so that frame 0 is an
	// ordinary frame: Traceback walks every frame the same way instead of
	// special-casing the bottom of the stack.
	mainfn := &object.CompiledFunction{
		Instructions: mainInstructions,
		Name:         mainFrameName,
		LineTable:    bc.LineTable,
		MacroTable:   bc.MacroTable,
		EndTable:     bc.EndTable,
	}
	frames := make([]*Frame, initialFrameCapacity)

	mainClosure := &object.Closure{Fn: mainfn}
	mainFrame := NewFrame(mainClosure, 0)
	frames[0] = mainFrame

	frameIntegrity := make(map[*object.CompiledFunction][32]byte)
	frameIntegrity[mainfn] = sha256.Sum256(mainfn.Instructions)
	integritySeed := deriveIntegritySeed(mainInstructions)

	vm := &VM{
		bytecode:        bc,
		opcodeReverse:   normalizeOpcodeMap(bc.OpcodeMap),
		constants:       bc.Constants,
		stack:           make([]object.Object, initialStackCapacity),
		stackPointer:    0,
		globals:         make([]object.Object, initialGlobalsCapacity),
		secureGlobals:   make(map[int]*object.SecureGlobal),
		frames:          frames,
		frameIndex:      1,
		inslen:          len(bc.Instructions),
		password:        "",
		stepCount:       0,
		integrityEvery:  64,
		integrityJitter: integritySeed,
		frameIntegrity:  frameIntegrity,
		secureMode:      true,
		structDefs:      convertStructDefs(bc.StructDefs),
		enumDefs:        convertEnumDefs(bc.EnumDefs),
		memoryMode:      resolveVMGlobalMemoryMode(),

		enforceSecurityCheckOpcodes: false,
	}
	vm.nextIntegrityAt = 0
	vm.nextSweepAt = vm.nextSweepInterval()
	if bc != nil {
		vm.builtinsVersion = bc.Version
	}
	vm.builtins, vm.builtinsErr = resolveBuiltins(bc)
	return vm
}

// resolveBuiltins binds the builtin names a program references to the functions
// this runtime actually has, before a single instruction runs.
//
// Doing it eagerly is the point: a missing builtin is a property of the artifact,
// not of the path taken through it, and resolving lazily at the call site would
// hide it behind whichever branch happens not to be exercised.
func resolveBuiltins(bc *compiler.ByteCode) ([]*builtin.BuiltIn, error) {
	if bc == nil {
		return nil, nil
	}
	switch version := compiler.NormalizeVersion(bc.Version); {
	case version > compiler.BytecodeVersion:
		return nil, fmt.Errorf(
			"this program uses bytecode container v%d; this mutant runtime reads up to v%d -- upgrade mutant, or recompile the program from source",
			version, compiler.BytecodeVersion)
	case version >= compiler.BytecodeVersionNamedBuiltins:
		return builtin.ResolveNames(bc.BuiltinNames)
	default:
		return builtin.ResolveLegacyOrdinals()
	}
}

// builtinTableIndex turns a raw OpGetBuiltin operand into a position in the
// table resolved at construction.
//
// In a name-indexed program the operand carries code.BuiltinNameTableFlag, and
// its absence means the container claims one format while its instructions were
// written in the other -- a mismatch worth reporting rather than reading the
// operand as though it were a registry ordinal.
func (vm *VM) builtinTableIndex(operand uint16) (int, error) {
	index := int(operand)
	if compiler.NormalizeVersion(vm.builtinsVersion) >= compiler.BytecodeVersionNamedBuiltins {
		if index&code.BuiltinNameTableFlag == 0 {
			return 0, fmt.Errorf(
				"OpGetBuiltin: operand %d is not a name-table index, but this program declares bytecode container v%d; the file is corrupt or was assembled by hand",
				index, compiler.NormalizeVersion(vm.builtinsVersion))
		}
		index &^= code.BuiltinNameTableFlag
	}
	if index >= len(vm.builtins) {
		return 0, fmt.Errorf("OpGetBuiltin: invalid builtin index=%d, len=%d", index, len(vm.builtins))
	}
	return index, nil
}

// normalizeOpcodeMap accepts a reverse opcode table only if it can address every
// byte an instruction stream might hold. A short table would panic on the first
// opcode past its end, and a table that is present but wrong is worse than none
// -- so anything malformed is treated as absent, and the program runs as though
// it had never been remapped. That fails loudly at the first instruction rather
// than executing something else.
func normalizeOpcodeMap(reverse []byte) []byte {
	if len(reverse) != 256 {
		return nil
	}
	return reverse
}

// decodeOpcode turns a byte read from an instruction stream into the opcode it
// stands for, undoing polymorphic remapping when the program carries a table.
func (vm *VM) decodeOpcode(b byte) code.Opcode {
	if vm.opcodeReverse == nil {
		return code.Opcode(b)
	}
	return code.Opcode(vm.opcodeReverse[b])
}

func convertStructDefs(structDefs map[string][]*ast.Identifier) map[string]interface{} {
	result := make(map[string]interface{})
	for key, val := range structDefs {
		result[key] = val
	}
	return result
}

func convertEnumDefs(enumDefs map[string][]string) map[string]interface{} {
	result := make(map[string]interface{})
	for key, val := range enumDefs {
		result[key] = val
	}
	return result
}

func growSize(current, required, fallback int) int {
	if required <= current {
		return current
	}

	newSize := current
	if newSize == 0 {
		newSize = fallback
	}
	if newSize == 0 {
		newSize = 1
	}

	for newSize < required {
		newSize *= 2
	}

	return newSize
}

func (vm *VM) ensureStackCapacity(required int) {
	if required <= len(vm.stack) {
		return
	}

	newSize := growSize(len(vm.stack), required, initialStackCapacity)
	resized := make([]object.Object, newSize)
	copy(resized, vm.stack)
	vm.stack = resized
}

func (vm *VM) ensureGlobalCapacity(index int) {
	required := index + 1
	if required <= len(vm.globals) {
		return
	}

	newSize := growSize(len(vm.globals), required, initialGlobalsCapacity)
	resized := make([]object.Object, newSize)
	copy(resized, vm.globals)
	vm.globals = resized
}

// initialFrameCapacity is how much room the frame slice is allocated with before
// anything runs. ensureFrameCapacity grows it on demand, so it is a starting size
// and not a ceiling; maxCallDepth below is the ceiling.
//
// It was global.MaxFrames, which is the whole of M26-VM-021's complaint about that
// package and half of why M26-VM-006 went unnoticed: traceback.go and resource.go
// are both written as though a runaway recursion ends in an error the VM reports,
// and a constant called MaxFrames is why anyone would think so.
const initialFrameCapacity = 2048

// maxCallDepth is how many calls may be on the stack at once. The next one past it
// is refused with an error naming the number, which is a diagnostic the author can
// act on; what happened before was not.
//
// Nothing bounded depth at all. A recursion with no stopping case grew the frame
// slice until the host gave out -- measured at 73,298 frames in 8 seconds with no
// error -- and a recursion written through map, filter, each, reduce, sort_by,
// with_resource or test grew the Go stack as well, because each of those re-enters
// execLoop through CallClosureSync. That form ends in `fatal error: stack
// overflow`, which no recover contains, so the process dies with the runner's
// deferred cleanup unrun: no CleanupSensitiveData, no WaitForTasks.
//
// 10,000 is high enough that it is not a program's problem -- Python's default is
// 1,000 and Node's is around 11,000 -- and low enough to hold the Go stack well
// inside its own default. Measured: 10,000 nested CallClosureSync re-entries fit
// in 32 MiB of Go stack and not in 16 MiB, against a 1 GiB default, so the frame
// ceiling is what stops the native path too and no second limit is needed. The
// refusal takes about two seconds to arrive, which is the per-sweep frame integrity
// walk being quadratic in depth (M26-VM-012) and not this check.
//
//mutant:limit depth
const maxCallDepth = 10_000

func (vm *VM) ensureFrameCapacity(required int) {
	if required <= len(vm.frames) {
		return
	}

	newSize := growSize(len(vm.frames), required, initialFrameCapacity)
	resized := make([]*Frame, newSize)
	copy(resized, vm.frames)
	vm.frames = resized
}

func (vm *VM) encryptForStorage(obj object.Object) object.Object {
	encObj, err := mutil.EncryptObjectWithStream(obj, vm.inslen, vm.password, vm.valueStream())
	if err == nil {
		return encObj
	}
	return obj
}

func (vm *VM) decryptForUse(obj object.Object) object.Object {
	decObj, err := mutil.DecryptObjectWithStream(obj, vm.inslen, vm.password, vm.valueStream())
	if err == nil {
		return decObj
	}
	return obj
}

func (vm *VM) clearObjectSensitiveData(obj object.Object) {
	if obj == nil {
		return
	}

	switch o := obj.(type) {
	case *object.Encrypted:
		security.SecureZero(o.Value)
		o.Value = nil
	// A bytes is the one value type whose payload can actually be wiped: a
	// string's bytes are immutable, so the conversion needed to zero them
	// produces a copy and clears that instead. Key material held in a buffer is
	// therefore gone here, not merely dereferenced.
	case *object.Bytes:
		o.Zero()
	case *object.Array:
		for i := range o.Elements {
			vm.clearObjectSensitiveData(o.Elements[i])
			o.Elements[i] = nil
		}
	case *object.Hash:
		for key, pair := range o.Pairs {
			vm.clearObjectSensitiveData(pair.Key)
			vm.clearObjectSensitiveData(pair.Value)
			delete(o.Pairs, key)
		}
	// A captured variable's storage, which the frame slot and every closure over
	// it share. Recursing is what makes a secret held in one reachable at all:
	// the slot holds the cell, so wiping the slot alone leaves the value alive
	// behind a pointer some closure is still holding.
	case *object.Cell:
		vm.clearObjectSensitiveData(o.Value)
		o.Value = nil
	case *object.Closure:
		for i := range o.Free {
			vm.clearObjectSensitiveData(o.Free[i])
			o.Free[i] = nil
		}
	}
}

func (vm *VM) useWrapperGlobals() bool {
	return vm.memoryMode == vMMemoryModeWrapper
}

func (vm *VM) setGlobal(index int, obj object.Object) {
	if vm.useWrapperGlobals() {
		if wrapped, err := object.NewSecureGlobal(obj, int64(vm.inslen)); err == nil {
			if previous, ok := vm.secureGlobals[index]; ok {
				previous.Clear()
			}
			vm.secureGlobals[index] = wrapped
			vm.globals[index] = nil
			return
		}
	}

	if previous, ok := vm.secureGlobals[index]; ok {
		previous.Clear()
		delete(vm.secureGlobals, index)
	}
	vm.globals[index] = vm.encryptForStorage(obj)
}

func (vm *VM) getGlobal(index int) object.Object {
	if wrapped, ok := vm.secureGlobals[index]; ok {
		obj, err := wrapped.Get()
		if err == nil {
			return obj
		}
		wrapped.Clear()
		delete(vm.secureGlobals, index)
	}

	return vm.decryptForUse(vm.globals[index])
}

// CleanupRuntimeSensitiveData clears encrypted runtime data buffers after execution.
// clearGlobals controls whether globals are wiped; clearConstants controls whether constants are wiped.
func (vm *VM) CleanupRuntimeSensitiveData(clearGlobals bool, clearConstants bool) {
	// Whether the stack is wiped or merely released follows clearGlobals, and it
	// has to: since M26-VM-001 a stack slot and a global can be the same object.
	// A value that is only moving is moved rather than opened and sealed again,
	// so OpSetGlobal hands the stack's own object to the global, and pop leaves
	// its pointer behind in the slot it vacated -- so the backing array still
	// reaches a global after the value has been stored there.
	//
	// Wiping in place is therefore incompatible with keeping the globals, and
	// the caller has already said which it wants. clearGlobals is false only for
	// the REPL, where the next line is the same program continuing and the
	// globals are its state. Wiping the stack there emptied a hash a global still
	// held, and record_seal refused a range with no "offset" on the line after
	// the one that built it.
	//
	// So when the globals stay, the slots are dropped and not wiped. What no
	// global owns becomes garbage, and in storage form: the stack holds sealed
	// values, and the REPL keeps the password alive between lines in any case,
	// because without it no global could be opened. When the globals go, the run
	// is over and everything the stack can reach is wiped as before.
	for i := range vm.stack {
		if clearGlobals {
			vm.clearObjectSensitiveData(vm.stack[i])
		}
		vm.stack[i] = nil
	}
	vm.stackPointer = 0

	if clearGlobals {
		for index, wrapped := range vm.secureGlobals {
			if wrapped != nil {
				wrapped.Clear()
			}
			delete(vm.secureGlobals, index)
		}
		for i := range vm.globals {
			vm.clearObjectSensitiveData(vm.globals[i])
			vm.globals[i] = nil
		}
	}

	if clearConstants {
		for i := range vm.constants {
			if compiledFn, ok := vm.constants[i].(*object.CompiledFunction); ok {
				security.SecureZero(compiledFn.Instructions)
				compiledFn.Instructions = nil
			}
			vm.clearObjectSensitiveData(vm.constants[i])
			vm.constants[i] = nil
		}
	}

	for i := range vm.frames {
		vm.frames[i] = nil
	}
	vm.frameIndex = 0
	vm.password = ""

	// The stream was derived from the password the line above just dropped, and
	// it now carries the key this VM's values are sealed with as well as its
	// instructions (M26-VM-001). Nothing derived from the secret outlives it.
	vm.xorStream.Zero()
}

// CleanupSensitiveData clears runtime buffers and constants. Intended for one-shot execution paths.
func (vm *VM) CleanupSensitiveData(clearGlobals bool) {
	vm.CleanupRuntimeSensitiveData(clearGlobals, true)
}

// GlobalStore returns the VM global storage slice reference.
func (vm *VM) GlobalStore() []object.Object {
	return vm.globals
}

func NewWithPassword(bc *compiler.ByteCode, password string) *VM {
	return NewWithPasswordMode(bc, password, true)
}

func NewWithPasswordMode(bc *compiler.ByteCode, password string, secureMode bool) *VM {
	vm := New(bc)
	vm.password = password
	// No polymorphic-marker trim here. The marker is compile-time metadata that
	// generator.encode removes before anything is written, using the level the
	// compiler reports -- so a marker never reaches the VM. What used to stand
	// here guessed instead, treating a trailing [0xFF, n<=10] (in either order)
	// as a marker and cutting two bytes. Ordinary bytecode produces that pattern:
	// `OpConstant 255` is 0x00 0x00 0xFF, and a following OpPop makes 0xFF 0x01.
	// Programs were truncated and failed on "not enough bytes for operand".
	//
	// If a marker ever did survive, 0xFF is not a defined opcode, so the VM
	// reports an undecodable instruction -- a clean failure rather than a
	// silently shortened program.
	vm.secureMode = secureMode
	vm.enforceSecurityCheckOpcodes = true
	vm.ensureFrameBoundaries()
	return vm
}

func NewWithGlobalStore(bc *compiler.ByteCode, globals []object.Object) *VM {
	return NewWithGlobalStoreMode(bc, globals, true)
}

func NewWithGlobalStoreAndPassword(bc *compiler.ByteCode, globals []object.Object, password string) *VM {
	vm := NewWithGlobalStore(bc, globals)
	vm.password = password
	return vm
}

func NewWithPasswordAndGlobalStore(bc *compiler.ByteCode, password string, globals []object.Object) *VM {
	return NewWithPasswordAndGlobalStoreMode(bc, password, globals, true)
}

func NewWithGlobalStoreMode(bc *compiler.ByteCode, globals []object.Object, secureMode bool) *VM {
	vm := New(bc)
	if globals != nil {
		vm.globals = globals
	}
	vm.secureMode = secureMode
	return vm
}

func NewWithPasswordAndGlobalStoreMode(bc *compiler.ByteCode, password string, globals []object.Object, secureMode bool) *VM {
	vm := NewWithPasswordMode(bc, password, secureMode)
	if globals != nil {
		vm.globals = globals
	}
	vm.ensureFrameBoundaries()
	return vm
}

// SecureMode reports whether a tamper probe that fires ends the run or only
// warns. The constructors default it to true; the callers that build a VM for a
// development activity -- `mutant test`, a debug session -- pass false, and this
// is what lets them state which posture they chose rather than imply it.
func (vm *VM) SecureMode() bool { return vm != nil && vm.secureMode }

func (vm *VM) ensureFrameBoundaries() {
	if vm == nil || vm.password == "" {
		return
	}

	if vm.frameBoundaries == nil {
		vm.frameBoundaries = make(map[*object.CompiledFunction]map[int]struct{})
	}

	// The main program's function is synthesised in New rather than taken from
	// the constants pool, so it is mapped on its own.
	if frame := vm.currentFrame(); frame != nil && frame.cl != nil && frame.cl.Fn != nil {
		fn := frame.cl.Fn
		if _, exists := vm.frameBoundaries[fn]; !exists {
			vm.frameBoundaries[fn] = vm.buildInstructionBoundaries(fn.Instructions)
		}
	}

	if vm.constantBoundariesMapped {
		return
	}
	vm.constantBoundariesMapped = true

	for _, constant := range vm.constants {
		compiledFn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		if _, exists := vm.frameBoundaries[compiledFn]; !exists {
			vm.frameBoundaries[compiledFn] = vm.buildInstructionBoundaries(compiledFn.Instructions)
		}
	}
}

// instructionStream returns the cached keystream for this VM's instructions,
// deriving it on first use. Every instruction byte -- opcode, operand, and the
// boundary map's decode pass -- is at a stream offset under the same (inslen,
// password) pair, so the key and nonce are derived exactly once per VM instead
// of twice per byte.
func (vm *VM) instructionStream() *security.XORStream {
	if vm.xorStream == nil {
		vm.xorStream = security.NewXORStream(int64(vm.inslen), vm.password)
	}
	return vm.xorStream
}

// valueStream is the same derived key under the name the other half of the VM
// reads it by. A stored value's payload is sealed from the start of the
// keystream under (inslen, password) -- the pair the instruction stream is
// derived from -- so one derivation per run now covers the opcodes and the
// values both.
//
// Deriving it per value was the cost of a container load rather than the
// cipher: building an array of 800 elements in a loop made 2,890,011
// derivations, two SHA-256 hashes each, for 22 MiB of payload (M26-VM-001).
// A value that records a seed of its own is still opened with a key derived
// for that seed; mutil.sealKey has the case and the reason.
func (vm *VM) valueStream() *security.XORStream {
	return vm.instructionStream()
}

// readUint16 and readUint8 decode an operand at an absolute instruction offset.
// They are the cached-stream equivalents of code.ReadUint16/code.ReadUint8,
// which take the password and re-derive the key and nonce on every call -- two
// SHA-256 hashes to decrypt two bytes, on a path the fetch loop walks for
// nearly every instruction it executes.
func (vm *VM) readUint16(ins code.Instructions, at int) (uint16, error) {
	if at < 0 || at+2 > len(ins) {
		return 0, fmt.Errorf("instruction slice too short for uint16")
	}
	dec, err := vm.instructionStream().XORAt(ins[at:at+2], int64(at))
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(dec), nil
}

func (vm *VM) readUint8(ins code.Instructions, at int) (uint8, error) {
	if at < 0 || at >= len(ins) {
		return 0, fmt.Errorf("instruction slice too short for uint8")
	}
	dec, err := vm.instructionStream().XOROneAt(ins[at], int64(at))
	if err != nil {
		return 0, err
	}
	return dec, nil
}

func (vm *VM) buildInstructionBoundaries(ins code.Instructions) map[int]struct{} {
	boundaries := make(map[int]struct{})
	if vm.password == "" {
		return boundaries
	}
	stream := vm.instructionStream()

	for i := 0; i < len(ins); {
		boundaries[i] = struct{}{}
		opcodeByte, err := stream.XOROneAt(ins[i], int64(i))
		if err != nil {
			break
		}

		def, err := code.Lookup(byte(vm.decodeOpcode(opcodeByte)))
		if err != nil {
			break
		}

		next := 1
		for _, width := range def.OperandWidths {
			next += width
		}
		i += next
	}

	return boundaries
}

func (vm *VM) verifyFrameControlFlow(frame *Frame, stage string) error {
	if frame == nil || frame.cl == nil || frame.cl.Fn == nil {
		return nil
	}

	// New frames start at ip=-1 until the first opcode fetch.
	if frame.ip < 0 {
		return nil
	}

	vm.ensureFrameBoundaries()
	fn := frame.cl.Fn
	boundaries, exists := vm.frameBoundaries[fn]
	if !exists {
		boundaries = vm.buildInstructionBoundaries(fn.Instructions)
		vm.frameBoundaries[fn] = boundaries
	}

	if _, ok := boundaries[frame.ip]; !ok {
		// Jump opcodes set ip to target-1 so the fetch loop can increment before reading the next opcode.
		if _, nextOk := boundaries[frame.ip+1]; nextOk {
			return nil
		}
		security.RecordIntegrityFailure(stage)
		return security.ApplyTamperResponse("integrity_failed", stage, vm.secureMode, fmt.Errorf("control-flow integrity check failed at ip=%d", frame.ip))
	}

	return nil
}

// prepareForExecution performs the one-time setup execLoop depends on. Run()
// does it before driving a whole program; a worker VM (see parallel.go) needs it
// too, because it enters through CallClosureSync and never calls Run at all --
// without this its xorStream is nil and the first opcode fetch dereferences it.
func (vm *VM) prepareForExecution() {
	vm.ensureFrameBoundaries()
	vm.instructionStream()
}

func (vm *VM) Run() error {
	// Reported before anything executes: a builtin this runtime does not have is
	// a fact about the program, and running half of it first tells the user less.
	if vm.builtinsErr != nil {
		return vm.builtinsErr
	}

	vm.prepareForExecution()

	if err := vm.validateSecurityCheckOpcodes("before-execution"); err != nil {
		return err
	}

	if err := vm.execLoop(0); err != nil {
		return err
	}

	if err := vm.validateSecurityCheckOpcodes("after-execution"); err != nil {
		return err
	}

	return nil
}

// execLoop runs the fetch/decode/execute loop until the frame stack unwinds back
// to baseFrameIndex. Run() drives the whole program via execLoop(0); the
// closure-from-builtin bridge (CallClosureSync) re-enters with a higher base to
// run exactly one closure to completion, then returns control to its caller.
//
// It is also the fault boundary, which is why the loop body lives in a separate
// function. Every path into the executor goes through here -- Run, and through
// CallClosureSync also pmap, spawn and every net_serve handler -- so one recover
// here is what makes bytecode the VM cannot decode report an error instead of
// taking the process down. Those three had their own recovers already; the main
// program path had none, so the same corrupt .mu file errored inside a worker
// and panicked on the main thread. See vm/fault.go.
func (vm *VM) execLoop(baseFrameIndex int) (err error) {
	defer func() {
		containFault(recover(), &err)
		// After containFault, so a fault is given a location too, and inside
		// the same defer because the VM's frame stack still describes the
		// failure at this point -- returning first would be too late.
		err = vm.attachTraceback(err)
	}()
	return vm.runInstructions(baseFrameIndex)
}

func (vm *VM) runInstructions(baseFrameIndex int) error {
	var ip int
	var ins code.Instructions
	var op code.Opcode

	for vm.frameIndex > baseFrameIndex && vm.currentFrame().ip < len(vm.currentFrame().Instructions())-1 {
		if err := vm.runIntegrityProbes(); err != nil {
			return err
		}

		vm.currentFrame().ip++
		vm.stepCount++

		ip = vm.currentFrame().ip
		ins = vm.currentFrame().Instructions()

		// The debugger sees the instruction before it runs, with ip already
		// advanced to it -- which is the position Traceback reports, so a stop
		// here and a crash here name the same line. It blocks inside this call
		// for as long as the session is parked.
		if vm.debug != nil {
			if err := vm.debug.step(); err != nil {
				return err
			}
		}

		if vm.cover != nil {
			vm.cover.mark(vm.currentFrame().cl.Fn, ip)
		}

		opcodeByte, err := vm.xorStream.XOROneAt(ins[ip], int64(ip))
		if err != nil {
			return vm.runtimeErrorAt(ip, op, err)
		}
		op = vm.decodeOpcode(opcodeByte)

		switch op {
		case code.OpChkDbg:
			if isDebuggerPresent() {
				security.RecordDebuggerDetected("vm-run")
				if !vm.secureMode {
					logSecurityWarning("debugger_detected", "vm-run")
					continue
				}
				// The security opcodes return their error directly rather than
				// going through ApplyTamperResponse, so they explain themselves
				// here instead. Without this the run stopped mid-instruction
				// with one sentence naming no probe and no remedy. (M-7)
				security.ExplainTamperTermination("debugger_detected", "vm-run", security.DebuggerTamperDetail())
				return security.ErrDebuggerDetected
			}
		case code.OpChkSnd:
			if isSandboxed() {
				security.RecordSandboxDetected("vm-run")
				if !vm.secureMode {
					logSecurityWarning("sandbox_detected", "vm-run")
					continue
				}
				security.ExplainTamperTermination("sandbox_detected", "vm-run", security.SandboxTamperDetail())
				return security.ErrSandboxDetected
			}
		case code.OpConstant:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			constIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			vm.currentFrame().ip += 2

			constant, err := vm.constantAt(int(constIndex))
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			if err := vm.push(constant); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpBang:
			if err := vm.execBangOperation(); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpMinus:
			if err := vm.execMinusOperation(); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpBitNot:
			if err := vm.execBitNotOperation(); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpAdd, code.OpSub, code.OpMul, code.OpDiv, code.OpMod,
			code.OpBitAnd, code.OpBitOr, code.OpBitXor, code.OpShiftLeft, code.OpShiftRight:
			if err := vm.execBinaryOperation(op); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpTrue:
			if err := vm.push(global.True); err != nil {
				return err
			}
		case code.OpFalse:
			if err := vm.push(global.False); err != nil {
				return err
			}
		case code.OpArray:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			numElements := int(res)
			vm.currentFrame().ip += 2
			if vm.stackPointer-numElements < 0 {
				return vm.runtimeErrorfAt(ip, op, "stack underflow for %d elements (sp=%d)", numElements, vm.stackPointer)
			}
			array := vm.buildArray(vm.stackPointer-numElements, vm.stackPointer)
			vm.stackPointer = vm.stackPointer - numElements // pop the elements (OpHash does this; OpArray had omitted it)
			if err := vm.push(array); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpConcat:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			numPieces := int(res)
			vm.currentFrame().ip += 2
			if vm.stackPointer-numPieces < 0 {
				return vm.runtimeErrorfAt(ip, op, "stack underflow for %d pieces (sp=%d)", numPieces, vm.stackPointer)
			}
			joined := vm.buildInterpolation(vm.stackPointer-numPieces, vm.stackPointer)
			vm.stackPointer = vm.stackPointer - numPieces
			if err := vm.push(joined); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpHash:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			numElements := int(res)
			vm.currentFrame().ip += 2
			// buildHash reads pairs, so an odd count would read one past the top.
			if vm.stackPointer-numElements < 0 || numElements%2 != 0 {
				return vm.runtimeErrorfAt(ip, op, "stack underflow for %d key/value slots (sp=%d)", numElements, vm.stackPointer)
			}
			hash, err := vm.buildHash(vm.stackPointer-numElements, vm.stackPointer)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			vm.stackPointer = vm.stackPointer - numElements
			if err := vm.push(hash); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpEqual, code.OpUnEqual, code.OpGreater, code.OpGreaterEqual:
			if err := vm.execComparison(op); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpJump:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpJump: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			pos := int(res)
			vm.currentFrame().ip = pos - 1
		case code.OpMatchFail:
			// Reached only by falling past every arm of a match with no `_`.
			// The subject is still on the stack because each arm drops it
			// itself; naming it is the whole point of failing here rather
			// than pushing a null and letting it flow on.
			unmatched := vm.pop()
			rendered := "null"
			if unmatched != nil {
				rendered = unmatched.Inspect()
			}
			return vm.runtimeErrorfAt(ip, op, "no match arm matched %s", rendered)

		case code.OpIterInit:
			iterable := vm.decryptForUse(vm.pop())
			if iterable == nil {
				return vm.runtimeErrorfAt(ip, op, "nothing to iterate over")
			}
			iterator, iterable_ok := object.NewIterator(iterable)
			if !iterable_ok {
				return vm.runtimeErrorfAt(ip, op, "cannot iterate over %s", iterable.Type())
			}
			if err := vm.push(iterator); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}

		case code.OpIterNext:
			if ip+3 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operands, len=%d", len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			endPosition := int(res)
			// readUint8, not ins[ip+3]: instruction bytes are not read raw
			// here, and a direct index gives the obfuscated byte rather than
			// the operand.
			bindingCount, err := vm.readUint8(ins, ip+3)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			bindings := int(bindingCount)
			vm.currentFrame().ip += 3

			// Peeked, not popped: the cursor stays on the stack for the whole
			// loop and is dropped by the OpPop at the loop's end, which is
			// where both the exhausted jump and every break land.
			if vm.stackPointer < 1 {
				return vm.runtimeErrorfAt(ip, op, "stack underflow reading the loop cursor")
			}
			iterator, isIterator := vm.stack[vm.stackPointer-1].(*object.Iterator)
			if !isIterator {
				return vm.runtimeErrorfAt(ip, op, "loop cursor was replaced on the stack")
			}

			key, value, more := iterator.Next()
			if !more {
				vm.currentFrame().ip = endPosition - 1
				break
			}

			if bindings == 2 {
				if err := vm.push(key); err != nil {
					return vm.runtimeErrorAt(ip, op, err)
				}
				if err := vm.push(value); err != nil {
					return vm.runtimeErrorAt(ip, op, err)
				}
				break
			}
			if err := vm.push(iterator.Primary(key, value)); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}

		case code.OpJumpFalse:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpJumpFalse: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			res, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			pos := int(res)
			vm.currentFrame().ip += 2
			condition := vm.pop()
			if !object.IsTruthy(condition) {
				vm.currentFrame().ip = pos - 1
			}
		case code.OpSetGlobal:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpSetGlobal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			globalIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2
			vm.ensureGlobalCapacity(int(globalIndex))
			vm.setGlobalStored(int(globalIndex))
		case code.OpGetGlobal:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpGetGlobal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			globalIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2
			vm.ensureGlobalCapacity(int(globalIndex))
			if err := vm.pushGlobal(int(globalIndex)); err != nil {
				return err
			}
		case code.OpSetLocal:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpSetLocal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			localIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			slot := frame.bp + int(localIndex)
			if slot < 0 || slot >= len(vm.stack) {
				return vm.runtimeErrorfAt(ip, op, "local slot %d outside the stack (bp=%d, len=%d)", slot, frame.bp, len(vm.stack))
			}
			vm.stack[slot] = vm.popStored()
		case code.OpGetLocal:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpGetLocal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			localIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			slot := frame.bp + int(localIndex)
			if slot < 0 || slot >= len(vm.stack) {
				return vm.runtimeErrorfAt(ip, op, "local slot %d outside the stack (bp=%d, len=%d)", slot, frame.bp, len(vm.stack))
			}
			if err := vm.pushStored(vm.stack[slot]); err != nil {
				return err
			}
		case code.OpGetBuiltin:
			// 2-byte operand: there are >255 builtins, so a single byte would alias
			// high-index builtins to (index mod 256).
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpGetBuiltin: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			builtinIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2
			// Indexes the table resolved at construction -- this program's own
			// referenced-builtin names, or the frozen ordinal snapshot for
			// bytecode compiled before names travelled with the program. Never
			// the live registry, whose order is no longer part of the ABI.
			index, err := vm.builtinTableIndex(builtinIndex)
			if err != nil {
				return err
			}
			if err := vm.push(vm.builtins[index]); err != nil {
				return err
			}
		case code.OpGetFree:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpGetFree: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			freeIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			currentClosure := vm.currentFrame().cl
			if currentClosure == nil || int(freeIndex) >= len(currentClosure.Free) {
				return vm.runtimeErrorfAt(ip, op, "free variable index=%d outside this closure's %d captured values", freeIndex, freeCount(currentClosure))
			}
			// A captured local is boxed, so the Free entry is the cell and the
			// value is inside it. The two cases the type switch distinguishes
			// are both real: a free whose original is the enclosing function's
			// own name is captured by value for recursion and is a closure, not
			// a cell, and every free in bytecode compiled before boxing existed
			// is a plain value. Nothing a program can compute is ever a *Cell,
			// so the test cannot be fooled by a user value.
			captured := currentClosure.Free[freeIndex]
			if cell, ok := captured.(*object.Cell); ok {
				captured = cell.Value
			}
			if err := vm.pushStored(captured); err != nil {
				return err
			}
		case code.OpSetFree:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpSetFree: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			freeIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			currentClosure := vm.currentFrame().cl
			if currentClosure == nil || int(freeIndex) >= len(currentClosure.Free) {
				return vm.runtimeErrorfAt(ip, op, "free variable index=%d outside this closure's %d captured values", freeIndex, freeCount(currentClosure))
			}
			cell, ok := currentClosure.Free[freeIndex].(*object.Cell)
			if !ok {
				// The compiler refuses the one unboxed free it can produce (the
				// enclosing function's own name), so reaching here means the
				// bytecode did not come from this compiler.
				return vm.runtimeErrorfAt(ip, op, "captured variable %d is not assignable storage", freeIndex)
			}
			cell.Value = vm.popStored()
		case code.OpGetLocalCell, code.OpSetLocalCell, code.OpCaptureLocal:
			if ip+1 >= len(ins) {
				return fmt.Errorf("%s: not enough bytes for operand at ip=%d, len=%d", runtimeOpcodeName(op), ip, len(ins))
			}
			localIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			slot := frame.bp + int(localIndex)
			if slot < 0 || slot >= len(vm.stack) {
				return vm.runtimeErrorfAt(ip, op, "local slot %d outside the stack (bp=%d, len=%d)", slot, frame.bp, len(vm.stack))
			}
			cell, ok := vm.stack[slot].(*object.Cell)
			if !ok {
				// callClosure boxes every slot named in CapturedLocals before a
				// single instruction runs, and only slots in that list are given
				// these opcodes. A miss means the function object and its
				// instruction stream disagree.
				return vm.runtimeErrorfAt(ip, op, "local slot %d is not boxed", localIndex)
			}
			switch op {
			case code.OpGetLocalCell:
				if err := vm.pushStored(cell.Value); err != nil {
					return err
				}
			case code.OpSetLocalCell:
				cell.Value = vm.popStored()
			case code.OpCaptureLocal:
				// The cell itself, not its contents: OpClosure copies what is on
				// the stack into the new closure's Free list, and copying the
				// pointer is what makes the two sides one location.
				if err := vm.push(cell); err != nil {
					return err
				}
			}
		case code.OpCaptureFree:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpCaptureFree: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			freeIndex, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			currentClosure := vm.currentFrame().cl
			if currentClosure == nil || int(freeIndex) >= len(currentClosure.Free) {
				return vm.runtimeErrorfAt(ip, op, "free variable index=%d outside this closure's %d captured values", freeIndex, freeCount(currentClosure))
			}
			// Re-capturing a capture: a function three levels down closing over a
			// variable two levels up. Passing this frame's entry along unread is
			// what keeps all three levels pointing at the one cell the owner
			// boxed.
			if err := vm.push(currentClosure.Free[freeIndex]); err != nil {
				return err
			}
		case code.OpIndex:
			index := vm.pop()
			left := vm.pop()
			if err := vm.execIndexOperation(left, index); err != nil {
				return err
			}
		case code.OpSetIndex:
			value := vm.decryptForUse(vm.pop())
			index := vm.decryptForUse(vm.pop())
			container := vm.decryptForUse(vm.pop())
			mutated, err := vm.execSetIndex(container, index, value)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			if err := vm.push(mutated); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpClosure:
			if ip+3 >= len(ins) {
				return fmt.Errorf("OpClosure: not enough bytes for operands at ip=%d, len=%d", ip, len(ins))
			}
			constIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			numFree, err := vm.readUint8(ins, ip+3)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 3
			if err := vm.pushClosure(int(constIndex), int(numFree)); err != nil {
				return err
			}
		case code.OpCurrentClosure:
			currentClosure := vm.currentFrame().cl
			if err := vm.push(vm.decryptForUse(currentClosure)); err != nil {
				return err
			}
		case code.OpCall:
			if ip+1 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			numArgs, err := vm.readUint8(ins, ip+1)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			vm.currentFrame().ip++
			if err := vm.execCall(int(numArgs)); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpReturnValue:
			returnValue := vm.pop()
			frame := vm.popFrame()
			vm.stackPointer = frame.bp - 1
			if vm.stackPointer < 0 {
				vm.stackPointer = 0
			}
			if err := vm.push(returnValue); err != nil {
				return err
			}
			vm.settleProgramResult()
		case code.OpReturn:
			frame := vm.popFrame()
			vm.stackPointer = frame.bp - 1
			if vm.stackPointer < 0 {
				vm.stackPointer = 0
			}
			if err := vm.push(global.Null); err != nil {
				return err
			}
			vm.settleProgramResult()
		case code.OpMultiValue:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpMultiValue: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			count, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			start := vm.stackPointer - int(count)
			if start < 0 {
				return fmt.Errorf("OpMultiValue: stack underflow for count=%d", count)
			}

			multiValue := vm.buildMultiValue(start, vm.stackPointer)
			vm.stackPointer -= int(count)
			if err := vm.push(multiValue); err != nil {
				return err
			}
		case code.OpNull:
			if err := vm.push(global.Null); err != nil {
				return err
			}
		case code.OpPop:
			vm.pop()
		case code.OpDup:
			if vm.stackPointer <= 0 {
				return vm.runtimeErrorfAt(ip, op, "stack underflow")
			}
			if err := vm.pushStored(vm.stack[vm.stackPointer-1]); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpDestructure:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpDestructure: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			count, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			source := vm.pop()
			values := vm.destructureValues(source, int(count))
			for _, value := range values {
				if err := vm.push(value); err != nil {
					return err
				}
			}
		case code.OpBreak:
			// Push break sentinel value
			if err := vm.push(&object.Break{}); err != nil {
				return err
			}
		case code.OpContinue:
			// Push continue sentinel value
			if err := vm.push(&object.Continue{}); err != nil {
				return err
			}
		case code.OpMakeStruct:
			if ip+3 >= len(ins) {
				return fmt.Errorf("OpMakeStruct: not enough bytes for operands at ip=%d, len=%d", ip, len(ins))
			}
			typeIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			fieldCountRaw, err := vm.readUint8(ins, ip+3)
			if err != nil {
				return err
			}
			fieldCount := int(fieldCountRaw)
			vm.currentFrame().ip += 3

			typeObj, err := vm.constantString("OpMakeStruct: type constant", int(typeIndex))
			if err != nil {
				return err
			}
			typeName := typeObj.Value

			// Get field names from struct definition
			fieldNames := []string{}
			if structDefVal, exists := vm.structDefs[typeName]; exists {
				if structDef, ok := structDefVal.([]*ast.Identifier); ok {
					for _, ident := range structDef {
						fieldNames = append(fieldNames, ident.Value)
					}
				}
			}

			// If no definition found, this will cause an error in Inspect but allow execution
			if len(fieldNames) != fieldCount {
				return fmt.Errorf("struct %s expects %d fields, got %d", typeName, len(fieldNames), fieldCount)
			}

			fields := make(map[string]object.Object)
			for i := 0; i < fieldCount; i++ {
				fieldValue := vm.pop()
				// Pop in reverse order (last field popped first)
				fieldName := fieldNames[fieldCount-1-i]
				fields[fieldName] = fieldValue
			}

			// fieldNames came from the struct's own definition above, in
			// declaration order, which is the order Inspect renders.
			structObj := &object.Struct{
				TypeName:   typeName,
				FieldOrder: fieldNames,
				Fields:     fields,
			}
			if err := vm.push(structObj); err != nil {
				return err
			}
		case code.OpGetField:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpGetField: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			fieldNameIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			fieldObj, err := vm.constantString("OpGetField: field constant", int(fieldNameIndex))
			if err != nil {
				return err
			}
			fieldName := fieldObj.Value
			obj := vm.pop()
			switch target := obj.(type) {
			case *object.Struct:
				val, exists := target.Fields[fieldName]
				if !exists {
					// This used to be null. A struct's field set is declared in
					// the program, so a name outside it is a mistake, and the
					// null made it a value instead: it compared unequal to
					// everything, printed as nothing, and flowed on into
					// whatever read it. The compiler refuses this before the
					// program runs wherever it can prove the receiver's type;
					// this is the rest.
					return errors.New(object.UnknownStructFieldMessage(
						target.TypeName, fieldName, target.FieldNames()))
				}
				if err := vm.push(val); err != nil {
					return err
				}
			case *object.Error:
				// An unknown name is null on an error and a refusal on a struct.
				// That was one rule and is now two, because the reasons were
				// never the same: a struct's field set is declared in the
				// program, so a name outside it can be reported, while an
				// error's field set is the runtime's own and a field a stripped
				// build stamps nothing into still has to read, as 0 or "".
				// TestUnknownErrorFieldIsNullNotAFault keeps this half.
				val, exists := target.Field(fieldName)
				if !exists {
					val = global.Null
				}
				if err := vm.push(val); err != nil {
					return err
				}
			default:
				return fmt.Errorf("cannot access field on non-struct: %s", obj.Type())
			}
		case code.OpSetField:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpSetField: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			fieldNameIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			fieldObj, err := vm.constantString("OpSetField: field constant", int(fieldNameIndex))
			if err != nil {
				return err
			}
			fieldName := fieldObj.Value
			value := vm.pop()
			obj := vm.pop()
			if structObj, ok := obj.(*object.Struct); ok {
				if _, declared := structObj.Fields[fieldName]; !declared {
					// Writing a field the type does not declare used to add it.
					// The record then stopped matching its declaration, two
					// records of one type could hold different field sets, and
					// the field the author meant to change kept its old value --
					// with the write appearing to succeed.
					return errors.New(object.UnknownStructFieldWriteMessage(
						structObj.TypeName, fieldName, structObj.FieldNames()))
				}
				structObj.Fields[fieldName] = value
				if err := vm.push(structObj); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("cannot set field on non-struct: %s", obj.Type())
			}
		case code.OpEnumValue:
			if ip+4 >= len(ins) {
				return fmt.Errorf("OpEnumValue: not enough bytes for operands at ip=%d, len=%d", ip, len(ins))
			}
			typeIndex, err := vm.readUint16(ins, ip+1)
			if err != nil {
				return err
			}
			tagIndex, err := vm.readUint16(ins, ip+3)
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 4

			typeObj, err := vm.constantString("OpEnumValue: type constant", int(typeIndex))
			if err != nil {
				return err
			}
			tagObj, err := vm.constantString("OpEnumValue: tag constant", int(tagIndex))
			if err != nil {
				return err
			}
			typeName := typeObj.Value
			tagName := tagObj.Value
			ordinal := -1

			if tagsVal, ok := vm.enumDefs[typeName]; ok {
				if tags, ok := tagsVal.([]string); ok {
					for idx, t := range tags {
						if t == tagName {
							ordinal = idx
							break
						}
					}
					if ordinal < 0 {
						return fmt.Errorf("unknown enum tag %s.%s", typeName, tagName)
					}
				}
			}

			enumObj := &object.EnumValue{TypeName: typeName, Tag: tagName, Value: &object.Integer{Value: int64(ordinal)}}
			if err := vm.push(enumObj); err != nil {
				return err
			}
		default:
			// An opcode this build does not know. Refusing is the whole point of
			// the arm: without it the switch simply matched nothing, the
			// instruction pointer advanced by one, and the operand bytes of the
			// instruction it did not recognise were executed as opcodes -- a
			// program that runs to completion and answers with nonsense. Refusing
			// to run half of it is the same choice Run() already makes for a
			// builtin this runtime lacks.
			//
			// Naming one cause was wrong. The arm used to state flatly that the
			// program was built by a newer version of mutant, reasoning that
			// opcodes are only ever appended so an unknown value can only come
			// from a newer toolchain. That holds for the byte the compiler
			// emitted; it does not hold for the byte that arrives here, which is
			// whatever the instruction stream decrypted to. An opcode that
			// decodes to nothing is just as likely to mean the stream did not
			// decrypt -- the key derives from (instruction length, password), so
			// bytecode decrypted under the wrong length produces uniformly random
			// opcodes, which is precisely what the REPL's own re-encryption bug
			// (M26-TOOL-013) did to a function defined on an earlier line. Every
			// such session was told to upgrade mutant.
			//
			// Both causes are therefore named, in the order a reader can act on:
			// the local one first. The fix for M26-TOOL-013 removes the only
			// known in-tree way to reach this through decryption, so the
			// remaining ones are damaged or truncated bytecode, a wrong
			// --password, and a genuinely newer toolchain that added an opcode
			// without raising the container version (a newer container version is
			// refused earlier, by resolveBuiltins, with its own message).
			return vm.runtimeErrorfAt(ip, op,
				"unknown opcode %d: this instruction did not decode -- the bytecode may be damaged or decrypted with the wrong key, or it may have been built by a newer version of mutant",
				byte(op))
		}
	}

	return nil
}

func runtimeOpcodeName(op code.Opcode) string {
	if def, err := code.Lookup(byte(op)); err == nil {
		return def.Name
	}
	return fmt.Sprintf("opcode_%d", op)
}

// instructionError is a failure named by where in the bytecode it happened.
//
// The instruction pointer and the opcode are fields now as well as text. As
// text they are what a crash report needs, and an error that ends the run
// still carries them exactly as it did. As fields they can be left back out,
// which is what a failure on its way to becoming a value the program holds
// needs: mutation rewrites the instruction stream, so both numbers describe
// the build rather than the program. See scriptFacingMessage.
type instructionError struct {
	IP  int
	Op  code.Opcode
	Err error
}

func (e *instructionError) Error() string {
	return fmt.Sprintf("vm_runtime_error ip=%d op=%s: %s", e.IP, runtimeOpcodeName(e.Op), e.Err)
}

// Unwrap keeps errors.Is and errors.As answering about the cause, which is
// what the %w this replaced did.
func (e *instructionError) Unwrap() error { return e.Err }

func (vm *VM) runtimeErrorAt(ip int, op code.Opcode, err error) error {
	if err == nil {
		return nil
	}
	return &instructionError{IP: ip, Op: op, Err: err}
}

func (vm *VM) runtimeErrorfAt(ip int, op code.Opcode, format string, args ...interface{}) error {
	return vm.runtimeErrorAt(ip, op, fmt.Errorf(format, args...))
}

func (vm *VM) validateSecurityCheckOpcodes(stage string) error {
	if !vm.enforceSecurityCheckOpcodes {
		return nil
	}
	if vm.frameIndex == 0 {
		return nil
	}

	foundDbg, foundSnd, err := vm.scanSecurityCheckOpcodes()
	if err != nil {
		return err
	}

	if !foundDbg || !foundSnd {
		return fmt.Errorf("required security check opcodes missing %s: OpChkDbg=%t OpChkSnd=%t", stage, foundDbg, foundSnd)
	}

	return nil
}

func (vm *VM) scanSecurityCheckOpcodes() (bool, bool, error) {
	foundDbg := false
	foundSnd := false

	if vm.frameIndex > 0 {
		mainFoundDbg, mainFoundSnd, err := vm.scanInstructionsForSecurityCheckOpcodes(vm.currentFrame().Instructions())
		if err != nil {
			return false, false, err
		}
		foundDbg = foundDbg || mainFoundDbg
		foundSnd = foundSnd || mainFoundSnd
	}

	for _, constant := range vm.constants {
		compiledFn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}

		fnFoundDbg, fnFoundSnd, scanErr := vm.scanInstructionsForSecurityCheckOpcodes(compiledFn.Instructions)
		if scanErr != nil {
			return false, false, scanErr
		}
		foundDbg = foundDbg || fnFoundDbg
		foundSnd = foundSnd || fnFoundSnd
	}

	return foundDbg, foundSnd, nil
}

func (vm *VM) scanInstructionsForSecurityCheckOpcodes(ins code.Instructions) (bool, bool, error) {
	foundDbg := false
	foundSnd := false
	stream := vm.instructionStream()

	for i := 0; i < len(ins); {
		opcodeByte, err := stream.XOROneAt(ins[i], int64(i))
		if err != nil {
			return false, false, err
		}

		op := vm.decodeOpcode(opcodeByte)
		if op == code.OpChkDbg {
			foundDbg = true
		}
		if op == code.OpChkSnd {
			foundSnd = true
		}

		def, err := code.Lookup(byte(op))
		if err != nil {
			return false, false, err
		}

		next := 1
		for _, width := range def.OperandWidths {
			next += width
		}
		i += next
	}

	return foundDbg, foundSnd, nil
}

func (vm *VM) runIntegrityProbes() error {
	if vm.integrityEvery == 0 {
		return nil
	}

	// Deliberately no ensureFrameBoundaries call here. This runs before every
	// single opcode, and the only reader of the boundary map is
	// verifyFrameControlFlow, which ensures (and, on a miss, builds) its own --
	// so mapping here was both redundant and charged to every step.

	if vm.stepCount >= vm.nextIntegrityAt {
		if err := vm.verifyFrameControlFlow(vm.currentFrame(), "vm-cfi"); err != nil {
			return err
		}
		if err := vm.verifyCurrentFrameIntegrity(); err != nil {
			return err
		}
		vm.nextIntegrityAt = vm.stepCount + vm.nextProbeInterval()
	}

	if vm.stepCount >= vm.nextSweepAt {
		if err := vm.verifyFrameControlFlow(vm.currentFrame(), "vm-cfi-sweep"); err != nil {
			return err
		}
		if err := vm.verifyActiveFramesIntegrity(); err != nil {
			return err
		}
		vm.nextSweepAt = vm.stepCount + vm.nextSweepInterval()
	}

	return nil
}

// settleProgramResult puts the value of a top-level `return` where the rest of
// the runtime looks for a program's result.
//
// Returning from the outermost frame ends the program, and nothing pops after
// it -- so the returned value sat at stack[sp-1] while LastPoppedStackElement,
// which the CLI prints and the REPL echoes, reads stack[sp]. That slot still
// held whatever the last expression left behind, so `return 7;` at the top level
// printed a leftover comparison operand rather than 7. Which leftover it was
// depended on the exact instruction layout, which is how mutation could change a
// program's printed result without changing what the program did.
//
// Dropping the pointer by one is exactly what OpPop does, so the value lands in
// the slot everything already reads. Only the outermost frame is adjusted:
// CallClosureSync enters with a base frame of its own and pops its result from
// stack[sp-1], so a worker returning to it must be left alone.
func (vm *VM) settleProgramResult() {
	if vm.frameIndex == 0 && vm.stackPointer > 0 {
		vm.stackPointer--
	}
}

func (vm *VM) StackTop() object.Object {
	if vm.stackPointer == 0 {
		return nil
	}

	return vm.decryptForUse(vm.stack[vm.stackPointer-1])
}

// LastPoppedStackElement reports the value the program finished with: the slot
// just above the stack pointer, which the final OpPop vacated. It is what the
// CLI prints and what the REPL echoes.
//
// Unlike everything else that reads the stack, this one runs after execution has
// ended and outside the fault boundary -- runner, repl and webrepl call it on
// the way to printing a result, with no error return between here and the
// terminal. So an out-of-range read reports null rather than raising a fault: by
// this point the program has either already succeeded or already reported why it
// did not, and neither is improved by a panic on the way to printing it.
func (vm *VM) LastPoppedStackElement() object.Object {
	if vm.stackPointer < 0 || vm.stackPointer >= len(vm.stack) {
		return global.Null
	}
	return vm.decryptForUse(vm.stack[vm.stackPointer])
}

// constantAt reads the constant an operand pointed at. The index is only as
// trustworthy as the instruction stream it came out of, so it is bounded here
// the way OpGetBuiltin bounds its own index -- the two are the same kind of
// operand and were guarded inconsistently.
func (vm *VM) constantAt(index int) (object.Object, error) {
	if index < 0 || index >= len(vm.constants) {
		return nil, fmt.Errorf("constant index %d out of range, len=%d", index, len(vm.constants))
	}
	return vm.constants[index], nil
}

// constantString reads a constant an opcode requires to be a string: a struct or
// enum type name, a field name, an enum tag. what names the operand, so the
// error says which one of an instruction's several constants was wrong.
func (vm *VM) constantString(what string, index int) (*object.String, error) {
	constant, err := vm.constantAt(index)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	str, ok := vm.decryptForUse(constant).(*object.String)
	if !ok {
		return nil, fmt.Errorf("%s is not string at index=%d", what, index)
	}
	return str, nil
}

// freeCount reports how many values a closure captured, for an error message
// raised on the path where the closure itself may be missing.
func freeCount(cl *object.Closure) int {
	if cl == nil {
		return 0
	}
	return len(cl.Free)
}

func (vm *VM) pushClosure(constIndex, numFree int) error {
	constant, err := vm.constantAt(constIndex)
	if err != nil {
		return err
	}
	fun, ok := constant.(*object.CompiledFunction)
	if !ok {
		return fmt.Errorf("not a function: %+v", constant)
	}

	if numFree < 0 || vm.stackPointer-numFree < 0 {
		return fmt.Errorf("free-variable count %d reaches below the stack floor (sp=%d)", numFree, vm.stackPointer)
	}

	free := make([]object.Object, numFree)
	for i := 0; i < numFree; i++ {
		free[i] = vm.stack[vm.stackPointer-numFree+i]
	}
	vm.stackPointer = vm.stackPointer - numFree

	closure := &object.Closure{Fn: fun, Free: free}
	return vm.push(closure)
}

func (vm *VM) push(obj object.Object) error {
	vm.ensureStackCapacity(vm.stackPointer + 1)
	obj = vm.encryptForStorage(obj)

	vm.stack[vm.stackPointer] = obj
	vm.stackPointer++

	return nil
}

// pushStored puts on the stack a value that is already in storage form, which
// is what a stack slot, a global and a cell all hold.
//
// It is push(decryptForUse(obj)) with the two halves that cancel removed.
// decryptForUse opens the value and push seals the result with the same seed
// and the same password, so what lands on the stack is what it started as --
// and for a sealed value that round trip is two ChaCha20 passes and two
// allocations over the whole payload. Reading a 3 MiB buffer inside a loop
// spent two thirds of its time on it (M26-VM-001).
//
// A container moves this way too, and that is the case the sweep cares about:
// the example that failed its time limit keeps its 3 MiB buffer in a struct
// field, so the value being moved is a struct and the round trip was four
// passes over the buffer for every field read.
//
// For a container the stored object and the plaintext object are different
// objects, so this does make the slot and the stack entry one object. That is
// safe here, and the reason holds across the whole dispatch loop rather than
// case by case: *nothing in this VM mutates a container in storage form*. Every
// path that writes one opens it first -- execSetIndex and OpSetField both take
// their target from pop(), and opening rebuilds the container and every element
// in it -- so the write lands on a fresh copy and is stored back into the
// binding that asked for it. `let b = a; b[0] = 9;` leaves a alone because the
// write never touched the object a holds.
//
// The one place that writes a stored container in place is
// clearObjectSensitiveData, and it is the exception that has to be handled
// rather than waved through: a global is reachable from the stack's backing
// array once a value has been moved into it, so a wipe of the stack reaches a
// global. CleanupRuntimeSensitiveData therefore wipes the stack only when the
// globals go with it; see the comment there, and
// TestAGlobalSurvivesTheStackBeingReleased, which is the test this kit was
// missing. vm/stored_form_test.go holds the aliasing invariant itself.
func (vm *VM) pushStored(obj object.Object) error {
	vm.ensureStackCapacity(vm.stackPointer + 1)
	vm.stack[vm.stackPointer] = obj
	vm.stackPointer++
	return nil
}

// popStored takes the top of the stack in storage form: the mirror of
// pushStored, for the stores, which seal what pop has just opened.
func (vm *VM) popStored() object.Object {
	if vm.stackPointer <= 0 {
		faultf("stack underflow: pop with nothing on the stack")
	}

	obj := vm.stack[vm.stackPointer-1]
	vm.stackPointer--
	return obj
}

// pushGlobal is pushStored for a global, with the one case that has no storage
// form to hand on: the wrapper memory mode keeps a global as ciphertext bytes
// in a SecureGlobal rather than as an object, so there the value has to be
// opened and resealed as it always was.
func (vm *VM) pushGlobal(index int) error {
	if _, wrapped := vm.secureGlobals[index]; !wrapped && index >= 0 && index < len(vm.globals) {
		return vm.pushStored(vm.globals[index])
	}
	return vm.push(vm.getGlobal(index))
}

// setGlobalStored stores into a global a value that is already in storage form:
// pushGlobal's mirror, and the other half of not opening a value that is only
// moving. setGlobal(pop()) opened the top of the stack and sealed it again with
// the same key, which is the same identity round trip in the other direction.
//
// The wrapper memory mode is the one case that cannot take it, for the reason
// pushGlobal has: a SecureGlobal holds ciphertext bytes it produces itself,
// from a value in the clear, so there the stack's value is opened as it always
// was. The SecureGlobal a non-wrapper store replaces is still cleared, because
// a global that has been one keeps its wrapper until something overwrites it.
func (vm *VM) setGlobalStored(index int) {
	if vm.useWrapperGlobals() {
		vm.setGlobal(index, vm.pop())
		return
	}

	if previous, ok := vm.secureGlobals[index]; ok {
		previous.Clear()
		delete(vm.secureGlobals, index)
	}
	vm.globals[index] = vm.popStored()
}

// pop takes the top of the stack. An empty stack is a fault rather than an
// error return: pop is called from more than twenty places in the dispatch
// switch, and it cannot happen for bytecode this toolchain produced. See
// vm/fault.go for why that is a panic and where it is caught.
func (vm *VM) pop() object.Object {
	if vm.stackPointer <= 0 {
		faultf("stack underflow: pop with nothing on the stack")
	}

	obj := vm.decryptForUse(vm.stack[vm.stackPointer-1])

	vm.stackPointer--
	return obj
}

// bitwiseOperatorSymbol maps a bitwise opcode back to its source spelling.
//
// The VM does not compute bitwise results itself: it hands the spelling and the
// two int64s to object.BitwiseInfix, which is the function the evaluator and the
// WASM REPL call. The arithmetic opcodes are each a single Go operator with no
// guard worth sharing, so they stay inline; the bitwise ones carry a negative-
// shift check that has to answer the same way in all three engines, and one
// implementation is the only way to be sure it does.
var bitwiseOperatorSymbol = map[code.Opcode]string{
	code.OpBitAnd:     "&",
	code.OpBitOr:      "|",
	code.OpBitXor:     "^",
	code.OpShiftLeft:  "<<",
	code.OpShiftRight: ">>",
}

func (vm *VM) execBinaryOperation(op code.Opcode) error {
	right := vm.pop()
	left := vm.pop()

	rtype := right.Type()
	ltype := left.Type()

	// Bitwise operands are checked before the type dispatch below, not inside
	// the integer path: a FLOAT would otherwise reach execBinaryFloatOperation
	// and be turned away as an unknown float operator, which is not what went
	// wrong. `1.5 & 1` is a type error, and it should say so.
	if sym, ok := bitwiseOperatorSymbol[op]; ok {
		if ltype != object.INTEGER_OBJ || rtype != object.INTEGER_OBJ {
			return fmt.Errorf("%s", object.BitwiseOperandError(sym, left, right).Message)
		}
	}

	if rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ {
		return vm.execBinaryIntegerOperation(op, left, right)
	}

	switch {
	case rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ:
		return vm.execBinaryIntegerOperation(op, left, right)
	case rtype == object.STRING_OBJ && ltype == object.STRING_OBJ:
		return vm.execBinaryStringOperation(op, left, right)
	case rtype == object.BYTES_OBJ && ltype == object.BYTES_OBJ:
		return vm.execBinaryBytesOperation(op, left, right)
	}

	ans1 := mutil.AssertObjectTypes(string(rtype), object.INTEGER_OBJ, object.FLOAT_OBJ)
	ans2 := mutil.AssertObjectTypes(string(ltype), object.INTEGER_OBJ, object.FLOAT_OBJ)
	if ans1 && ans2 {
		return vm.execBinaryFloatOperation(op, left, right)
	}

	opName := fmt.Sprintf("opcode_%d", op)
	if def, err := code.Lookup(byte(op)); err == nil {
		opName = def.Name
	}
	ip := -1
	if frame := vm.currentFrame(); frame != nil {
		ip = frame.ip
	}
	return fmt.Errorf("%s at ip=%d: unsupported types for binary operation: %s, %s", opName, ip, ltype, rtype)
}

func (vm *VM) execBinaryIntegerOperation(op code.Opcode, left, right object.Object) error {
	rval := right.(*object.Integer).Value
	lval := left.(*object.Integer).Value

	if sym, ok := bitwiseOperatorSymbol[op]; ok {
		bits := object.BitwiseInfix(sym, lval, rval)
		if e, ok := bits.(*object.Error); ok {
			return fmt.Errorf("%s", e.Message)
		}
		return vm.push(bits)
	}

	var result int64

	switch op {
	case code.OpAdd:
		result = lval + rval
	case code.OpSub:
		result = lval - rval
	case code.OpMul:
		result = lval * rval
	case code.OpDiv:
		if rval == 0 {
			return fmt.Errorf("integer division by zero")
		}
		result = lval / rval
	case code.OpMod:
		if rval == 0 {
			return fmt.Errorf("integer modulo by zero")
		}
		result = lval % rval
	default:
		return fmt.Errorf("Unknown integer operator: %d", op)
	}

	return vm.push(&object.Integer{Value: result})
}

func getFloatVal(obj object.Object) float64 {
	if obj.Type() == object.INTEGER_OBJ {
		val := obj.(*object.Integer).Value
		return float64(val)
	}
	return obj.(*object.Float).Value
}
func (vm *VM) execBinaryFloatOperation(op code.Opcode, left, right object.Object) error {
	rval := getFloatVal(right)
	lval := getFloatVal(left)
	var result float64

	switch op {
	case code.OpAdd:
		result = lval + rval
	case code.OpSub:
		result = lval - rval
	case code.OpMul:
		result = lval * rval
	case code.OpDiv:
		result = lval / rval
	case code.OpMod:
		result = math.Mod(lval, rval)
	default:
		return fmt.Errorf("Unknown float operator: %d", op)
	}

	return vm.push(&object.Float{Value: result})
}

func (vm *VM) execBinaryStringOperation(op code.Opcode, left, right object.Object) error {
	rval := right.(*object.String).Value
	lval := left.(*object.String).Value

	if op != code.OpAdd {
		return fmt.Errorf("Unknown string operator: %d", op)
	}

	return vm.push(&object.String{Value: lval + rval})
}

// execSetIndex mutates a container in place for `container[index] = value` and
// returns the (same) container so the caller can persist it to its variable slot.
// execBinaryBytesOperation concatenates two buffers. Bytes deliberately support
// no other operator: subtraction and division of buffers mean nothing, and the
// alternative to refusing them is inventing a semantic nobody asked for.
//
// The result is a fresh buffer rather than an append onto the left operand,
// because `a + b` must not mutate `a` -- append would when a has spare capacity.
func (vm *VM) execBinaryBytesOperation(op code.Opcode, left, right object.Object) error {
	if op != code.OpAdd {
		return fmt.Errorf("unknown bytes operator: %d", op)
	}

	lbuf := left.(*object.Bytes)
	rbuf := right.(*object.Bytes)

	joined := make([]byte, 0, len(lbuf.Value)+len(rbuf.Value))
	joined = append(joined, lbuf.Value...)
	joined = append(joined, rbuf.Value...)

	// Classified plaintext joined to anything is still classified plaintext;
	// see object.JoinClassification.
	return vm.push(&object.Bytes{Value: joined,
		Classified: object.JoinClassification(lbuf.Classified, rbuf.Classified)})
}

func (vm *VM) execSetIndex(container, index, value object.Object) (object.Object, error) {
	switch c := container.(type) {
	case *object.Array:
		idx, ok := index.(*object.Integer)
		if !ok {
			return nil, fmt.Errorf("array index must be INTEGER, got %s", index.Type())
		}
		if idx.Value < 0 || idx.Value >= int64(len(c.Elements)) {
			return nil, fmt.Errorf("array index out of bounds: %d (len %d)", idx.Value, len(c.Elements))
		}
		c.Elements[idx.Value] = value
		return c, nil
	case *object.Bytes:
		idx, ok := index.(*object.Integer)
		if !ok {
			return nil, fmt.Errorf("bytes index must be INTEGER, got %s", index.Type())
		}
		if idx.Value < 0 || idx.Value >= int64(len(c.Value)) {
			return nil, fmt.Errorf("bytes index out of bounds: %d (len %d)", idx.Value, len(c.Value))
		}
		// A buffer holds bytes, so the only thing that can be stored in one is a
		// value that is a byte. Truncating a larger integer silently would make
		// b[0] = 256 write a zero.
		val, ok := value.(*object.Integer)
		if !ok {
			return nil, fmt.Errorf("bytes element must be INTEGER, got %s", value.Type())
		}
		if val.Value < 0 || val.Value > 255 {
			return nil, fmt.Errorf("bytes element out of range: %d (want 0-255)", val.Value)
		}
		c.Value[idx.Value] = byte(val.Value)
		return c, nil
	case *object.Hash:
		hashKey, ok := index.(object.Hashable)
		if !ok {
			return nil, fmt.Errorf("unusable as a hashkey: %s", index.Type())
		}
		if c.Pairs == nil {
			c.Pairs = make(map[object.HashKey]object.HashPair)
		}
		c.Pairs[hashKey.HashKey()] = object.HashPair{Key: index, Value: value}
		return c, nil
	default:
		return nil, fmt.Errorf("index assignment not supported on %s", container.Type())
	}
}

func (vm *VM) execIndexOperation(left, index object.Object) error {
	switch {
	case left.Type() == object.ARRAY_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execArrayIndex(left, index)
	case left.Type() == object.MULTI_VALUE_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execMultiValueIndex(left, index)
	case left.Type() == object.STRING_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execStringIndex(left, index)
	case left.Type() == object.BYTES_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execBytesIndex(left, index)
	case left.Type() == object.HASH_OBJ:
		return vm.execHashIndex(left, index)
	case left.Type() == object.ERROR_OBJ && index.Type() == object.STRING_OBJ:
		return vm.execErrorField(left, index)
	default:
		return fmt.Errorf("index operator not supported: %s", left.Type())
	}
}

// execErrorField reads err["message"] through the same table err.message reads,
// so the two spellings cannot disagree. An unknown name is null, not a fault.
func (vm *VM) execErrorField(errObj, index object.Object) error {
	val, ok := errObj.(*object.Error).Field(index.(*object.String).Value)
	if !ok {
		return vm.push(global.Null)
	}
	return vm.push(val)
}

func (vm *VM) execMultiValueIndex(multiValue, index object.Object) error {
	multi := multiValue.(*object.MultiValue)
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(multi.Values))
	if !ok {
		return vm.push(global.Null)
	}
	return vm.push(multi.Values[at])
}

// execStringIndex yields the rune at i as a one-rune string.
//
// By rune, not by byte, because that is what every other string operation here
// means: the for-in iterator, str_char_at, str_substr and str_reverse all work in
// runes, and object.NewIterator's comment says why. Indexing by byte did not even
// return the byte -- Go converts a byte to the rune of that number, so byte 0xc3
// came back as U+00C3, a character the string does not contain.
//
// Both rules are object.RuneAt's; see the head of object/index.go.
func (vm *VM) execStringIndex(str, index object.Object) error {
	char, ok := object.RuneAt(str.(*object.String).Value, index.(*object.Integer).Value)
	if !ok {
		return vm.push(global.Null)
	}
	return vm.push(&object.String{Value: char})
}

// execBytesIndex yields the byte at i as an INTEGER 0-255.
//
// This is where bytes deliberately part company with strings, which yield a
// one-character string. A buffer is indexed to compare a value -- b[0] == 0x4d
// -- and returning a one-byte buffer would make every such test go through a
// conversion. Negative indices count from the end, as they do everywhere else.
func (vm *VM) execBytesIndex(buf, index object.Object) error {
	data := buf.(*object.Bytes).Value
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(data))
	if !ok {
		return vm.push(global.Null)
	}
	return vm.push(&object.Integer{Value: int64(data[at])})
}

func (vm *VM) execArrayIndex(array, index object.Object) error {
	elements := array.(*object.Array).Elements
	at, ok := object.IndexOf(index.(*object.Integer).Value, len(elements))
	if !ok {
		return vm.push(global.Null)
	}
	return vm.push(elements[at])
}

func (vm *VM) execHashIndex(hash, index object.Object) error {
	hashObj := hash.(*object.Hash)

	key, ok := index.(object.Hashable)
	if !ok {
		return fmt.Errorf("unusable as hash key: %s", index.Type())
	}

	pair, ok := hashObj.Pairs[key.HashKey()]
	if !ok {
		return vm.push(global.Null)
	}

	return vm.push(pair.Value)
}

// execBangOperation pushes the negation of the operand's truthiness, which is what
// `!` means.
//
// It used to switch on pointer identity against global.True, global.False and
// global.Null, and push False for anything else. Those three are the only values
// such a rule can see, so the four falsy values that are not singletons -- 0, 0.0,
// "" and an empty buffer -- came back false, the same answer as !true. 0 was falsy
// and !0 was falsy, so `if (x)` and `if (!x)` both skipped their branch and `!!x`
// was not `x` (M26-VM-007).
//
// Identity was not the fault, and that is worth recording because it looks like it
// was. A false held in a variable, an array element, a hash value or a parameter
// still arrives here as global.False: the pointer survives encryptForStorage,
// mutil.EncryptObject in the global store, and decryptForUse on the way back. That
// was measured, not assumed, and TestBangIsRightWhereverTheValueCameFrom keeps it
// measured. The fault was a default arm standing in for a rule, and object.IsTruthy
// is the rule.
func (vm *VM) execBangOperation() error {
	return vm.push(nativeBoolToBooleanObject(!object.IsTruthy(vm.pop())))
}

func (vm *VM) execMinusOperation() error {
	operand := vm.pop()
	assertion := mutil.AssertObjectTypes(string(operand.Type()), object.INTEGER_OBJ, object.FLOAT_OBJ)
	if !assertion {
		return fmt.Errorf("unsupported object type for negation: %s", operand.Type())
	}

	switch operand.Type() {
	case object.INTEGER_OBJ:
		value := operand.(*object.Integer).Value
		return vm.push(&object.Integer{Value: -value})
	case object.FLOAT_OBJ:
		value := operand.(*object.Float).Value
		return vm.push(&object.Float{Value: -value})
	}

	return fmt.Errorf("unknown object: %s", operand.Type())
}

// execBitNotOperation evaluates `~x`. Like the binary bitwise operators it
// defers to object, so the complement and the message it refuses non-integers
// with are written once.
func (vm *VM) execBitNotOperation() error {
	operand := vm.pop()

	result := object.BitwiseNot(operand)
	if e, ok := result.(*object.Error); ok {
		return fmt.Errorf("%s", e.Message)
	}
	return vm.push(result)
}

func (vm *VM) execComparison(op code.Opcode) error {
	right := vm.pop()
	left := vm.pop()

	if left.Type() == object.INTEGER_OBJ && right.Type() == object.INTEGER_OBJ {
		return vm.execIntegerComparison(op, left, right)
	}

	rtype := right.Type()
	ltype := left.Type()
	ans1 := mutil.AssertObjectTypes(string(rtype), object.INTEGER_OBJ, object.FLOAT_OBJ)
	ans2 := mutil.AssertObjectTypes(string(ltype), object.INTEGER_OBJ, object.FLOAT_OBJ)
	if ans1 && ans2 {
		return vm.execFloatComparison(op, left, right)
	}

	// The fallback below compares rendered forms, and Bytes renders as hex, so
	// without this a buffer would equal the string spelling its own hex.
	if ltype == object.BYTES_OBJ || rtype == object.BYTES_OBJ {
		return vm.execBytesComparison(op, left, right)
	}

	// Errors are compared before the fallback too, and for a sharper reason:
	// the fallback compares Inspect, Inspect renders the position, and only
	// this engine stamps one. Comparing rendered errors would make equality an
	// artefact of which engine ran the program.
	if ltype == object.ERROR_OBJ || rtype == object.ERROR_OBJ {
		return vm.execErrorComparison(op, left, right)
	}

	// Enum values, for the same reason as bytes: the fallback compares
	// rendered forms, an enum renders as `Status.Ok(0)`, and a string spelling
	// that text would otherwise compare equal to the variant. `match` makes
	// that reachable in a way plain `==` rarely was.
	if ltype == object.ENUM_VALUE_OBJ || rtype == object.ENUM_VALUE_OBJ {
		return vm.execEnumComparison(op, left, right)
	}

	// Structs, for the same reason again and with the sharpest edge of the
	// four: a struct renders as `P { b: 2, a: 1 }`, so under the fallback the
	// string spelling that text was equal to the record itself -- and until
	// Inspect was given an order, the fallback could not even answer that two
	// structs built from one literal were equal.
	if ltype == object.STRUCT_OBJ || rtype == object.STRUCT_OBJ {
		return vm.execStructComparison(op, left, right)
	}

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() == left.Inspect()))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() != left.Inspect()))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

// execEnumComparison decides equality for any comparison with an enum value on
// either side. Two variants are equal when they are the same variant of the
// same enum, and an enum value is never equal to a value of another type --
// whatever it renders as.
//
// Ordering is undefined, as it is for bytes and errors: a variant's ordinal
// exists to identify it, and reading `Status.Ok < Status.Failed` as a fact
// about severity is the kind of meaning a declaration order should not
// silently acquire.
func (vm *VM) execEnumComparison(op code.Opcode, left, right object.Object) error {
	leftEnum, leftOK := left.(*object.EnumValue)
	rightEnum, rightOK := right.(*object.EnumValue)
	equal := leftOK && rightOK &&
		leftEnum.TypeName == rightEnum.TypeName &&
		leftEnum.Tag == rightEnum.Tag

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(equal))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(!equal))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

// execStructComparison decides equality for any comparison with a struct on
// either side. Two structs are equal when they are the same type and hold an
// equal value under every field name; a struct is never equal to a value of
// another type, whatever it renders as.
//
// Structs used to reach the Inspect fallback, and Inspect ranged a Go map.
// Ranging a map yields a different order on every call -- not merely on every
// run -- so two structs built from the same literal were usually unequal, and a
// struct was usually unequal to itself. Giving Inspect a declaration order
// settles what is printed. It does not make a render the right thing to
// compare, for exactly the reason it is not for bytes, errors and enum values.
//
// Ordering is undefined, as it is for those three. The operand domains behind
// the analyzer's diagnostics are derived from these functions, and `<` on two
// records has no meaning worth inventing here.
func (vm *VM) execStructComparison(op code.Opcode, left, right object.Object) error {
	leftStruct, leftOK := left.(*object.Struct)
	rightStruct, rightOK := right.(*object.Struct)
	equal := leftOK && rightOK && leftStruct.Equals(rightStruct)

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(equal))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(!equal))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

// execErrorComparison decides equality for any comparison with an error on
// either side. Only two errors can be equal; an error is never equal to a value
// of another type, whatever it renders as.
//
// Ordering is undefined, as it is for bytes: `<` on two errors has no meaning
// worth inventing, and the operand domains the analyzer derives from this
// function are what its diagnostics are built on.
func (vm *VM) execErrorComparison(op code.Opcode, left, right object.Object) error {
	leftErr, leftOK := left.(*object.Error)
	rightErr, rightOK := right.(*object.Error)
	equal := leftOK && rightOK && leftErr.Equals(rightErr)

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(equal))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(!equal))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

// execBytesComparison decides equality for any comparison with a bytes on
// either side. Only two buffers can be equal: a bytes is never equal to a value
// of another type, whatever it renders as.
//
// Ordering is not defined. `<` on two buffers has an obvious lexicographic
// answer, but the operand domains the analyzer derives from this function are
// what its diagnostics are built on, so widening the operator set is a language
// decision rather than a convenience.
func (vm *VM) execBytesComparison(op code.Opcode, left, right object.Object) error {
	leftBytes, leftOK := left.(*object.Bytes)
	rightBytes, rightOK := right.(*object.Bytes)
	equal := leftOK && rightOK && bytes.Equal(leftBytes.Value, rightBytes.Value)

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(equal))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(!equal))
	default:
		return fmt.Errorf("unknown operator: %d (%s %s)", op, left.Type(), right.Type())
	}
}

func (vm *VM) execFloatComparison(op code.Opcode, left, right object.Object) error {
	leftValue := getFloatVal(left)
	rightValue := getFloatVal(right)
	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue == leftValue))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue != leftValue))
	case code.OpGreater:
		return vm.push(nativeBoolToBooleanObject(leftValue > rightValue))
	case code.OpGreaterEqual:
		return vm.push(nativeBoolToBooleanObject(leftValue >= rightValue))
	default:
		return fmt.Errorf("unknown operator: %d", op)
	}
}
func (vm *VM) execIntegerComparison(op code.Opcode, left, right object.Object) error {
	leftValue := left.(*object.Integer).Value
	rightValue := right.(*object.Integer).Value
	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue == leftValue))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(rightValue != leftValue))
	case code.OpGreater:
		return vm.push(nativeBoolToBooleanObject(leftValue > rightValue))
	case code.OpGreaterEqual:
		return vm.push(nativeBoolToBooleanObject(leftValue >= rightValue))
	default:
		return fmt.Errorf("unknown operator: %d", op)
	}
}

func (vm *VM) buildArray(startIndex, endIndex int) object.Object {
	elements := make([]object.Object, endIndex-startIndex)
	for i := startIndex; i < endIndex; i++ {
		elements[i-startIndex] = vm.decryptForUse(vm.stack[i])
	}
	return &object.Array{Elements: elements}
}

// buildInterpolation joins the pieces of a string literal's holes and text
// into the one string they spell.
//
// A piece that is already a string contributes its own text; anything else
// contributes what it would print. There is no conversion to fail and no
// protocol for a value to implement, because a value this language can print
// is a value it can interpolate.
func (vm *VM) buildInterpolation(startIndex, endIndex int) object.Object {
	var out strings.Builder
	for i := startIndex; i < endIndex; i++ {
		piece := vm.decryptForUse(vm.stack[i])
		if piece == nil {
			continue
		}
		if str, isString := piece.(*object.String); isString {
			out.WriteString(str.Value)
			continue
		}
		out.WriteString(piece.Inspect())
	}
	return &object.String{Value: out.String()}
}

func (vm *VM) buildMultiValue(startIndex, endIndex int) object.Object {
	values := make([]object.Object, endIndex-startIndex)
	for i := startIndex; i < endIndex; i++ {
		values[i-startIndex] = vm.decryptForUse(vm.stack[i])
	}
	return &object.MultiValue{Values: values}
}

func (vm *VM) destructureValues(source object.Object, arity int) []object.Object {
	values := make([]object.Object, arity)
	for i := range values {
		values[i] = global.Null
	}

	switch obj := source.(type) {
	case *object.MultiValue:
		for i := 0; i < arity && i < len(obj.Values); i++ {
			if obj.Values[i] != nil {
				values[i] = obj.Values[i]
			}
		}
	case *object.Array:
		for i := 0; i < arity && i < len(obj.Elements); i++ {
			if obj.Elements[i] != nil {
				values[i] = obj.Elements[i]
			}
		}
	default:
		if arity > 0 && source != nil {
			values[0] = source
		}
	}

	return values
}

func (vm *VM) buildHash(startIndex, endIndex int) (object.Object, error) {
	hashedPairs := make(map[object.HashKey]object.HashPair)
	for i := startIndex; i < endIndex; i += 2 {
		key := vm.decryptForUse(vm.stack[i])
		value := vm.decryptForUse(vm.stack[i+1])

		pair := object.HashPair{Key: key, Value: value}
		hashKey, ok := key.(object.Hashable)
		if !ok {
			return nil, fmt.Errorf("unusable as a hashkey: %s", key.Type())
		}
		hashedPairs[hashKey.HashKey()] = pair
	}
	return &object.Hash{Pairs: hashedPairs}, nil
}

func (vm *VM) currentFrame() *Frame {
	if vm.frameIndex <= 0 {
		faultf("frame underflow: no frame is executing")
	}
	return vm.frames[vm.frameIndex-1]
}

// pushFrame enters a frame, or refuses to because the call would be too deep.
//
// The refusal belongs here rather than in callClosure because this is the only
// place a frame is entered. OpCall reaches it through callClosure and so does
// CallClosureSync, the bridge the executor-native builtins call a closure through,
// so one check bounds both -- and a path added later is bounded without having to
// be told. Counting frames rather than calls is deliberate: a program that calls a
// function sixty thousand times in a loop is ordinary, and a program with ten
// thousand calls open at once is not.
func (vm *VM) pushFrame(f *Frame) error {
	if vm.frameIndex >= maxCallDepth {
		return fmt.Errorf("this call would be %d deep, over the limit of %d nested calls",
			vm.frameIndex+1, maxCallDepth)
	}
	vm.ensureFrameCapacity(vm.frameIndex + 1)
	vm.frames[vm.frameIndex] = f
	vm.frameIndex++
	if f != nil && f.cl != nil && f.cl.Fn != nil {
		vm.registerFrameIntegrity(f.cl.Fn)
	}
	return nil
}
func (vm *VM) popFrame() *Frame {
	if vm.frameIndex <= 0 {
		faultf("frame underflow: returning from no frame")
	}
	vm.frameIndex--
	return vm.frames[vm.frameIndex]
}

func (vm *VM) execCall(numArgs int) error {
	// numArgs arrives as an instruction operand, so it decides how far below the
	// stack pointer the callee sits. A corrupted one reaches past the floor.
	calleeIndex := vm.stackPointer - 1 - numArgs
	if numArgs < 0 || calleeIndex < 0 || calleeIndex >= len(vm.stack) {
		return fmt.Errorf("call with %d arguments reaches outside the stack (sp=%d)", numArgs, vm.stackPointer)
	}

	// What stood here fell back to vm.stack[0] whenever the slot held anything
	// that was not callable, so calling a non-function did not fail: it called
	// whatever sat at the bottom of the stack, which is usually the function
	// currently running or the first builtin the top-level statement pushed. A
	// dispatch table with no entry for the value it was keyed on therefore
	// re-invoked its own caller and handed back that result, with nothing
	// reported anywhere. When that result was the caller itself the program did
	// not merely answer wrongly -- it recursed until something stopped it, and
	// the frame-integrity probe walks every active frame, so what stopped it
	// was the clock. Only when stack[0] happened not to be callable either did
	// the program get the refusal it should always have had. (M26-VM-003)
	//
	// The callee is read raw, and the raw slot is what gets called. A callable
	// is never stored encrypted -- EncryptObject has no arm for a closure or a
	// builtin -- and this switch is the same test the fallback's own condition
	// made, so a working call pays nothing here and callClosure still receives
	// the closure that is on the stack. Decrypting first would not: the
	// CLOSURE_OBJ arm of DecryptObject rebuilds the closure around a fresh Free
	// slice, which is both a copy per call and a second decryption of every
	// free variable that OpGetFree decrypts again where it reads it.
	switch callee := vm.stack[calleeIndex].(type) {
	case *object.Closure:
		return vm.callClosure(callee, numArgs)
	case *builtin.BuiltIn:
		return vm.callBuiltin(callee, numArgs)
	}

	// Not callable, so the only thing left to do is say what it was.
	//
	// A slot below the stack pointer can still be nil: callClosure raises the
	// pointer over a frame's locals without writing them.
	at := vm.stack[calleeIndex]
	if at == nil {
		return fmt.Errorf("calling non-function and non-built-in: the callee slot holds nothing")
	}

	// Decrypted here and nowhere else. A scalar on the stack is stored
	// encrypted, so the raw slot reports ENCRYPTED where the author wrote an
	// integer, and naming the stack's word instead of the program's would make
	// the message useless to the person who has to fix the call.
	return fmt.Errorf("calling non-function and non-built-in: %s", vm.decryptForUse(at).Type())
}

func (vm *VM) callClosure(cl *object.Closure, numArgs int) error {
	if numArgs != cl.Fn.NumParams {
		return fmt.Errorf("wrong number of arguments. want=%d, got=%d", cl.Fn.NumParams, numArgs)
	}

	frame := NewFrame(cl, vm.stackPointer-numArgs)
	// Nothing is half-done when this fails: the frame was built but not entered and
	// the stack pointer has not moved, so the error unwinds exactly like a wrong-arity
	// one, and CallClosureSync's own restore puts a native re-entry back as it was.
	if err := vm.pushFrame(frame); err != nil {
		return err
	}
	vm.ensureStackCapacity(frame.bp + cl.Fn.NumLocals)
	vm.stackPointer = frame.bp + cl.Fn.NumLocals
	// Before boxing, so a captured local starts its cell empty rather than
	// holding whatever the previous frame left in that slot.
	if vm.debug != nil {
		vm.clearUnsetLocals(frame, cl.Fn)
	}
	vm.boxCapturedSlots(frame, cl.Fn)
	return nil
}

// boxCapturedSlots replaces the frame slots an inner function closes over with
// cells, so a write through the closure and a write through the frame land in
// the same place.
//
// It runs after the arguments are already at their slots, which is the whole
// reason a captured *parameter* needs no special case: slot i holds argument i,
// and boxing it wraps the value that is already there. Slots above the
// parameters have not been written yet -- a `let` always precedes any use of the
// name it binds -- so they are boxed around Null rather than around whatever the
// previous frame left on the stack.
//
// One cell per slot per frame, which is also the tree-walking evaluator's
// scoping: it makes one environment per call and one per loop, not one per
// iteration, so two closures made in different turns of the same loop share a
// variable in both engines.
func (vm *VM) boxCapturedSlots(frame *Frame, fn *object.CompiledFunction) {
	for _, index := range fn.CapturedLocals {
		slot := frame.bp + index
		if slot < 0 || slot >= len(vm.stack) {
			continue
		}
		if index < fn.NumParams {
			vm.stack[slot] = &object.Cell{Value: vm.stack[slot]}
			continue
		}
		vm.stack[slot] = &object.Cell{Value: global.Null}
	}
}

// CallClosureSync runs a Mutant closure to completion from Go and returns its
// result. It is the closure-from-builtin bridge that powers the VM-native
// higher-order operations (map/filter/reduce/each/sort_by). It lays out the call
// on the stack exactly as OpCall does (callee then args), enters the closure
// frame via the normal callClosure path (so frame-integrity registration and the
// per-instruction security probes all apply), and re-runs the execution loop
// bounded to that single frame. On any failure the frame and stack pointers are
// restored to their pre-call state so the outer run is unaffected.
//
// It runs on the calling VM's own goroutine (a builtin invoked by execLoop runs
// synchronously), so it needs no cross-goroutine routing and is safe under
// concurrent VMs (e.g. net_serve handlers): each VM only ever re-enters itself.
func (vm *VM) CallClosureSync(cl *object.Closure, args []object.Object) (result object.Object, err error) {
	baseFrameIndex := vm.frameIndex
	baseStackPointer := vm.stackPointer

	defer func() {
		if err != nil {
			if vm.frameIndex > baseFrameIndex {
				vm.frameIndex = baseFrameIndex
			}
			vm.stackPointer = baseStackPointer
		}
	}()

	if err = vm.push(cl); err != nil { // callee slot (consumed on return)
		return nil, err
	}
	for _, a := range args {
		if err = vm.push(a); err != nil {
			return nil, err
		}
	}
	if err = vm.callClosure(cl, len(args)); err != nil {
		return nil, err
	}
	if err = vm.execLoop(baseFrameIndex); err != nil {
		return nil, err
	}

	// OpReturnValue left the result where the callee was, one slot above base.
	if vm.stackPointer <= baseStackPointer {
		return global.Null, nil
	}
	return vm.pop(), nil
}

func (vm *VM) registerFrameIntegrity(fn *object.CompiledFunction) {
	if vm.frameIntegrity == nil {
		vm.frameIntegrity = make(map[*object.CompiledFunction][32]byte)
	}
	if _, exists := vm.frameIntegrity[fn]; !exists {
		vm.frameIntegrity[fn] = sha256.Sum256(fn.Instructions)
	}
	if vm.frameBoundaries == nil {
		vm.frameBoundaries = make(map[*object.CompiledFunction]map[int]struct{})
	}
	if vm.password != "" {
		if _, exists := vm.frameBoundaries[fn]; !exists {
			vm.frameBoundaries[fn] = vm.buildInstructionBoundaries(fn.Instructions)
		}
	}
}

func (vm *VM) verifyCurrentFrameIntegrity() error {
	frame := vm.currentFrame()
	return vm.verifyFrameIntegrity(frame, "vm-frame")
}

func (vm *VM) verifyActiveFramesIntegrity() error {
	for i := 0; i < vm.frameIndex; i++ {
		if err := vm.verifyFrameControlFlow(vm.frames[i], "vm-cfi-sweep"); err != nil {
			return err
		}
		if err := vm.verifyFrameIntegrity(vm.frames[i], "vm-frame-sweep"); err != nil {
			return err
		}
	}

	return nil
}

func (vm *VM) verifyFrameIntegrity(frame *Frame, stage string) error {
	if frame == nil || frame.cl == nil || frame.cl.Fn == nil {
		return nil
	}

	fn := frame.cl.Fn
	expected, exists := vm.frameIntegrity[fn]
	if !exists {
		vm.registerFrameIntegrity(fn)
		expected = vm.frameIntegrity[fn]
	}

	actual := sha256.Sum256(fn.Instructions)
	if !security.SecureCompare(expected[:], actual[:]) {
		security.RecordIntegrityFailure(stage)
		return security.ApplyTamperResponse("integrity_failed", stage, vm.secureMode, fmt.Errorf("runtime integrity check failed"))
	}

	return nil
}

func (vm *VM) callBuiltin(bi *builtin.BuiltIn, numArgs int) error {
	// Some builtins need something only the VM has -- the ability to call a user
	// closure, or the running program's serve context -- so the VM runs them
	// itself rather than invoking the registered Fn.
	if kind := builtin.ExecutorNativeKind(bi); kind != "" {
		return vm.callExecutorNative(kind, numArgs)
	}

	storedArgs := vm.stack[vm.stackPointer-numArgs : vm.stackPointer]
	args := make([]object.Object, len(storedArgs))
	for i, arg := range storedArgs {
		args[i] = vm.decryptForUse(arg)
	}
	rawResult := bi.Fn(args...)
	result := rawResult
	if result == nil {
		result = global.Null
	}
	result = vm.decorateError(result)

	vm.stackPointer = vm.stackPointer - numArgs - 1

	vm.push(result)

	return nil
}

// callExecutorNative gathers the builtin's arguments and dispatches to the
// VM-native implementation, which is free to drive user closures via
// CallClosureSync and to read the VM's own state.
func (vm *VM) callExecutorNative(kind string, numArgs int) error {
	storedArgs := vm.stack[vm.stackPointer-numArgs : vm.stackPointer]
	args := make([]object.Object, len(storedArgs))
	for i, arg := range storedArgs {
		args[i] = vm.decryptForUse(arg)
	}
	result, err := vm.applyExecutorNative(kind, args)
	if err != nil {
		return err
	}
	if result == nil {
		result = global.Null
	}
	result = vm.decorateError(result)
	vm.stackPointer = vm.stackPointer - numArgs - 1
	return vm.push(result)
}

func nativeBoolToBooleanObject(native bool) *object.Boolean {
	if native {
		return global.True
	}
	return global.False
}
