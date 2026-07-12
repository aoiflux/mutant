package vm

import (
	"crypto/sha256"
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

	enforceSecurityCheckOpcodes bool
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
	initialFrameCapacity   = global.MaxFrames
	integritySweepBase     = uint64(251)
	integritySweepSpread   = uint64(83)
	integrityProbeSpread   = uint64(31)

	vMGlobalMemoryModeEnv = "MUTANT_VM_GLOBAL_MEMORY_MODE"
	vMMemoryModeRuntime   = "runtime"
	vMMemoryModeWrapper   = "wrapper"
)

func resolveVMGlobalMemoryMode() string {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(vMGlobalMemoryModeEnv)))
	switch raw {
	case vMMemoryModeWrapper:
		return vMMemoryModeWrapper
	case vMMemoryModeRuntime, "":
		return vMMemoryModeRuntime
	default:
		return vMMemoryModeRuntime
	}
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
	mainfn := &object.CompiledFunction{Instructions: mainInstructions}
	frames := make([]*Frame, initialFrameCapacity)

	mainClosure := &object.Closure{Fn: mainfn}
	mainFrame := NewFrame(mainClosure, 0)
	frames[0] = mainFrame

	frameIntegrity := make(map[*object.CompiledFunction][32]byte)
	frameIntegrity[mainfn] = sha256.Sum256(mainfn.Instructions)
	integritySeed := deriveIntegritySeed(mainInstructions)

	vm := &VM{
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
	return vm
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
	encObj, err := mutil.EncryptObject(obj, vm.inslen, vm.password)
	if err == nil {
		return encObj
	}
	return obj
}

func (vm *VM) decryptForUse(obj object.Object) object.Object {
	decObj, err := mutil.DecryptObject(obj, vm.inslen, vm.password)
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
	for i := range vm.stack {
		vm.clearObjectSensitiveData(vm.stack[i])
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
	vm.stripEncryptedPolymorphicMarker()
	vm.secureMode = secureMode
	vm.enforceSecurityCheckOpcodes = true
	vm.ensureFrameBoundaries()
	return vm
}

func (vm *VM) stripEncryptedPolymorphicMarker() {
	if vm == nil || vm.password == "" || vm.currentFrame() == nil || vm.currentFrame().cl == nil || vm.currentFrame().cl.Fn == nil {
		return
	}

	ins := vm.currentFrame().Instructions()
	if len(ins) < 2 {
		return
	}

	markerPos := len(ins) - 2
	levelPos := len(ins) - 1

	markerByte, err := security.SecureXOROneAt(ins[markerPos], int64(vm.inslen), vm.password, int64(markerPos))
	if err != nil {
		return
	}
	levelByte, err := security.SecureXOROneAt(ins[levelPos], int64(vm.inslen), vm.password, int64(levelPos))
	if err != nil {
		return
	}

	validMarker := (markerByte == 0xFF && levelByte <= 10) || (levelByte == 0xFF && markerByte <= 10)
	if !validMarker {
		return
	}

	trimmed := ins[:len(ins)-2]
	vm.currentFrame().cl.Fn.Instructions = trimmed

	if vm.frameIntegrity == nil {
		vm.frameIntegrity = make(map[*object.CompiledFunction][32]byte)
	}
	vm.frameIntegrity[vm.currentFrame().cl.Fn] = sha256.Sum256(trimmed)
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

func (vm *VM) ensureFrameBoundaries() {
	if vm == nil || vm.password == "" {
		return
	}

	if vm.frameBoundaries == nil {
		vm.frameBoundaries = make(map[*object.CompiledFunction]map[int]struct{})
	}

	if frame := vm.currentFrame(); frame != nil && frame.cl != nil && frame.cl.Fn != nil {
		fn := frame.cl.Fn
		if _, exists := vm.frameBoundaries[fn]; !exists {
			vm.frameBoundaries[fn] = buildInstructionBoundaries(fn.Instructions, vm.password, vm.inslen)
		}
	}

	for _, constant := range vm.constants {
		compiledFn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		if _, exists := vm.frameBoundaries[compiledFn]; !exists {
			vm.frameBoundaries[compiledFn] = buildInstructionBoundaries(compiledFn.Instructions, vm.password, vm.inslen)
		}
	}
}

func buildInstructionBoundaries(ins code.Instructions, password string, length int) map[int]struct{} {
	boundaries := make(map[int]struct{})
	if password == "" {
		return boundaries
	}

	for i := 0; i < len(ins); {
		boundaries[i] = struct{}{}
		opcodeByte, err := security.SecureXOROneAt(ins[i], int64(length), password, int64(i))
		if err != nil {
			break
		}

		def, err := code.Lookup(opcodeByte)
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
		boundaries = buildInstructionBoundaries(fn.Instructions, vm.password, vm.inslen)
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

func (vm *VM) Run() error {
	var ip int
	var ins code.Instructions
	var op code.Opcode
	vm.ensureFrameBoundaries()

	if err := vm.validateSecurityCheckOpcodes("before-execution"); err != nil {
		return err
	}

	for vm.frameIndex > 0 && vm.currentFrame().ip < len(vm.currentFrame().Instructions())-1 {
		if err := vm.runIntegrityProbes(); err != nil {
			return err
		}

		vm.currentFrame().ip++
		vm.stepCount++

		ip = vm.currentFrame().ip
		ins = vm.currentFrame().Instructions()

		opcodeByte, err := security.SecureXOROneAt(ins[ip], int64(vm.inslen), vm.password, int64(ip))
		if err != nil {
			return vm.runtimeErrorAt(ip, op, err)
		}
		op = code.Opcode(opcodeByte)

		switch op {
		case code.OpChkDbg:
			if isDebuggerPresent() {
				security.RecordDebuggerDetected("vm-run")
				if !vm.secureMode {
					logSecurityWarning("debugger_detected", "vm-run")
					continue
				}
				return security.ErrDebuggerDetected
			}
		case code.OpChkSnd:
			if isSandboxed() {
				security.RecordSandboxDetected("vm-run")
				if !vm.secureMode {
					logSecurityWarning("sandbox_detected", "vm-run")
					continue
				}
				return security.ErrSandboxDetected
			}
		case code.OpConstant:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			constIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			vm.currentFrame().ip += 2

			if err := vm.push(vm.constants[constIndex]); err != nil {
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
		case code.OpAdd, code.OpSub, code.OpMul, code.OpDiv:
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
			res, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			numElements := int(res)
			vm.currentFrame().ip += 2
			array := vm.buildArray(vm.stackPointer-numElements, vm.stackPointer)
			if err := vm.push(array); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpHash:
			if ip+2 >= len(ins) {
				return vm.runtimeErrorfAt(ip, op, "not enough bytes for operand, len=%d", len(ins))
			}
			res, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			numElements := int(res)
			vm.currentFrame().ip += 2
			hash, err := vm.buildHash(vm.stackPointer-numElements, vm.stackPointer)
			if err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
			vm.stackPointer = vm.stackPointer - numElements
			if err := vm.push(hash); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpEqual, code.OpUnEqual, code.OpGreater:
			if err := vm.execComparison(op); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpJump:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpJump: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			res, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			pos := int(res)
			vm.currentFrame().ip = pos - 1
		case code.OpJumpFalse:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpJumpFalse: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			res, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			pos := int(res)
			vm.currentFrame().ip += 2
			condition := vm.pop()
			if !isTruthy(condition) {
				vm.currentFrame().ip = pos - 1
			}
		case code.OpSetGlobal:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpSetGlobal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			globalIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2
			vm.ensureGlobalCapacity(int(globalIndex))
			vm.setGlobal(int(globalIndex), vm.pop())
		case code.OpGetGlobal:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpGetGlobal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			globalIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2
			vm.ensureGlobalCapacity(int(globalIndex))
			if err := vm.push(vm.getGlobal(int(globalIndex))); err != nil {
				return err
			}
		case code.OpSetLocal:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpSetLocal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			localIndex, err := code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			obj := vm.pop()
			vm.stack[frame.bp+int(localIndex)] = vm.encryptForStorage(obj)
		case code.OpGetLocal:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpGetLocal: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			localIndex, err := code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			frame := vm.currentFrame()
			if err := vm.push(vm.decryptForUse(vm.stack[frame.bp+int(localIndex)])); err != nil {
				return err
			}
		case code.OpGetBuiltin:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpGetBuiltin: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			builtinIndex, err := code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			if int(builtinIndex) >= len(builtin.Builtins) {
				return fmt.Errorf("OpGetBuiltin: invalid builtin index=%d, len=%d", builtinIndex, len(builtin.Builtins))
			}
			definition := builtin.Builtins[builtinIndex]
			if err := vm.push(definition.Builtin); err != nil {
				return err
			}
		case code.OpGetFree:
			if ip+1 >= len(ins) {
				return fmt.Errorf("OpGetFree: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			freeIndex, err := code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip++
			currentClosure := vm.currentFrame().cl
			if err := vm.push(vm.decryptForUse(currentClosure.Free[freeIndex])); err != nil {
				return err
			}
		case code.OpIndex:
			index := vm.pop()
			left := vm.pop()
			if err := vm.execIndexOperation(left, index); err != nil {
				return err
			}
		case code.OpClosure:
			if ip+3 >= len(ins) {
				return fmt.Errorf("OpClosure: not enough bytes for operands at ip=%d, len=%d", ip, len(ins))
			}
			constIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			numFree, err := code.ReadUint8(ins[ip+3:], int64(vm.inslen), vm.password, int64(ip+3))
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
			numArgs, err := code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
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
		case code.OpReturn:
			frame := vm.popFrame()
			vm.stackPointer = frame.bp - 1
			if vm.stackPointer < 0 {
				vm.stackPointer = 0
			}
			if err := vm.push(global.Null); err != nil {
				return err
			}
		case code.OpMultiValue:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpMultiValue: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			count, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
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
			if err := vm.push(vm.decryptForUse(vm.stack[vm.stackPointer-1])); err != nil {
				return vm.runtimeErrorAt(ip, op, err)
			}
		case code.OpDestructure:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpDestructure: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			count, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
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
			typeIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			fieldCountRaw, err := code.ReadUint8(ins[ip+3:], int64(vm.inslen), vm.password, int64(ip+3))
			if err != nil {
				return err
			}
			fieldCount := int(fieldCountRaw)
			vm.currentFrame().ip += 3

			typeObj, ok := vm.decryptForUse(vm.constants[typeIndex]).(*object.String)
			if !ok {
				return fmt.Errorf("OpMakeStruct: type constant is not string at index=%d", typeIndex)
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

			structObj := &object.Struct{
				TypeName: typeName,
				Fields:   fields,
			}
			if err := vm.push(structObj); err != nil {
				return err
			}
		case code.OpGetField:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpGetField: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			fieldNameIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			fieldObj, ok := vm.decryptForUse(vm.constants[fieldNameIndex]).(*object.String)
			if !ok {
				return fmt.Errorf("OpGetField: field constant is not string at index=%d", fieldNameIndex)
			}
			fieldName := fieldObj.Value
			obj := vm.pop()
			if structObj, ok := obj.(*object.Struct); ok {
				if val, exists := structObj.Fields[fieldName]; exists {
					if err := vm.push(val); err != nil {
						return err
					}
				} else {
					if err := vm.push(global.Null); err != nil {
						return err
					}
				}
			} else {
				return fmt.Errorf("cannot access field on non-struct: %s", obj.Type())
			}
		case code.OpSetField:
			if ip+2 >= len(ins) {
				return fmt.Errorf("OpSetField: not enough bytes for operand at ip=%d, len=%d", ip, len(ins))
			}
			fieldNameIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 2

			fieldObj, ok := vm.decryptForUse(vm.constants[fieldNameIndex]).(*object.String)
			if !ok {
				return fmt.Errorf("OpSetField: field constant is not string at index=%d", fieldNameIndex)
			}
			fieldName := fieldObj.Value
			value := vm.pop()
			obj := vm.pop()
			if structObj, ok := obj.(*object.Struct); ok {
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
			typeIndex, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
			if err != nil {
				return err
			}
			tagIndex, err := code.ReadUint16(ins[ip+3:], int64(vm.inslen), vm.password, int64(ip+3))
			if err != nil {
				return err
			}
			vm.currentFrame().ip += 4

			typeObj, ok := vm.decryptForUse(vm.constants[typeIndex]).(*object.String)
			if !ok {
				return fmt.Errorf("OpEnumValue: type constant is not string at index=%d", typeIndex)
			}
			tagObj, ok := vm.decryptForUse(vm.constants[tagIndex]).(*object.String)
			if !ok {
				return fmt.Errorf("OpEnumValue: tag constant is not string at index=%d", tagIndex)
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
		}
	}

	if err := vm.validateSecurityCheckOpcodes("after-execution"); err != nil {
		return err
	}

	return nil
}

func runtimeOpcodeName(op code.Opcode) string {
	if def, err := code.Lookup(byte(op)); err == nil {
		return def.Name
	}
	return fmt.Sprintf("opcode_%d", op)
}

func (vm *VM) runtimeErrorAt(ip int, op code.Opcode, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("vm_runtime_error ip=%d op=%s: %w", ip, runtimeOpcodeName(op), err)
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

	for i := 0; i < len(ins); {
		opcodeByte, err := security.SecureXOROneAt(ins[i], int64(vm.inslen), vm.password, int64(i))
		if err != nil {
			return false, false, err
		}

		op := code.Opcode(opcodeByte)
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

	vm.ensureFrameBoundaries()

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

func (vm *VM) StackTop() object.Object {
	if vm.stackPointer == 0 {
		return nil
	}

	return vm.decryptForUse(vm.stack[vm.stackPointer-1])
}

func (vm *VM) LastPoppedStackElement() object.Object {
	return vm.decryptForUse(vm.stack[vm.stackPointer])
}

func (vm *VM) pushClosure(constIndex, numFree int) error {
	constant := vm.constants[constIndex]
	fun, ok := constant.(*object.CompiledFunction)
	if !ok {
		return fmt.Errorf("not a function: %+v", constant)
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

func (vm *VM) pop() object.Object {
	obj := vm.decryptForUse(vm.stack[vm.stackPointer-1])

	vm.stackPointer--
	return obj
}

func (vm *VM) execBinaryOperation(op code.Opcode) error {
	right := vm.pop()
	left := vm.pop()

	rtype := right.Type()
	ltype := left.Type()

	if rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ {
		return vm.execBinaryIntegerOperation(op, left, right)
	}

	switch {
	case rtype == object.INTEGER_OBJ && ltype == object.INTEGER_OBJ:
		return vm.execBinaryIntegerOperation(op, left, right)
	case rtype == object.STRING_OBJ && ltype == object.STRING_OBJ:
		return vm.execBinaryStringOperation(op, left, right)
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
	var result int64

	switch op {
	case code.OpAdd:
		result = lval + rval
	case code.OpSub:
		result = lval - rval
	case code.OpMul:
		result = lval * rval
	case code.OpDiv:
		result = lval / rval
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

func (vm *VM) execIndexOperation(left, index object.Object) error {
	switch {
	case left.Type() == object.ARRAY_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execArrayIndex(left, index)
	case left.Type() == object.MULTI_VALUE_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execMultiValueIndex(left, index)
	case left.Type() == object.STRING_OBJ && index.Type() == object.INTEGER_OBJ:
		return vm.execStringIndex(left, index)
	case left.Type() == object.HASH_OBJ:
		return vm.execHashIndex(left, index)
	default:
		return fmt.Errorf("index operator not supported: %s", left.Type())
	}
}

func (vm *VM) execMultiValueIndex(multiValue, index object.Object) error {
	multi := multiValue.(*object.MultiValue)
	i := index.(*object.Integer).Value
	max := int64(len(multi.Values) - 1)
	if i > max || i < 0 {
		return vm.push(global.Null)
	}
	return vm.push(multi.Values[i])
}

func (vm *VM) execStringIndex(str, index object.Object) error {
	strVal := str.(*object.String).Value
	i := index.(*object.Integer).Value
	max := int64(len(strVal) - 1)
	if i > max {
		return vm.push(global.Null)
	} else if i < 0 {
		strObj := &object.String{Value: string(strVal[max+i+1])}
		return vm.push(strObj)
	}
	strObj := &object.String{Value: string(strVal[i])}
	return vm.push(strObj)
}

func (vm *VM) execArrayIndex(array, index object.Object) error {
	arrayObj := array.(*object.Array)
	i := index.(*object.Integer).Value
	max := int64(len(arrayObj.Elements) - 1)
	if i > max {
		return vm.push(global.Null)
	} else if i < 0 {
		return vm.push(arrayObj.Elements[max+i+1])
	}
	return vm.push(arrayObj.Elements[i])
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

func (vm *VM) execBangOperation() error {
	operand := vm.pop()

	switch operand {
	case global.True:
		return vm.push(global.False)
	case global.False:
		return vm.push(global.True)
	case global.Null:
		return vm.push(global.True)
	default:
		return vm.push(global.False)
	}
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

	switch op {
	case code.OpEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() == left.Inspect()))
	case code.OpUnEqual:
		return vm.push(nativeBoolToBooleanObject(right.Inspect() != left.Inspect()))
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

func (vm *VM) currentFrame() *Frame { return vm.frames[vm.frameIndex-1] }
func (vm *VM) pushFrame(f *Frame) {
	vm.ensureFrameCapacity(vm.frameIndex + 1)
	vm.frames[vm.frameIndex] = f
	vm.frameIndex++
	if f != nil && f.cl != nil && f.cl.Fn != nil {
		vm.registerFrameIntegrity(f.cl.Fn)
	}
}
func (vm *VM) popFrame() *Frame {
	vm.frameIndex--
	return vm.frames[vm.frameIndex]
}

func (vm *VM) execCall(numArgs int) error {
	var callee object.Object
	if vm.stack[vm.stackPointer-1-numArgs].Type() == object.CLOSURE_OBJ || vm.stack[vm.stackPointer-1-numArgs].Type() == object.BUILTIN_OBJ {
		callee = vm.stack[vm.stackPointer-1-numArgs]
	} else {
		callee = vm.stack[0]
	}

	switch calleeType := callee.(type) {
	case *object.Closure:
		return vm.callClosure(calleeType, numArgs)
	case *builtin.BuiltIn:
		return vm.callBuiltin(calleeType, numArgs)

	default:
		return fmt.Errorf("calling non-function and non-built-in")
	}
}

func (vm *VM) callClosure(cl *object.Closure, numArgs int) error {
	if numArgs != cl.Fn.NumParams {
		return fmt.Errorf("wrong number of arguments. want=%d, got=%d", cl.Fn.NumParams, numArgs)
	}

	frame := NewFrame(cl, vm.stackPointer-numArgs)
	vm.pushFrame(frame)
	vm.ensureStackCapacity(frame.bp + cl.Fn.NumLocals)
	vm.stackPointer = frame.bp + cl.Fn.NumLocals
	return nil
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
			vm.frameBoundaries[fn] = buildInstructionBoundaries(fn.Instructions, vm.password, vm.inslen)
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
		return security.ApplyTamperResponse("integrity_failed", stage, true, fmt.Errorf("runtime integrity check failed"))
	}

	return nil
}

func (vm *VM) callBuiltin(builtin *builtin.BuiltIn, numArgs int) error {
	storedArgs := vm.stack[vm.stackPointer-numArgs : vm.stackPointer]
	args := make([]object.Object, len(storedArgs))
	for i, arg := range storedArgs {
		args[i] = vm.decryptForUse(arg)
	}
	rawResult := builtin.Fn(args...)
	result := rawResult
	if result == nil {
		result = global.Null
	}

	vm.stackPointer = vm.stackPointer - numArgs - 1

	vm.push(result)

	return nil
}

func nativeBoolToBooleanObject(native bool) *object.Boolean {
	if native {
		return global.True
	}
	return global.False
}

func isTruthy(obj object.Object) bool {
	switch obj := obj.(type) {
	case *object.Boolean:
		return obj.Value
	case *object.Null:
		return false
	default:
		return true
	}
}
