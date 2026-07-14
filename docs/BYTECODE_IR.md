# Mutant IR / ByteCode Reference

> This document covers every layer of the bytecode pipeline: instruction
> encoding, the constant pool, compiler internals, the stack-machine VM,
> security machinery, and the polymorphic mutation engine.

> **Status note:** this is a deep technical reference. For current feature
> enablement and rollout status (especially anti-tamper gates and polymorphic
> activation depth), use:
>
> 1. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
> 2. [PROCESS_INJECTION_DETECTION_LLD](PROCESS_INJECTION_DETECTION_LLD.md)
> 3. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Instruction Encoding](#2-instruction-encoding)
3. [Opcode Reference](#3-opcode-reference)
4. [ByteCode Object](#4-bytecode-object)
5. [Constant Pool](#5-constant-pool)
6. [Compiler Internals](#6-compiler-internals)
7. [Symbol Table & Scoping](#7-symbol-table--scoping)
8. [VM: Stack Machine Design](#8-vm-stack-machine-design)
9. [VM: Execution Loop](#9-vm-execution-loop)
10. [Closures & Free Variables](#10-closures--free-variables)
11. [Structs at the Bytecode Level](#11-structs-at-the-bytecode-level)
12. [Enums at the Bytecode Level](#12-enums-at-the-bytecode-level)
13. [Loop Control Flow](#13-loop-control-flow)
14. [Operand Encryption](#14-operand-encryption)
15. [Runtime Security Features](#15-runtime-security-features)
16. [Polymorphic Mutation Engine](#16-polymorphic-mutation-engine)
17. [Object Type System](#17-object-type-system)
18. [VM Constructor Variants](#18-vm-constructor-variants)
19. [Common Pitfalls](#19-common-pitfalls)

---

## 1. Architecture Overview

```
Source text
    │
    ▼
  Lexer  (token/)
    │
    ▼
  Parser (parser/)  ──► AST (ast/)
    │
    ▼
 Compiler (compiler/)
    │  ├─ SymbolTable    resolves variable scopes
    │  ├─ CompilationScopes  one per function nesting level
    │  └─ PolymorphicEngine  optional bytecode mutation
    │
    ▼
 ByteCode struct
    │  ├─ Instructions   []byte  flat bytecode stream
    │  ├─ Constants      []object.Object  literal pool
    │  ├─ StructDefs     map[string][]*ast.Identifier
    │  └─ EnumDefs       map[string][]string
    │
    ▼
   VM  (vm/)
    │  ├─ Stack          []object.Object (grows dynamically)
    │  ├─ Globals        []object.Object (grows dynamically)
    │  ├─ Frames         []*Frame        (call stack)
    │  └─ Security subsystem
```

Mutant compiles to a **flat, linear byte stream**. There is no intermediate
representation between the AST and the bytecode – the compiler walks the AST and
emits bytes directly. The VM then executes those bytes in a **register-less,
expression-stack machine**.

---

## 2. Instruction Encoding

### 2.1 Types

```go
// code/code.go
type Instructions []byte   // the raw bytecode stream
type Opcode       byte     // a single opcode value (0-based iota)
```

### 2.2 Instruction Layout

Every instruction is:

```
┌──────────┬──────────────────────────────────────────┐
│  1 byte  │  0, 1, 2, 3, or 4 bytes of operands      │
│  opcode  │  (widths defined per opcode in Definition) │
└──────────┴──────────────────────────────────────────┘
```

Multi-byte operands are always **big-endian**.

### 2.3 `Definition` Registry

```go
type Definition struct {
    Name          string
    OperandWidths []int   // widths of each operand in bytes (1 or 2)
}
```

The `definitions` map in `code/code.go` is the single source of truth for every
opcode's operand layout. `code.Lookup(byte)` returns the definition or an error
for unknown opcodes.

### 2.4 `Make` — Building Instructions

```go
func Make(op Opcode, operands ...int) []byte
```

- Allocates `1 + sum(OperandWidths)` bytes.
- Writes the opcode at `[0]`.
- Writes each operand using `binary.BigEndian.PutUint16` (2-byte) or a direct
  `byte()` cast (1-byte).

```go
// Example: emit OpConstant with index 42
ins := code.Make(code.OpConstant, 42)
// Result: [0x00, 0x00, 0x2A]   (OpConstant=0, 42 big-endian)
```

### 2.5 Reading Operands

**Unencrypted** (compiler / test use only):

```go
func ReadOperands(def *Definition, ins Instructions) ([]int, int)
```

Returns a `[]int` of decoded operand values and the total bytes consumed by
those operands (not including the opcode byte itself).

**Encrypted** (VM runtime use — the only correct way during execution):

```go
func ReadUint16(ins Instructions, length int64, password string, offset int64) (uint16, error)
func ReadUint8 (ins Instructions, length int64, password string, offset int64) (uint8,  error)
```

Both functions call `security.SecureXOR*` before decoding. `length` is the total
byte length of the **main** function's instruction stream (used as part of the
XOR key derivation). `offset` is the absolute byte position of the first operand
byte within the instruction stream.

> **Critical rule (from project memory):** Never read encrypted operands with
> `ins[offset]` or `binary.BigEndian.Uint16(ins[offset:])` directly inside the
> VM. Always call `ReadUint8` / `ReadUint16`. Reading raw bytes gives corrupted
> values when encryption is active.

### 2.6 Disassembling

`Instructions.String()` produces a human-readable listing:

```
0000 OpConstant 0
0003 OpConstant 1
0006 OpAdd
0007 OpSetGlobal 0
0010 OpGetGlobal 0
...
```

It is **not** safe to call this on encrypted bytecode (it uses the unencrypted
`ReadOperands` path). Use it only in tests or during non-password compilation.

---

## 3. Opcode Reference

Opcodes are declared as an `iota` in `code/code.go`. Their **numeric values are
fixed** by the declaration order below, so do not reorder them.

### 3.1 Complete Table

| #  | Name               | Operands (bytes)                | Stack effect             | Description                                                      |
| -- | ------------------ | ------------------------------- | ------------------------ | ---------------------------------------------------------------- |
| 0  | `OpConstant`       | `idx` (2)                       | `→ val`                  | Push `constants[idx]`                                            |
| 1  | `OpPop`            | —                               | `val →`                  | Discard top of stack                                             |
| 2  | `OpAdd`            | —                               | `b, a → a+b`             | Integer or float add; string concat                              |
| 3  | `OpSub`            | —                               | `b, a → a-b`             | Subtract                                                         |
| 4  | `OpMul`            | —                               | `b, a → a*b`             | Multiply                                                         |
| 5  | `OpDiv`            | —                               | `b, a → a/b`             | Divide                                                           |
| 6  | `OpMod`            | —                               | `b, a → a%b`             | Modulo                                                           |
| 7  | `OpTrue`           | —                               | `→ true`                 | Push the singleton `True` object                                 |
| 8  | `OpFalse`          | —                               | `→ false`                | Push the singleton `False` object                                |
| 9  | `OpEqual`          | —                               | `b, a → bool`            | `a == b`                                                         |
| 10 | `OpUnEqual`        | —                               | `b, a → bool`            | `a != b`                                                         |
| 11 | `OpGreater`        | —                               | `b, a → bool`            | `a > b` (also used for `<` by swapping operands at compile time) |
| 12 | `OpMinus`          | —                               | `a → -a`                 | Unary negation                                                   |
| 13 | `OpBang`           | —                               | `a → !a`                 | Unary logical NOT                                                |
| 14 | `OpJumpFalse`      | `target` (2)                    | `cond →`                 | Pop condition; if falsy jump to `target`                         |
| 15 | `OpJump`           | `target` (2)                    | —                        | Unconditional jump to `target`                                   |
| 16 | `OpNull`           | —                               | `→ null`                 | Push the singleton `Null` object                                 |
| 17 | `OpGetGlobal`      | `idx` (2)                       | `→ val`                  | Push `globals[idx]` (decrypted)                                  |
| 18 | `OpSetGlobal`      | `idx` (2)                       | `val →`                  | Pop and store to `globals[idx]` (encrypted)                      |
| 19 | `OpGetLocal`       | `idx` (1)                       | `→ val`                  | Push `stack[bp+idx]` (decrypted)                                 |
| 20 | `OpSetLocal`       | `idx` (1)                       | `val →`                  | Pop and store to `stack[bp+idx]` (encrypted)                     |
| 21 | `OpArray`          | `n` (2)                         | `eN…e0 → arr`            | Pop `n` elements, build `Array`, push it                         |
| 22 | `OpHash`           | `n` (2)                         | `vN,kN…v0,k0 → hash`     | Pop `n` key+value pairs (`n` is even), build `Hash`, push it     |
| 23 | `OpIndex`          | —                               | `idx, obj → val`         | Pop index then object; resolve `obj[idx]`                        |
| 24 | `OpCall`           | `argc` (1)                      | `argN…arg0, fn →` result | Call function with `argc` arguments                              |
| 25 | `OpReturnValue`    | —                               | `val → (caller frame)`   | Pop return value, restore frame, push value                      |
| 26 | `OpReturn`         | —                               | `(caller frame)`         | Void return; restores frame, pushes `Null`                       |
| 27 | `OpGetBuiltin`     | `idx` (1)                       | `→ fn`                   | Push built-in function at `Builtins[idx]`                        |
| 28 | `OpClosure`        | `fnIdx` (2), `numFree` (1)      | `fN…f0 → closure`        | Pop `numFree` free vars; wrap `constants[fnIdx]` in a `Closure`  |
| 29 | `OpGetFree`        | `idx` (1)                       | `→ val`                  | Push `currentClosure.Free[idx]` (decrypted)                      |
| 30 | `OpCurrentClosure` | —                               | `→ closure`              | Push the currently executing closure (for named recursion)       |
| 31 | `OpChkDbg`         | —                               | —                        | Halt (or warn) if a debugger is detected                         |
| 32 | `OpChkSnd`         | —                               | —                        | Halt (or warn) if a sandbox environment is detected              |
| 33 | `OpBreak`          | —                               | `→ Break{}`              | Push a `Break` sentinel onto the stack                           |
| 34 | `OpContinue`       | —                               | `→ Continue{}`           | Push a `Continue` sentinel onto the stack                        |
| 35 | `OpMakeStruct`     | `typeIdx` (2), `fieldCount` (1) | `fN…f0 → struct`         | Pop `fieldCount` values, create a `Struct`                       |
| 36 | `OpGetField`       | `nameIdx` (2)                   | `struct → val`           | Pop struct; push `struct.Fields[constants[nameIdx]]`             |
| 37 | `OpSetField`       | `nameIdx` (2)                   | `val, struct → struct`   | Pop value then struct; set field; push struct back               |
| 38 | `OpEnumValue`      | `typeIdx` (2), `tagIdx` (2)     | `→ EnumValue`            | Create `EnumValue{TypeName, Tag, ordinal}`                       |

### 3.2 Stack Notation

The "Stack effect" column uses the convention:

- Values left of `→` are **consumed** (popped), listed bottom-first (so `b, a`
  means `a` is on top).
- Values right of `→` are **produced** (pushed).
- `(caller frame)` means the caller's frame is restored — no net stack value in
  the new frame's context.

### 3.3 The `<` Operator Trick

There is no `OpLess` opcode. When the compiler sees `a < b` it compiles:

```
[compile b]         ← right operand first
[compile a]         ← left operand second  (reversed!)
OpGreater
```

This reuses `OpGreater` without a dedicated less-than opcode.

---

## 4. ByteCode Object

```go
// compiler/compiler.go
type ByteCode struct {
    Instructions code.Instructions              // Main function byte stream
    Constants    []object.Object                // Constant pool (see §5)
    StructDefs   map[string][]*ast.Identifier   // Field name lists per struct type
    EnumDefs     map[string][]string            // Tag name lists per enum type
    LuaPatches   map[string]*object.LuaPatch    // Lua security hook patches
}
```

`ByteCode` is the artifact handed from the compiler to the VM. It is immutable
after construction (the VM clones nothing; it reads the slices directly).

The `LuaPatches` field is populated by the Lua integration layer, not by the
core compiler. See `builtin/lua.go` for context.

---

## 5. Constant Pool

The constant pool is `[]object.Object` stored in `ByteCode.Constants`. It is
built incrementally by `compiler.addConstant`:

```go
func (c *Compiler) addConstant(obj object.Object) int {
    c.constants = append(c.constants, obj)
    return len(c.constants) - 1  // index used as OpConstant operand
}
```

**What lives in the pool:**

| Object type                | Example source                     | Notes                                                                                                        |
| -------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `*object.Integer`          | `42`, `-7`                         | `int64`                                                                                                      |
| `*object.Float`            | `3.14`                             | `float64`                                                                                                    |
| `*object.String`           | `"hello"`, field names, type names | All string literals; also struct/enum type-name strings and field-name strings needed by struct/enum opcodes |
| `*object.CompiledFunction` | Any `fn(…){…}`                     | The function body's bytecode + metadata                                                                      |

**Booleans and Null are NOT pooled.** They use dedicated singleton opcodes
(`OpTrue`, `OpFalse`, `OpNull`) that push global singleton objects.

**Maximum pool size:** 65 535 entries (uint16 operand range). In practice the
limit is never reached in normal programs.

**Constant indices are stable** within a single compilation. If polymorphic
constant-pool randomization is enabled (see §16), the indices in `OpConstant`
instructions are rewritten to match the shuffled pool order before the
`ByteCode` is returned.

---

## 6. Compiler Internals

### 6.1 Compiler Struct

```go
type Compiler struct {
    constants         []object.Object        // Accumulates the constant pool
    symbolTable       *SymbolTable            // Current scope's symbol table
    scopes            []CompilationScope      // Stack of compilation scopes
    scopeIndex        int                     // Index into scopes[]
    structDefinitions map[string][]*ast.Identifier
    enumDefinitions   map[string][]string
    loopContexts      []LoopContext           // Stack of active for-loop contexts

    injectSecurityChecks bool                 // Enables OpChkDbg/OpChkSnd injection
    hasChkDbg            bool                 // Tracks whether DbgCheck was emitted
    hasChkSnd            bool                 // Tracks whether SndCheck was emitted

    polymorphicEngine *PolymorphicEngine      // nil = no mutation
}
```

### 6.2 Compilation Scope

A `CompilationScope` holds:

```go
type CompilationScope struct {
    instructions    code.Instructions    // byte buffer being built
    lastInstruction EmittedInstruction   // most recently emitted instruction
    prevInstruction EmittedInstruction   // the one before last (for pop-removal)
}
```

The main program compiles into `scopes[0]`. Each function literal pushes a new
scope via `enterScope()` and pops it with `leaveScope()`.

### 6.3 `emit` and Instruction Patching

```go
func (c *Compiler) emit(op code.Opcode, operands ...int) int
```

Returns the **byte offset** of the emitted instruction. This offset is saved so
jumps can be back-patched:

```go
// Emit jump with placeholder target
jumpPos := c.emit(code.OpJumpFalse, 9999)

// ... compile consequence ...

// Back-patch: replace the 9999 target with the real destination
c.changeOperand(jumpPos, realTarget)
```

`changeOperand` calls `replaceInstruction` which overwrites the bytes at `pos`
in the current instruction buffer. This works because `Make` produces the same
byte length regardless of the operand value.

### 6.4 Pop-Removal Optimisation

Expression statements emit `OpPop` after the expression so the stack stays
balanced. But when an expression is the last statement of a function body, the
`OpPop` must not be emitted (the value becomes the implicit return value).

The compiler detects this with `lastInstructionIs(code.OpPop)` and either:

- Calls `removeLastPop()` — truncates the instruction buffer by one byte.
- Calls `replaceLastPopWithReturn()` — overwrites the `OpPop` with
  `OpReturnValue` in-place (same size, no shift needed).

### 6.5 Function Literal Compilation

```
1. enterScope()
2. If named function: symbolTable.DefineFunctionName(name)   → OpCurrentClosure support
3. For each parameter: symbolTable.Define(param)             → LocalScope
4. Compile body block
5. If last instruction is OpPop → replaceLastPopWithReturn()
6. If last instruction is not OpReturnValue → emit OpReturn
7. Snapshot freeSymbols = symbolTable.FreeSymbols
8. Snapshot numLocals    = symbolTable.numDefinitions
9. leaveScope() → captures finished instruction bytes
10. For each free symbol: loadSymbol(sym)  → pushes captured values onto parent stack
11. compiledFn = &CompiledFunction{Instructions, NumLocals, NumParams}
12. fnIndex = addConstant(compiledFn)
13. emit(OpClosure, fnIndex, len(freeSymbols))
```

### 6.6 Security Opcode Injection

When `injectSecurityChecks = true` (enabled by
`EnableSecurityOpcodeInjection()`):

- After each top-level statement, `maybeEmitRandomSecurityCheckOpcodes()` is
  called. It uses `crypto/rand` to decide with probability `1/3` whether to emit
  `OpChkDbg` and/or `OpChkSnd`.
- When `ByteCode()` is called, `ensureRequiredSecurityCheckOpcodes()` appends
  whichever of the two opcodes were never randomly inserted, guaranteeing both
  are present at least once.

The VM enforces that both opcodes exist in the instruction stream when running
in password/secure mode (validated before and after execution via
`validateSecurityCheckOpcodes`).

---

## 7. Symbol Table & Scoping

### 7.1 Symbol and Scope Types

```go
type SymbolScope string

const (
    GlobalScope   SymbolScope = "GLOBAL"    // top-level let bindings
    LocalScope    SymbolScope = "LOCAL"     // function-local let bindings
    BuiltinScope  SymbolScope = "BUILTIN"   // built-in functions
    FreeScope     SymbolScope = "FREE"      // captured from enclosing scope
    FunctionScope SymbolScope = "FUNCTION"  // self-reference for named functions
)

type Symbol struct {
    Name  string
    Scope SymbolScope
    Index int   // offset in its storage (globals[], stack[bp+i], Free[i], Builtins[i])
}
```

### 7.2 `Define`

```go
func (st *SymbolTable) Define(name string) Symbol
```

- If `st.Outer == nil` → `GlobalScope`, index = `numDefinitions++`
- Otherwise → `LocalScope`, index = `numDefinitions++`

`numDefinitions` also becomes the `CompiledFunction.NumLocals` (the VM reserves
this many stack slots for the frame).

### 7.3 `Resolve` and Free Variable Promotion

```go
func (st *SymbolTable) Resolve(name string) (Symbol, bool)
```

Resolution order:

1. Look up in `st.store` (current scope).
2. If not found and `st.Outer != nil`, recurse into outer scope.
3. If found in outer scope:
   - `GlobalScope` or `BuiltinScope` → return as-is (loaded via `OpGetGlobal` /
     `OpGetBuiltin`).
   - Any other scope → call `defineFree(original)`:
     - Appends `original` to `st.FreeSymbols`.
     - Stores a new `FreeScope` symbol with `Index = len(FreeSymbols)-1`.
     - Returns the free symbol.

`FreeSymbols` is consumed at the end of function compilation (step 10 in §6.5)
to emit the instructions that push captured values onto the stack before
`OpClosure`.

### 7.4 `DefineFunctionName`

```go
func (st *SymbolTable) DefineFunctionName(name string) Symbol
```

Creates a `FunctionScope` symbol at index 0. When the compiler resolves the
function's own name inside its body, `loadSymbol` emits `OpCurrentClosure`,
which pushes the currently-running closure without going through the variable
system. This allows direct recursion without a free-variable round-trip.

### 7.5 `loadSymbol` — Scope to Opcode Mapping

```go
func (c *Compiler) loadSymbol(s Symbol) {
    switch s.Scope {
    case GlobalScope:   c.emit(code.OpGetGlobal,  s.Index)
    case LocalScope:    c.emit(code.OpGetLocal,   s.Index)
    case BuiltinScope:  c.emit(code.OpGetBuiltin, s.Index)
    case FreeScope:     c.emit(code.OpGetFree,    s.Index)
    case FunctionScope: c.emit(code.OpCurrentClosure)
    }
}
```

---

## 8. VM: Stack Machine Design

### 8.1 Constants

```go
// global/const.go
StackSize  = 2048   // initial stack capacity (doubles on overflow)
GlobalSize = 65536  // initial globals capacity (doubles on overflow)
MaxFrames  = 2048   // initial call-stack frame capacity (doubles on overflow)
```

All three slices are **dynamically resized** using `growSize` (doubles until
large enough) and `copy`. There is no hard cap beyond memory limits.

### 8.2 VM Struct Layout

```go
type VM struct {
    constants    []object.Object     // constant pool from compilation
    stack        []object.Object     // value stack; TOS = stack[stackPointer-1]
    stackPointer int                 // points one past top-of-stack

    globals      []object.Object     // global variable storage

    frames       []*Frame            // call stack
    frameIndex   int                 // index of the *next* free slot (current = frames[frameIndex-1])

    inslen       int                 // byte length of the main bytecode stream (key derivation input)
    password     string              // XOR decryption key (empty = no encryption)

    stepCount    uint64              // instructions executed so far
    // ... integrity scheduling fields (see §15) ...

    secureMode   bool                // true = fatal errors on security violations
    structDefs   map[string]any      // struct field name lists
    enumDefs     map[string]any      // enum tag name lists
    enforceSecurityCheckOpcodes bool // true when running with a password
}
```

### 8.3 Frame

```go
type Frame struct {
    cl *object.Closure   // currently executing closure
    ip int               // instruction pointer; starts at -1
    bp int               // base pointer: stack[bp..bp+NumLocals-1] are locals
}

func (f *Frame) Instructions() code.Instructions { return f.cl.Fn.Instructions }
```

The IP is initialised to `-1`. On every iteration the main loop increments it
before reading. This means the first instruction is read at `ip=0` after the
first increment.

### 8.4 Stack Layout During a Call

```
Before OpCall:
  stack[...] = captured globals / earlier temps
  stack[sp-argc-1] = closure/builtin being called   ← fn
  stack[sp-argc]   = arg[0]
  stack[sp-argc+1] = arg[1]
  ...
  stack[sp-1]      = arg[argc-1]

execCall sets: newFrame.bp = sp - argc
               sp          = bp + fn.NumLocals   (reserves local slots)

Inside function:
  stack[bp + 0]    = local variable 0 (first parameter fills this slot)
  stack[bp + 1]    = local variable 1
  ...
  stack[bp + NumLocals-1] = last local
  stack[sp..]      = temporaries for expression evaluation

On return (OpReturnValue):
  returnValue = pop()
  sp = bp - 1         (unwinds frame including the fn slot below args)
  push(returnValue)

On return (OpReturn / void):
  sp = bp - 1
  push(Null)
```

**Important:** `bp - 1` rewinds past the closure slot that was on the stack
before the call, effectively consuming the function object itself.

---

## 9. VM: Execution Loop

### 9.1 `Run()` Structure

```
vm.ensureFrameBoundaries()
vm.validateSecurityCheckOpcodes("before-execution")

loop:
    while currentFrame.ip < len(currentFrame.Instructions()) - 1:
        runIntegrityProbes()                  // SHA-256 + CFI checks
        currentFrame.ip++
        stepCount++

        ip  = currentFrame.ip
        ins = currentFrame.Instructions()

        opcodeByte = SecureXOROneAt(ins[ip], inslen, password, ip)
        op = Opcode(opcodeByte)

        switch op:
            ... (one case per opcode) ...

vm.validateSecurityCheckOpcodes("after-execution")
```

### 9.2 IP Advancement Protocol

Opcodes with operands **must advance the IP** by the number of operand bytes
consumed. This is done explicitly inside each case, **after** reading the
operand. Pattern:

```go
case code.OpConstant:
    constIndex, _ := code.ReadUint16(ins[ip+1:], ...)
    vm.currentFrame().ip += 2     // skip 2-byte operand
    vm.push(vm.constants[constIndex])
```

**Jump opcodes set IP to `target - 1`** so the main loop's `ip++` at the top of
the next iteration lands exactly at the target byte:

```go
case code.OpJump:
    pos := int(readUint16(...))
    vm.currentFrame().ip = pos - 1   // loop will +1 before fetching
```

`OpJumpFalse` still advances by 2 (`ip += 2`) when the condition is _truthy_
(i.e., the jump is not taken), to skip past the operand and continue linearly.

### 9.3 Per-Opcode Behaviour Summary

| Opcode                    | IP advance                    | Push/Pop details                              |
| ------------------------- | ----------------------------- | --------------------------------------------- |
| `OpConstant`              | +2                            | push `constants[idx]`                         |
| `OpPop`                   | 0                             | pop (discard)                                 |
| `OpAdd/Sub/Mul/Div`       | 0                             | pop b, pop a, push result                     |
| `OpMod`                   | 0                             | pop b, pop a, push `a % b`                    |
| `OpTrue/False/Null`       | 0                             | push singleton                                |
| `OpEqual/UnEqual/Greater` | 0                             | pop b, pop a, push Boolean                    |
| `OpMinus`                 | 0                             | pop a, push `-a`                              |
| `OpBang`                  | 0                             | pop a, push `!a`                              |
| `OpJump`                  | sets ip = target-1            | —                                             |
| `OpJumpFalse`             | +2 (not taken) or ip=target-1 | pop condition                                 |
| `OpGetGlobal`             | +2                            | push decrypted `globals[idx]`                 |
| `OpSetGlobal`             | +2                            | pop, encrypt, store to `globals[idx]`         |
| `OpGetLocal`              | +1                            | push decrypted `stack[bp+idx]`                |
| `OpSetLocal`              | +1                            | pop, encrypt, store `stack[bp+idx]`           |
| `OpArray`                 | +2                            | pop n, push Array                             |
| `OpHash`                  | +2                            | pop n (must be even: k,v pairs), push Hash    |
| `OpIndex`                 | 0                             | pop index, pop obj, push result               |
| `OpCall`                  | +1                            | pop argc args + fn; push new frame            |
| `OpReturnValue`           | —                             | pop return val; pop frame; push val           |
| `OpReturn`                | —                             | pop frame; push Null                          |
| `OpGetBuiltin`            | +1                            | push `Builtins[idx]`                          |
| `OpClosure`               | +3                            | pop numFree values; push Closure              |
| `OpGetFree`               | +1                            | push `currentClosure.Free[idx]`               |
| `OpCurrentClosure`        | 0                             | push current Closure                          |
| `OpChkDbg`                | 0                             | detect debugger → error or warn               |
| `OpChkSnd`                | 0                             | detect sandbox → error or warn                |
| `OpBreak`                 | 0                             | push `Break{}` sentinel                       |
| `OpContinue`              | 0                             | push `Continue{}` sentinel                    |
| `OpMakeStruct`            | +3                            | pop fieldCount values; push Struct            |
| `OpGetField`              | +2                            | pop struct; push field value                  |
| `OpSetField`              | +2                            | pop value, pop struct; set field; push struct |
| `OpEnumValue`             | +4                            | push EnumValue                                |

### 9.4 Global & Local Encryption at Runtime

Values are **encrypted on write** and **decrypted on read** for globals and
locals when a `password` is set:

```go
// Write path
vm.globals[idx] = vm.encryptForStorage(vm.pop())
vm.stack[bp+idx] = vm.encryptForStorage(vm.pop())

// Read path
vm.push(vm.decryptForUse(vm.globals[idx]))
vm.push(vm.decryptForUse(vm.stack[bp+idx]))
```

`mutil.EncryptObject` / `mutil.DecryptObject` wrap the object in / unwrap from
`*object.Encrypted`. If encryption fails (e.g., unsupported type), the object is
stored/returned as-is.

---

## 10. Closures & Free Variables

### 10.1 Compilation

Given:

```mutant
let outer = fn() {
    let x = 5;
    let inner = fn() { x };
    inner
};
```

The compiler for `inner`:

1. Sees `x` → resolves to outer's `LocalScope`.
2. Calls `defineFree(x_local)` →
   `FreeSymbols = [{Name:"x", Scope:LOCAL, Index:0}]`.
3. After body compilation, `FreeSymbols` has one entry.
4. In the parent scope, `loadSymbol` for each free symbol emits `OpGetLocal 0`
   (loading `x` onto the stack).
5. Emits `OpClosure <innerFnIdx> 1`.

Bytecode for `outer`:

```
0000 OpConstant 0       ; integer 5
0003 OpSetLocal 0       ; let x = 5
0005 OpGetLocal 0       ; push x (as free var capture for inner)
0007 OpClosure 1 1      ; wrap constants[1] (inner fn) with 1 free var
0011 OpSetLocal 1       ; let inner = <closure>
0013 OpGetLocal 1       ; return inner
0015 OpReturnValue
```

### 10.2 Runtime: `pushClosure`

```go
func (vm *VM) pushClosure(constIndex, numFree int) error {
    fn   := vm.constants[constIndex].(*object.CompiledFunction)
    free := make([]object.Object, numFree)
    for i := 0; i < numFree; i++ {
        free[i] = vm.stack[vm.stackPointer-numFree+i]
    }
    vm.stackPointer -= numFree
    closure := &object.Closure{Fn: fn, Free: free}
    return vm.push(closure)
}
```

The captured values are read from the stack in **forward order** (they were
pushed in forward order by the parent's `loadSymbol` calls).

### 10.3 Accessing Free Variables

```go
case code.OpGetFree:
    freeIndex := ReadUint8(...)
    vm.push(vm.decryptForUse(vm.currentFrame().cl.Free[freeIndex]))
```

Free variables are stored inside the `Closure` object itself, isolated per call
instance. Mutating a free variable inside the function mutates the captured slot
directly in the closure's `Free` slice.

---

## 11. Structs at the Bytecode Level

### 11.1 Definition (compile-time only)

```mutant
struct Point { x, y }
```

No bytecode is emitted. The compiler records:

```go
c.structDefinitions["Point"] = []*ast.Identifier{{Value:"x"}, {Value:"y"}}
```

This map is carried in `ByteCode.StructDefs` and loaded into `vm.structDefs` at
VM construction.

### 11.2 Construction

```mutant
let p = Point { x: 1, y: 2 };
```

Compiled to:

```
OpConstant <idx of "Point">   ; push type name string
OpConstant <idx of 1>          ; push field value 1
OpConstant <idx of 2>          ; push field value 2
OpMakeStruct <typeIdx> 2       ; typeIdx = constant index of "Point", fieldCount = 2
OpSetGlobal <p_idx>
```

**`OpMakeStruct` runtime behaviour:**

1. Reads `typeIdx` (2 bytes) and `fieldCount` (1 byte).
2. Looks up `constants[typeIdx]` → must be `*object.String` containing the
   struct name.
3. Looks up `vm.structDefs[typeName]` → ordered field name list.
4. Verifies `len(fieldNames) == fieldCount` (error if not).
5. Pops `fieldCount` values from stack **in reverse** (last field popped first),
   mapping them to `fieldNames[fieldCount-1-i]` so the first field value pushed
   maps to the first field name.
6. Creates `&object.Struct{TypeName, Fields: map[string]Object{...}}`.

### 11.3 Field Access / Mutation

```mutant
p.x          ; OpGetField
p.x = 10    ; OpSetField
```

Field names are stored as string constants in the pool. The opcodes carry the
constant index:

```
OpGetField <nameIdx>   ; pop struct, push struct.Fields[constants[nameIdx]]
OpSetField <nameIdx>   ; pop value, pop struct, set field, push struct back
```

Accessing a non-existent field pushes `Null` (no error). Setting a field on a
non-struct object is a runtime error.

---

## 12. Enums at the Bytecode Level

### 12.1 Definition (compile-time only)

```mutant
enum Color { Red, Green, Blue }
```

No bytecode emitted. Compiler records:

```go
c.enumDefinitions["Color"] = []string{"Red", "Green", "Blue"}
```

Carried in `ByteCode.EnumDefs` → `vm.enumDefs`.

### 12.2 Tag Reference

```mutant
let c = Color.Red;
```

Compiled to:

```
OpEnumValue <typeIdx> <tagIdx>
```

Both operands are 2-byte constant indices pointing to string constants `"Color"`
and `"Red"` respectively.

**`OpEnumValue` runtime behaviour:**

1. Reads `typeIdx` (2 bytes) and `tagIdx` (2 bytes); advances IP by 4.
2. Looks up both strings in the constant pool.
3. Looks up `vm.enumDefs[typeName]` → `[]string`.
4. Scans the tag list for the matching string; ordinal = position index
   (0-based).
5. Returns error if the tag is not found.
6. Pushes `&object.EnumValue{TypeName, Tag, Value: &Integer{int64(ordinal)}}`.

---

## 13. Loop Control Flow

### 13.1 For Loop Structure

```mutant
for (let i = 0; i < 10; i = i + 1) { body }
```

Compiler emits (pseudocode):

```
[init: OpConstant 0, OpSetLocal 0]           ; let i = 0
[conditionStart: label A]
[condition: push (i < 10)]
OpJumpFalse → loopEnd                        ; if false, exit
[body: ...]
[OpPop if last statement is expression]
[post: i = i + 1]
OpJump → A                                   ; loop back
[loopEnd: label B]
```

A missing condition (`for(;;)`) emits `OpTrue` as the condition. A missing init
or post simply emits nothing for those phases.

### 13.2 `LoopContext` and Back-Patching

```go
type LoopContext struct {
    breakPositions    []int   // byte offsets of OpJump instructions from break
    continuePositions []int   // byte offsets of OpJump instructions from continue
}
```

When `break` or `continue` is encountered:

- Emit `OpJump 9999` (placeholder).
- Append the emitted position to `ctx.breakPositions` / `ctx.continuePositions`.

After the loop body and post-increment are fully compiled:

- Patch all `breakPositions` → `loopEnd` address.
- Patch all `continuePositions` → `conditionStart` address (re-runs the
  condition check, which then falls through to the post-increment).

At runtime, `OpBreak` / `OpContinue` push sentinel objects (`&object.Break{}` /
`&object.Continue{}`). These are only meaningful in the evaluator (tree-walk)
path; the compiled VM path uses only the jump instructions.

---

## 14. Operand Encryption

### 14.1 Key Derivation

When a `password` string is provided to the VM, every opcode byte and every
operand byte is XOR-encrypted using `security.SecureXOR*`. The key material is
derived from:

- The `password` string.
- `inslen` — the total byte length of the **main** instruction stream.
- `offset` — the absolute byte position of the byte being encrypted/decrypted.

This makes the key unique per byte position in the stream, so the same operand
value at different offsets produces different encrypted bytes.

### 14.2 Encryption in the VM Loop

Every single byte read from the instruction stream goes through decryption:

```go
// Opcode byte
opcodeByte, _ = security.SecureXOROneAt(ins[ip], int64(vm.inslen), vm.password, int64(ip))

// 2-byte operand
value, _ = code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))

// 1-byte operand
value, _ = code.ReadUint8(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
```

The `length` and `offset` arguments in `ReadUint16` / `ReadUint8` must match the
actual position of those bytes in the stream. A mismatch produces a wrong value
silently — there is no authentication tag.

### 14.3 No Encryption Path

When `password == ""` (the default for `vm.New`):

- `security.SecureXOROneAt(b, ...)` is a no-op that returns `b` unchanged.
- `ReadUint16` / `ReadUint8` still call the XOR functions but effectively just
  do `binary.BigEndian.Uint16`.

---

## 15. Runtime Security Features

### 15.1 Integrity Probes

The VM maintains `SHA-256` checksums of every `CompiledFunction`'s instruction
slice:

```go
frameIntegrity map[*object.CompiledFunction][32]byte
```

The checksum is computed at VM construction for the main function. For closures,
it is computed when the frame is first pushed.

**Probe schedule (jittered to frustrate timing analysis):**

```
integrityEvery  = 64 steps       (base interval for instruction-hash checks)
integrityJitter = XorShift64 PRNG seeded from SHA-256(mainInstructions)

nextProbeInterval = integrityEvery + (jitter % 31)
nextSweepInterval = 251 + (jitter % 83)
```

At each probe:

1. Recompute `SHA-256(frame.Instructions())`.
2. Compare to the stored checksum.
3. If mismatch → `security.RecordIntegrityFailure` + `ApplyTamperResponse`.

### 15.2 Control-Flow Integrity (CFI)

```go
frameBoundaries map[*object.CompiledFunction]map[int]struct{}
```

Before execution begins, `buildInstructionBoundaries` walks the encrypted
instruction stream and records the byte offset of every opcode (i.e., every
legal IP value). Jump targets are validated by checking whether the resolved
`ip` (or `ip+1` to account for the pre-decrement protocol) is in this set.

CFI is only active when `password != ""`.

### 15.3 Security Opcodes

| Opcode     | Trigger                                     | Secure mode behaviour        | Non-secure mode                 |
| ---------- | ------------------------------------------- | ---------------------------- | ------------------------------- |
| `OpChkDbg` | `security.IsDebuggerPresent()` returns true | Return `ErrDebuggerDetected` | Log warning to stderr, continue |
| `OpChkSnd` | `security.IsSandboxed()` returns true       | Return `ErrSandboxDetected`  | Log warning to stderr, continue |

`secureMode = true` for any VM constructed with `NewWithPassword*`.
`secureMode = false` for plain `vm.New`.

### 15.4 Tamper Response

`security.ApplyTamperResponse(event, stage, secureMode, err)` is the central
tamper handler:

- If `secureMode` → return the error immediately (halts the VM).
- If not `secureMode` → log a warning, return `nil` (execution continues).

### 15.5 Secure Memory Cleanup

```go
vm.CleanupRuntimeSensitiveData(clearGlobals bool, clearConstants bool)
vm.CleanupSensitiveData(clearGlobals bool)  // alias: always clears constants
```

These zero-out the stack, optionally the globals, and optionally zero and nil
the `CompiledFunction.Instructions` byte slices using `security.SecureZero`
(which prevents the compiler from optimising the wipe away). The password string
is also cleared.

Intended to be called immediately after `vm.Run()` returns, before the `VM`
object is GC'd.

### 15.6 Polymorphic Marker Stripping

When a password-encrypted `ByteCode` was produced with the polymorphic engine,
the last 2 bytes of the main instruction stream encode `[0xFF, level]` (or
`[level, 0xFF]`). On VM construction (`stripEncryptedPolymorphicMarker`):

1. Those 2 bytes are decrypted.
2. If the pattern matches, the instruction slice is trimmed.
3. The integrity checksum is updated to the trimmed slice.

---

## 16. Polymorphic Mutation Engine

> All mutation flags in `getConfig()` are currently **gated off** (all return
> `false`). The infrastructure is in place but disabled pending instruction-
> boundary-aware rewriting in the VM runtime. The marker and detection code are
> active.

### 16.1 Engine Configuration

```go
type PolymorphicEngine struct {
    mutationLevel int          // 0 = disabled, 1–10 = intensity
    randomSeed    int64        // for reproducible builds
    rng           *mathrand.Rand
}
```

Constructed with `compiler.EnablePolymorphism(level)` (random seed via
`crypto/rand`) or `EnablePolymorphismWithSeed(level, seed)` (deterministic).

### 16.2 Mutation Pipeline

```
ByteCode.Mutate(bc):
    if InsertNOPs       → insertNOPs(bc.Instructions)
    if MutateOpcodes    → mutateOpcodes(bc)
    if RandomizeConstants → randomizeConstantPool(bc)
    append PolymorphicMarker
```

### 16.3 NOP Insertion

Inserts push-then-pop sequences at random positions:

```
OpNull  + OpPop
OpTrue  + OpPop
OpFalse + OpPop
```

Rate: `level × 1.5 %` of instructions. Uses `crypto/rand` for the insertion
decision (not the deterministic RNG).

### 16.4 Opcode Remapping

A Fisher-Yates shuffle of all 39 opcode values using the deterministic RNG
creates a bijective mapping `original → shuffled`. Every opcode byte in the
instruction stream and in all `CompiledFunction` constants is rewritten through
this mapping.

> **Not yet active:** the VM has no corresponding remapping table, so any
> remapped bytecode would be misinterpreted.

### 16.5 Constant Pool Randomisation

Fisher-Yates shuffle of the constant pool using the deterministic RNG. All
`OpConstant` operands in the instruction stream and in compiled functions are
updated to reference the new indices.

> **Not yet active** for the same reason.

### 16.6 Polymorphic Marker Format

```
[... instructions ...][ 0xFF ][ level_byte ]
```

The marker is appended to `Instructions` **after** all mutations. It is
encrypted together with the rest of the bytecode when a password is used.

Detection:

```go
compiler.DetectPolymorphicLevel(instructions) int
```

Returns the level (0–10) or 0 if no valid marker is found.

---

## 17. Object Type System

### 17.1 Core Interface

```go
type Object interface {
    Type()    ObjectType   // string constant, e.g. "INTEGER"
    Inspect() string       // human-readable value
}
```

### 17.2 Object Types

| `ObjectType` constant | Go struct           | Notes                                                  |
| --------------------- | ------------------- | ------------------------------------------------------ |
| `INTEGER_OBJ`         | `*Integer`          | `Value int64`                                          |
| `FLOAT_OBJ`           | `*Float`            | `Value float64`                                        |
| `BOOLEAN_OBJ`         | `*Boolean`          | `Value bool`; singletons `global.True`, `global.False` |
| `NULL_OBJ`            | `*Null`             | singleton `global.Null`                                |
| `STRING_OBJ`          | `*String`           | `Value string`                                         |
| `ARRAY_OBJ`           | `*Array`            | `Elements []Object`                                    |
| `HASH_OBJ`            | `*Hash`             | `Pairs map[HashKey]HashPair`                           |
| `COMPILED_FN_OBJ`     | `*CompiledFunction` | `Instructions`, `NumLocals`, `NumParams`               |
| `CLOSURE_OBJ`         | `*Closure`          | `Fn *CompiledFunction`, `Free []Object`                |
| `BUILTIN_OBJ`         | `*Builtin`          | `Fn func(args ...Object) Object`                       |
| `FUNCTION_OBJ`        | `*Function`         | AST-level function (evaluator path only)               |
| `RETURN_VALUE_OBJ`    | `*ReturnValue`      | Sentinel (evaluator path only)                         |
| `ERROR_OBJ`           | `*Error`            | `Message string`                                       |
| `STRUCT_OBJ`          | `*Struct`           | `TypeName string`, `Fields map[string]Object`          |
| `ENUM_VALUE_OBJ`      | `*EnumValue`        | `TypeName`, `Tag string`, `Value *Integer` (ordinal)   |
| `ENCRYPTED_OBJ`       | `*Encrypted`        | `Value []byte` — XOR-encrypted payload                 |
| `BREAK_OBJ`           | `*Break`            | Control-flow sentinel                                  |
| `CONTINUE_OBJ`        | `*Continue`         | Control-flow sentinel                                  |
| `QUOTE_OBJ`           | `*Quote`            | Macro / meta-programming AST wrapper                   |
| `MACRO_OBJ`           | `*Macro`            | Macro object (evaluator path only)                     |
| `LUA_PATCH_OBJ`       | `*LuaPatch`         | Lua security patch payload                             |

### 17.3 `HashKey` Interface

For types usable as hash keys, the object must implement:

```go
type Hashable interface {
    HashKey() HashKey
}

type HashKey struct {
    Type  ObjectType
    Value uint64
}
```

Implemented by `Integer`, `Boolean`, and `String`.

### 17.4 `CompiledFunction`

```go
type CompiledFunction struct {
    Instructions code.Instructions   // bytecode for this function's body
    NumLocals    int                 // number of local variables (stack slots)
    NumParams    int                 // number of parameters
}
```

`NumLocals` includes the parameters (parameters are the first `NumParams`
locals). The VM advances `stackPointer` by `NumLocals` when entering a frame to
pre-allocate the local variable slots.

---

## 18. VM Constructor Variants

| Constructor                                                   | Password | SecureMode   | Globals  | Notes                                    |
| ------------------------------------------------------------- | -------- | ------------ | -------- | ---------------------------------------- |
| `vm.New(bc)`                                                  | —        | `true`       | fresh    | Plain execution; no CFI                  |
| `vm.NewWithPassword(bc, pw)`                                  | ✓        | `true`       | fresh    | Full security; enforces security opcodes |
| `vm.NewWithPasswordMode(bc, pw, mode)`                        | ✓        | configurable | fresh    |                                          |
| `vm.NewWithGlobalStore(bc, globals)`                          | —        | `true`       | provided | REPL: share globals across compilations  |
| `vm.NewWithGlobalStoreAndPassword(bc, globals, pw)`           | ✓        | `true`       | provided |                                          |
| `vm.NewWithPasswordAndGlobalStore(bc, pw, globals)`           | ✓        | `true`       | provided |                                          |
| `vm.NewWithPasswordAndGlobalStoreMode(bc, pw, globals, mode)` | ✓        | configurable | provided | Maximum flexibility                      |

"SecureMode = true" means security violations abort execution. "false" means
they emit a warning to stderr and continue.

---

## 19. Common Pitfalls

### P1: Reading Encrypted Operands Without Decryption

**Wrong:**

```go
idx := binary.BigEndian.Uint16(ins[ip+1 : ip+3])
```

**Correct:**

```go
idx, err := code.ReadUint16(ins[ip+1:], int64(vm.inslen), vm.password, int64(ip+1))
```

Applies to every operand read inside the VM's `Run()` loop, including opcode
bytes themselves.

### P2: Jump Off-by-One

Jumps set `ip = target - 1`, not `ip = target`. The main loop does `ip++`
_before_ fetching. If you set `ip = target`, the VM skips the first byte of the
target instruction.

### P3: `OpHash` Operand is 2× Pair Count

`OpHash n` expects `n/2` key-value pairs, so `n` is always even. The compiler
emits `len(node.Pairs) * 2`. The VM pops exactly `n` objects to build the hash.
Confusing pair count with element count causes a stack underflow.

### P4: Struct Field Pop Order

`OpMakeStruct` pops fields in **reverse** order (last field first). The compiler
must push field values in **forward declaration order**. The mapping inside the
VM is:

```go
fieldName := fieldNames[fieldCount-1-i]  // i=0 → last field; i=fieldCount-1 → first field
```

### P5: `OpSetField` Consumes and Re-Pushes the Struct

```
stack: [..., structObj, value]
OpSetField: pop value, pop struct, mutate struct.Fields[name], push struct
```

The struct reference is consumed and re-pushed. Code after `OpSetField` has the
(mutated) struct on top of the stack. If the mutation result is not needed, emit
`OpPop` to discard it.

### P6: `inslen` Must Match the Main Function's Byte Length

The `inslen` field used in all XOR decryption calls is set once to
`len(bc.Instructions)` (the main function's length) and never changes, even when
executing inner closures. Inner functions' operands are decrypted with the same
key parameter. This is by design — changing it for inner functions would break
operand decryption.

### P7: Do Not Disassemble Encrypted Bytecode with `Instructions.String()`

`Instructions.String()` uses the unencrypted `ReadOperands` path. On encrypted
bytecode it will produce garbage output or crash. Use it only in tests or
non-password compilation paths.
