package compiler

import (
	"sort"
	"strings"

	"mutant/sema"
)

type SymbolScope string

const (
	GlobalScope   SymbolScope = "GLOBAL"
	LocalScope    SymbolScope = "LOCAL"
	BuiltinScope  SymbolScope = "BUILTIN"
	FreeScope     SymbolScope = "FREE"
	FunctionScope SymbolScope = "FUNCTION"
)

type Symbol struct {
	Name  string
	Scope SymbolScope
	Index int
}

type SymbolTable struct {
	Outer          *SymbolTable
	store          map[string]Symbol
	numDefinitions int
	FreeSymbols    []Symbol

	// capturedLocals is the set of this table's own local slots that some inner
	// function closed over. It is populated by Resolve at the moment a capture
	// is discovered, which is the only moment the information exists: the outer
	// function is mid-compilation and may already have emitted plain
	// OpGetLocal/OpSetLocal for the slot, so the compiler patches those to their
	// cell forms once the scope closes. See Compiler.boxCapturedLocals.
	//
	// A set, not a slice, because a variable captured by three inner functions
	// is still one slot and must be boxed once.
	capturedLocals map[int]bool

	// builtinRefs is the table an OpGetBuiltin operand indexes into: the names
	// of the builtins this compilation unit actually referenced, in first-use
	// order. Only the root table's copy is ever used; see ReferenceBuiltin.
	builtinRefs []string
	builtinRef  map[string]int

	// currentModule is the module whose top level is being compiled right now.
	// Only the root table's copy is read, for the same reason builtinRefs is:
	// a module's top level and the bodies of the functions it declares are one
	// module, however deeply the enclosed tables nest.
	//
	// The empty string means "no modules", which is the state every REPL,
	// playground and test compiler stays in. It makes qualify a no-op, so a
	// program that never imports anything is stored and resolved exactly as it
	// was before modules existed.
	currentModule string

	// moduleNamespaces maps a module key to the namespaces that module's
	// imports bound, and each of those to the key of the module it names.
	//
	// It is keyed by importer because a namespace is not global: two files may
	// both import something called `util` and mean two different files, and
	// each has to see its own.
	moduleNamespaces map[string]map[string]string
}

// moduleSeparator joins a module key to a top-level name to form the key that
// name is stored under. NUL is used because it is the one byte that can appear
// in neither an identifier nor a path, so a qualified key can never collide
// with an unqualified one.
//
// It is sema's constant rather than its own so that sema.DeclID.String and
// qualify cannot drift: the graph identifies a top-level declaration by the
// very key the symbol table files it under, and a parity test compares the two
// as strings. Two separately-declared bytes that happen to be equal today
// would make that comparison meaningless.
const moduleSeparator = sema.ModuleSeparator

// qualify returns the store key that module's top-level name is filed under.
//
// With no module -- the REPL, the playground, a single file compiled by a test
// -- the key is the bare name, which is what makes module scoping invisible to
// every caller that does not use it.
func qualify(module, name string) string {
	if module == "" {
		return name
	}
	return module + moduleSeparator + name
}

// IsModulePrivate reports whether a top-level name is visible only inside the
// module that declares it. A leading underscore is the entire rule: there is no
// export list to keep in step with the code, and the mark travels with every
// mention of the name rather than living in one place far away from it.
//
// The rule itself lives in sema, because the editor has to apply exactly this
// one and cannot import the compiler. This forwards rather than repeating it:
// two copies of an export rule is how a language server comes to offer a name
// the build will refuse.
func IsModulePrivate(name string) bool {
	return sema.IsModulePrivate(name)
}

func NewSymbolTable() *SymbolTable {
	s := make(map[string]Symbol)
	free := []Symbol{}
	return &SymbolTable{store: s, FreeSymbols: free}
}

func NewEnclosedSymbolTable(outer *SymbolTable) *SymbolTable {
	s := NewSymbolTable()
	s.Outer = outer
	return s
}

// Define allocates a slot for name in this table.
//
// At the root -- and only there -- the store key is qualified by the module
// being compiled, so two modules may each declare `helper` without one silently
// overwriting the other. Symbol.Name stays the bare name: it is what error
// messages print, what the builtin intern table keys on, and what defineFree
// files a capture under.
func (st *SymbolTable) Define(name string) Symbol {
	symbol := Symbol{Name: name, Index: st.numDefinitions}
	key := name
	if st.Outer == nil {
		symbol.Scope = GlobalScope
		key = qualify(st.currentModule, name)
	} else {
		symbol.Scope = LocalScope
	}
	st.store[key] = symbol
	st.numDefinitions++
	return symbol
}

// DefineInternal claims a slot the compiler needs and no source line can name.
//
// It is Define with an empty Symbol.Name, which is the existing contract for "a
// slot with nothing to show": the debugger, the REPL's completion and the name
// tables all read Symbol.Name, and a compiler temporary is not a variable anyone
// wrote. key still has to be unique within the table, because the store is keyed
// by it -- callers use a spelling no lexer will produce.
func (st *SymbolTable) DefineInternal(key string) Symbol {
	symbol := Symbol{Index: st.numDefinitions}
	storeKey := key
	if st.Outer == nil {
		symbol.Scope = GlobalScope
		storeKey = qualify(st.currentModule, key)
	} else {
		symbol.Scope = LocalScope
	}
	st.store[storeKey] = symbol
	st.numDefinitions++
	return symbol
}

// ResolveInternal finds a slot DefineInternal claimed, so one compilation scope
// reuses its temporary rather than claiming a new slot per assignment.
func (st *SymbolTable) ResolveInternal(key string) (Symbol, bool) {
	storeKey := key
	if st.Outer == nil {
		storeKey = qualify(st.currentModule, key)
	}
	symbol, ok := st.store[storeKey]
	return symbol, ok
}
func (st *SymbolTable) Resolve(name string) (Symbol, bool) {
	obj, ok := st.own(name)

	if !ok && st.Outer != nil {
		obj, ok = st.Outer.Resolve(name)
		if !ok {
			return obj, ok
		}

		if obj.Scope == GlobalScope || obj.Scope == BuiltinScope {
			return obj, ok
		}

		// The capture is discovered here, on the way back out, and this is where
		// the owning table gets told about it. A LocalScope original means
		// st.Outer owns the slot, so st.Outer is what has to box it. A FreeScope
		// original means st.Outer had already captured the variable itself, and
		// the recursive Resolve that produced it has already marked whichever
		// table truly owns the slot -- so the marking propagates outward on its
		// own, which is what makes a capture two functions deep work.
		//
		// A FunctionScope original -- an inner function referring to the
		// enclosing function's own name for recursion -- is not a slot at all,
		// and deliberately gets no marking: it is loaded with OpCurrentClosure
		// and captured by value, because a function's own name cannot be
		// reassigned.
		if obj.Scope == LocalScope {
			st.Outer.markCaptured(obj.Index)
		}

		free := st.defineFree(obj)
		return free, true
	}

	return obj, ok
}

// root walks out to the table that owns the compilation unit. The builtin
// reference table lives there rather than on each enclosing scope so that a
// builtin called inside a function body and the same builtin called at the top
// level intern to one entry.
func (st *SymbolTable) root() *SymbolTable {
	for st.Outer != nil {
		st = st.Outer
	}
	return st
}

// own reads this table's own store, without walking outward.
//
// At the root of a modular program the current module's own top level is tried
// first and the bare name second. The bare name is what builtins are filed
// under -- DefineBuiltin writes them unqualified precisely so that every module
// can see them -- so the two-step is "my module, then the builtins", which is
// the whole of a module's global scope. Nothing else is stored bare at the root
// once a module is set, so one module's names cannot leak into another's
// through the fallback.
func (st *SymbolTable) own(name string) (Symbol, bool) {
	if st.Outer == nil && st.currentModule != "" {
		if obj, ok := st.store[qualify(st.currentModule, name)]; ok {
			return obj, true
		}
	}
	obj, ok := st.store[name]
	return obj, ok
}

// SetCurrentModule makes key the module that Define files top-level names under
// and that Resolve reads them back from. Pass the empty string to compile with
// no module scoping at all.
//
// The key has to be stable and unique across one program; the linker uses each
// file's canonical absolute path.
func (st *SymbolTable) SetCurrentModule(key string) {
	st.root().currentModule = key
}

// CurrentModule returns the key set by SetCurrentModule, or "" when the program
// has no modules.
func (st *SymbolTable) CurrentModule() string {
	return st.root().currentModule
}

// BindNamespace records that, inside the module currently being compiled, the
// name namespace refers to the module filed under key.
func (st *SymbolTable) BindNamespace(namespace, key string) {
	root := st.root()
	if root.moduleNamespaces == nil {
		root.moduleNamespaces = make(map[string]map[string]string)
	}
	bindings, ok := root.moduleNamespaces[root.currentModule]
	if !ok {
		bindings = make(map[string]string, 2)
		root.moduleNamespaces[root.currentModule] = bindings
	}
	bindings[namespace] = key
}

// LookupNamespace returns the module key that namespace names inside the module
// currently being compiled.
func (st *SymbolTable) LookupNamespace(namespace string) (string, bool) {
	root := st.root()
	key, ok := root.moduleNamespaces[root.currentModule][namespace]
	return key, ok
}

// ResolveIn resolves name as a top-level definition of the module filed under
// key, whichever module is currently being compiled. It is the lookup behind
// `ns.name`, and deliberately does not walk outward: another module's locals
// and captures are not addressable, only its top level.
func (st *SymbolTable) ResolveIn(key, name string) (Symbol, bool) {
	obj, ok := st.root().store[qualify(key, name)]
	return obj, ok
}

// ModuleNames returns the top-level names the module filed under key declares,
// sorted, with the module-private ones left out. Editor completion behind `ns.`
// wants exactly this list.
func (st *SymbolTable) ModuleNames(key string) []string {
	root := st.root()
	prefix := qualify(key, "")
	names := make([]string, 0, 8)
	for stored, symbol := range root.store {
		if symbol.Scope != GlobalScope || !strings.HasPrefix(stored, prefix) {
			continue
		}
		if IsModulePrivate(symbol.Name) {
			continue
		}
		names = append(names, symbol.Name)
	}
	sort.Strings(names)
	return names
}

// ReferenceBuiltin interns name and returns the operand OpGetBuiltin should
// carry for it. Repeated references to one builtin share an index.
//
// The table lives on the symbol table, not on the Compiler, because a REPL keeps
// one symbol table and one constant pool across lines while building a fresh
// Compiler for each of them. A closure compiled on line 1 and called on line 3
// still holds line 1's operands, so whatever those operands index has to outlive
// the Compiler that emitted them. Interning is append-only for the same reason:
// an index, once emitted, can never be made to mean something else.
func (st *SymbolTable) ReferenceBuiltin(name string) int {
	root := st.root()
	if root.builtinRef == nil {
		root.builtinRef = make(map[string]int)
	}
	if index, seen := root.builtinRef[name]; seen {
		return index
	}
	index := len(root.builtinRefs)
	root.builtinRefs = append(root.builtinRefs, name)
	root.builtinRef[name] = index
	return index
}

// ReferencedBuiltins returns a copy of the interned table for the compiler to
// ship in the bytecode -- a copy, because the caller stores it in a *ByteCode
// that may outlive further compilation against the same symbol table.
func (st *SymbolTable) ReferencedBuiltins() []string {
	root := st.root()
	names := make([]string, len(root.builtinRefs))
	copy(names, root.builtinRefs)
	return names
}

func (st *SymbolTable) DefineBuiltin(index int, name string) Symbol {
	symbol := Symbol{Name: name, Index: index, Scope: BuiltinScope}
	st.store[name] = symbol
	return symbol
}

func (st *SymbolTable) DefineFunctionName(name string) Symbol {
	symbol := Symbol{Name: name, Index: 0, Scope: FunctionScope}
	st.store[name] = symbol
	return symbol
}

// markCaptured records that local slot index of this table is closed over by
// some inner function and therefore has to live in a cell.
func (st *SymbolTable) markCaptured(index int) {
	if st.capturedLocals == nil {
		st.capturedLocals = make(map[int]bool)
	}
	st.capturedLocals[index] = true
}

// CapturedLocals returns this table's boxed slot indices in ascending order.
// Sorted because it travels in the bytecode as CompiledFunction.CapturedLocals,
// and a map's iteration order would make one program compile to two different
// .mu files.
func (st *SymbolTable) CapturedLocals() []int {
	if len(st.capturedLocals) == 0 {
		return nil
	}
	indices := make([]int, 0, len(st.capturedLocals))
	for index := range st.capturedLocals {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices
}

// IsCaptured reports whether local slot index of this table is boxed.
func (st *SymbolTable) IsCaptured(index int) bool { return st.capturedLocals[index] }

func (st *SymbolTable) defineFree(original Symbol) Symbol {
	st.FreeSymbols = append(st.FreeSymbols, original)
	symbol := Symbol{Name: original.Name, Index: len(st.FreeSymbols) - 1}
	symbol.Scope = FreeScope
	st.store[original.Name] = symbol
	return symbol
}

// GlobalNames returns the names defined in this table's global scope, excluding
// builtins. A REPL session uses it to offer the user's own bindings as
// completion candidates, the way object.Environment.Keys() does for the
// tree-walking path.
func (st *SymbolTable) GlobalNames() []string {
	names := make([]string, 0, len(st.store))
	for _, symbol := range st.store {
		if symbol.Scope == GlobalScope {
			// symbol.Name, not the store key: at the root of a modular program
			// the key carries a module qualifier that no user ever typed.
			names = append(names, symbol.Name)
		}
	}
	sort.Strings(names)
	return names
}

// LocalSlotNames returns this table's local slots as a slice indexed by slot,
// each entry the name declared there and empty where there is none to report.
//
// A slot loses its name when a later declaration takes the name over, since the
// store is keyed by name and holds one symbol per key. `let x = 1; let x = 2;`
// allocates two slots; the second answers to `x` and the first answers to
// nothing, which is the honest reading -- the alternative is a debugger showing
// two variables called `x`, one of them unreachable from any source line.
//
// nil at the root, where the definitions are globals rather than locals:
// GlobalSlotNames answers for those.
func (st *SymbolTable) LocalSlotNames() []string {
	if st.Outer == nil || st.numDefinitions == 0 {
		return nil
	}
	return slotNames(st.store, LocalScope, st.numDefinitions)
}

// GlobalSlotNames returns the program's global slots as a slice indexed by
// slot, under the same contract LocalSlotNames describes.
//
// Symbol.Name, not the store key: at the root of a modular program the key
// carries a module qualifier that no user ever typed. Builtins are skipped
// because DefineBuiltin allocates them no slot -- their index is a registry
// ordinal in a different space, and letting one through would overwrite the
// name of whichever global happens to hold that slot.
func (st *SymbolTable) GlobalSlotNames() []string {
	root := st.root()
	if root.numDefinitions == 0 {
		return nil
	}
	return slotNames(root.store, GlobalScope, root.numDefinitions)
}

// slotNames projects a store onto a slice indexed by slot, keeping only the
// symbols in the scope that owns those slots. Out-of-range indices are dropped
// rather than grown into: a scope's slot count comes from its own definition
// counter, and a symbol claiming a slot past it is in the wrong table.
func slotNames(store map[string]Symbol, scope SymbolScope, count int) []string {
	names := make([]string, count)
	populated := false
	for _, symbol := range store {
		if symbol.Scope != scope || symbol.Index < 0 || symbol.Index >= count {
			continue
		}
		// A nameless symbol is a compiler temporary (see DefineInternal). It
		// holds a slot but answers to nothing, so it leaves its entry empty and
		// does not on its own make the table worth reporting -- a function whose
		// only slot is a temporary has no variables to show.
		if symbol.Name == "" {
			continue
		}
		names[symbol.Index] = symbol.Name
		populated = true
	}
	if !populated {
		return nil
	}
	return names
}

// freeOriginal returns the outer symbol that this table's free variable index
// captures. The compiler uses it to tell an ordinary captured variable, which
// lives in a cell and can be assigned, from the enclosing function's own name,
// which is captured by value and cannot.
func (st *SymbolTable) freeOriginal(index int) (Symbol, bool) {
	if index < 0 || index >= len(st.FreeSymbols) {
		return Symbol{}, false
	}
	return st.FreeSymbols[index], true
}
