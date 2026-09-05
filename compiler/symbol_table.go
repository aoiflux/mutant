package compiler

import "sort"

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

	// builtinRefs is the table an OpGetBuiltin operand indexes into: the names
	// of the builtins this compilation unit actually referenced, in first-use
	// order. Only the root table's copy is ever used; see ReferenceBuiltin.
	builtinRefs []string
	builtinRef  map[string]int
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

func (st *SymbolTable) Define(name string) Symbol {
	symbol := Symbol{Name: name, Index: st.numDefinitions}
	if st.Outer == nil {
		symbol.Scope = GlobalScope
	} else {
		symbol.Scope = LocalScope
	}
	st.store[name] = symbol
	st.numDefinitions++
	return symbol
}
func (st *SymbolTable) Resolve(name string) (Symbol, bool) {
	obj, ok := st.store[name]

	if !ok && st.Outer != nil {
		obj, ok = st.Outer.Resolve(name)
		if !ok {
			return obj, ok
		}

		if obj.Scope == GlobalScope || obj.Scope == BuiltinScope {
			return obj, ok
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
	for name, symbol := range st.store {
		if symbol.Scope == GlobalScope {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
