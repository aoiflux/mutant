package sema

import "mutant/ast"

// SymKind is what a declaration declares.
//
// It is deliberately coarser than the language server's CompletionItemKind and
// narrower than the compiler's SymbolScope: those describe how a name is
// presented and where its slot lives, which are the two things this package is
// careful not to decide.
type SymKind uint8

const (
	SymValue SymKind = iota
	SymFunction
	SymStruct
	SymEnum
)

// ExportFact is one top-level declaration, as seen from outside its module.
//
// It carries only what a reach from another file can legitimately use. In
// particular it carries no ast.Node: a fact about a module travels to every
// module that imports it, and nothing in this package may hold a node belonging
// to a file other than its own. DeclRange is a position inside the declaring
// file and is meaningless without knowing which file that is, so it is only
// ever read alongside the module key that produced it.
type ExportFact struct {
	Name string
	Kind SymKind

	// Private is IsModulePrivate(Name), precomputed because every consumer
	// filters on it.
	Private bool

	// DeclRange is the identifier's own range, file-local. It is the zero value
	// on the compile path, which has no use for it.
	DeclRange ast.Range
}
