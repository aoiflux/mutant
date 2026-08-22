package analyzer

import (
	"sync"

	mast "mutant/ast"
	"mutant/parser"
)

// Snapshot is a parsed view of one document.
//
// ParseErrors are hard failures: the tree cannot be trusted and the formatter
// falls back to whitespace normalisation. Recoverables are problems the
// parser repaired around — missing or redundant semicolons — which leave the
// tree fully usable. Keeping the two apart is what lets the formatter fix a
// missing `;` instead of bailing out on it.
type Snapshot struct {
	Source       string
	Program      *mast.Program
	ParseErrors  []parser.ParseError
	Recoverables []parser.RecoverableError

	// typeMap is the lazily-built, best-effort type of each confidently-typed AST
	// node (see infer.go). It powers hover/completion/inlay type info and has no
	// runtime effect. Built once via typeOnce.
	typeOnce sync.Once
	typeMap  map[mast.Node]Type
}

// types returns the inferred type map, building it once on first use.
func (s *Snapshot) types() map[mast.Node]Type {
	if s == nil {
		return nil
	}
	s.typeOnce.Do(func() {
		s.typeMap = inferTypes(s)
	})
	return s.typeMap
}

// TypeOf returns the inferred type of an AST node and whether one was inferred.
func (s *Snapshot) TypeOf(node mast.Node) (Type, bool) {
	m := s.types()
	if m == nil {
		return AnyType, false
	}
	t, ok := m[node]
	return t, ok
}

// SemicolonProblems returns the recoverable semicolon issues in source order.
// It exists so diagnostics and code actions do not have to know how
// recoverables are stored.
func (s *Snapshot) SemicolonProblems() []parser.RecoverableError {
	if s == nil {
		return nil
	}
	return s.Recoverables
}
