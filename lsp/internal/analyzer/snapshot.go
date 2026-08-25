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
	// runtime effect. Built once via typeOnce. structFields (structName ->
	// fieldName -> Type) is built in the same pass and backs struct field-type
	// hover/completion detail.
	typeOnce     sync.Once
	typeMap      map[mast.Node]Type
	structFields map[string]map[string]Type

	// solvedOnce guards the constraint solver in fn_solver.go, which works out
	// each user function's parameter kinds from how its body uses them. It runs
	// before inference rather than inside it, because inference consumes its
	// result: a parameter solved to a single kind is seeded into the function's
	// scope, so the body — and therefore the return type — can be typed from it.
	solvedOnce sync.Once
	solvedFns  map[*mast.FunctionLiteral]*solvedFunction
}

// solvedFunctions returns the solved parameter kinds for every user function in
// the document, building them once on first use.
func (s *Snapshot) solvedFunctions() map[*mast.FunctionLiteral]*solvedFunction {
	if s == nil {
		return nil
	}
	s.solvedOnce.Do(func() {
		s.solvedFns = solveFunctionParams(s.Program)
	})
	return s.solvedFns
}

// types returns the inferred type map, building it once on first use.
func (s *Snapshot) types() map[mast.Node]Type {
	if s == nil {
		return nil
	}
	s.typeOnce.Do(func() {
		s.typeMap, s.structFields = inferTypes(s)
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

// StructFieldType returns a struct field's inferred type, present only when every
// initializer of that struct in the document agreed on one known type for it. It
// backs field-type detail in hover and member completion; zero runtime effect.
func (s *Snapshot) StructFieldType(structName, field string) (Type, bool) {
	if s == nil {
		return AnyType, false
	}
	s.types() // ensure the inference pass has run and populated structFields
	m, ok := s.structFields[structName]
	if !ok {
		return AnyType, false
	}
	t, ok := m[field]
	if !ok || !t.IsKnown() {
		return AnyType, false
	}
	return t, true
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
