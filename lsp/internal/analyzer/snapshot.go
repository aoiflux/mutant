package analyzer

import (
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
