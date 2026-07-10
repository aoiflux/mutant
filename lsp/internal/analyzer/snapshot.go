package analyzer

import (
	mast "mutant/ast"
	"mutant/parser"
)

type Snapshot struct {
	Source      string
	Program     *mast.Program
	ParseErrors []parser.ParseError
}
