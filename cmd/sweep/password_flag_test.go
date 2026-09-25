package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// refusedPasswordFlags are the argv spellings mutant refuses since 2.6.0. Every
// sweep run that passed one would fail before running its example, and the
// sweep would report the whole examples tree broken for a reason in the sweep.
var refusedPasswordFlags = map[string]bool{
	"--password": true, "-password": true, "--pwd": true, "-pwd": true,
}

// TestSweepNeverPassesARefusedPasswordFlag: the sweep hands its build password
// to mutant with --password-insecure, the explicit opt-in. Its password is a
// public constant, so argv exposure costs nothing here, but the bare flag is
// refused outright.
func TestSweepNeverPassesARefusedPasswordFlag(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sweeper.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	optIns := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if refusedPasswordFlags[value] {
			t.Errorf("%s passes %s, which mutant refuses; use --password-insecure", fset.Position(lit.Pos()), value)
		}
		if value == "--password-insecure" {
			optIns++
		}
		return true
	})
	if optIns == 0 {
		t.Error("sweeper.go never passes --password-insecure; update this test if the sweep now hands mutant its password another way")
	}
}
