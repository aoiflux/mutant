package compiler

import (
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/parser"
)

// Macros are expanded into ordinary AST before compilation. If expansion is
// skipped, the macro literal used to reach codegen, where the compiler had no
// case for it and silently emitted nothing -- leaving the `let` with no value on
// the stack. The VM then popped past the bottom of the stack and brought the
// process down with an index-out-of-range panic. Compiling must report the
// problem instead.
func TestCompilingAnUnexpandedMacroIsAnErrorNotAPanic(t *testing.T) {
	inputs := []string{
		`let m = macro() { quote(1 + 2); }; m();`,
		`let unless = macro(cond, body) { quote(if (!unquote(cond)) { unquote(body) }); };`,
		`macro(x) { quote(unquote(x)); };`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Compile(%q) panicked: %v", input, r)
				}
			}()

			program := parser.New(lexer.New(input)).ParseProgram()

			err := New().Compile(program)
			if err == nil {
				t.Fatalf("Compile(%q) succeeded; an unexpanded macro must be rejected", input)
			}
			if !strings.Contains(err.Error(), "macro") {
				t.Fatalf("Compile(%q) error = %q, want it to name the macro problem", input, err)
			}
		})
	}
}
