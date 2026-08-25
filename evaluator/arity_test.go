package evaluator

import (
	"strings"
	"testing"

	"mutant/lexer"
	"mutant/object"
	"mutant/parser"
)

// Calling a function with the wrong number of arguments used to index the
// argument slice positionally while binding parameters, so an under-applied
// call crashed the process with an index-out-of-range panic instead of
// reporting the mistake. Macro bodies are evaluated through this path, so the
// crash was reachable from ordinary source.
func TestCallArityIsReportedNotPanicked(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "too few arguments", input: `let f = fn(a, b) { a + b; }; f(1);`},
		{name: "no arguments at all", input: `let f = fn(a, b) { a + b; }; f();`},
		{name: "too many arguments", input: `let f = fn(a) { a; }; f(1, 2, 3);`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Eval(%q) panicked: %v", tt.input, r)
				}
			}()

			program := parser.New(lexer.New(tt.input)).ParseProgram()
			result := Eval(program, object.NewEnvironment())

			errObj, ok := result.(*object.Error)
			if !ok {
				t.Fatalf("Eval(%q) = %T (%v), want *object.Error", tt.input, result, result)
			}
			if !strings.Contains(errObj.Message, "wrong number of arguments") {
				t.Fatalf("Eval(%q) error = %q, want it to mention the argument count", tt.input, errObj.Message)
			}
		})
	}
}
