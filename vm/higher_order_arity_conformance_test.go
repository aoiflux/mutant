package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/object"
)

// The language server derives its argument-count diagnostic from the teaching
// signatures in the builtin package, and builtin's own conformance probe checks
// them by calling each registered Fn with an illegal count.
//
// That probe is blind to map/filter/reduce/each/sort_by. Their registered Fn is
// a stub (builtin/higher_order.go) that only explains they must be applied
// inside a running program, because they call user closures and so must be run
// by an executor. callBuiltin intercepts them through builtin.HigherOrderKind
// before the stub is reached, which means the real argument-count check lives
// here in the VM. This test closes that gap by driving them the way a program
// does, so a signature that drifts from applyHigherOrder still fails the suite.

// higherOrderCall renders a call to name with n arguments that are valid in
// shape, so the only thing wrong with the call is how many there are.
//
// All five builtins start (array, function); reduce takes a third seed value
// and nothing takes a fourth, so any extra positions are filled with a plain
// integer. The callback takes two parameters because reduce's is called with an
// accumulator and an element, and the others tolerate a second parameter (they
// pass the index).
func higherOrderCall(name string, n int) string {
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		switch i {
		case 0:
			args = append(args, "[1]")
		case 1:
			args = append(args, "fn(a, b) { a }")
		default:
			args = append(args, "0")
		}
	}
	return fmt.Sprintf("%s(%s)", name, strings.Join(args, ", "))
}

// TestHigherOrderArityMatchesExecutor requires the VM to reject every argument
// count the builtin's signature forbids. A disagreement means the signature is
// narrower than the implementation, which is the direction that turns into a
// warning on correct code.
func TestHigherOrderArityMatchesExecutor(t *testing.T) {
	for _, name := range []string{"map", "filter", "reduce", "each", "sort_by"} {
		t.Run(name, func(t *testing.T) {
			signature, _, _, ok := builtin.TeachingDoc(name)
			if !ok {
				t.Fatalf("%s has no teaching doc", name)
			}
			_, params, ok := builtin.ParseSignature(signature)
			if !ok {
				t.Fatalf("%s has an unparseable signature %q", name, signature)
			}
			minArgs, maxArgs := builtin.SignatureArity(params)
			if maxArgs < 0 {
				t.Fatalf("%s is documented as variadic (%q); this test assumes a bounded arity", name, signature)
			}

			for _, n := range []int{minArgs - 1, maxArgs + 1} {
				if n < 0 {
					continue
				}

				source := higherOrderCall(name, n)
				machine, err := runEncryptedVM(source)
				if err != nil {
					t.Errorf("%s: %s failed to run: %v", signature, source, err)
					continue
				}

				result := machine.LastPoppedStackElement()
				errObj, isError := result.(*object.Error)
				if !isError {
					t.Errorf("%s: signature forbids %d arguments but %s returned %s; the signature disagrees with applyHigherOrder",
						signature, n, source, result.Type())
					continue
				}
				// The executors phrase this as "want N arguments (...)" rather
				// than the builtin package's "wrong number of arguments".
				if !strings.Contains(errObj.Message, "arguments") {
					t.Errorf("%s: %s returned %q, which does not read as an argument-count error",
						signature, source, errObj.Message)
				}
			}
		})
	}
}
