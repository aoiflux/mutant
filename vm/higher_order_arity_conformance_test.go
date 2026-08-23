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
// That probe is blind to the builtins the executor runs itself. For the
// closure-calling ones -- map/filter/reduce/each/sort_by, pmap/peach, spawn --
// the registered Fn is a stub (builtin/higher_order.go) that only explains they
// must be applied inside a running program, so it never sees an argument count.
// callBuiltin intercepts them through builtin.ExecutorNativeKind before the stub
// is reached, which means the real argument-count check lives here in the VM.
// This test closes that gap by driving every intercepted builtin the way a
// program does, so a signature that drifts from applyExecutorNative still fails
// the suite.

// higherOrderCall renders a call to name with n arguments that are valid in
// shape, so the only thing wrong with the call is how many there are.
//
// Most of them start (array, function); reduce takes a third seed value and
// pmap/peach an optional worker count, and nothing takes a fourth, so any extra
// positions are filled with a plain integer. The callback takes two parameters
// because reduce's is called with an accumulator and an element, and the others
// tolerate a second parameter (they pass the index). serve_conn and serve_arg
// take nothing at all, so they are only ever probed with one argument too many,
// and what fills that position does not matter.
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

// executorNativeBuiltinNames lists every builtin the executors intercept, read
// from the registry rather than hardcoded, so a newly intercepted builtin is
// covered here the moment it is registered instead of quietly going unchecked.
func executorNativeBuiltinNames() []string {
	var names []string
	for _, entry := range builtin.Builtins {
		if builtin.ExecutorNativeKind(entry.Builtin) != "" {
			names = append(names, entry.Name)
		}
	}
	return names
}

// TestExecutorNativeArityMatchesExecutor requires the VM to reject every argument
// count the builtin's signature forbids. A disagreement means the signature is
// narrower than the implementation, which is the direction that turns into a
// warning on correct code.
func TestExecutorNativeArityMatchesExecutor(t *testing.T) {
	for _, name := range executorNativeBuiltinNames() {
		t.Run(name, func(t *testing.T) {
			signature, _, _, ok := builtin.TeachingDoc(name)
			if !ok {
				t.Fatalf("%s has no teaching doc", name)
			}
			_, params, ok := builtin.ParseSignature(signature)
			if !ok {
				t.Fatalf("%s has an unparseable signature %q", name, signature)
			}
			returns, ok := builtin.ReturnSpec(name)
			if !ok {
				t.Fatalf("%s has no declared return contract", name)
			}
			pairShaped := returns.Pair

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
				errObj, isError := errorFromResult(result, pairShaped)
				if !isError {
					t.Errorf("%s: signature forbids %d arguments but %s returned %s; the signature disagrees with applyExecutorNative",
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

// errorFromResult reads the error a call reported, from wherever the builtin's
// declared return shape puts it: a bare *object.Error for the collection
// operations, or the second slot of the (value, err) pair for spawn. Taking the
// shape from the metadata rather than assuming one keeps this test honest about
// what each builtin actually promises.
func errorFromResult(result object.Object, pairShaped bool) (*object.Error, bool) {
	if !pairShaped {
		errObj, ok := result.(*object.Error)
		return errObj, ok
	}
	multi, ok := result.(*object.MultiValue)
	if !ok || len(multi.Values) != 2 {
		return nil, false
	}
	errObj, ok := multi.Values[1].(*object.Error)
	return errObj, ok
}
