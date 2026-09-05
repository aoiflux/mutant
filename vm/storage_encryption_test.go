package vm

import (
	"testing"

	"mutant/object"
)

// unprotected walks a stored value and returns the first thing sitting in the
// clear, or nil when everything is covered.
//
// Containers are sealed element-wise rather than as a whole -- an array at rest
// is still an *object.Array, holding *object.Encrypted elements -- so a check
// that only looked at the top-level type would call every array protected.
func unprotected(obj object.Object) object.Object {
	switch value := obj.(type) {
	case nil:
		return nil
	case *object.Encrypted:
		return nil
	case *object.Array:
		for _, element := range value.Elements {
			if leak := unprotected(element); leak != nil {
				return leak
			}
		}
		return nil
	case *object.MultiValue:
		for _, element := range value.Values {
			if leak := unprotected(element); leak != nil {
				return leak
			}
		}
		return nil
	case *object.Hash:
		for _, pair := range value.Pairs {
			if leak := unprotected(pair.Value); leak != nil {
				return leak
			}
		}
		return nil
	case *object.Struct:
		for _, field := range value.Fields {
			if leak := unprotected(field); leak != nil {
				return leak
			}
		}
		return nil
	case *object.Closure, *object.CompiledFunction:
		// Code, not data at rest; see the pass-through arm in mutil.EncryptObject.
		return nil
	default:
		return obj
	}
}

// TestGlobalsAreEncryptedAtRest runs real programs and inspects what the VM
// actually left in its globals array.
//
// Globals are the values that live for the whole run, which makes them what a
// memory scrape finds. Every one of these cases used to store its value in
// plaintext, and none of them failed while doing so: mutil.EncryptObject
// returned an error, encryptForStorage discarded it, and the plaintext object
// was stored with nothing said.
func TestGlobalsAreEncryptedAtRest(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"string", `let g = "secret";`},
		// One empty element used to fail the whole container, because the array
		// arm propagates a child's error and the caller then keeps the plaintext
		// array -- siblings included.
		{"array holding an empty string", `let g = ["", "secret"];`},
		{"hash holding an empty string", `let g = {"a": "", "b": "secret"};`},
		// A multi-value is what every (value, err) call produces.
		{"bound multi-value", `let f = fn() { return 1, "secret"; }; let g = f();`},
		{"array holding a multi-value", `let f = fn() { return 1, 2; }; let g = [f(), "secret"];`},
		// An error carries the path that failed in its Message.
		{"bound error", `let v, g = fs_read("/no/such/path/for/a/test");`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm, err := runEncryptedVM(tt.src)
			if err != nil {
				t.Fatalf("run: %s", err)
			}

			stored := 0
			for i, global := range vm.globals {
				if global == nil {
					continue
				}
				stored++
				if leak := unprotected(global); leak != nil {
					t.Errorf("global %d holds %s in the clear: %s",
						i, leak.Type(), leak.Inspect())
				}
			}
			if stored == 0 {
				t.Fatal("the program stored no global; the test proves nothing")
			}
		})
	}
}

// Encryption at rest is only worth having if the value still reads back, so
// these run the same shapes through to a result.
func TestEncryptedGlobalsStillReadBack(t *testing.T) {
	runVMTests(t, []vmTestCase{
		{`let g = ["", "secret"]; g[1];`, "secret"},
		{`let g = ["", "secret"]; g[0];`, ""},
		{`let g = {"a": "", "b": "secret"}; g["b"];`, "secret"},
		{`let f = fn() { return 1, 2; }; let g = f(); g[1];`, 2},
		{`let f = fn() { return 1, 2; }; let g = [f(), 9]; g[1];`, 9},
	})
}

// An error survives storage with its fields intact -- the position and the
// context are what a report is built from, and they travel inside the sealed
// payload rather than beside it.
func TestStoredErrorKeepsItsFields(t *testing.T) {
	vm, err := runEncryptedVM(`let v, e = fs_read("/no/such/path/for/a/test"); let g = e;`)
	if err != nil {
		t.Fatalf("run: %s", err)
	}

	var restored *object.Error
	for i := range vm.globals {
		if vm.globals[i] == nil {
			continue
		}
		if errObj, ok := vm.decryptForUse(vm.globals[i]).(*object.Error); ok {
			restored = errObj
		}
	}
	if restored == nil {
		t.Fatal("no error survived storage")
	}

	if restored.Message == "" {
		t.Error("the restored error lost its message")
	}
	if restored.Context == "" {
		t.Error("the restored error lost its context")
	}
	if restored.Line <= 0 {
		t.Errorf("the restored error lost its position: line %d", restored.Line)
	}
}
