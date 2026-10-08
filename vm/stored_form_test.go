package vm

import (
	"fmt"
	"testing"

	"mutant/compiler"
	"mutant/global"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
)

// M26-VM-001 took an encrypt/decrypt round trip out of every variable read. A
// stack slot, a global and a cell all hold their value in storage form, so a
// read that only moves the value hands the stored object straight to the stack
// instead of opening it and sealing the result with the same key -- which is
// what push(decryptForUse(x)) was doing, two ChaCha20 passes and two
// allocations over the whole payload to arrive back where it started.
//
// For a sealed scalar the move is an identity: nothing in the dispatch loop
// mutates an *object.Encrypted. Teardown does -- clearObjectSensitiveData
// zeroes one in place -- so "in the dispatch loop" is load-bearing here and
// not a hedge, and it is why the third group below pins what teardown does to
// a shared value rather than assuming it leaves values alone.
//
// For a container it is an aliasing change, because a container's storage form
// is an *object.Array (or Hash, or Struct) holding sealed elements -- a real
// object, which two slots now point at where they used to point at two copies.
// What makes that safe is an invariant of the dispatch loop rather than of any
// one opcode:
//
//	nothing in this VM mutates a container in storage form.
//
// Every path that writes one takes its target from pop(), and pop() decrypts:
// mutil.DecryptObject allocates a new slice or map in every container arm, so
// the write lands on a fresh copy and is stored back into the binding that
// asked for it. Two types are deliberate exceptions and both are documented on
// both sides of mutil, because for them the stored form and the plaintext form
// are one object rather than two. An *object.Cell passes through sealing and
// opening by pointer, because a cell is the storage location a captured
// variable has and a fresh cell would be a second one. An *object.Iterator
// does the same, and there the consequence is sharper: OpIterNext peeks the
// cursor rather than popping it and advances it in place, so handing back a
// copy would restart every for-in loop at its first element forever. Neither
// is a container in the invariant's sense, which is why the invariant holds
// with both of them in the language.
//
// This file holds that invariant. The first group is what a program can see,
// the second is what the sealing layer can see, and the third is the two
// lifetimes the fix touches: a value that outlives the VM that sealed it, and a
// key that must not outlive the password it came from.
type aliasingCase struct {
	name string
	src  string
	want interface{}
}

// Each copy-then-write case is paired with the write through the variable's own
// name, because a fix that broke the second would pass the first: a VM that
// quietly dropped every container write would also report an untouched
// original.
var aliasingCases = []aliasingCase{
	// Locals, which is where OpGetLocal and OpSetLocal move a value -- the two
	// opcodes this fix changes most often.
	{"an array copied between locals",
		`let f = fn() { let a = [1, 2]; let b = a; b[0] = 9; return a[0]; }; f();`, 1},
	{"an array written through its own name",
		`let f = fn() { let a = [1, 2]; a[0] = 9; return a[0]; }; f();`, 9},
	{"a hash copied between locals",
		`let f = fn() { let a = {"k": 1}; let b = a; b["k"] = 9; return a["k"]; }; f();`, 1},
	{"a hash written through its own name",
		`let f = fn() { let a = {"k": 1}; a["k"] = 9; return a["k"]; }; f();`, 9},
	{"a struct copied between locals",
		`struct P { x; y; }; let f = fn() { let a = P { x: 1, y: 2 }; let b = a; b.x = 9; return a.x; }; f();`, 1},
	{"a struct written through its own name",
		`struct P { x; y; }; let f = fn() { let a = P { x: 1, y: 2 }; a.x = 9; return a.x; }; f();`, 9},

	// Globals, both ways. pushGlobal reads one without opening it and
	// setGlobalStored writes one without resealing it, so two globals can hold
	// one object where a global assignment used to build a fresh one. The
	// wrapper memory mode is the exception at both ends and keeps the old path.
	{"an array copied between globals", `let a = [1, 2]; let b = a; b[0] = 9; a[0];`, 1},
	{"an array written at the top level", `let a = [1, 2]; a[0] = 9; a[0];`, 9},
	{"a hash copied between globals", `let a = {"k": 1}; let b = a; b["k"] = 9; a["k"];`, 1},
	{"a struct copied between globals",
		`struct P { x; y; }; let a = P { x: 1, y: 2 }; let b = a; b.x = 9; a.x;`, 1},

	// A write through two containers, which is both the path that was silently
	// losing the value until the nested-assignment fix and the shape the
	// sweep's slowest example actually runs: it keeps a 3 MiB buffer in a
	// struct field, so every read of it moves a container.
	{"a nested array copied", `let a = [[1, 2]]; let b = a; b[0][0] = 9; a[0][0];`, 1},
	{"a nested array written", `let a = [[1, 2]]; a[0][0] = 9; a[0][0];`, 9},
	{"an array in a struct field copied",
		`struct S { data; }; let a = S { data: [1, 2] }; let b = a; b.data[0] = 9; a.data[0];`, 1},
	{"an array in a struct field written",
		`struct S { data; }; let a = S { data: [1, 2] }; a.data[0] = 9; a.data[0];`, 9},

	// A captured variable is the one thing that is deliberately shared, so both
	// halves say more here: the copy must not reach through the cell, and the
	// name must.
	{"a captured array copied",
		`let f = fn() { let a = [1, 2]; let g = fn() { let b = a; b[0] = 9; return 0; }; g(); return a[0]; }; f();`, 1},
	{"a captured array written",
		`let f = fn() { let a = [1, 2]; let g = fn() { a[0] = 9; return 0; }; g(); return a[0]; }; f();`, 9},

	// An argument arrives in a local slot, so a callee writing into one is the
	// copy case seen from the caller's side.
	{"an array passed to a function",
		`let g = fn(b) { b[0] = 9; return 0; }; let f = fn() { let a = [1, 2]; g(a); return a[0]; }; f();`, 1},
	{"the callee's own view of that write", `let g = fn(b) { b[0] = 9; return b[0]; }; g([1, 2]);`, 9},

	// A buffer takes the sealed path rather than the container path, and its
	// elements are bytes: execSetIndex writes into the slice itself, so the
	// copy that write lands on had better be a fresh one.
	{"a buffer copied", `let a, e = string_to_bytes("ab", "utf8"); let b = a; b[0] = 9; a[0];`, 97},
	{"a buffer written", `let a, e = string_to_bytes("ab", "utf8"); a[0] = 9; a[0];`, 9},
}

func TestWritingThroughACopyLeavesTheOriginalAlone(t *testing.T) {
	for _, tt := range aliasingCases {
		t.Run(tt.name, func(t *testing.T) {
			runVMTests(t, []vmTestCase{{tt.src, tt.want}})
		})
	}
}

// storedFormLeak walks what a slot, a global or a cell holds and returns the
// first value sitting in the clear, or nil when everything is covered.
//
// It is unprotected() from storage_encryption_test.go plus the two shapes a
// stack walk meets that a globals walk does not. A cell passes through sealing
// by pointer, so it is followed rather than judged. The three singletons carry
// no payload and are compared by identity wherever they are read, and
// boxCapturedSlots deliberately boxes an unwritten capture around global.Null.
func storedFormLeak(obj object.Object) object.Object {
	if obj == global.Null || obj == global.True || obj == global.False {
		return nil
	}
	if cell, ok := obj.(*object.Cell); ok {
		return storedFormLeak(cell.Value)
	}
	return unprotected(obj)
}

// TestMovingAValueBetweenSlotsLeavesNothingInTheClear runs the same programs
// again and inspects what the VM left behind rather than what it returned.
//
// This is the half of the fix a result cannot show. pushStored hands a stored
// object to the stack without looking at it, so if any slot, global or cell
// ever held a plaintext value, the next read of it would spread that value
// rather than seal it. Both the globals array and the whole stack are walked:
// a returned frame's slots are not cleared, and a memory scrape finds them
// there.
//
// The programs above are loop-free on purpose. An *object.Iterator passes
// through sealing by pointer like a cell does, and a `for` loop would leave one
// on the stack for this walk to find.
func TestMovingAValueBetweenSlotsLeavesNothingInTheClear(t *testing.T) {
	for _, tt := range aliasingCases {
		t.Run(tt.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tt.src)
			if err != nil {
				t.Fatalf("run: %s", err)
			}

			held := 0
			for i, value := range machine.globals {
				if value == nil {
					continue
				}
				held++
				if leak := storedFormLeak(value); leak != nil {
					t.Errorf("global %d holds %s in the clear: %s", i, leak.Type(), leak.Inspect())
				}
			}
			for i, value := range machine.stack {
				if value == nil {
					continue
				}
				held++
				if leak := storedFormLeak(value); leak != nil {
					t.Errorf("stack slot %d holds %s in the clear: %s", i, leak.Type(), leak.Inspect())
				}
			}
			if held == 0 {
				t.Fatal("the program left nothing behind; the walk proves nothing")
			}
		})
	}
}

// runWithGlobals compiles and runs one program against a globals slice that
// outlives it, with a password that outlives it too and a symbol table that
// carries bindings forward. That is the REPL, in repl.go: a new VM per line,
// one password for the session, and an instruction length that changes with
// every line.
//
// The instruction length is the seed every value is sealed under, so a global
// stored by one line is sealed under a seed the next line's VM does not have.
// That is what *object.Encrypted.Seed records, and what mutil.sealKey refuses
// to answer for with a stream derived under a different one.
func runWithGlobals(t *testing.T, src string, password string, table *compiler.SymbolTable,
	constants *[]object.Object, globals []object.Object) object.Object {
	t.Helper()

	comp := compiler.NewWithState(table, *constants)
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile %q: %s", src, err)
	}

	byteCode := comp.ByteCode()
	*constants = byteCode.Constants
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := NewWithGlobalStoreAndPassword(byteCode, globals, password)
	if err := machine.Run(); err != nil {
		t.Fatalf("run %q: %s", src, err)
	}
	return machine.LastPoppedStackElement()
}

// TestAGlobalOutlivesTheVMThatSealedIt is the case where handing the VM its own
// derived key could have gone silently wrong.
//
// The key is derived from (inslen, password). The REPL keeps one password and
// one global store across lines while compiling a new program for each, so a
// global is routinely read by a VM whose seed is not the one the value was
// sealed under -- and a stream that answered anyway would hand back plausible
// bytes rather than an error. The lines below differ in length on purpose.
func TestAGlobalOutlivesTheVMThatSealedIt(t *testing.T) {
	password := mutil.GetPwd()
	table := compiler.NewSymbolTable()
	constants := []object.Object{}
	globals := make([]object.Object, global.GlobalSize)

	runWithGlobals(t, `let secret = "across";`, password, table, &constants, globals)
	runWithGlobals(t, `let padding = 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9;`, password, table, &constants, globals)

	last := runWithGlobals(t, `secret;`, password, table, &constants, globals)
	str, ok := last.(*object.String)
	if !ok {
		t.Fatalf("a global sealed by an earlier program came back as %T (%v)", last, last)
	}
	if str.Value != "across" {
		t.Errorf("the global read back as %q, want %q", str.Value, "across")
	}

	// And a container, which is what the fix hands over by pointer.
	runWithGlobals(t, `let shared = [1, 2, 3];`, password, table, &constants, globals)
	runWithGlobals(t, `let more = "a longer line, so the instruction length moves again";`,
		password, table, &constants, globals)

	last = runWithGlobals(t, `shared[1];`, password, table, &constants, globals)
	num, ok := last.(*object.Integer)
	if !ok {
		t.Fatalf("an element of a container sealed earlier came back as %T (%v)", last, last)
	}
	if num.Value != 2 {
		t.Errorf("the element read back as %d, want 2", num.Value)
	}
}

// TestAGlobalSurvivesTheStackBeingReleased is the regression this kit's own
// stack gate found, and the case TestAGlobalOutlivesTheVMThatSealedIt above
// misses.
//
// The REPL does two things between lines: it keeps one global store, and it
// calls CleanupRuntimeSensitiveData(false, false) -- clean the stack, keep the
// globals. Those used to be two object graphs and are now one, because a value
// that is only moving is moved: OpSetGlobal hands the stack's own object to the
// global, and pop leaves its pointer in the slot it vacated. So a wipe of the
// whole backing array reached a live global.
//
// It was found as kit 13's TestTheReplDoesNotEchoClassifiedPlaintext failing in
// the stacked tree, where record_seal was handed a range hash with no pairs at
// all and refused it for having no "offset" -- one line after the line that
// built it. A hash is what shows it: clearObjectSensitiveData deletes a map's
// entries in place, so an emptied hash comes back as {} and reads like a value,
// where an emptied integer comes back as an error.
//
// The other half of the contract -- that the globals do go when the caller asks
// for them -- is TestTeardownStillWipesAValueTwoSlotsShare, below.
func TestAGlobalSurvivesTheStackBeingReleased(t *testing.T) {
	password := mutil.GetPwd()
	table := compiler.NewSymbolTable()
	constants := []object.Object{}
	globals := make([]object.Object, global.GlobalSize)

	runReleasingTheStack(t, `let span = {"offset": 10, "length": 20};`,
		password, table, &constants, globals)
	// A line of a different length, so the next VM's seed is not the one the
	// hash was sealed under either.
	runReleasingTheStack(t, `let padding = "a line of some other length";`,
		password, table, &constants, globals)

	last := runReleasingTheStack(t, `span["offset"];`, password, table, &constants, globals)
	num, ok := last.(*object.Integer)
	if !ok {
		t.Fatalf("a hash global read after the stack was released came back as %T (%v)", last, last)
	}
	if num.Value != 10 {
		t.Errorf("the global read back as %d, want 10", num.Value)
	}

	// The shape, not just the one key: an emptied hash answers nothing, so a
	// second read of the same global is what a builtin handed the hash would do.
	last = runReleasingTheStack(t, `span["length"];`, password, table, &constants, globals)
	if num, ok := last.(*object.Integer); !ok || num.Value != 20 {
		t.Errorf("the second key read back as %v, want 20", last)
	}
}

// runReleasingTheStack is runWithGlobals plus the call the REPL makes between
// lines. The last popped element is taken before the release, because
// LastPoppedStackElement reads the slot above the stack pointer and the release
// drops it.
func runReleasingTheStack(t *testing.T, src string, password string, table *compiler.SymbolTable,
	constants *[]object.Object, globals []object.Object) object.Object {
	t.Helper()

	comp := compiler.NewWithState(table, *constants)
	if err := comp.Compile(parse(src)); err != nil {
		t.Fatalf("compile %q: %s", src, err)
	}

	byteCode := comp.ByteCode()
	*constants = byteCode.Constants
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := NewWithGlobalStoreAndPassword(byteCode, globals, password)
	if err := machine.Run(); err != nil {
		t.Fatalf("run %q: %s", src, err)
	}

	last := machine.LastPoppedStackElement()
	machine.CleanupRuntimeSensitiveData(false, false)
	return last
}

// TestTeardownStillWipesAValueTwoSlotsShare covers the one place that does
// write a stored container in place.
//
// clearObjectSensitiveData walks what it is given and zeroes it, and aliasing
// means it now reaches the same object twice where it used to reach two copies.
// That is fine because the walk is idempotent, which is worth a test rather
// than an assumption: the second pass meets the nils the first one left.
func TestTeardownStillWipesAValueTwoSlotsShare(t *testing.T) {
	machine, err := runEncryptedVM(`let a = [1, 2]; let b = a; b[0];`)
	if err != nil {
		t.Fatalf("run: %s", err)
	}

	machine.CleanupRuntimeSensitiveData(true, false)
	machine.CleanupRuntimeSensitiveData(true, false)

	for i := range machine.globals {
		if machine.globals[i] != nil {
			t.Fatalf("global %d survived the teardown", i)
		}
	}
	if machine.password != "" {
		t.Error("the teardown left the password behind")
	}
}

// TestARunAfterATeardownStillOpensItsOwnValues follows the key's lifetime.
//
// The teardown zeroes the derived stream along with the password it came from,
// and the REPL calls it after every line. A run that follows one must therefore
// derive again -- and a cleared key that was still being used would not fail,
// it would decrypt to rubbish.
func TestARunAfterATeardownStillOpensItsOwnValues(t *testing.T) {
	first, err := runEncryptedVM(`let a = ["x", "y"]; a[1];`)
	if err != nil {
		t.Fatalf("first run: %s", err)
	}
	first.CleanupRuntimeSensitiveData(true, false)

	runVMTests(t, []vmTestCase{
		{`let a = ["x", "y"]; a[1];`, "y"},
		{`let s = "after the wipe"; s;`, "after the wipe"},
	})
}

// TestTheValueStreamIsTheInstructionStream states the identity the fix rests
// on, rather than leaving it to be re-derived by whoever reads the two names:
// an object's payload and an instruction byte are covered by one key per run.
func TestTheValueStreamIsTheInstructionStream(t *testing.T) {
	machine, err := runEncryptedVM(`let a = 1; a;`)
	if err != nil {
		t.Fatalf("run: %s", err)
	}
	if machine.valueStream() != machine.instructionStream() {
		t.Error("the values and the instructions are using two derived keys")
	}

	// The seal path is handed that stream, so what it produces must be what the
	// deriving path produces. mutil holds the equivalence test; this one is
	// here because it is the VM's own call that has to stay in step with it.
	sealed := machine.encryptForStorage(&object.String{Value: "same either way"})
	derived, err := mutil.EncryptObject(&object.String{Value: "same either way"},
		machine.inslen, machine.password)
	if err != nil {
		t.Fatalf("derive: %s", err)
	}

	streamed, ok := sealed.(*object.Encrypted)
	if !ok {
		t.Fatalf("the VM sealed a string into %T", sealed)
	}
	reference, ok := derived.(*object.Encrypted)
	if !ok {
		t.Fatalf("mutil sealed a string into %T", derived)
	}
	if fmt.Sprintf("%x", streamed.Value) != fmt.Sprintf("%x", reference.Value) {
		t.Errorf("the stream sealed %x where deriving gives %x", streamed.Value, reference.Value)
	}
	if streamed.Seed != reference.Seed {
		t.Errorf("the stream recorded seed %d where deriving records %d",
			streamed.Seed, reference.Seed)
	}
}

// A sanity check on the test above: security.DerivePasswordFromInstructions is
// what runVMTests uses, so the VM under test has a password at all.
func TestTheTestHarnessGivesTheVMAPassword(t *testing.T) {
	machine, err := runEncryptedVM(`let a = 1; a;`)
	if err != nil {
		t.Fatalf("run: %s", err)
	}
	if machine.password == "" {
		t.Fatal("the harness ran a VM with no password; every sealing test above proves nothing")
	}
	if _, err := security.SecureXOR([]byte("x"), int64(machine.inslen), machine.password); err != nil {
		t.Fatalf("the VM's own key does not derive: %s", err)
	}
}
