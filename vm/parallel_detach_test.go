package vm

import (
	"testing"

	"mutant/object"
)

// M26-VM-004. The parallel builtins promise that a worker's writes stay local,
// and until this test existed that promise held for exactly one shape: a
// variable the callback itself captured. Every other route to the same cell
// reached the caller's copy, from eight goroutines, with no synchronisation --
// `go test -race` reported six races on the shapes below and none after.
//
// Each case is written so the leak shows up as a number rather than as a flaky
// failure: the callback writes through some route to a cell the caller also
// holds, and the caller reads it afterwards. Under share-nothing the caller's
// value is the one it started with. Before the fix these answered 6, 7, 2, 4, 3
// and 6 respectively -- lost updates, which is what an unsynchronised
// accumulator looks like when it does not crash.
func TestParallelWorkersDoNotShareCellsThroughNestedClosures(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			// The route the row was opened for: the callback captures `bump`,
			// and `bump` captures `n`. Detaching the callback's own cells gives
			// the worker its own `bump` cell, holding the caller's `bump` --
			// whose `n` cell was still the caller's.
			name: "a closure reached through a captured variable",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				pmap([1, 2, 3, 4, 5, 6, 7, 8], fn(x) { return bump(); }, 4);
				return n;
			}; probe()`,
			want: 0,
		},
		{
			// A global: snapshotGlobals copies the slice, and a slot holding a
			// closure copies the closure's pointer, cells and all. The caller's
			// counter must still read 1 on its own first call.
			name: "a closure held in a global",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			pmap([1, 2, 3, 4, 5, 6, 7, 8], fn(x) { return tick(); }, 4);
			tick()`,
			want: 1,
		},
		{
			// spawn's argument was never detached at all: only the task closure
			// was. A task outlives the call, so this one is a write racing the
			// caller's next instruction rather than a write while it waits.
			name: "a closure passed as spawn's argument",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				let t, e = spawn(fn(g) { g(); g(); return 0; }, bump);
				task_wait(t);
				return n;
			}; probe()`,
			want: 0,
		},
		{
			// The elements are the caller's array contents, handed to a worker
			// one at a time.
			name: "a closure handed to the callback as an element",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				pmap([bump, bump, bump, bump], fn(f) { return f(); }, 4);
				return n;
			}; probe()`,
			want: 0,
		},
		{
			// A container between the capture and the closure. The comment this
			// fix removed said a captured array "is still the same array in
			// both" and treated that as harmless; it is the vector.
			name: "a closure inside a captured array",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				let fns = [bump];
				pmap([1, 2, 3, 4], fn(x) { return fns[0](); }, 4);
				return n;
			}; probe()`,
			want: 0,
		},
		{
			name: "a closure inside a captured hash",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				let h = {"go": bump};
				pmap([1, 2, 3, 4], fn(x) { return h["go"](); }, 4);
				return n;
			}; probe()`,
			want: 0,
		},
		{
			// A recursive function's cell holds the closure that holds the
			// cell. Walking it without a memo filled before the descent does
			// not return; this case is why the memo is filled first.
			name: "a closure that captures itself",
			input: `let probe = fn() {
				let hits = 0;
				let rec = fn(k) { hits = hits + 1; if (k > 0) { return rec(k - 1); }; return hits; };
				pmap([1, 2], fn(x) { return rec(2); }, 2);
				return hits;
			}; probe()`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("vm error: %s", err)
			}
			if err := testIntegerObject(int64(tc.want), machine.LastPoppedStackElement()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Detaching must not go so far that it changes the program's own aliasing. One
// variable in the caller is one variable in the worker, however many ways the
// worker can reach it -- otherwise a program run in parallel would see state
// split in two, which is a different bug of the same family.
func TestWorkerCellsKeepTheProgramsOwnAliasing(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			// Two closures over one variable, both captured by the callback.
			// Two copies would make `read` answer 0 after two bumps.
			name: "two closures over one variable stay one variable",
			input: `let probe = fn() {
				let n = 0;
				let bump = fn() { n = n + 1; return n; };
				let read = fn() { return n; };
				return pmap([1], fn(x) { bump(); bump(); return read(); }, 1)[0];
			}; probe()`,
			want: 2,
		},
		{
			// One counter reached two ways: captured directly, and through a
			// global array that holds it. Two copies would answer 1.
			name: "one counter reached two ways is one counter",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			let both = [tick];
			let probe = fn() { return pmap([1], fn(x) { tick(); return both[0](); }, 1)[0]; };
			probe()`,
			want: 2,
		},
		{
			// One worker, four elements: its own counter is still its own
			// across all of them, so the detach happens once per worker and not
			// once per element.
			name: "a worker's own counter persists across its elements",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			let probe = fn() { let r = pmap([1, 2, 3, 4], fn(x) { return tick(); }, 1); return r[3]; };
			probe()`,
			want: 4,
		},
		{
			// A worker reads the value that existed at the call, which is the
			// other half of the documented rule.
			name: "a worker starts from the value the caller had reached",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			tick(); tick(); tick();
			let probe = fn() { return pmap([1], fn(x) { return tick(); }, 1)[0]; };
			probe()`,
			want: 4,
		},
		{
			// And the caller carries on from where it was, not from where a
			// worker left it.
			name: "the caller keeps counting from where it was",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			tick(); tick();
			pmap([1, 2, 3, 4], fn(x) { return tick(); }, 4);
			tick()`,
			want: 3,
		},
		{
			// A spawned task answers with its return value, and the caller's
			// counter is where the caller left it.
			name: "a spawned task's counter is its own",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; };
			let tick = make_counter();
			let t, e = spawn(fn() { tick(); tick(); return tick(); });
			let got, werr = task_wait(t);
			got + tick() * 10`,
			want: 13,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("vm error: %s", err)
			}
			if err := testIntegerObject(int64(tc.want), machine.LastPoppedStackElement()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// globalsHoldingCells is the one place the fix trades work for an assumption: a
// global slot it does not name is never detached. If it ever stopped naming a
// slot that can reach a cell, the global route would silently leak again and the
// tests above are the only thing that would catch it -- so the scan is held to
// its answer directly as well.
func TestGlobalsHoldingCellsNamesEveryGlobalThatCanReachACell(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			// Scalars, a string, an array and a hash: a program's ordinary
			// globals hold no cell, and the workers must be given nothing to do.
			name:  "ordinary globals hold no cell",
			input: `let a = 1; let s = "x"; let d = [1, 2, 3]; let h = {"k": 1}; a`,
			want:  0,
		},
		{
			// A top-level function with no captures is a closure with an empty
			// Free, which reaches no cell either.
			name:  "a function with no captures reaches no cell",
			input: `let f = fn(x) { return x + 1; }; f(1)`,
			want:  0,
		},
		{
			// A closure over a variable: one slot, the one holding it.
			name:  "a counter in a global is named",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; }; let tick = make_counter(); tick()`,
			want:  1,
		},
		{
			// The same counter in a global array: the slot holding the array,
			// because that is the slot a worker has to rebuild.
			name:  "a counter inside a global array is named",
			input: `let make_counter = fn() { let c = 0; return fn() { c = c + 1; return c; }; }; let tick = make_counter(); let fns = [tick]; fns[0]()`,
			want:  2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("vm error: %s", err)
			}
			holding := machine.globalsHoldingCells()
			if len(holding) != tc.want {
				t.Fatalf("globalsHoldingCells named %d slots (%v), want %d", len(holding), holding, tc.want)
			}
		})
	}
}

// A worker pays this walk on every start, so the walk has to be free when there
// is nothing to detach -- which for a globals slice of global.GlobalSize slots
// means not copying it. The property is pinned here rather than left to a
// benchmark, because a copy would still pass every test above.
func TestTheWorkerBoundaryDoesNotCopyWhatItDoesNotChange(t *testing.T) {
	boundary := newWorkerBoundary()

	values := []object.Object{
		&object.Integer{Value: 1},
		&object.String{Value: "x"},
		nil,
		&object.Array{Elements: []object.Object{&object.Integer{Value: 2}}},
		&object.Bytes{Value: []byte{1, 2, 3}},
	}

	detached, changed := boundary.elements(values)
	if changed {
		t.Fatal("elements reported a change over values that hold no cell")
	}
	if &detached[0] != &values[0] {
		t.Fatal("elements copied a slice it did not change")
	}

	// The containers inside it must come back as themselves too, or something
	// above them would have been rebuilt for nothing.
	array := values[3]
	if boundary.value(array) != array {
		t.Fatal("an array holding no cell was rebuilt")
	}

	// And the opposite: a cell is always replaced, and replaced once.
	cell := &object.Cell{Value: &object.Integer{Value: 7}}
	first := boundary.value(cell)
	if first == cell {
		t.Fatal("a cell was not detached")
	}
	if second := boundary.value(cell); second != first {
		t.Fatal("the same cell was detached twice")
	}
	if replacement, ok := first.(*object.Cell); !ok {
		t.Fatalf("a detached cell is a %T", first)
	} else if integer, ok := replacement.Value.(*object.Integer); !ok || integer.Value != 7 {
		t.Fatalf("a detached cell lost its value: %v", replacement.Value)
	}
}
