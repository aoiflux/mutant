package vm

import (
	"fmt"
	"strings"
	"testing"

	"mutant/object"
)

// pmap must agree with map on every result and on their order. Work is handed
// out from a shared cursor, so workers finish out of order; the results still
// have to land back in the input's positions.
func TestPMapMatchesMap(t *testing.T) {
	cases := []string{
		`[1, 2, 3]`,
		`[5, 3, 8, 1, 9, 2, 7, 4, 6, 0]`,
		`[]`,
		`[42]`,
	}

	for _, arr := range cases {
		t.Run(arr, func(t *testing.T) {
			body := `fn(x) { x * 2 + 1 }`

			sequential, err := runEncryptedVM(fmt.Sprintf("map(%s, %s)", arr, body))
			if err != nil {
				t.Fatalf("map failed: %s", err)
			}
			parallel, err := runEncryptedVM(fmt.Sprintf("pmap(%s, %s)", arr, body))
			if err != nil {
				t.Fatalf("pmap failed: %s", err)
			}

			want := sequential.LastPoppedStackElement().Inspect()
			got := parallel.LastPoppedStackElement().Inspect()
			if got != want {
				t.Fatalf("pmap(%s) = %s, want map's %s", arr, got, want)
			}
		})
	}
}

// Ordering is the property most easily lost when work is distributed, so pin it
// on a larger array with a callback whose cost varies by element.
func TestPMapPreservesOrderUnderUnevenWork(t *testing.T) {
	// Elements early in the array do more work than later ones, so workers
	// genuinely finish out of order.
	input := `
		let spin = fn(n) {
			let total = 0;
			for (let i = 0; i < n; i++) { total += i; }
			return total;
		};
		let xs = range(0, 200);
		pmap(xs, fn(x, i) { spin(200 - i); return x; }, 8)
	`

	machine, err := runEncryptedVM(input)
	if err != nil {
		t.Fatalf("pmap failed: %s", err)
	}

	arr, ok := machine.LastPoppedStackElement().(*object.Array)
	if !ok {
		t.Fatalf("pmap returned %T, want *object.Array", machine.LastPoppedStackElement())
	}
	if len(arr.Elements) != 200 {
		t.Fatalf("pmap returned %d elements, want 200", len(arr.Elements))
	}
	for i, el := range arr.Elements {
		got, ok := el.(*object.Integer)
		if !ok {
			t.Fatalf("element %d is %T, want *object.Integer", i, el)
		}
		if got.Value != int64(i) {
			t.Fatalf("element %d = %d, want %d (results landed out of order)", i, got.Value, i)
		}
	}
}

// Each worker is a separate VM over the same compiled program, so the machinery
// that lets a callback see its captured and global environment has to keep
// working across that boundary.
func TestPMapCallbackEnvironment(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []int
	}{
		{
			name:  "globals are visible to workers",
			input: `let n = 100; pmap([1, 2, 3], fn(x) { x + n })`,
			want:  []int{101, 102, 103},
		},
		{
			name:  "captured free variables survive the worker boundary",
			input: `let adder = fn(n) { fn(x) { x + n } }; pmap([1, 2, 3], adder(10))`,
			want:  []int{11, 12, 13},
		},
		{
			name:  "two-parameter callbacks receive the index",
			input: `pmap([10, 20, 30], fn(x, i) { x + i })`,
			want:  []int{10, 21, 32},
		},
		{
			name:  "callbacks may allocate containers",
			input: `pmap([1, 2, 3], fn(x) { let h = {"v": x * 3}; let a = [h["v"]]; a[0] })`,
			want:  []int{3, 6, 9},
		},
		{
			name:  "a nested sequential map inside a parallel one",
			input: `pmap([1, 2], fn(x) { reduce(map([1, 1], fn(y) { y }), fn(a, b) { a + b }, x) })`,
			want:  []int{3, 4},
		},
		{
			name:  "explicit worker count",
			input: `pmap([1, 2, 3, 4], fn(x) { x * x }, 3)`,
			want:  []int{1, 4, 9, 16},
		},
		{
			name:  "more workers requested than elements",
			input: `pmap([7], fn(x) { x + 1 }, 64)`,
			want:  []int{8},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("pmap failed: %s", err)
			}
			arr, ok := machine.LastPoppedStackElement().(*object.Array)
			if !ok {
				t.Fatalf("got %T, want *object.Array", machine.LastPoppedStackElement())
			}
			if len(arr.Elements) != len(tc.want) {
				t.Fatalf("got %d elements, want %d", len(arr.Elements), len(tc.want))
			}
			for i, want := range tc.want {
				got, ok := arr.Elements[i].(*object.Integer)
				if !ok {
					t.Fatalf("element %d is %T, want *object.Integer", i, arr.Elements[i])
				}
				if got.Value != int64(want) {
					t.Fatalf("element %d = %d, want %d", i, got.Value, want)
				}
			}
		})
	}
}

// peach runs for side effects and yields null. Workers get a globals snapshot,
// so the documented way to collect results is a shared store, not a global.
func TestPEachRunsForSideEffectsAndReturnsNull(t *testing.T) {
	machine, err := runEncryptedVM(`peach([1, 2, 3], fn(x) { x * 2 })`)
	if err != nil {
		t.Fatalf("peach failed: %s", err)
	}
	if _, ok := machine.LastPoppedStackElement().(*object.Null); !ok {
		t.Fatalf("peach returned %s, want NULL", machine.LastPoppedStackElement().Inspect())
	}
}

// Argument problems are catchable values, matching map/filter/reduce, rather
// than aborting the run.
func TestParallelArgumentValidation(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`pmap(5, fn(x) { x })`, "pmap: first argument must be ARRAY, got INTEGER"},
		{`pmap([1], 7)`, "pmap: second argument must be a function, got INTEGER"},
		{`pmap([1], fn(x) { x }, "eight")`, "pmap: third argument (workers) must be INTEGER, got STRING"},
		{`pmap([1], fn(x) { x }, 0)`, "pmap: workers must be at least 1, got 0"},
		{`pmap([1], fn(x) { x }, -3)`, "pmap: workers must be at least 1, got -3"},
		{`pmap([1])`, "pmap: want 2 or 3 arguments (array, function[, workers]), got 1"},
		{`pmap([1], fn(x) { x }, 2, 3)`, "pmap: want 2 or 3 arguments (array, function[, workers]), got 4"},
		{`pmap([1], fn(a, b, c) { a })`, "pmap: function must take 1 or 2 parameters (element[, index]), got 3"},
		{`peach(5, fn(x) { x })`, "peach: first argument must be ARRAY, got INTEGER"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("expected a catchable error value, got a run failure: %s", err)
			}
			errObj, ok := machine.LastPoppedStackElement().(*object.Error)
			if !ok {
				t.Fatalf("got %T (%s), want *object.Error", machine.LastPoppedStackElement(), machine.LastPoppedStackElement().Inspect())
			}
			if errObj.Message != tc.want {
				t.Fatalf("error = %q, want %q", errObj.Message, tc.want)
			}
		})
	}
}

// A runtime failure inside one element's callback must stop the whole call and
// surface, not be swallowed by the worker that hit it.
func TestPMapPropagatesCallbackRuntimeError(t *testing.T) {
	_, err := runEncryptedVM(`pmap([1, 2, 0, 4], fn(x) { 10 / x })`)
	if err == nil {
		t.Fatal("expected the division-by-zero inside the callback to surface")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "zero") {
		t.Fatalf("error = %q, want it to report the division by zero", err)
	}
}

// The workers share one compiled program: the instruction stream and the
// constants pool. Reading those is pure, but a worker that ran the VM's cleanup
// sweep would zero constants its siblings are still decrypting. Hammer a
// callback that forces plenty of constant decryption, with far more elements
// than workers, so any such corruption shows up. Run under -race for the rest.
func TestPMapDoesNotCorruptSharedConstants(t *testing.T) {
	input := `
		let xs = range(0, 500);
		let out = pmap(xs, fn(x) {
			let h = {"a": "constant-string", "b": [1, 2, 3], "c": 2.5};
			let a = h["b"];
			return x + a[0] + a[1] + a[2];
		}, 16);
		reduce(out, fn(acc, v) { acc + v }, 0)
	`

	machine, err := runEncryptedVM(input)
	if err != nil {
		t.Fatalf("pmap over shared constants failed: %s", err)
	}

	// sum(0..499) + 500*(1+2+3) = 124750 + 3000
	const want = 127750
	got, ok := machine.LastPoppedStackElement().(*object.Integer)
	if !ok {
		t.Fatalf("got %T, want *object.Integer", machine.LastPoppedStackElement())
	}
	if got.Value != want {
		t.Fatalf("sum = %d, want %d (a worker likely corrupted shared state)", got.Value, want)
	}
}

// pmap must remain usable from inside another callback: the outer call's worker
// VM is itself the parent of the inner call's workers.
func TestNestedPMap(t *testing.T) {
	machine, err := runEncryptedVM(`pmap([1, 2, 3], fn(x) { reduce(pmap([1, 2], fn(y) { y * x }), fn(a, b) { a + b }, 0) })`)
	if err != nil {
		t.Fatalf("nested pmap failed: %s", err)
	}

	arr, ok := machine.LastPoppedStackElement().(*object.Array)
	if !ok {
		t.Fatalf("got %T, want *object.Array", machine.LastPoppedStackElement())
	}
	for i, want := range []int64{3, 6, 9} {
		got, ok := arr.Elements[i].(*object.Integer)
		if !ok || got.Value != want {
			t.Fatalf("element %d = %v, want %d", i, arr.Elements[i].Inspect(), want)
		}
	}
}
