package vm

import (
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/object"
)

// pairValues splits a (value, err) result and fails the test if the shape is
// wrong, so every assertion below can talk about the value alone.
func pairValues(t *testing.T, result object.Object) (object.Object, object.Object) {
	t.Helper()
	multi, ok := result.(*object.MultiValue)
	if !ok {
		t.Fatalf("result is %T (%s), want a (value, err) pair", result, result.Inspect())
	}
	if len(multi.Values) != 2 {
		t.Fatalf("result pair has %d values, want 2", len(multi.Values))
	}
	return multi.Values[0], multi.Values[1]
}

// runForInteger runs a program whose last expression is an integer.
func runForInteger(t *testing.T, source string) int64 {
	t.Helper()
	machine, err := runEncryptedVM(source)
	if err != nil {
		t.Fatalf("program failed: %s\nsource: %s", err, source)
	}
	result := machine.LastPoppedStackElement()
	got, ok := result.(*object.Integer)
	if !ok {
		t.Fatalf("program returned %s, want an INTEGER\nsource: %s", result.Inspect(), source)
	}
	return got.Value
}

// The basic contract: a spawned closure runs, and task_wait hands back what it
// returned.
func TestSpawnRunsAClosureAndTaskWaitCollectsIt(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   int64
	}{
		{
			name:   "no argument",
			source: `let t, se = spawn(fn() { return 6 * 7; }); let v, we = task_wait(t); v`,
			want:   42,
		},
		{
			name:   "one argument",
			source: `let t, se = spawn(fn(n) { return n + 1; }, 10); let v, we = task_wait(t); v`,
			want:   11,
		},
		{
			name:   "the task reads a global",
			source: `let base = 100; let t, se = spawn(fn() { return base + 5; }); let v, we = task_wait(t); v`,
			want:   105,
		},
		{
			name:   "the task uses a captured free variable",
			source: `let adder = fn(n) { fn() { n * 3 } }; let t, se = spawn(adder(9)); let v, we = task_wait(t); v`,
			want:   27,
		},
		{
			name:   "the task calls other builtins and allocates",
			source: `let t, se = spawn(fn(xs) { return reduce(map(xs, fn(x) { x * x }), fn(a, b) { a + b }, 0); }, [1, 2, 3, 4]); let v, we = task_wait(t); v`,
			want:   30,
		},
		{
			name:   "a task may spawn a task",
			source: `let t, se = spawn(fn() { let inner, ie = spawn(fn() { return 21; }); let v, we = task_wait(inner); return v * 2; }); let outer, oe = task_wait(t); outer`,
			want:   42,
		},
		{
			name:   "a task may run pmap",
			source: `let t, se = spawn(fn() { return reduce(pmap([1, 2, 3, 4], fn(x) { x * 10 }), fn(a, b) { a + b }, 0); }); let v, we = task_wait(t); v`,
			want:   100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runForInteger(t, tc.source); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// spawn's handle is the first binding and its error the second, matching every
// other fallible builtin.
func TestSpawnReturnsAHandleAndNoError(t *testing.T) {
	machine, err := runEncryptedVM(`spawn(fn() { 1 })`)
	if err != nil {
		t.Fatalf("spawn failed: %s", err)
	}

	handle, errSlot := pairValues(t, machine.LastPoppedStackElement())
	if _, ok := handle.(*object.Integer); !ok {
		t.Fatalf("spawn's first value is %s, want an INTEGER handle", handle.Inspect())
	}
	if errSlot.Type() != object.NULL_OBJ {
		t.Fatalf("spawn's error slot is %s, want null", errSlot.Inspect())
	}

	// Leave nothing running for the next test.
	builtin.WaitForTasks()
}

// A channel is how a task and its parent meet, since they share no variables.
func TestSpawnAndChannelHandOffValues(t *testing.T) {
	source := `
		let ch, ce = chan_new(4);
		let t, se = spawn(fn(c) {
			for (let i = 1; i <= 4; i++) { let sent, e = chan_send(c, i * i); }
			let closed, cle = chan_close(c);
			return 4;
		}, ch);

		let total = 0;
		for (;;) {
			let r, re = chan_recv(ch, 5000);
			if (!r["ok"]) { break; }
			total += r["value"];
		}
		let count, we = task_wait(t);
		total + count
	`
	// 1 + 4 + 9 + 16 = 30, plus the task's own return of 4.
	if got := runForInteger(t, source); got != 34 {
		t.Fatalf("got %d, want 34", got)
	}
}

// task_done answers without waiting, so a program can poll instead of blocking.
func TestTaskDonePollsWithoutBlocking(t *testing.T) {
	source := `
		let gate, ge = chan_new(0);
		let t, se = spawn(fn(g) { let r, re = chan_recv(g, 5000); return 7; }, gate);

		// The task is parked on the gate, so task_done must say so without
		// waiting for it.
		let running, de = task_done(t);

		let opened, oe = chan_send(gate, 1, 5000);

		// Now poll rather than wait, so task_done is what observes the finish.
		let finished = false;
		for (let i = 0; i < 500; i++) {
			let d, dd = task_done(t);
			if (d) { finished = true; break; }
			sleep_ms(10);
		}

		let v, we = task_wait(t);
		if (running) { return 0; }
		if (!finished) { return 0; }
		v
	`
	if got := runForInteger(t, source); got != 7 {
		t.Fatalf("got %d, want 7 (task_done misreported one of the two states)", got)
	}
}

// A task that fails reports through task_wait's error slot rather than taking
// the program down with it.
func TestTaskWaitSurfacesAFailedTask(t *testing.T) {
	machine, err := runEncryptedVM(`let t, se = spawn(fn() { return 1 / 0; }); task_wait(t)`)
	if err != nil {
		t.Fatalf("the failing task aborted the whole program: %s", err)
	}

	value, errSlot := pairValues(t, machine.LastPoppedStackElement())
	errObj, ok := errSlot.(*object.Error)
	if !ok {
		t.Fatalf("task_wait returned (%s, %s), want the failure in the error slot", value.Inspect(), errSlot.Inspect())
	}
	if !strings.Contains(strings.ToLower(errObj.Message), "zero") {
		t.Fatalf("error = %q, want it to report the division by zero", errObj.Message)
	}
}

// The task's globals are a snapshot: it sees what existed at the spawn, and its
// writes stay its own. This is the same rule pmap's workers follow, and the
// reason the documented way back is a return value or a channel.
func TestSpawnedTaskGetsAGlobalsSnapshot(t *testing.T) {
	source := `
		let shared = 1;
		let gate, ge = chan_new(0);
		let t, se = spawn(fn(g) {
			let r, re = chan_recv(g, 5000);
			shared = 99;
			return shared;
		}, gate);

		shared = 2;
		let opened, oe = chan_send(gate, 1, 5000);
		let inside, we = task_wait(t);

		// The task saw the value from the spawn, not the parent's later write,
		// and its own write did not come back.
		inside * 100 + shared
	`
	if got := runForInteger(t, source); got != 9902 {
		t.Fatalf("got %d, want 9902 (the task saw %d and the parent ended with %d)", got, got/100, got%100)
	}
}

// Many tasks at once must all run and all be collected, with nothing lost to a
// shared constants pool that every worker is decrypting. Run with -race for the
// rest.
func TestManyConcurrentTasksAllComplete(t *testing.T) {
	source := `
		let handles = map(range(0, 64), fn(i) {
			let t, se = spawn(fn(n) {
				let h = {"a": "constant-string", "b": [1, 2, 3]};
				let parts = h["b"];
				return n + parts[0] + parts[1] + parts[2];
			}, i);
			return t;
		});
		reduce(handles, fn(acc, t) { let v, we = task_wait(t); acc + v }, 0)
	`
	// sum(0..63) + 64*6 = 2016 + 384
	if got := runForInteger(t, source); got != 2400 {
		t.Fatalf("got %d, want 2400", got)
	}
}

// The whole reason the runtime waits at exit: a task the program never collects
// must still finish its work. This drives builtin.WaitForTasks the way
// runner.runvm does, before anything would wipe the constants the task reads.
func TestUncollectedTaskStillFinishesBeforeWaitForTasksReturns(t *testing.T) {
	machine, err := runEncryptedVM(`
		let ch, ce = chan_new(1);
		let t, se = spawn(fn(c) {
			let total = 0;
			for (let i = 0; i < 5000; i++) { total += i; }
			let sent, sse = chan_send(c, total);
			return total;
		}, ch);
		ch
	`)
	if err != nil {
		t.Fatalf("program failed: %s", err)
	}

	channel, ok := machine.LastPoppedStackElement().(*object.Integer)
	if !ok {
		t.Fatalf("program returned %s, want the channel handle", machine.LastPoppedStackElement().Inspect())
	}

	builtin.WaitForTasks()

	if live := builtin.LiveTaskCount(); live != 0 {
		t.Fatalf("WaitForTasks returned with %d tasks still live", live)
	}

	// The value is already queued, so a non-blocking receive must find it.
	result := builtin.ChanTryRecv(channel)
	multi, ok := result.(*object.MultiValue)
	if !ok || len(multi.Values) != 2 {
		t.Fatalf("chan_try_recv returned %s, want a pair", result.Inspect())
	}
	hash, ok := multi.Values[0].(*object.Hash)
	if !ok {
		t.Fatalf("chan_try_recv's value is %s, want a hash", multi.Values[0].Inspect())
	}
	got := hash.Pairs[(&object.String{Value: "value"}).HashKey()].Value
	total, ok := got.(*object.Integer)
	if !ok || total.Value != 12497500 {
		t.Fatalf("the uncollected task delivered %s, want 12497500", got.Inspect())
	}
}

// Argument problems are catchable values in the error slot, matching every other
// fallible builtin, rather than aborting the run.
func TestSpawnArgumentValidation(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`spawn()`, "spawn: want 1 or 2 arguments (function[, arg]), got 0"},
		{`spawn(fn() { 1 }, 1, 2)`, "spawn: want 1 or 2 arguments (function[, arg]), got 3"},
		{`spawn(7)`, "spawn: first argument must be a function, got INTEGER"},
		{`spawn(fn(a) { a })`, "spawn: spawn(fn) needs a function that takes no parameters, but this one takes 1"},
		{`spawn(fn() { 1 }, 5)`, "spawn: spawn(fn, arg) needs a function that takes one parameter, but this one takes 0"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			machine, err := runEncryptedVM(tc.input)
			if err != nil {
				t.Fatalf("expected a catchable error value, got a run failure: %s", err)
			}
			_, errSlot := pairValues(t, machine.LastPoppedStackElement())
			errObj, ok := errSlot.(*object.Error)
			if !ok {
				t.Fatalf("error slot holds %s, want an ERROR", errSlot.Inspect())
			}
			if errObj.Message != tc.want {
				t.Fatalf("error = %q, want %q", errObj.Message, tc.want)
			}
		})
	}
}
