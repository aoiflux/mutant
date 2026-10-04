package vm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"mutant/code"
	"mutant/object"
)

// M26-VM-002. A VM error that ends the run names the instruction it died on.
// A VM error the program receives as a value must not, because mutation
// rewrites the instruction stream: the sweep caught one division by zero
// reporting ip=6 at mutation 0 and ip=12 at mutation 10, from one source file.
//
// These tests hold both halves of that at once. Taking the metadata out of the
// fatal path would lose a bug report's best evidence; leaving it in a value
// makes a program's output depend on how it was built.

// The fatal path is unchanged: the text runtimeErrorAt produces is what it
// always produced, and the cause is still reachable through errors.Is.
func TestInstructionErrorKeepsItsTextAndItsCause(t *testing.T) {
	cause := errors.New("integer division by zero")
	err := (&VM{}).runtimeErrorAt(6, code.OpDiv, cause)

	if got, want := err.Error(), "vm_runtime_error ip=6 op=OpDiv: integer division by zero"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is no longer reaches the cause through %T", err)
	}
	if (&VM{}).runtimeErrorAt(6, code.OpDiv, nil) != nil {
		t.Fatalf("a nil cause should stay nil")
	}
}

// The value path drops exactly the metadata and nothing else, including when
// something wrapped the instruction error on its way out.
func TestWithoutInstructionMetadataStripsOnlyTheMetadata(t *testing.T) {
	inner := (&VM{}).runtimeErrorAt(12, code.OpDiv, errors.New("integer division by zero"))

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"bare", inner, "integer division by zero"},
		{"wrapped after", fmt.Errorf("%w (the close also failed: shut)", inner),
			"integer division by zero (the close also failed: shut)"},
		{"wrapped before", fmt.Errorf("task failed: %w", inner), "task failed: integer division by zero"},
		{"no metadata at all", errors.New("task panicked: boom"), "task panicked: boom"},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withoutInstructionMetadata(tc.err); got != tc.want {
				t.Fatalf("withoutInstructionMetadata = %q, want %q", got, tc.want)
			}
		})
	}
}

// Two mutation levels produce two different ips for one source position. Both
// what the program reads and where it is told to look have to be the same at
// every level, which is the whole of M26-VM-002.
func TestTheSameFailureReadsTheSameAtEveryMutationLevel(t *testing.T) {
	frames := []TracebackFrame{{Function: "<anonymous>", File: "worker_pool.mut", Line: 103, Column: 12}}

	seen := map[string]bool{}
	for _, ip := range []int{6, 11, 12} {
		err := scriptFacingError(&RuntimeError{
			Err:    (&VM{}).runtimeErrorAt(ip, code.OpDiv, errors.New("integer division by zero")),
			Frames: frames,
		})
		file, line, column := err.(*scriptError).Position()
		seen[fmt.Sprintf("%s|%s:%d:%d", err.Error(), file, line, column)] = true
	}
	if len(seen) != 1 {
		t.Fatalf("three mutation levels produced %d different failures: %v", len(seen), seen)
	}
	for rendered := range seen {
		if want := "integer division by zero|worker_pool.mut:103:12"; rendered != want {
			t.Fatalf("failure = %q, want %q", rendered, want)
		}
	}
}

// The position is the innermost frame's -- where it broke -- and the stack is
// the task's own, not the waiter's.
func TestScriptFacingErrorCarriesTheFailingFrame(t *testing.T) {
	wrapped := scriptFacingError(&RuntimeError{
		Err: (&VM{}).runtimeErrorAt(6, code.OpDiv, errors.New("integer division by zero")),
		Frames: []TracebackFrame{
			{Function: "divide", File: "w.mut", Line: 3, Column: 9},
			{Function: "<main>", File: "w.mut", Line: 11, Column: 1},
		},
	}).(*scriptError)

	file, line, column := wrapped.Position()
	if file != "w.mut" || line != 3 || column != 9 {
		t.Fatalf("Position() = %s:%d:%d, want w.mut:3:9", file, line, column)
	}
	if got := len(wrapped.Stack()); got != 2 {
		t.Fatalf("Stack() has %d frames, want 2", got)
	}
	if !strings.Contains(wrapped.Stack()[0], "divide") {
		t.Fatalf("Stack() is not innermost first: %v", wrapped.Stack())
	}
}

// Without debug info there are no frames. The cause alone is the honest
// answer -- an ip would not have helped a reader who has no line table either
// -- and a zero line is how the caller is told there is no site to report.
func TestScriptFacingErrorWithoutFramesHasNoPosition(t *testing.T) {
	wrapped := scriptFacingError(&RuntimeError{
		Err: (&VM{}).runtimeErrorAt(6, code.OpDiv, errors.New("integer division by zero")),
	}).(*scriptError)

	if got, want := wrapped.Error(), "integer division by zero"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if _, line, _ := wrapped.Position(); line != 0 {
		t.Fatalf("Position() reported line %d for a failure with no frames", line)
	}
	if wrapped.Stack() != nil {
		t.Fatalf("Stack() = %v, want nil", wrapped.Stack())
	}
}

// The sanitised text is presented while the chain is kept, so a caller that
// matches on a sentinel still finds it.
func TestScriptFacingErrorKeepsTheChain(t *testing.T) {
	cause := errors.New("integer division by zero")
	wrapped := scriptFacingError(&RuntimeError{
		Err:    (&VM{}).runtimeErrorAt(6, code.OpDiv, cause),
		Frames: []TracebackFrame{{File: "w.mut", Line: 3, Column: 9}},
	})

	if got, want := wrapped.Error(), "integer division by zero"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(wrapped, cause) {
		t.Fatalf("errors.Is stopped reaching the cause")
	}
	if scriptFacingError(nil) != nil {
		t.Fatalf("nil should stay nil")
	}
}

// End to end, through the real sink the sweep failed on: a failing task, the
// error value task_wait hands back, and no ip anywhere in it.
func TestAFailedTasksErrorValueNamesTheSourceNotTheInstruction(t *testing.T) {
	machine, err := runEncryptedVM(`let t, se = spawn(fn() { return 1 / 0; }); task_wait(t)`)
	if err != nil {
		t.Fatalf("the failing task aborted the whole program: %s", err)
	}

	_, errSlot := pairValues(t, machine.LastPoppedStackElement())
	errObj, ok := errSlot.(*object.Error)
	if !ok {
		t.Fatalf("task_wait returned %s in the error slot, want an ERROR", errSlot.Inspect())
	}

	rendered := errObj.Inspect()
	for _, forbidden := range []string{"ip=", "op=Op", "vm_runtime_error"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("the value a program receives still carries %q: %s", forbidden, rendered)
		}
	}
	if !strings.Contains(strings.ToLower(rendered), "zero") {
		t.Fatalf("the failure stopped saying what went wrong: %s", rendered)
	}
	// Exactly one position, and it is the task's. Two would leave the reader
	// to work out which of them was the failure and which the collection.
	if got := strings.Count(rendered, " at "); got != 1 {
		t.Fatalf("the error carries %d positions, want exactly 1: %s", got, rendered)
	}
	if errObj.Line <= 0 {
		t.Fatalf("the failure names no source position: %s", rendered)
	}
	if len(errObj.Stack) == 0 {
		t.Fatalf("the failure carries no stack: %s", rendered)
	}
}

// The other value sink the row names: with_resource, whose closer failing is
// reported alongside the body's result rather than ending the run.
func TestAFailedCloserReportsWithoutTheInstruction(t *testing.T) {
	machine, err := runEncryptedVM(`
		let v, e = with_resource(fn() { return 1; }, fn(h) { return 1 / 0; }, fn(h) { return h; });
		e`)
	if err != nil {
		t.Fatalf("the failing closer aborted the whole program: %s", err)
	}

	rendered := machine.LastPoppedStackElement().Inspect()
	if !strings.Contains(rendered, "the closer failed") {
		t.Fatalf("with_resource reported something else, so this path went untested: %s", rendered)
	}
	for _, forbidden := range []string{"ip=", "op=Op", "vm_runtime_error"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("a closer failure still carries %q: %s", forbidden, rendered)
		}
	}
}
