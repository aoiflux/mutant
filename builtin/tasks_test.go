package builtin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// registerTestTask reserves a handle and fails the test if the registry refuses.
func registerTestTask(t *testing.T) int64 {
	t.Helper()
	handle, err := RegisterTask()
	if err != nil {
		t.Fatalf("RegisterTask failed: %s", err.Message)
	}
	return handle
}

// A finished task hands back what it produced, and collecting it releases the
// handle -- which is what keeps a long-running program that spawns and collects
// from accumulating results forever.
func TestTaskWaitReturnsTheResultAndReleasesTheHandle(t *testing.T) {
	handle := registerTestTask(t)
	CompleteTask(handle, &object.String{Value: "collected"}, nil)

	result, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}))
	if err != nil {
		t.Fatalf("task_wait failed: %s", err.Message)
	}
	got, ok := result.(*object.String)
	if !ok || got.Value != "collected" {
		t.Fatalf("task_wait returned %s, want \"collected\"", result.Inspect())
	}

	_, err = unwrapPair(t, TaskWait(&object.Integer{Value: handle}))
	if err == nil {
		t.Fatal("the handle survived being collected")
	}
	if !strings.Contains(err.Message, "already collected") {
		t.Fatalf("error = %q, want it to say the handle was already collected", err.Message)
	}
}

// A wait that times out must NOT release the handle: the task is still running
// and the caller has to be able to come back for it.
func TestTaskWaitKeepsTheHandleWhenItTimesOut(t *testing.T) {
	handle := registerTestTask(t)

	if _, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}, &object.Integer{Value: 10})); err == nil {
		t.Fatal("task_wait reported success for a task that never finished")
	}

	CompleteTask(handle, &object.Integer{Value: 5}, nil)

	result, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}))
	if err != nil {
		t.Fatalf("the timed-out handle was released: %s", err.Message)
	}
	if got, ok := result.(*object.Integer); !ok || got.Value != 5 {
		t.Fatalf("task_wait returned %s, want 5", result.Inspect())
	}
}

// Fire-and-forget is the case retention exists for: a server that spawns per
// connection and never collects must not grow a result per connection forever.
func TestUncollectedResultsAreBoundedByRetention(t *testing.T) {
	const spawned = maxRetainedTasks + 512

	first := int64(0)
	for i := 0; i < spawned; i++ {
		handle := registerTestTask(t)
		if i == 0 {
			first = handle
		}
		CompleteTask(handle, &object.Integer{Value: handle}, nil)
	}

	taskRegistry.Lock()
	retained := len(taskRegistry.tasks)
	taskRegistry.Unlock()
	if retained > maxRetainedTasks {
		t.Fatalf("registry holds %d results, above the %d retention bound", retained, maxRetainedTasks)
	}

	// The oldest uncollected result is the one dropped, and saying so beats
	// pretending the handle never existed.
	_, err := unwrapPair(t, TaskWait(&object.Integer{Value: first}))
	if err == nil {
		t.Fatal("the oldest uncollected result survived past the retention bound")
	}
	if !strings.Contains(err.Message, "unknown task handle") {
		t.Fatalf("error = %q, want it to report the dropped handle", err.Message)
	}
}

// Whatever stopped a task arrives in the error slot, so a failed task reads the
// same way as any failed builtin.
func TestTaskWaitReportsTheFailure(t *testing.T) {
	handle := registerTestTask(t)
	CompleteTask(handle, nil, errors.New("division by zero"))

	_, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}))
	if err == nil {
		t.Fatal("task_wait reported success for a failed task")
	}
	if err.Message != "task failed: division by zero" {
		t.Fatalf("error = %q, want it to carry the task's own message", err.Message)
	}
}

// A wait that runs out of time is an error rather than a null result, because
// there is no value to hand back and null would look like success.
func TestTaskWaitTimesOut(t *testing.T) {
	handle := registerTestTask(t)
	defer CompleteTask(handle, &object.Null{}, nil)

	start := time.Now()
	_, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}, &object.Integer{Value: 60}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("task_wait reported success for a task that never finished")
	}
	if err.Message != "task_wait: task is still running after 60ms" {
		t.Fatalf("error = %q, want it to name the timeout", err.Message)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("task_wait returned after %s, so it did not actually wait", elapsed)
	}
}

// task_done answers without waiting, which is what makes a poll loop possible.
func TestTaskDoneDoesNotWait(t *testing.T) {
	handle := registerTestTask(t)

	result, err := unwrapPair(t, TaskDone(&object.Integer{Value: handle}))
	if err != nil {
		t.Fatalf("task_done failed: %s", err.Message)
	}
	if b, ok := result.(*object.Boolean); !ok || b.Value {
		t.Fatalf("task_done returned %s for a running task, want false", result.Inspect())
	}

	CompleteTask(handle, &object.Integer{Value: 1}, nil)

	result, err = unwrapPair(t, TaskDone(&object.Integer{Value: handle}))
	if err != nil {
		t.Fatalf("task_done failed: %s", err.Message)
	}
	if b, ok := result.(*object.Boolean); !ok || !b.Value {
		t.Fatalf("task_done returned %s for a finished task, want true", result.Inspect())
	}
}

// Completing twice must be harmless, because the VM completes from a deferred
// recover and a caller may reasonably complete defensively.
func TestCompleteTaskIsIdempotent(t *testing.T) {
	handle := registerTestTask(t)
	before := LiveTaskCount()

	CompleteTask(handle, &object.Integer{Value: 1}, nil)
	CompleteTask(handle, &object.Integer{Value: 2}, errors.New("ignored"))

	if after := LiveTaskCount(); after != before-1 {
		t.Fatalf("live count went from %d to %d; the second completion was counted", before, after)
	}

	result, err := unwrapPair(t, TaskWait(&object.Integer{Value: handle}))
	if err != nil {
		t.Fatalf("task_wait failed: %s", err.Message)
	}
	if got, ok := result.(*object.Integer); !ok || got.Value != 1 {
		t.Fatalf("task_wait returned %s; the second completion overwrote the first", result.Inspect())
	}
}

// WaitForTasks is what lets the runtime tear a program down safely, so it must
// actually wait for work that is still in flight.
func TestWaitForTasksWaitsForOutstandingWork(t *testing.T) {
	const tasks = 16

	finished := make(chan int64, tasks)
	for i := 0; i < tasks; i++ {
		handle := registerTestTask(t)
		go func(h int64) {
			time.Sleep(30 * time.Millisecond)
			// Record the work before completing, in that order: completing is
			// the task saying it is finished, so anything it must do has to
			// happen first. Doing it the other way round would let WaitForTasks
			// legitimately return before the record landed.
			finished <- h
			CompleteTask(h, &object.Integer{Value: h}, nil)
		}(handle)
	}

	WaitForTasks()

	if count := len(finished); count != tasks {
		t.Fatalf("WaitForTasks returned with %d of %d tasks finished", count, tasks)
	}
	if live := LiveTaskCount(); live != 0 {
		t.Fatalf("WaitForTasks returned with %d tasks still live", live)
	}
}

// The ceiling is reported rather than made to block: blocking would deadlock a
// task waiting on a sibling it cannot spawn, while an error can be backed off
// from.
func TestTaskCeilingIsReported(t *testing.T) {
	handles := make([]int64, 0, maxLiveTasks)
	defer func() {
		for _, h := range handles {
			CompleteTask(h, &object.Null{}, nil)
		}
	}()

	for len(handles) < maxLiveTasks {
		handle, err := RegisterTask()
		if err != nil {
			t.Fatalf("RegisterTask refused at %d tasks, below the %d ceiling: %s", len(handles), maxLiveTasks, err.Message)
		}
		handles = append(handles, handle)
	}

	_, err := RegisterTask()
	if err == nil {
		t.Fatalf("RegisterTask allowed a %dth task past the %d ceiling", maxLiveTasks+1, maxLiveTasks)
	}
	if err.Message != "spawn: too many tasks running at once (limit 1024); wait for some with task_wait" {
		t.Fatalf("error = %q, want it to name the ceiling and the way out", err.Message)
	}
}

// Argument problems come back as catchable errors.
func TestTaskArgumentValidation(t *testing.T) {
	cases := []struct {
		name string
		call func() object.Object
		want string
	}{
		{"unknown handle", func() object.Object { return TaskWait(&object.Integer{Value: 999999}) },
			"task_wait: unknown task handle 999999; it was either never spawned or already collected"},
		{"handle is not an integer", func() object.Object { return TaskDone(&object.String{Value: "t"}) },
			"argument 1 to task_done must be INTEGER, got STRING"},
		{"too many arguments", func() object.Object {
			return TaskWait(&object.Integer{Value: 1}, &object.Integer{Value: 1}, &object.Integer{Value: 1})
		}, "wrong number of arguments. got=3, want=1 or 2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unwrapPair(t, tc.call())
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Message != tc.want {
				t.Fatalf("error = %q, want %q", err.Message, tc.want)
			}
		})
	}
}
