package builtin

// Tasks are the general form of the concurrency pmap gives you for arrays: run
// one closure alongside the rest of the program and collect its result later.
//
// The registry lives here rather than in the vm package because task_wait and
// task_done need nothing from the executor -- they look up a handle and wait.
// Only spawn itself is executor-native (see vm/spawn.go), because only the VM
// can run a closure. The split keeps the handle idiom identical to net_listen's
// and lets a task be awaited from anywhere, including from another task.

import (
	"sync"
	"time"

	"mutant/object"
)

// maxLiveTasks bounds how many spawned tasks may be running at once, so a spawn
// inside a loop cannot create unbounded VMs. It matches the ceiling net_serve
// puts on handler goroutines and pmap puts on worker VMs.
//
// Reaching it is reported as an error rather than made to block. Blocking would
// be backpressure for an accept loop but a deadlock for a task waiting on a
// sibling it cannot spawn, and an error the caller can see and back off from is
// the honest outcome.
const maxLiveTasks = 1024

// maxRetainedTasks bounds how many finished-but-uncollected results the registry
// holds on to. It is a backstop, not the usual path: task_wait releases a
// handle when it collects it, so a program that collects what it spawns never
// approaches this no matter how many tasks it runs. What it bounds is
// fire-and-forget -- a server that spawns per connection and never looks back --
// where the results would otherwise accumulate for the life of the process.
const maxRetainedTasks = 4096

// managedTask holds one spawned closure's outcome. Both fields are written
// before done is closed and only read after it, so the close is the entire
// synchronisation: no mutex is needed around the result.
type managedTask struct {
	done    chan struct{}
	result  object.Object
	failure error
}

var taskRegistry = struct {
	sync.Mutex
	tasks  map[int64]*managedTask
	nextID int64
	live   int
	// finished lists handles in completion order, so the oldest uncollected
	// results are the ones dropped once retention fills. Entries stay here
	// after a handle is released; dropping one is then a no-op delete, which
	// keeps both collecting and evicting constant-time.
	finished []int64
}{
	tasks:  map[int64]*managedTask{},
	nextID: 1,
}

// liveTasks counts tasks that have been registered but have not completed, so
// the runtime can wait for them before tearing the program down.
//
// The Add/Wait interleaving is safe for a reason worth stating: a spawn that
// raises the counter from zero can only come from the main program, which has
// already stopped by the time WaitForTasks runs. A spawn from inside a task
// raises it from at least one, which sync.WaitGroup explicitly permits.
var liveTasks sync.WaitGroup

// RegisterTask reserves a task handle and counts the task as live. The caller
// must pair every successful call with exactly one CompleteTask, including when
// the work panics -- otherwise WaitForTasks never returns.
func RegisterTask() (int64, *object.Error) {
	taskRegistry.Lock()
	if taskRegistry.live >= maxLiveTasks {
		taskRegistry.Unlock()
		return 0, newError("spawn: too many tasks running at once (limit %d); wait for some with task_wait", maxLiveTasks)
	}
	id := taskRegistry.nextID
	taskRegistry.nextID++
	taskRegistry.live++
	taskRegistry.tasks[id] = &managedTask{done: make(chan struct{})}
	taskRegistry.Unlock()

	liveTasks.Add(1)
	return id, nil
}

// CompleteTask records a finished task's outcome and wakes everything waiting on
// it. A second call for the same handle is ignored, so a caller may complete
// defensively from a deferred recover without risking a double close.
func CompleteTask(id int64, result object.Object, failure error) {
	taskRegistry.Lock()
	task, ok := taskRegistry.tasks[id]
	if !ok {
		taskRegistry.Unlock()
		return
	}
	select {
	case <-task.done:
		taskRegistry.Unlock()
		return
	default:
	}
	if result == nil {
		result = &object.Null{}
	}
	task.result = result
	task.failure = failure
	taskRegistry.live--
	close(task.done)

	taskRegistry.finished = append(taskRegistry.finished, id)
	for len(taskRegistry.finished) > maxRetainedTasks {
		delete(taskRegistry.tasks, taskRegistry.finished[0])
		taskRegistry.finished = taskRegistry.finished[1:]
	}
	taskRegistry.Unlock()

	liveTasks.Done()
}

// WaitForTasks blocks until every spawned task has finished. One-shot execution
// paths call it before wiping the program's constants: a task still running is
// still decrypting the very constants the teardown zeroes, so exiting without
// waiting would corrupt work that was about to succeed.
//
// It waits without a deadline on purpose. A task that never finishes therefore
// keeps the program alive, which is the visible symptom of a real bug -- silently
// discarding its work would hide one. A task parked on a channel is released by
// closing that channel, or by giving its receive a timeout.
func WaitForTasks() { liveTasks.Wait() }

// releaseTask drops a collected task's result. The handle stays in the finished
// list, where evicting it later is a harmless second delete.
func releaseTask(id int64) {
	taskRegistry.Lock()
	delete(taskRegistry.tasks, id)
	taskRegistry.Unlock()
}

// LiveTaskCount reports how many spawned tasks have not finished yet.
func LiveTaskCount() int {
	taskRegistry.Lock()
	defer taskRegistry.Unlock()
	return taskRegistry.live
}

func lookupTask(op string, arg object.Object) (*managedTask, *object.Error) {
	handle, ok := arg.(*object.Integer)
	if !ok {
		return nil, newError("argument 1 to %s must be INTEGER, got %s", op, arg.Type())
	}
	taskRegistry.Lock()
	task, found := taskRegistry.tasks[handle.Value]
	taskRegistry.Unlock()
	if !found {
		return nil, newError("%s: unknown task handle %d; it was either never spawned or already collected", op, handle.Value)
	}
	return task, nil
}

// TaskWait blocks until a spawned task finishes and returns what it produced.
// task_wait(handle, timeoutMs?) -> (value, err)
//
// The error slot carries whatever stopped the task, so a failed task reads the
// same way as any failed builtin. Without a timeout it waits indefinitely; with
// one, running out of time is itself reported as an error, because there is no
// value to hand back and returning null would look like success.
//
// Collecting a task releases its handle, the way closing a connection releases
// that one: the result has been handed over and there is nothing left to hold.
// That is also what keeps a long-running program bounded, since a task the
// program does collect never occupies retention at all.
func TaskWait(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	task, errObj := lookupTask("task_wait", args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	handle := args[0].(*object.Integer).Value

	timeoutMs := int64(-1)
	if len(args) == 2 {
		var terr *object.Error
		if timeoutMs, terr = timeoutArg("task_wait", 2, args[1]); terr != nil {
			return resultAndError(nil, terr)
		}
	}

	if timeoutMs >= 0 {
		timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-task.done:
		case <-timer.C:
			return resultAndError(nil, newError("task_wait: task is still running after %dms", timeoutMs))
		}
	} else {
		<-task.done
	}

	releaseTask(handle)

	if task.failure != nil {
		return resultAndError(nil, newError("task failed: %s", task.failure.Error()))
	}
	return resultAndError(task.result, nil)
}

// TaskDone reports whether a spawned task has finished, without waiting.
// task_done(handle) -> (BOOLEAN, err)
func TaskDone(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	task, errObj := lookupTask("task_done", args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	select {
	case <-task.done:
		return resultAndError(boolObj(true), nil)
	default:
		return resultAndError(boolObj(false), nil)
	}
}
