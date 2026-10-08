package builtin

import (
	"testing"
	"time"

	"mutant/object"
)

// M26-NET-003. ProcessTree walked byParent breadth-first with no visited set:
//
//	queue := append([]sfProcess{}, byParent[rootPID]...)
//	for len(queue) > 0 {
//		cur := queue[0]
//		queue = queue[1:]
//		desc = append(desc, ...)
//		queue = append(queue, byParent[cur.pid]...)
//	}
//
// On Windows pid 0, the System Idle Process, reports ppid 0 -- so byParent[0]
// holds pid 0 itself. Every time the walk dequeued pid 0 it appended byParent[0]
// again, and the queue and the descendants array both grew until the process
// died: 2 MiB to over 1 GiB in under five seconds when the audit reproduced it.
// Nothing panicked, so the recover() around a builtin could not help, and
// process_list reports pid 0 first on Windows, so a script that called
// process_tree for each pid in process_list met it on the first one. A ppid
// cycle from pid reuse does the same thing starting from an ordinary pid.
//
// The walk is now sfDescendants, a function of a process slice rather than of
// the live process table, so these tests can state the contract on inputs no
// real host has to be holding at the time: a self-parented pid, a four-process
// cycle, a pid listed twice, and an ordinary tree that must still come out in
// the order it always did.

// sfWalkWithin runs the walk off the test goroutine, so that a walk which does
// not terminate fails the test rather than hanging it.
//
// The goroutine cannot be cancelled: sfDescendants takes no context, and a walk
// that terminates needs none. So a regression here leaks a goroutine that goes
// on allocating. That is the deliberate trade -- the failure is reported first,
// and `go test`'s own timeout is the backstop. A test that hung silently would
// be worse than one that fails loudly and is then killed.
func sfWalkWithin(t *testing.T, procs []sfProcess, rootPID int, limit time.Duration) []object.Object {
	t.Helper()

	done := make(chan []object.Object, 1)
	go func() { done <- sfDescendants(procs, rootPID) }()

	select {
	case got := <-done:
		return got
	case <-time.After(limit):
		t.Fatalf("sfDescendants(root=%d) did not return within %s: the walk does not terminate",
			rootPID, limit)
		return nil
	}
}

// sfWalkPIDs reduces the walk's output to the pids it reported, in order. The
// order is part of the contract: children are sorted by pid at each level, and
// that is what a script printing a tree depends on.
func sfWalkPIDs(t *testing.T, descendants []object.Object) []int64 {
	t.Helper()

	pids := make([]int64, 0, len(descendants))
	for i, d := range descendants {
		hash, ok := d.(*object.Hash)
		if !ok {
			t.Fatalf("descendant %d is not a HASH. got=%T", i, d)
		}
		pids = append(pids, hashFieldInt(t, hash, "pid"))
	}
	return pids
}

func sfSamePIDs(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestTheProcessWalkTerminatesOnASelfParentedPid is the row itself, with the
// process table Windows actually reports.
func TestTheProcessWalkTerminatesOnASelfParentedPid(t *testing.T) {
	procs := []sfProcess{
		{pid: 0, ppid: 0, name: "System Idle Process"},
		{pid: 4, ppid: 0, name: "System"},
		{pid: 88, ppid: 4, name: "Registry"},
	}

	got := sfWalkPIDs(t, sfWalkWithin(t, procs, 0, 5*time.Second))

	// pid 0's real children, and pid 0 itself exactly nowhere: a process is not
	// its own descendant, whatever the table says about its parent.
	want := []int64{4, 88}
	if !sfSamePIDs(got, want) {
		t.Errorf("descendants of pid 0 = %v, want %v", got, want)
	}
}

// TestTheProcessWalkTerminatesOnAPpidCycle uses the four-process cycle the
// audit found on a real host: 2204 -> 25668 -> 16896 -> 14520 -> 2204.
func TestTheProcessWalkTerminatesOnAPpidCycle(t *testing.T) {
	procs := []sfProcess{
		{pid: 2204, ppid: 14520, name: "a"},
		{pid: 25668, ppid: 2204, name: "b"},
		{pid: 16896, ppid: 25668, name: "c"},
		{pid: 14520, ppid: 16896, name: "d"},
	}

	got := sfWalkPIDs(t, sfWalkWithin(t, procs, 2204, 5*time.Second))

	// Walking from 2204 reaches 25668, then 16896, then 14520, whose child is
	// 2204 -- the root, already accounted for, so the walk stops there.
	want := []int64{25668, 16896, 14520}
	if !sfSamePIDs(got, want) {
		t.Errorf("descendants of pid 2204 in a cycle = %v, want %v", got, want)
	}
}

// TestTheProcessWalkEmitsEachPidOnce covers the other way a pid can be reached
// twice: not a cycle, but a table that lists the same pid under two parents,
// which pid reuse between two snapshot passes can produce.
func TestTheProcessWalkEmitsEachPidOnce(t *testing.T) {
	procs := []sfProcess{
		{pid: 10, ppid: 1, name: "a"},
		{pid: 20, ppid: 1, name: "b"},
		{pid: 30, ppid: 10, name: "c"},
		{pid: 30, ppid: 20, name: "c again, under another parent"},
	}

	got := sfWalkPIDs(t, sfWalkWithin(t, procs, 1, 5*time.Second))

	want := []int64{10, 20, 30}
	if !sfSamePIDs(got, want) {
		t.Errorf("descendants of pid 1 = %v, want %v (pid 30 exactly once)", got, want)
	}
}

// TestTheProcessWalkStillWalksAnOrdinaryTreeInPidOrder is the guard: the fix
// must not change what the walk answers for a table with nothing wrong with it.
// Breadth-first, and children sorted by pid at each level.
func TestTheProcessWalkStillWalksAnOrdinaryTreeInPidOrder(t *testing.T) {
	procs := []sfProcess{
		{pid: 100, ppid: 1, name: "root"},
		{pid: 300, ppid: 100, name: "second child, listed first"},
		{pid: 200, ppid: 100, name: "first child, listed second"},
		{pid: 250, ppid: 200, name: "grandchild"},
	}

	got := sfWalkPIDs(t, sfWalkWithin(t, procs, 100, 5*time.Second))

	// Level one sorted by pid, then level two.
	want := []int64{200, 300, 250}
	if !sfSamePIDs(got, want) {
		t.Errorf("descendants of pid 100 = %v, want %v", got, want)
	}
}

// TestTheProcessWalkOfAPidWithNoChildrenIsEmpty pins the two empty cases, so
// that "no descendants" and "no such pid" both answer the same way rather than
// one of them reaching for a nil slice.
func TestTheProcessWalkOfAPidWithNoChildrenIsEmpty(t *testing.T) {
	procs := []sfProcess{
		{pid: 10, ppid: 1, name: "a"},
		{pid: 20, ppid: 1, name: "b"},
	}

	for _, root := range []int{10, 99999} {
		got := sfWalkWithin(t, procs, root, 5*time.Second)
		if got == nil {
			t.Errorf("descendants of pid %d is a nil slice; want an empty one", root)
		}
		if len(got) != 0 {
			t.Errorf("descendants of pid %d = %v, want none", root, sfWalkPIDs(t, got))
		}
	}
}
