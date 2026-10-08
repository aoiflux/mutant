package builtin

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

// M26-NET-029. process_kill's refuse-self guard compared its argument with
// os.Getpid() and nothing else, and a thread id of this process is not that
// number. On Linux a signal addressed to a non-leader thread id is delivered to
// the whole thread group, so process_kill(process_threads()["tids"][0]) ended
// the run through a documented pair of builtins while the guard reported
// nothing.
//
// NO TEST HERE DELIVERS A SIGNAL, and the way that is arranged is the one thing
// to read before editing this file. Every call to ProcessKill below passes
// signal 0 explicitly. Signal 0 is the POSIX existence probe: the kernel does
// the permission and liveness checks and delivers nothing. So if the guard is
// ever removed, these tests FAIL -- ProcessKill returns true where a refusal was
// asserted -- instead of killing the test binary and taking the rest of the
// suite's results with it. A test that asserted the refusal with SIGKILL would
// be a test that cannot report its own failure.
//
// Declared duplication: TestProcessKillRefusesSelf in system_forensics_test.go
// already asserts that this process's own pid is refused. It is asserted again
// in TestProcessKillRefusesThisProcessByPidAndSaysWhich, because the point here
// is that the two refusals stay distinguishable from each other -- a script
// author who sees the wrong one of the two has been told the wrong thing about
// the number they passed.

// sfTestThreadIDs returns the tids process_threads reports for this process,
// which is the exact path a script reaches a thread id by.
func sfTestThreadIDs(t *testing.T) []int64 {
	t.Helper()
	payload, errObj := unwrapPair(t, ProcessThreads())
	if errObj != nil {
		t.Fatalf("process_threads error: %s", errObj.Inspect())
	}
	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("process_threads payload type: %T", payload)
	}
	arr, ok := sfHashValue(t, hash, "tids").(*object.Array)
	if !ok {
		t.Fatalf("process_threads tids must be an ARRAY")
	}
	tids := make([]int64, 0, len(arr.Elements))
	for i, element := range arr.Elements {
		value, ok := element.(*object.Integer)
		if !ok {
			t.Fatalf("process_threads tids[%d] is %T, not INTEGER", i, element)
		}
		tids = append(tids, value.Value)
	}
	return tids
}

// TestProcessKillRefusesAThreadIDOfThisProcess is the regression test for the
// row: the whole bypass, through the two builtins a script would use.
func TestProcessKillRefusesAThreadIDOfThisProcess(t *testing.T) {
	tids := sfTestThreadIDs(t)

	checked := 0
	for _, tid := range tids {
		if tid == int64(os.Getpid()) {
			// The leader's tid IS the pid, and that one is refused by the older
			// guard with a different sentence. Covered separately below.
			continue
		}
		// Signal 0 and not SIGKILL: see the file comment. If the guard does not
		// fire, this call probes and returns true, and the t.Fatalf below is
		// reached rather than the process dying mid-suite.
		result, errObj := unwrapPair(t,
			ProcessKill(&object.Integer{Value: tid}, &object.Integer{Value: 0}))
		if errObj == nil {
			t.Fatalf("process_kill(%d, 0) was allowed through and returned %s; %d is a thread "+
				"of this process (pid %d) and a signal to it would have ended this run",
				tid, result.Inspect(), tid, os.Getpid())
		}
		message := errObj.Message
		for _, want := range []string{
			"thread of this one",
			strconv.FormatInt(tid, 10),
			strconv.Itoa(os.Getpid()),
		} {
			if !strings.Contains(message, want) {
				t.Errorf("process_kill(%d, 0) refused, but the refusal does not contain %q, so "+
					"a script author cannot tell that the number named a thread of their own "+
					"run: %s", tid, want, message)
			}
		}
		if strings.Contains(message, "only supports SIGKILL") {
			t.Fatalf("process_kill(%d, 0) was refused for the signal rather than for the id, so "+
				"this test proved nothing about the guard: %s", tid, message)
		}
		checked++
	}

	if checked == 0 {
		t.Skipf("process_threads reports %d thread id(s) on %s and none of them is a non-leader "+
			"tid, so there is no id on this host that can stand in for a pid; the guard is "+
			"still exercised by TestSfIsThreadOfThisProcessMatchesWhatProcessThreadsHandsOut",
			len(tids), runtime.GOOS)
	}
}

// TestProcessKillRefusesThisProcessByPidAndSaysWhich keeps the two refusals
// apart. The pid refusal is the older one and its wording is unchanged by this
// fix; a reader who gets the thread sentence for a bare pid has been told
// something false about the number they passed.
func TestProcessKillRefusesThisProcessByPidAndSaysWhich(t *testing.T) {
	_, errObj := unwrapPair(t,
		ProcessKill(&object.Integer{Value: int64(os.Getpid())}, &object.Integer{Value: 0}))
	if errObj == nil {
		t.Fatalf("process_kill(%d, 0) did not refuse this process's own pid", os.Getpid())
	}
	if !strings.Contains(errObj.Message, "current process") {
		t.Errorf("the pid refusal no longer says it is the current process: %s", errObj.Message)
	}
	if strings.Contains(errObj.Message, "thread of this one") {
		t.Errorf("a bare pid was refused with the thread sentence, which says the wrong thing "+
			"about what was passed: %s", errObj.Message)
	}
}

// TestProcessKillStillLetsAForeignPidPastTheGuard is the control. Without it a
// fix that refused every pid would pass every other test in this file.
//
// The foreign pid is the parent -- under `go test` that is the go tool, a live
// process in range that is certainly not one of this process's threads. Signal
// 0 is what makes naming it safe: the parent is probed and nothing is delivered
// to it. Nothing here asserts that the probe SUCCEEDS, because a host may
// refuse the probe for its own reasons (privileges, a reaped parent); what it
// asserts is that whatever comes back is not one of the two refuse-self
// refusals, which is the whole of what the control is for.
func TestProcessKillStillLetsAForeignPidPastTheGuard(t *testing.T) {
	foreign := os.Getppid()
	if foreign <= 0 || foreign == os.Getpid() {
		t.Skipf("getppid() is %d, which is no use as a foreign pid here", foreign)
	}
	if isThread, answered := sfIsThreadOfThisProcess(foreign); answered && isThread {
		t.Skipf("procfs reports pid %d as a thread of this process, which it should not be; "+
			"skipping rather than signalling it", foreign)
	}

	result, errObj := unwrapPair(t,
		ProcessKill(&object.Integer{Value: int64(foreign)}, &object.Integer{Value: 0}))
	if errObj == nil {
		// The probe went through, which is the expected result on a POSIX host.
		if result == nil {
			t.Fatalf("process_kill(%d, 0) returned neither a result nor an error", foreign)
		}
		return
	}
	for _, refusal := range []string{"thread of this one", "current process"} {
		if strings.Contains(errObj.Message, refusal) {
			t.Fatalf("process_kill refused the foreign live pid %d as if it were this process, "+
				"so the fix refuses too much: %s", foreign, errObj.Message)
		}
	}
	t.Logf("process_kill(%d, 0) was refused for an unrelated reason on %s, which is tolerated "+
		"here: %s", foreign, runtime.GOOS, errObj.Message)
}

// TestSfIsThreadOfThisProcessMatchesWhatProcessThreadsHandsOut checks the guard
// against the builtin that supplies the ids, in both directions, and pins the
// claim the (false, false) answer rests on: that a host which cannot answer here
// is a host where process_threads hands out no thread id to begin with. If that
// symmetry ever breaks -- ids handed to scripts on a host where the guard is
// blind -- this fails, and it is the only place that would notice.
func TestSfIsThreadOfThisProcessMatchesWhatProcessThreadsHandsOut(t *testing.T) {
	tids := sfTestThreadIDs(t)
	_, answered := sfIsThreadOfThisProcess(os.Getpid())

	if !answered {
		if len(tids) != 0 {
			t.Fatalf("process_threads handed out %d thread id(s) on %s while the guard cannot "+
				"read this process's thread directory (%s): the ids are reachable and the "+
				"guard is blind, which is M26-NET-029 again on a host nobody measured",
				len(tids), runtime.GOOS, sfSelfTaskDir())
		}
		t.Skipf("no procfs thread directory at %s on %s, and process_threads reports no tids "+
			"either, so there is no id here that can stand in for a pid",
			sfSelfTaskDir(), runtime.GOOS)
	}

	if isThread, _ := sfIsThreadOfThisProcess(os.Getpid()); !isThread {
		t.Errorf("the guard does not recognise this process's own pid %d as one of its threads; "+
			"the leader's thread id is the pid", os.Getpid())
	}
	for _, tid := range tids {
		isThread, answered := sfIsThreadOfThisProcess(int(tid))
		if !answered {
			t.Errorf("the guard stopped answering between two calls, for tid %d", tid)
			continue
		}
		if !isThread {
			t.Errorf("process_threads reported tid %d for this process but the guard does not "+
				"recognise it, so process_kill(%d) would be allowed through", tid, tid)
		}
	}
	if parent := os.Getppid(); parent > 0 && parent != os.Getpid() {
		if isThread, _ := sfIsThreadOfThisProcess(parent); isThread {
			t.Errorf("the guard calls the parent pid %d a thread of this process, which would "+
				"refuse a kill that should be allowed", parent)
		}
	}
}
