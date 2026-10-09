package builtin

import (
	"math"
	"os"
	"strings"
	"testing"

	"mutant/object"
)

// pidTooBig is the attack from M26-NET-005: a pid that is this process once the
// low 32 bits are all that survive. gopsutil takes an int32 and Windows takes a
// DWORD, so the value was truncated back to the current process after the
// refuse-self guard had already compared the untruncated one and let it past.
func pidTooBig() int64 { return int64(os.Getpid()) + (int64(1) << 32) }

// TestProcessKillRefusesAPidThatTruncatesOntoThisProcess is M26-NET-005. Before
// the fix process_kill(getpid()) was refused and process_kill(getpid()+2^32)
// killed the run: the guard compared a 64-bit number that was not equal to
// os.Getpid(), and the kill then used the low 32 bits, which were.
//
// No child process is needed to show it is closed, because the refusal now
// happens while the argument is being read, before any handle is opened. That
// the test keeps running after the call is the assertion.
func TestProcessKillRefusesAPidThatTruncatesOntoThisProcess(t *testing.T) {
	_, errObj := unwrapPair(t, ProcessKill(&object.Integer{Value: pidTooBig()}))
	if errObj == nil {
		t.Fatal("process_kill(getpid()+2^32) must be refused, not truncated onto this process")
	}
	if !strings.Contains(errObj.Message, "between 0 and") {
		t.Fatalf("expected the pid range refusal, got %q", errObj.Message)
	}

	// The guard it used to walk past is still there for the honest spelling.
	if _, selfErr := unwrapPair(t, ProcessKill(&object.Integer{Value: int64(os.Getpid())})); selfErr == nil {
		t.Fatal("process_kill(getpid()) must still be refused")
	}
}

// TestEveryPidArgumentIsRangeChecked covers the rest of M26-NET-005. Five
// builtins read a pid through sfParsePIDArg and three more read one themselves,
// and a fix that reached only some of them would leave process_hash answering
// about one process while labelling the answer with another.
func TestEveryPidArgumentIsRangeChecked(t *testing.T) {
	big := &object.Integer{Value: pidTooBig()}
	pattern := stringObj("needle")

	cases := []struct {
		name string
		call func() object.Object
	}{
		{"process_hash", func() object.Object { return ProcessHash(big) }},
		{"process_env", func() object.Object { return ProcessEnv(big) }},
		{"process_open_files", func() object.Object { return ProcessOpenFiles(big) }},
		{"process_threads", func() object.Object { return ProcessThreads(big) }},
		{"process_modules", func() object.Object { return ProcessModules(big) }},
		{"process_tree", func() object.Object { return ProcessTree(big) }},
		{"process_memory_scan", func() object.Object { return ProcessMemoryScan(big, pattern) }},
		{"process_kill", func() object.Object { return ProcessKill(big) }},
	}

	for _, tc := range cases {
		_, errObj := unwrapPair(t, tc.call())
		if errObj == nil {
			t.Fatalf("%s accepted a pid past math.MaxInt32", tc.name)
		}
		if !strings.Contains(errObj.Message, "between 0 and") {
			t.Fatalf("%s: expected the pid range refusal, got %q", tc.name, errObj.Message)
		}
	}
}

// TestNegativePidsAreRefusedEverywhere is the half of the floor that is the
// same for every builtin here. A negative number is not a pid in any of the
// backends under this file: kill(2) reads it as a process group addressed by
// id, gopsutil's process.NewProcess has nothing to look up, and no builtin in
// the tree has ever had a reason to produce one.
func TestNegativePidsAreRefusedEverywhere(t *testing.T) {
	for _, pid := range []int64{-1, -int64(os.Getpid()), math.MinInt32} {
		if _, killErr := unwrapPair(t, ProcessKill(&object.Integer{Value: pid})); killErr == nil {
			t.Fatalf("process_kill(%d) must be refused", pid)
		}
		_, hashErr := unwrapPair(t, ProcessHash(&object.Integer{Value: pid}))
		if hashErr == nil {
			t.Fatalf("process_hash(%d) must be refused", pid)
		}
		if !strings.Contains(hashErr.Message, "must be a pid") {
			t.Fatalf("process_hash(%d): expected the pid refusal, got %q", pid, hashErr.Message)
		}
	}
}

// TestOnlyProcessKillRefusesPidZero is the false-refusal guard on the other
// half, and it is the whole reason the floor is not 1 everywhere.
//
// Zero reaches these builtins without a script ever typing it. On Windows
// process_list() returns the System Idle Process as pid 0, and the list is
// sorted ascending, so it is the first entry a loop sees; syslog_parse writes
// 0 for any line that carries no procid. The ordinary program
//
//	each(process_list(), fn(p) { process_threads(p["pid"]) })
//
// therefore reaches process_threads(0) on the first iteration. That answers
// today, and a floor of 1 would have turned a working script into an error --
// which is the one failure this package is not allowed to introduce.
//
// process_kill is the exception, and not by preference: to kill(2) zero is not
// a pid at all. It names every process in the caller's group, which includes
// the shell the examiner is sitting in.
//
// Both of the builtins this list used to leave out are back in it, because the
// rows they were waiting on are closed.
//
// process_tree was out because M26-NET-003's walk did not terminate when a pid
// is its own parent, which on Windows pid 0 is: calling process_tree(0) here
// grew the heap until the allocator killed the test binary. The seen set in
// sfDescendants fixed that, and it was measured again when this list changed --
// process_tree(0) returns the real children of ppid 0 over a table of 399
// processes.
//
// process_modules was out because M26-NET-019 was open: Toolhelp32 reads a
// process id of 0 as the calling process, so it answered with this binary's own
// DLLs. It refuses pid 0 now, and that is why both are asserted the way this
// list asserts everything -- not that they answer, but that if they refuse,
// they do not refuse for the RANGE. A range refusal is this package's own
// invention and the one that would break a loop over process_list; a refusal
// that says what pid 0 is on this platform is the builtin doing its job.
func TestOnlyProcessKillRefusesPidZero(t *testing.T) {
	zero := &object.Integer{Value: 0}

	_, killErr := unwrapPair(t, ProcessKill(zero))
	if killErr == nil {
		t.Fatal("process_kill(0) must be refused: kill(2) reads 0 as the caller's process group")
	}
	if !strings.Contains(killErr.Message, "1 or more") {
		t.Fatalf("process_kill(0): expected the kill floor refusal, got %q", killErr.Message)
	}

	// What the query builtins answer for pid 0 is the platform's business, and
	// on Linux there is no such process at all. What they must not do is
	// refuse it for being out of range, because that refusal is this package's
	// own invention and it is what would break the loop above.
	queries := []struct {
		name string
		call func() object.Object
	}{
		{"process_hash", func() object.Object { return ProcessHash(zero) }},
		{"process_threads", func() object.Object { return ProcessThreads(zero) }},
		{"process_open_files", func() object.Object { return ProcessOpenFiles(zero) }},
		{"process_env", func() object.Object { return ProcessEnv(zero) }},
		{"process_memory_scan", func() object.Object { return ProcessMemoryScan(zero, stringObj("needle")) }},
		{"process_modules", func() object.Object { return ProcessModules(zero) }},
		{"process_tree", func() object.Object { return ProcessTree(zero) }},
	}

	for _, tc := range queries {
		_, errObj := unwrapPair(t, tc.call())
		if errObj == nil {
			continue
		}
		if strings.Contains(errObj.Message, "must be a pid") {
			t.Fatalf("%s(0) was refused for its range, which no longer bounds it: %q",
				tc.name, errObj.Message)
		}
	}
}

// TestThePidDefaultAndThisProcessStillWork is the false-refusal guard. Every
// one of these builtins defaults to this process when the argument is left
// out, which is how the example and the docs use them, and an explicit
// os.Getpid() has to keep working too.
func TestThePidDefaultAndThisProcessStillWork(t *testing.T) {
	self := &object.Integer{Value: int64(os.Getpid())}

	if _, errObj := unwrapPair(t, ProcessHash()); errObj != nil {
		t.Fatalf("process_hash() with no argument: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, ProcessHash(self)); errObj != nil {
		t.Fatalf("process_hash(getpid()): %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, ProcessTree()); errObj != nil {
		t.Fatalf("process_tree() with no argument: %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, ProcessTree(self)); errObj != nil {
		t.Fatalf("process_tree(getpid()): %s", errObj.Message)
	}
	if _, errObj := unwrapPair(t, ProcessEnv()); errObj != nil {
		t.Fatalf("process_env() with no argument: %s", errObj.Message)
	}
	// process_memory_scan is the one builtin here that refuses this process,
	// and for a reason of its own: its pattern argument sits in the memory it
	// would scan, so every pattern matches (M26-NET-007). The guard this test
	// exists for still applies -- the refusal must not be a range refusal,
	// which is what would break the loop above.
	_, errObj := unwrapPair(t, ProcessMemoryScan(self, stringObj("needle")))
	if errObj == nil {
		t.Fatal("process_memory_scan(getpid(), ...) answered about the calling process")
	}
	if strings.Contains(errObj.Message, "must be a pid") {
		t.Fatalf("process_memory_scan(getpid()) was refused for its range: %q", errObj.Message)
	}
}
