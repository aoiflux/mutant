package builtin

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// One subject: a builtin here answers a question about a pid, and for seven
// reasons the thing it answered about was not the process the caller named --
// the calling process in place of the one asked for, a thread group in place of
// a thread, a process that was not running at all, an environment that could
// not be read reported as an empty one, and a per-drive variable reported under
// a name belonging to three others.
//
// Every expectation below is written from the platform's own documented
// behaviour or measured against the platform directly, never read from the
// table or the helper under test. A test that takes its expectation from the
// code it checks would have passed against all seven.

// procScanChild makes this binary hold a pattern in memory so another process
// can look for it. A flag rather than an environment variable, which this
// project does not use anywhere, and which the policy guard enforces.
var procScanChild = flag.String("procscan.child", "",
	"internal: hold a needle derived from this seed in memory and wait to be scanned")

// procScanNeedle derives the needle from a seed.
//
// The seed travels on the child's command line and the needle does not, so the
// needle cannot be matched out of the child's argv: a hit is the child's own
// data. The parent holds the needle too, which is the whole point -- that copy
// is why a self-scan can never answer, and a scan of another process cannot
// reach it.
func procScanNeedle(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "mutant-crossproc-" + hex.EncodeToString(sum[:])[:24]
}

// TestProcessScanChild is the other half of the cross-process scan test. It is
// not a test of anything on its own and does nothing unless its flag is set.
func TestProcessScanChild(t *testing.T) {
	if *procScanChild == "" {
		t.Skip("not the child")
	}
	needle := []byte(procScanNeedle(*procScanChild))
	held := make([]byte, len(needle))
	copy(held, needle)

	fmt.Println("ready")
	os.Stdout.Sync()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		runtime.KeepAlive(held)
	}
	runtime.KeepAlive(held)
}

func procScanFreshSeed(t *testing.T) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// startScanChild launches the holder and waits until it says it is holding the
// needle, so the scan cannot race the allocation.
func startScanChild(t *testing.T, seed string) int {
	t.Helper()
	child := exec.Command(os.Args[0], "-test.run=^TestProcessScanChild$", "-test.count=1",
		"-procscan.child="+seed)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start the holder: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	ready := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			if strings.TrimSpace(line) == "ready" {
				ready <- nil
				io.Copy(io.Discard, reader)
				return
			}
			if err != nil {
				ready <- err
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("the holder never reported ready: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatalf("the holder did not report ready in time")
	}
	return child.Process.Pid
}

// M26-NET-007, the capability half. A scan of another process finds what that
// process holds and does not find what it does not, which is the pair of
// answers a self-scan could not give: the pattern argument sits in the scanned
// memory there, so a pattern that exists nowhere else still matched -- twice
// when this was measured and six times when it was first reported.
func TestProcessMemoryScanReadsAnotherProcess(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skipf("no region walker on %s", runtime.GOOS)
	}
	seed := procScanFreshSeed(t)
	pid := startScanChild(t, seed)

	// The needle the child holds. This process holds it too, in the string
	// below and in whatever the derivation left behind; none of that is in the
	// child, so a match is the child's copy.
	held := procScanNeedle(seed)
	payload, errObj := unwrapPair(t, ProcessMemoryScan(intObj(int64(pid)), stringObj(held)))
	if errObj != nil {
		if strings.Contains(errObj.Message, "Access is denied") ||
			strings.Contains(errObj.Message, "permission denied") ||
			strings.Contains(errObj.Message, "operation not permitted") {
			t.Skipf("this host does not let the test read its own child: %s", errObj.Message)
		}
		t.Fatalf("scanning the holder: %s", errObj.Message)
	}
	h, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload %T", payload)
	}
	if got := hInt(t, h, "matched"); got < 1 {
		t.Errorf("the needle the holder is holding was not found: matched=%d", got)
	}
	if got := hInt(t, h, "pid"); got != int64(pid) {
		t.Errorf("the answer is labelled pid %d, the holder is %d", got, pid)
	}

	// The negative, which is the assertion the old scan could not have passed.
	// A needle derived from a different seed exists in this process -- the line
	// below builds it -- and nowhere in the child.
	absent := procScanNeedle(procScanFreshSeed(t))
	payload, errObj = unwrapPair(t, ProcessMemoryScan(intObj(int64(pid)), stringObj(absent)))
	if errObj != nil {
		t.Fatalf("scanning the holder for an absent needle: %s", errObj.Message)
	}
	h, ok = payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload %T", payload)
	}
	if got := hInt(t, h, "matched"); got != 0 {
		addrs, _ := hashValueByKey(h, "addresses").(*object.Array)
		t.Errorf("a needle no process holds matched %d time(s) in pid %d: %v", got, pid, addrs)
	}
}

// M26-NET-007, the refusal half. The calling process is the one process whose
// scan cannot mean anything, because the caller's own copy of the pattern is in
// the memory being scanned.
func TestProcessMemoryScanRefusesTheCallingProcess(t *testing.T) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	fresh := "zz-" + hex.EncodeToString(b[:])

	_, errObj := unwrapPair(t, ProcessMemoryScan(intObj(int64(os.Getpid())), stringObj(fresh)))
	if errObj == nil {
		t.Fatalf("process_memory_scan answered about the calling process")
	}
	for _, want := range []string{"cannot scan the calling process", "every pattern matches"} {
		if !strings.Contains(errObj.Message, want) {
			t.Errorf("the refusal does not say %q: %s", want, errObj.Message)
		}
	}
	// It must be refused for being this process, not for its range: the range
	// no longer bounds a pid that is merely large, and a range refusal here
	// would be a different defect wearing this one's message.
	if strings.Contains(errObj.Message, "must be a pid") {
		t.Errorf("refused for its range rather than for being this process: %s", errObj.Message)
	}
}

// M26-NET-019. CreateToolhelp32Snapshot documents a process id of 0 as meaning
// the current process, so process_modules(0) -- the System Idle Process, which
// process_list returns first -- answered with Mutant's own DLLs.
func TestProcessModulesRefusesPidZeroOnWindows(t *testing.T) {
	payload, errObj := unwrapPair(t, ProcessModules(intObj(0)))
	if runtime.GOOS != "windows" {
		// Elsewhere there is no such process to confuse, and the backend's own
		// error is the right answer; this only asserts no module list appears.
		if errObj == nil {
			if arr, ok := payload.(*object.Array); ok && len(arr.Elements) > 0 {
				t.Errorf("process_modules(0) on %s listed %d module(s)", runtime.GOOS, len(arr.Elements))
			}
		}
		return
	}
	if errObj == nil {
		arr, _ := payload.(*object.Array)
		n := 0
		if arr != nil {
			n = len(arr.Elements)
		}
		t.Fatalf("process_modules(0) answered with %d module(s)", n)
	}
	self, err := os.Executable()
	if err == nil && strings.Contains(errObj.Message, self) {
		t.Errorf("the refusal names this process: %s", errObj.Message)
	}
	if !strings.Contains(errObj.Message, "System Idle Process") {
		t.Errorf("the refusal does not say what pid 0 is: %s", errObj.Message)
	}
	// And the pid that is not 0 still works, so this is a refusal and not a
	// narrowing of what process_modules answers.
	if _, errObj := unwrapPair(t, ProcessModules(intObj(int64(os.Getpid())))); errObj != nil {
		t.Errorf("process_modules(getpid()) stopped working: %s", errObj.Message)
	}
}

// M26-NET-022. The name of a Windows per-drive entry begins with the separator,
// so splitting at the first one gave every such entry the empty name and each
// overwrote the last.
//
// The cases are written from the format Windows uses, not read from the helper.
func TestEnvironmentNamesThatBeginWithTheSeparator(t *testing.T) {
	cases := []struct {
		line  string
		key   string
		value string
		ok    bool
	}{
		// The per-drive working directories and the last exit status, which are
		// the entries that were lost. Their names are "=C:", "=O:", "=ExitCode".
		{`=C:=C:\Users\examiner`, "=C:", `C:\Users\examiner`, true},
		{`=O:=O:\project\mutant`, "=O:", `O:\project\mutant`, true},
		{"=ExitCode=00000000", "=ExitCode", "00000000", true},
		// Ordinary entries are untouched, including a value that holds the
		// separator itself, which is what a PATH-like list does.
		{"PATH=C:/windows", "PATH", "C:/windows", true},
		{"A=b=c", "A", "b=c", true},
		{"EMPTY=", "EMPTY", "", true},
		// A line that is not an assignment is not one.
		{"", "", "", false},
		{"NOEQUALS", "", "", false},
		// A lone separator names nothing and has no value, and must not be read
		// as the empty name with an empty value either.
		{"=", "", "", false},
	}
	for _, c := range cases {
		key, value, ok := sfSplitEnvLine(c.line)
		if ok != c.ok || key != c.key || value != c.value {
			t.Errorf("sfSplitEnvLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.line, key, value, ok, c.key, c.value, c.ok)
		}
	}

	// The three entries that used to collapse now hold three names.
	seen := map[string]string{}
	for _, line := range []string{`=C:=C:\one`, `=O:=O:\two`, "=ExitCode=3"} {
		key, value, ok := sfSplitEnvLine(line)
		if !ok {
			t.Fatalf("%q did not split", line)
		}
		if prior, clash := seen[key]; clash {
			t.Fatalf("%q took the name %q already held by %q", line, key, prior)
		}
		seen[key] = value
	}
	if len(seen) != 3 {
		t.Errorf("three per-drive entries produced %d name(s): %v", len(seen), seen)
	}
	if _, empty := seen[""]; empty {
		t.Error("a per-drive entry was filed under the empty name")
	}
}

// Beyond the rows, same class. gopsutil's Windows reader returns no variables
// AND no error when the read was refused, so process_env reported "this process
// has no environment variables" for every process out of reach: 189 of the 391
// other processes on the machine this was measured on.
func TestProcessEnvNeverReportsAnEnvironmentItCouldNotRead(t *testing.T) {
	payload, errObj := unwrapPair(t, ProcessList())
	if errObj != nil {
		t.Fatalf("process_list: %s", errObj.Message)
	}
	arr, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("payload %T", payload)
	}

	self := int64(os.Getpid())
	var answered, empty, refused int
	var emptyPids []int64
	for _, e := range arr.Elements {
		h, ok := e.(*object.Hash)
		if !ok {
			continue
		}
		pid := hInt(t, h, "pid")
		if pid == self {
			continue
		}
		res, rerr := unwrapPair(t, ProcessEnv(intObj(pid)))
		if rerr != nil {
			refused++
			continue
		}
		eh, _ := res.(*object.Hash)
		if eh == nil || len(eh.Pairs) == 0 {
			empty++
			if len(emptyPids) < 10 {
				emptyPids = append(emptyPids, pid)
			}
			continue
		}
		answered++
	}
	t.Logf("%d answered with variables, %d with none, %d refused", answered, empty, refused)
	if runtime.GOOS == "windows" && empty > 0 {
		t.Errorf("process_env reported an empty environment for %d process(es) on Windows, "+
			"where an empty answer means the read was refused: pids %v", empty, emptyPids)
	}
	if answered == 0 && refused == 0 {
		t.Skip("no other process was reachable at all")
	}
}

// Beyond the rows, same class. process_tree walks a snapshot of the table
// instead of opening the pid, so it never found out whether its root existed:
// it answered {root_pid: N, descendants: []} -- "that process is running and has
// nothing under it" -- for any number in range, which is how a Windows thread id
// got an answer out of it.
func TestProcessTreeRefusesARootThatIsNotRunning(t *testing.T) {
	const absent = 999331 // high, in range, and not a pid on any host running this
	payload, errObj := unwrapPair(t, ProcessTree(intObj(absent)))
	if errObj == nil {
		t.Fatalf("process_tree(%d) answered: %s", absent, payload.Inspect())
	}
	if !strings.Contains(errObj.Message, "no process with pid") {
		t.Errorf("the refusal does not say the pid is not running: %s", errObj.Message)
	}
	if strings.Contains(errObj.Message, "must be a pid") {
		t.Errorf("refused for its range, which no longer bounds it: %s", errObj.Message)
	}

	// The root that is running still works, with and without the argument, and
	// this process is its own root -- so this is a refusal of what is absent,
	// not a narrowing of what process_tree answers.
	for _, call := range []struct {
		name string
		run  func() object.Object
	}{
		{"process_tree()", func() object.Object { return ProcessTree() }},
		{"process_tree(getpid())", func() object.Object { return ProcessTree(intObj(int64(os.Getpid()))) }},
	} {
		h, errObj := unwrapPair(t, call.run())
		if errObj != nil {
			t.Fatalf("%s: %s", call.name, errObj.Message)
		}
		hash, ok := h.(*object.Hash)
		if !ok {
			t.Fatalf("%s payload %T", call.name, h)
		}
		if got := hInt(t, hash, "root_pid"); got != int64(os.Getpid()) {
			t.Errorf("%s reports root_pid %d, want %d", call.name, got, os.Getpid())
		}
	}
}

// M26-NET-024. The note said another signal was ignored on Windows; the code
// refuses it, which is the safer of the two, so the note was what had to move.
func TestProcessKillNoteMatchesTheWindowsBehaviour(t *testing.T) {
	note := builtinDocs[BuiltinNameProcessKill].platformNote
	if note == "" {
		t.Fatal("process_kill has no platform note")
	}
	if strings.Contains(note, "signal numbers are ignored") {
		t.Errorf("the note still says other signals are ignored: %s", note)
	}
	if !strings.Contains(note, "refused") {
		t.Errorf("the note does not say another signal is refused: %s", note)
	}
	if runtime.GOOS != "windows" {
		return
	}
	// And the code does refuse it, measured rather than taken from the note --
	// against a pid that is not running, so nothing is signalled either way.
	_, errObj := unwrapPair(t, ProcessKill(intObj(999331), intObj(15)))
	if errObj == nil {
		t.Fatal("process_kill(999331, SIGTERM) did not refuse on Windows")
	}
	if !strings.Contains(errObj.Message, "SIGKILL") {
		t.Errorf("the refusal does not name what Windows does support: %s", errObj.Message)
	}
}

// M26-NET-033. Linux puts a thread at /proc/<tid> as well as under
// /proc/<pid>/task/<tid>, so every builtin that took a pid answered for a thread
// id and labelled the answer with it -- a number process_list never returns.
func TestAThreadIDIsNotAProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("no thread directory under /proc on %s", runtime.GOOS)
	}
	self := int64(os.Getpid())
	payload, errObj := unwrapPair(t, ProcessThreads(intObj(self)))
	if errObj != nil {
		t.Fatalf("process_threads(self): %s", errObj.Message)
	}
	h, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload %T", payload)
	}
	tids, _ := hashValueByKey(h, "tids").(*object.Array)
	if tids == nil || len(tids.Elements) < 2 {
		t.Skip("this process has only one thread to ask about")
	}
	var tid int64
	for _, e := range tids.Elements {
		i, _ := e.(*object.Integer)
		if i != nil && i.Value != self {
			tid = i.Value
			break
		}
	}
	if tid == 0 {
		t.Skip("no non-leader thread id available")
	}

	// The two halves of the contradiction this closes: the id is a thread of
	// this process, and process_list does not list it.
	listPayload, listErr := unwrapPair(t, ProcessList())
	if listErr != nil {
		t.Fatalf("process_list: %s", listErr.Message)
	}
	for _, e := range listPayload.(*object.Array).Elements {
		ph, ok := e.(*object.Hash)
		if ok && hInt(t, ph, "pid") == tid {
			t.Fatalf("process_list lists %d, so it is not a thread id", tid)
		}
	}

	cases := []struct {
		name string
		run  func(int64) object.Object
	}{
		{"process_hash", func(p int64) object.Object { return ProcessHash(intObj(p)) }},
		{"process_env", func(p int64) object.Object { return ProcessEnv(intObj(p)) }},
		{"process_tree", func(p int64) object.Object { return ProcessTree(intObj(p)) }},
		{"process_threads", func(p int64) object.Object { return ProcessThreads(intObj(p)) }},
		{"process_open_files", func(p int64) object.Object { return ProcessOpenFiles(intObj(p)) }},
		{"process_modules", func(p int64) object.Object { return ProcessModules(intObj(p)) }},
		{"process_memory_scan", func(p int64) object.Object { return ProcessMemoryScan(intObj(p), stringObj("x")) }},
	}
	for _, c := range cases {
		res, rerr := unwrapPair(t, c.run(tid))
		if rerr == nil {
			t.Errorf("%s(%d) answered for a thread id: %s", c.name, tid, res.Inspect())
			continue
		}
		// The refusal has to name the pid to ask about instead, or the caller
		// is left with a number and no way forward.
		if !strings.Contains(rerr.Message, "not a process id") {
			t.Errorf("%s(%d) refused for another reason: %s", c.name, tid, rerr.Message)
			continue
		}
		if !strings.Contains(rerr.Message, fmt.Sprintf("%d", self)) {
			t.Errorf("%s(%d) does not name pid %d to ask about instead: %s",
				c.name, tid, self, rerr.Message)
		}
	}

	// And the thread group leader is answered, so this refuses a thread rather
	// than narrowing what a pid may be.
	if _, errObj := unwrapPair(t, ProcessHash(intObj(self))); errObj != nil {
		t.Errorf("process_hash(getpid()) stopped working: %s", errObj.Message)
	}
}
