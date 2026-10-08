package builtin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v3/common"
	"github.com/shirou/gopsutil/v3/process"

	"mutant/object"
)

// sfContext is the context every gopsutil call is made with. Without one,
// gopsutil builds each path it reads on Linux from HOST_PROC (and the other
// HOST_* variables), and decides that a pid exists by signalling it when that
// directory is not a mount, so the environment chose what the process_*
// builtins reported (M26-NET-025). It names every directory gopsutil would
// otherwise look up, as the one gopsutil falls back to.
var sfContext = context.WithValue(context.Background(), common.EnvKey, common.EnvMap{
	common.HostProcEnvKey: "/proc",
	common.HostSysEnvKey:  "/sys",
	common.HostEtcEnvKey:  "/etc",
	common.HostVarEnvKey:  "/var",
	common.HostRunEnvKey:  "/run",
	common.HostDevEnvKey:  "/dev",
	common.HostRootEnvKey: "/",
})

type sfProcess struct {
	pid  int
	ppid int
	name string
}

func ProcessList(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	procs, err := sfListProcesses()
	if err != nil {
		return resultAndError(nil, newError("process_list: %s", err.Error()))
	}

	elements := make([]object.Object, len(procs))
	for i, p := range procs {
		elements[i] = makeHashObject(map[string]object.Object{
			"pid":  intObj(int64(p.pid)),
			"ppid": intObj(int64(p.ppid)),
			"name": stringObj(p.name),
		})
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func ProcessTree(args ...object.Object) object.Object {
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}

	rootPID := os.Getpid()
	if len(args) == 1 {
		pidObj, ok := args[0].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 1 to `process_tree` must be INTEGER, got %s", args[0].Type()))
		}
		validated, errObj := sfValidatePID(BuiltinNameProcessTree, pidObj.Value)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		rootPID = validated
	}

	procs, err := sfListProcesses()
	if err != nil {
		return resultAndError(nil, newError("process_tree: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"root_pid":    intObj(int64(rootPID)),
		"descendants": &object.Array{Elements: sfDescendants(procs, rootPID)},
	}), nil)
}

// sfDescendants is the breadth-first walk from rootPID down, with each pid
// emitted at most once.
//
// It takes the process slice rather than reading the live process table so that
// the walk can be tested against a table no host has to be holding at the time.
// That matters here, because the two inputs that broke it are a self-parented
// pid and a ppid cycle, and neither can be arranged on a real machine on
// demand.
//
// The seen set is the fix for M26-NET-003. Without it, a process that is its own
// parent appeared in byParent[its own pid], so dequeuing it appended it again,
// and the queue and the output both grew until the process died -- 2 MiB to over
// 1 GiB in under five seconds. On Windows pid 0, the System Idle Process,
// reports ppid 0, and process_list returns it first, so a script that called
// process_tree for each pid in process_list met it on the first one. A ppid
// cycle from pid reuse did the same thing from an ordinary pid. Nothing
// panicked, so the recover() around a builtin never saw any of it.
//
// A pid is marked when it is ENQUEUED rather than when it is emitted, so each
// pid enters the queue at most once. Marking at emit time would terminate just
// as surely -- a pid could then sit in the queue once per parent that claims
// it, which is still bounded by len(procs), because every parent link is
// consumed at most once -- so the stronger invariant is not what makes this
// correct. It is kept because it is the one a reader can check at a glance.
//
// rootPID starts out marked, and that is what stops a process being reported as
// its own descendant: the one symptom of the old walk that was not simply "it
// never came back".
//
// No count cap is added on top of this. The seen set makes termination a
// property of the walk rather than something a limit rescues, and a cap would be
// one more named limit for Stage F to carry, guarding a case that can no longer
// arise.
func sfDescendants(procs []sfProcess, rootPID int) []object.Object {
	byParent := map[int][]sfProcess{}
	for _, p := range procs {
		byParent[p.ppid] = append(byParent[p.ppid], p)
	}

	for k := range byParent {
		sort.Slice(byParent[k], func(i, j int) bool { return byParent[k][i].pid < byParent[k][j].pid })
	}

	desc := make([]object.Object, 0)
	seen := map[int]bool{rootPID: true}
	queue := make([]sfProcess, 0, len(procs))

	enqueue := func(children []sfProcess) {
		for _, c := range children {
			if seen[c.pid] {
				continue
			}
			seen[c.pid] = true
			queue = append(queue, c)
		}
	}

	enqueue(byParent[rootPID])
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		desc = append(desc, makeHashObject(map[string]object.Object{
			"pid":  intObj(int64(cur.pid)),
			"ppid": intObj(int64(cur.ppid)),
			"name": stringObj(cur.name),
		}))
		enqueue(byParent[cur.pid])
	}

	return desc
}

func ProcessOpenFiles(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg(BuiltinNameProcessOpenFiles, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proc, err := process.NewProcessWithContext(sfContext, int32(pid))
	if err != nil {
		return resultAndError(nil, newError("process_open_files: %s", err.Error()))
	}

	files, err := proc.OpenFilesWithContext(sfContext)
	if err != nil {
		return resultAndError(nil, newError("process_open_files: %s", err.Error()))
	}

	paths := make([]string, 0, len(files))
	for _, f := range files {
		if f.Path != "" {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	paths = sfUniqueStrings(paths)

	elements := make([]object.Object, len(paths))
	for i, v := range paths {
		elements[i] = stringObj(v)
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func ProcessThreads(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg(BuiltinNameProcessThreads, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proc, err := process.NewProcessWithContext(sfContext, int32(pid))
	if err != nil {
		return resultAndError(nil, newError("process_threads: %s", err.Error()))
	}

	// NumThreads (the count) is available on every supported OS; the per-thread
	// IDs are only exposed on some (e.g. Linux). Surface the count always and the
	// TIDs where the platform provides them, rather than hard-failing off Linux.
	count, countErr := proc.NumThreadsWithContext(sfContext)
	threads, threadsErr := proc.ThreadsWithContext(sfContext)
	if countErr != nil && threadsErr != nil {
		return resultAndError(nil, newError("process_threads: %s", countErr.Error()))
	}

	tids := make([]int64, 0, len(threads))
	for tid := range threads {
		tids = append(tids, int64(tid))
	}
	sort.Slice(tids, func(i, j int) bool { return tids[i] < tids[j] })
	tidObjects := make([]object.Object, len(tids))
	for i, tid := range tids {
		tidObjects[i] = intObj(tid)
	}

	threadCount := int64(count)
	if countErr != nil {
		threadCount = int64(len(tids))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"pid":   intObj(int64(pid)),
		"count": intObj(threadCount),
		"tids":  &object.Array{Elements: tidObjects},
	}), nil)
}

func ProcessModules(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg(BuiltinNameProcessModules, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	mods, err := sfProcessModulePaths(pid)
	if err != nil {
		return resultAndError(nil, newError("process_modules: %s", err.Error()))
	}
	sort.Strings(mods)
	mods = sfUniqueStrings(mods)

	elements := make([]object.Object, len(mods))
	for i, m := range mods {
		elements[i] = stringObj(m)
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func ProcessHash(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg(BuiltinNameProcessHash, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	exePath, err := sfExecutableForPID(pid)
	if err != nil {
		return resultAndError(nil, newError("process_hash: %s", err.Error()))
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return resultAndError(nil, newError("process_hash: %s", err.Error()))
	}
	digest := sha256.Sum256(data)

	return resultAndError(makeHashObject(map[string]object.Object{
		"pid":    intObj(int64(pid)),
		"path":   stringObj(exePath),
		"sha256": stringObj(hex.EncodeToString(digest[:])),
		"size":   intObj(int64(len(data))),
	}), nil)
}

func ProcessMemoryScan(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	pidObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `process_memory_scan` must be INTEGER, got %s", args[0].Type()))
	}
	patternObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `process_memory_scan` must be STRING, got %s", args[1].Type()))
	}

	if patternObj.Value == "" {
		return resultAndError(nil, newError("process_memory_scan: pattern must be non-empty"))
	}
	pid, errObj := sfValidatePID(BuiltinNameProcessMemoryScan, pidObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Cross-process scanning needs elevated privileges and per-OS handle work;
	// for now only the self process is supported (honest error otherwise).
	if pid != os.Getpid() {
		return resultAndError(nil, newError("process_memory_scan currently supports the self process only (pid %d, self is %d)", pidObj.Value, os.Getpid()))
	}

	const maxMatches = 10000
	addresses, truncated, err := sfScanSelfMemory([]byte(patternObj.Value), maxMatches)
	if err != nil {
		return resultAndError(nil, newError("process_memory_scan: %s", err.Error()))
	}

	addrObjs := make([]object.Object, len(addresses))
	for i, a := range addresses {
		addrObjs[i] = stringObj(fmt.Sprintf("0x%x", a))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"pid":       intObj(pidObj.Value),
		"pattern":   stringObj(patternObj.Value),
		"matched":   intObj(int64(len(addresses))),
		"truncated": boolObj(truncated),
		"addresses": &object.Array{Elements: addrObjs},
	}), nil)
}

func ProcessEnv(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg(BuiltinNameProcessEnv, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var envLines []string
	if pid == os.Getpid() {
		envLines = os.Environ()
	} else {
		proc, err := process.NewProcessWithContext(sfContext, int32(pid))
		if err != nil {
			return resultAndError(nil, newError("process_env: %s", err.Error()))
		}
		envLines, err = proc.EnvironWithContext(sfContext)
		if err != nil {
			return resultAndError(nil, newError("process_env: %s", err.Error()))
		}
	}

	pairs := make(map[string]object.Object, len(envLines))
	for _, line := range envLines {
		if line == "" {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		pairs[line[:idx]] = stringObj(line[idx+1:])
	}

	return resultAndError(makeHashObject(pairs), nil)
}

func ProcessKill(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pidObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `process_kill` must be INTEGER, got %s", args[0].Type()))
	}
	sig := syscall.SIGKILL
	if len(args) == 2 {
		sigObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `process_kill` must be INTEGER, got %s", args[1].Type()))
		}
		sig = syscall.Signal(sigObj.Value)
	}

	// Validated here rather than where the pid is read, so that a bad second
	// argument is still reported as the second argument: process_kill(0, "nine")
	// should say what is wrong with "nine".
	pid, errObj := sfValidateKillPID(BuiltinNameProcessKill, pidObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if pid == os.Getpid() {
		return resultAndError(nil, newError("process_kill refuses to kill current process"))
	}

	// The guard above compares the argument with the pid and nothing else, and
	// a thread id of this process is not that number. process_threads() reports
	// one per OS thread, each positive and well inside int32, so neither that
	// comparison nor the pid range check M26-NET-005 adds sees it. On Linux a
	// signal addressed to a non-leader thread id is delivered to the whole
	// thread group, so process_kill(process_threads()["tids"][0]) ended the run
	// through a documented pair of builtins while the guard that exists to
	// refuse exactly that reported nothing (M26-NET-029). Nothing is truncated
	// on that path -- the number reaches the process it names -- which is why it
	// is a different defect from M26-NET-005 and needs a different check.
	//
	// Asked here rather than folded into that range check: a range narrows a
	// number, and this is not a range. It is a question about which process the
	// number names, answered against procfs at the moment of the kill.
	//
	// Both bits of the answer are read, so that the two cases this does NOT
	// refuse are written down rather than inferred. Answered and not a thread:
	// procfs answered and the id is not one of ours. Not answered: this host has
	// no procfs thread directory for this process, and so hands a script no
	// thread id either -- see sfIsThreadOfThisProcess.
	isThread, answered := sfIsThreadOfThisProcess(pid)
	if answered && isThread {
		return resultAndError(nil, newError("process_kill refuses %d: that is not another "+
			"process, it is a thread of this one (pid %d), and a signal sent to a thread is "+
			"delivered to the whole thread group -- it would end this run", pid, os.Getpid()))
	}

	if runtime.GOOS == "windows" {
		if len(args) == 2 && sig != syscall.SIGKILL {
			return resultAndError(nil, newError("process_kill on windows only supports SIGKILL semantic"))
		}
		p, err := os.FindProcess(pid)
		if err != nil {
			return resultAndError(nil, newError("process_kill: %s", err.Error()))
		}
		if err := p.Kill(); err != nil {
			return resultAndError(nil, newError("process_kill: %s", err.Error()))
		}
		return resultAndError(boolObj(true), nil)
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return resultAndError(nil, newError("process_kill: %s", err.Error()))
	}
	if err := p.Signal(sig); err != nil {
		return resultAndError(nil, newError("process_kill: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func sfParsePIDArg(opName string, args []object.Object) (int, *object.Error) {
	if len(args) > 1 {
		return 0, newError("wrong number of arguments. got=%d, want=0 or 1", len(args))
	}
	if len(args) == 0 {
		return os.Getpid(), nil
	}
	pidObj, ok := args[0].(*object.Integer)
	if !ok {
		return 0, newError("argument 1 to `%s` must be INTEGER, got %s", opName, args[0].Type())
	}
	return sfValidatePID(opName, pidObj.Value)
}

// sfValidatePID narrows a pid argument to the range the backends under this
// file can actually represent, and is the only place a pid enters them.
//
// A script's integer is 64 bits and a pid is not. gopsutil's process.NewProcess
// takes an int32 on every platform, and os.FindProcess on Windows takes a
// DWORD, so a value past math.MaxInt32 was never a pid this package could ask
// about -- it was a pid that got truncated into a different, live process.
// process_hash(2^32 + pid) answered about one process while labelling the
// answer with another, and process_kill(getpid() + 2^32) compared unequal to
// os.Getpid(), walked past the refuse-self guard, and then killed the run with
// the low 32 bits.
//
// Zero is accepted, and that is deliberate. On Windows process_list() returns
// the System Idle Process as pid 0 -- first, because the list is sorted
// ascending -- and syslog_parse writes 0 for any line with no procid, so a
// script that loops over what Mutant handed it reaches 0 without ever naming
// it. Those builtins answer for 0 today and go on doing so; what one of them
// answers WRONGLY for 0 on Windows is M26-NET-019, which is a refusal owed at
// that one site and not a range to narrow here. Negative values are refused
// because no platform has one.
//
// The one builtin that sends a signal rather than asking a question needs a
// floor of 1, and asks for it separately: see sfValidateKillPID.
func sfValidatePID(opName string, pid int64) (int, *object.Error) {
	if pid < 0 || pid > math.MaxInt32 {
		return 0, newError("argument 1 to `%s` must be a pid between 0 and %d, got %d", opName, int64(math.MaxInt32), pid)
	}
	return int(pid), nil
}

// sfValidateKillPID is sfValidatePID with the floor raised to 1, for
// process_kill. 0 and negative values are not pids to kill(2): it reads them as
// process GROUPS, so a signal sent to "pid" 0 goes to every process in the
// caller's group -- which includes the shell the examiner is sitting in -- and
// a negative one addresses the group by id. On Windows 0 is the idle process.
//
// This narrows a number, and a number is not the only way to name this process.
// A thread id from process_threads is in range and is not equal to os.Getpid(),
// and on Linux a signal sent to a non-leader tid is delivered to the whole
// thread group, so process_kill(process_threads()["tids"][0]) still ends the
// run. The refuse-self guard does not hold against that and nothing here makes
// it hold: M26-NET-029 is that, filed separately, because it needs no
// truncation and is a different fix.
func sfValidateKillPID(opName string, pid int64) (int, *object.Error) {
	if pid < 1 {
		return 0, newError("argument 1 to `%s` must be a pid of 1 or more, got %d", opName, pid)
	}
	return sfValidatePID(opName, pid)
}

func sfExecutableForPID(pid int) (string, error) {
	if pid == os.Getpid() {
		return os.Executable()
	}
	proc, err := process.NewProcessWithContext(sfContext, int32(pid))
	if err != nil {
		return "", err
	}
	return proc.ExeWithContext(sfContext)
}

// sfListProcesses enumerates running processes natively across Windows, Linux,
// and macOS via gopsutil (no external `tasklist`/`ps` shell-outs), including a
// real parent PID on every platform.
func sfListProcesses() ([]sfProcess, error) {
	procs, err := process.ProcessesWithContext(sfContext)
	if err != nil {
		return nil, err
	}

	out := make([]sfProcess, 0, len(procs))
	for _, p := range procs {
		ppid, _ := p.PpidWithContext(sfContext)
		name, _ := p.NameWithContext(sfContext)
		if name == "" {
			name = "pid-" + strconv.Itoa(int(p.Pid))
		}
		out = append(out, sfProcess{pid: int(p.Pid), ppid: int(ppid), name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out, nil
}

func sfUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	last := ""
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}
