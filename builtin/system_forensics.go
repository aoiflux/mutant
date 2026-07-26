package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v3/process"

	"mutant/object"
)

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
		rootPID = int(pidObj.Value)
	}

	procs, err := sfListProcesses()
	if err != nil {
		return resultAndError(nil, newError("process_tree: %s", err.Error()))
	}

	byParent := map[int][]sfProcess{}
	for _, p := range procs {
		byParent[p.ppid] = append(byParent[p.ppid], p)
	}

	for k := range byParent {
		sort.Slice(byParent[k], func(i, j int) bool { return byParent[k][i].pid < byParent[k][j].pid })
	}

	desc := make([]object.Object, 0)
	queue := append([]sfProcess{}, byParent[rootPID]...)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		desc = append(desc, makeHashObject(map[string]object.Object{
			"pid":  intObj(int64(cur.pid)),
			"ppid": intObj(int64(cur.ppid)),
			"name": stringObj(cur.name),
		}))
		queue = append(queue, byParent[cur.pid]...)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"root_pid":    intObj(int64(rootPID)),
		"descendants": &object.Array{Elements: desc},
	}), nil)
}

func ProcessOpenFiles(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg("process_open_files", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return resultAndError(nil, newError("process_open_files: %s", err.Error()))
	}

	files, err := proc.OpenFiles()
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
	pid, errObj := sfParsePIDArg("process_threads", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return resultAndError(nil, newError("process_threads: %s", err.Error()))
	}

	// NumThreads (the count) is available on every supported OS; the per-thread
	// IDs are only exposed on some (e.g. Linux). Surface the count always and the
	// TIDs where the platform provides them, rather than hard-failing off Linux.
	count, countErr := proc.NumThreads()
	threads, threadsErr := proc.Threads()
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
	pid, errObj := sfParsePIDArg("process_modules", args)
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
	pid, errObj := sfParsePIDArg("process_hash", args)
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

	if runtime.GOOS != "linux" {
		return resultAndError(nil, newError("process_memory_scan unsupported on %s", runtime.GOOS))
	}
	if int(pidObj.Value) != os.Getpid() {
		return resultAndError(nil, newError("process_memory_scan currently supports self process only"))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"pid":      intObj(pidObj.Value),
		"pattern":  stringObj(patternObj.Value),
		"matched":  intObj(0),
		"status":   stringObj("not_implemented"),
		"advisory": boolObj(true),
	}), nil)
}

func ProcessEnv(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg("process_env", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var envLines []string
	if pid == os.Getpid() {
		envLines = os.Environ()
	} else {
		proc, err := process.NewProcess(int32(pid))
		if err != nil {
			return resultAndError(nil, newError("process_env: %s", err.Error()))
		}
		envLines, err = proc.Environ()
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
	pid := int(pidObj.Value)

	sig := syscall.SIGKILL
	if len(args) == 2 {
		sigObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `process_kill` must be INTEGER, got %s", args[1].Type()))
		}
		sig = syscall.Signal(sigObj.Value)
	}

	if pid == os.Getpid() {
		return resultAndError(nil, newError("process_kill refuses to kill current process"))
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
	return int(pidObj.Value), nil
}

func sfExecutableForPID(pid int) (string, error) {
	if pid == os.Getpid() {
		return os.Executable()
	}
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", err
	}
	return proc.Exe()
}

// sfListProcesses enumerates running processes natively across Windows, Linux,
// and macOS via gopsutil (no external `tasklist`/`ps` shell-outs), including a
// real parent PID on every platform.
func sfListProcesses() ([]sfProcess, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	out := make([]sfProcess, 0, len(procs))
	for _, p := range procs {
		ppid, _ := p.Ppid()
		name, _ := p.Name()
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
