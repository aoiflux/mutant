package builtin

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

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

	if runtime.GOOS != "linux" {
		return resultAndError(nil, newError("process_open_files unsupported on %s", runtime.GOOS))
	}

	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return resultAndError(nil, newError("process_open_files: %s", err.Error()))
	}

	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		linkPath := filepath.Join(fdDir, e.Name())
		target, lerr := os.Readlink(linkPath)
		if lerr == nil {
			paths = append(paths, target)
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

	if runtime.GOOS != "linux" {
		return resultAndError(nil, newError("process_threads unsupported on %s", runtime.GOOS))
	}

	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return resultAndError(nil, newError("process_threads: %s", err.Error()))
	}

	elements := make([]object.Object, 0, len(entries))
	for _, e := range entries {
		tid, perr := strconv.Atoi(e.Name())
		if perr == nil {
			elements = append(elements, intObj(int64(tid)))
		}
	}
	sort.Slice(elements, func(i, j int) bool {
		li := elements[i].(*object.Integer)
		lj := elements[j].(*object.Integer)
		return li.Value < lj.Value
	})

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func ProcessModules(args ...object.Object) object.Object {
	pid, errObj := sfParsePIDArg("process_modules", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if runtime.GOOS != "linux" {
		return resultAndError(nil, newError("process_modules unsupported on %s", runtime.GOOS))
	}

	mapsPath := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return resultAndError(nil, newError("process_modules: %s", err.Error()))
	}

	mods := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			path := parts[len(parts)-1]
			if strings.HasPrefix(path, "/") {
				mods = append(mods, path)
			}
		}
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
	} else if runtime.GOOS == "linux" {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
		if err != nil {
			return resultAndError(nil, newError("process_env: %s", err.Error()))
		}
		envLines = strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	} else {
		return resultAndError(nil, newError("process_env for other pids unsupported on %s", runtime.GOOS))
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
	if runtime.GOOS == "linux" {
		return os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	}
	return "", fmt.Errorf("pid executable lookup unsupported on %s", runtime.GOOS)
}

func sfListProcesses() ([]sfProcess, error) {
	if runtime.GOOS == "linux" {
		return sfListProcessesLinux()
	}
	if runtime.GOOS == "windows" {
		return sfListProcessesWindows()
	}
	return sfListProcessesPS()
}

func sfListProcessesLinux() ([]sfProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	out := make([]sfProcess, 0)
	for _, e := range entries {
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		statBytes, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		ppid := 0
		if len(statBytes) > 0 {
			parts := strings.Fields(string(statBytes))
			if len(parts) > 3 {
				if v, err := strconv.Atoi(parts[3]); err == nil {
					ppid = v
				}
			}
		}
		name := strings.TrimSpace(string(comm))
		if name == "" {
			name = "pid-" + e.Name()
		}
		out = append(out, sfProcess{pid: pid, ppid: ppid, name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out, nil
}

func sfListProcessesWindows() ([]sfProcess, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	rows, err := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	if err != nil {
		return nil, err
	}

	res := make([]sfProcess, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(row[1]))
		if err != nil {
			continue
		}
		res = append(res, sfProcess{pid: pid, ppid: 0, name: strings.TrimSpace(row[0])})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].pid < res[j].pid })
	return res, nil
}

func sfListProcessesPS() ([]sfProcess, error) {
	cmd := exec.Command("ps", "-axo", "pid,ppid,comm")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	res := make([]sfProcess, 0, len(lines))
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		pid, e1 := strconv.Atoi(parts[0])
		ppid, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil {
			continue
		}
		name := strings.Join(parts[2:], " ")
		res = append(res, sfProcess{pid: pid, ppid: ppid, name: name})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].pid < res[j].pid })
	return res, nil
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
