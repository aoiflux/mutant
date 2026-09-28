//go:build linux

package builtin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

// TestTheProcessBuiltinsReadTheRealProc holds process_list, process_tree,
// process_env, process_hash, process_modules, process_open_files and
// process_threads to /proc. They read it through gopsutil, which on Linux reads
// whatever directory HOST_PROC names instead, and decides that a pid exists by
// signalling it when that directory is not a mount, so whoever set the
// examiner's environment decided what the live-response builtins reported
// (M26-NET-025).
//
// The test plants a /proc of its own for a child it starts -- another name,
// parent, environment, executable, module, open file and thread -- names it in
// HOST_PROC, and requires every builtin to report the child as it is.
func TestTheProcessBuiltinsReadTheRealProc(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("start a child to look at: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	pid := child.Process.Pid
	real := filepath.Join("/proc", strconv.Itoa(pid))
	exe, err := os.Readlink(filepath.Join(real, "exe"))
	if err != nil {
		t.Fatalf("read the child's executable: %v", err)
	}

	plant := t.TempDir()
	planted := filepath.Join(plant, strconv.Itoa(pid))
	plantedExe := filepath.Join(plant, "planted-binary")
	mustWrite(t, plantedExe, "planted binary\n")
	mustWrite(t, filepath.Join(plant, "stat"), mustRead(t, "/proc/stat"))
	stat := plantedStat(t, mustRead(t, filepath.Join(real, "stat")))
	mustWrite(t, filepath.Join(planted, "stat"), stat)
	mustWrite(t, filepath.Join(planted, "task", strconv.Itoa(pid), "stat"), stat)
	mustWrite(t, filepath.Join(planted, "task", "999999", "stat"), stat)
	mustWrite(t, filepath.Join(planted, "comm"), "planted\n")
	mustWrite(t, filepath.Join(planted, "status"), plantedStatus(mustRead(t, filepath.Join(real, "status"))))
	mustWrite(t, filepath.Join(planted, "environ"), "PLANTED=by-HOST_PROC\x00")
	mustWrite(t, filepath.Join(planted, "smaps"),
		strings.ReplaceAll(mustRead(t, filepath.Join(real, "smaps")), exe, "/planted/libevil.so"))
	if err := os.MkdirAll(filepath.Join(planted, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(planted, "exe"):     plantedExe,
		filepath.Join(planted, "fd", "7"): "/planted/open-file",
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("HOST_PROC", plant)

	list, errObj := unwrapPair(t, ProcessList())
	if errObj != nil {
		t.Fatalf("process_list: %s", errObj.Inspect())
	}
	if entry := processEntry(t, list, pid); entry == nil {
		t.Errorf("process_list did not list the child, pid %d: %s", pid, list.Inspect())
	} else if name, parent := sfMustHashString(t, entry, "name"), sfHashInt(t, entry, "ppid"); name != "sleep" ||
		parent != int64(os.Getpid()) {
		t.Errorf("process_list reported the child as %s under pid %d, not as sleep under pid %d", name, parent, os.Getpid())
	}
	// The planted /proc holds the child alone, so a list read from it hides
	// every other process, this test's among them.
	if processEntry(t, list, os.Getpid()) == nil {
		t.Errorf("process_list did not list this process, pid %d: the planted /proc hid it", os.Getpid())
	}
	tree, errObj := unwrapPair(t, ProcessTree(intObj(int64(os.Getpid()))))
	if errObj != nil {
		t.Fatalf("process_tree: %s", errObj.Inspect())
	}
	if processEntry(t, sfHashValue(t, tree.(*object.Hash), "descendants"), pid) == nil {
		t.Errorf("process_tree lost the child: %s", tree.Inspect())
	}

	target := intObj(int64(pid))
	for _, c := range []struct {
		name    string
		call    func(...object.Object) object.Object
		planted []string
	}{
		{"process_env", ProcessEnv, []string{"by-HOST_PROC"}},
		{"process_hash", ProcessHash, []string{plantedExe}},
		{"process_modules", ProcessModules, []string{"/planted/libevil.so"}},
		{"process_open_files", ProcessOpenFiles, []string{"/planted/open-file"}},
		{"process_threads", ProcessThreads, []string{"999999", "count: 99,"}},
	} {
		result, errObj := unwrapPairNoFatal(c.call(target))
		for _, planted := range c.planted {
			if errObj == nil && strings.Contains(result.Inspect(), planted) {
				t.Errorf("%s reported the planted /proc: %s", c.name, result.Inspect())
			}
		}
	}
}

// processEntry finds the pid's entry in an array of process hashes.
func processEntry(t *testing.T, list object.Object, pid int) *object.Hash {
	t.Helper()
	array, ok := list.(*object.Array)
	if !ok {
		t.Fatalf("want an ARRAY of processes, got %T", list)
	}
	for _, element := range array.Elements {
		if hash, ok := element.(*object.Hash); ok && sfHashInt(t, hash, "pid") == int64(pid) {
			return hash
		}
	}
	return nil
}

// plantedStat renames the process in a /proc/<pid>/stat line and gives it
// another parent.
func plantedStat(t *testing.T, stat string) string {
	t.Helper()
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		t.Fatalf("not a stat line: %q", stat)
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		t.Fatalf("a stat line with no parent: %q", stat)
	}
	fields[1] = "4242"
	return stat[:open] + "(planted) " + strings.Join(fields, " ") + "\n"
}

// plantedStatus renames the process in /proc/<pid>/status, gives it another
// parent and 99 threads.
func plantedStatus(status string) string {
	lines := strings.Split(status, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "Name:"):
			lines[i] = "Name:\tplanted"
		case strings.HasPrefix(line, "PPid:"):
			lines[i] = "PPid:\t4242"
		case strings.HasPrefix(line, "Threads:"):
			lines[i] = "Threads:\t99"
		}
	}
	return strings.Join(lines, "\n")
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
