package builtin

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"mutant/object"
)

// sfSelfTaskDir is this process's procfs thread directory.
//
// The path is a literal and is deliberately not configurable. sfContext in
// system_forensics.go pins gopsutil's HOST_PROC to /proc for the same reason
// (M26-NET-025): a guard whose reach the environment can move is not a guard,
// and this one decides whether a signal is delivered.
func sfSelfTaskDir() string {
	return "/proc/" + strconv.Itoa(os.Getpid()) + "/task"
}

// sfIsThreadOfThisProcess reports whether id names a thread of THIS process,
// and whether the question could be answered at all on this host.
//
// A pid is not the only number that names this process. process_threads() hands
// a script the OS thread ids of whatever process it was asked about, and every
// thread of this one has a positive id well inside int32 that is not equal to
// os.Getpid(). On Linux a signal addressed to a non-leader thread id is
// delivered to the whole thread group, so process_kill(process_threads()
// ["tids"][0]) ended the run while the guard that exists to refuse exactly that
// compared the argument with the pid and nothing else (M26-NET-029). Nothing is
// truncated on that path -- the number reaches the process it names -- so the
// pid range check M26-NET-005 adds never sees it either.
//
// Two bits, not one, because these are three different answers and a caller
// that collapsed the last two would be guessing:
//
//	(true, true)   id is one of this process's own threads.
//	(false, true)  procfs answered, and id is not one of them.
//	(false, false) this host has no procfs thread directory for this process,
//	               so nothing here can say either way.
//
// The set is read at the moment of the call and never cached. A Go runtime
// starts and retires OS threads on its own schedule, so a set read earlier is a
// guard with a hole that opens by itself; statting the one id that was asked
// about is also cheaper than listing the directory, and it cannot race a thread
// that appeared after the listing.
//
// Where the answer is (false, false) there is no thread id in play to refuse.
// process_threads reads the same procfs, through gopsutil, whose HOST_PROC
// sfContext pins to the same /proc -- so a host that cannot answer here is a
// host where process_threads reports an empty tids array and hands the script
// no thread id at all. That symmetry is measured on linux and on windows, the
// two hosts this build is released for, and reasoned rather than measured on
// the others; one of the tests beside this file pins it, and is the only place
// that would notice if it ever broke.
func sfIsThreadOfThisProcess(id int) (isThread bool, answered bool) {
	tasks := sfSelfTaskDir()
	info, err := os.Stat(tasks)
	if err != nil || !info.IsDir() {
		return false, false
	}
	entry, err := os.Stat(tasks + "/" + strconv.Itoa(id))
	if err != nil || !entry.IsDir() {
		return false, true
	}
	return true, true
}

// sfRefuseThreadID refuses an id that names a thread rather than a process, for
// the builtins that answer a question about a pid.
//
// This is the general form of the question above: not "is this one of my
// threads" but "is this a process at all". Linux puts a thread's directory at
// /proc/<tid> as well as under /proc/<pid>/task/<tid>, and nothing about it says
// which it is except its Tgid line, so gopsutil opens /proc/<id> without asking
// and every builtin that took a pid answered for a thread id -- then labelled
// the answer with it, a number process_list can never return, because /proc does
// not list thread directories. The two together were self-contradictory: a
// script could read a pid out of one builtin's answer that another said did not
// exist (M26-NET-033).
//
// It refuses rather than answering with a note saying which thread group the
// answer is really about. The data under that answer is the thread group's and
// is not wrong; only the label is, and a label is the one thing a forensic
// record cannot be unsure about. The caller asked about a process and there is
// no process by that number, so the refusal names the pid to ask about instead.
//
// No build tag, for the same reason the function above has none: off Linux there
// is no such file, sfThreadGroupID says it could not answer, and nothing is
// refused. That is correct and not a gap. Windows draws thread ids and process
// ids from one allocator, so a thread id is a plausible pid there too -- but it
// was measured, not assumed: passing the current thread's own id to all six
// builtins on Windows 11, five refused it already (OpenProcess and Toolhelp32
// will not accept an id that is not a process) and the sixth, process_tree,
// answered for any absent pid and now looks its root up in the process table.
func sfRefuseThreadID(opName string, pid int) *object.Error {
	tgid, answered := sfThreadGroupID(pid)
	if !answered || tgid == pid {
		return nil
	}
	return newError("argument 1 to `%s` is thread %d of pid %d, not a process id; ask about %d",
		opName, pid, tgid, tgid)
}

// sfThreadGroupID reads Tgid out of /proc/<pid>/status, which is the only place
// the kernel says whether an id is a thread group leader.
//
// Two bits like its neighbour, and for the same reason: "not a thread" and
// "could not say" are different answers, and a caller that collapsed them would
// refuse every pid on a host with no procfs. Not answered is also what a pid
// that does not exist gives, and that is deliberately not turned into a refusal
// here -- each builtin's own error path already answers for an absent pid, with
// its backend's message, and a second refusal in front of it would hide that.
//
// The path is a literal and deliberately not configurable, as sfSelfTaskDir
// above explains.
func sfThreadGroupID(pid int) (tgid int, answered bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rest, found := strings.CutPrefix(scanner.Text(), "Tgid:")
		if !found {
			continue
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}
