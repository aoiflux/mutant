package builtin

import (
	"os"
	"strconv"
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
