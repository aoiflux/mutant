//go:build unix

package security

import (
	"os/exec"
	"syscall"
)

// commandProcessTree is the set of processes one command may start, named by
// their process group.
//
// Setpgid makes the command's own process a group leader, so the group id is
// its pid and everything it starts inherits the group. One kill(-pgid) then
// reaches the whole group, where killing the command's own process -- which is
// all exec.CommandContext does -- leaves `sh -c 'sleep 30 & sleep 30'` with a
// live background sleep holding the output pipe, and Wait reads that pipe to
// EOF (M26-TMP-006).
//
// A descendant that calls setsid or setpgid for itself leaves the group and is
// out of reach. That is the one thing a process group cannot do, and it is why
// cmd.WaitDelay is set as well: the call is bounded whether or not the kill
// reached everything. Nothing here claims otherwise.
type commandProcessTree struct {
	// cmd is held, rather than the group id copied out of it, and that is a
	// synchronisation decision and not a convenience.
	//
	// terminate is cmd.Cancel, so it runs on the goroutine os/exec starts as
	// the LAST statement of Start -- `go c.watchCtx(resultc)`, exec.go:783 in
	// go1.26.6 -- while c.Process is assigned at :733, fifty lines before it.
	// Creating a goroutine happens-after everything the creating goroutine
	// wrote first, so terminate's read of cmd.Process is ordered against that
	// write and needs nothing else; os/exec's own default Cancel,
	// `func() error { return cmd.Process.Kill() }`, is race-free for exactly
	// that reason. Process.Pid is written once, where the Process is made, and
	// Cmd.Wait reaps through Process.Wait, which does not touch it.
	//
	// Recording the pid in adopt instead -- which is what this did first -- is
	// a data race, and one the release gate reports rather than tolerates:
	// adopt runs on the CALLING goroutine after Start has returned, so the
	// write is not ordered against terminate's read at all, and
	// scripts/release_gate.sh:64 has ./security/... in RACE_PACKAGES with
	// :186 running `go test -race`. Holding cmd also closes the window that
	// version left open, where a deadline passing before adopt ran found a
	// zero pid and killed nothing.
	cmd *exec.Cmd
}

// newProcessTree asks for a group of the command's own. It must be called
// before cmd.Start: SysProcAttr is read when the process is created and
// cmd.Cancel when it is started.
//
// A group of its own also takes the command out of Mutant's group, so a Ctrl-C
// at Mutant's terminal no longer reaches it. Nothing is lost by that here: the
// deadline is what bounds this command, stdin is /dev/null because nothing sets
// it, and both output streams are pipes, so there is no terminal read or write
// for a background group to be stopped on.
func newProcessTree(cmd *exec.Cmd) (*commandProcessTree, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	tree := &commandProcessTree{cmd: cmd}
	cmd.Cancel = tree.terminate
	return tree, nil
}

// adopt has nothing to do on this platform. The group id is the command's pid,
// and Start assigns cmd.Process itself before the goroutine that reads it
// exists, so there is nothing for the calling goroutine to hand over -- and
// nothing for it to hand over unsynchronised. See the cmd field.
func (t *commandProcessTree) adopt(cmd *exec.Cmd) {
	_ = cmd
}

// terminate kills the whole group.
//
// It is cmd.Cancel, so it runs from os/exec's cancellation goroutine the moment
// the deadline passes -- before Wait has reaped the command. The group leader
// is therefore still alive, the group id is still the command's, and it cannot
// have been handed to anything else.
//
// An already-empty group is not a failure: a command that exited in the same
// instant as the deadline is a race, not an error, and saying nothing here
// leaves os/exec to report the deadline it already knows about. The comparison
// is == on a syscall.Errno rather than errors.Is, which the purity walk
// forbids reaching for from an allowlisted builtin.
func (t *commandProcessTree) terminate() error {
	if t.cmd.Process == nil {
		return nil
	}
	pid := t.cmd.Process.Pid
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}

// release deliberately kills nothing.
//
// By the time this runs Wait has reaped the command, so its pid is free again
// -- and the group id is that pid. A group that still has members cannot be
// confused with anything else, but a group that emptied has given the id back,
// and a signal sent to a group id that something else has since taken kills a
// process Mutant never started. Unix has no handle that names the set the way
// a Windows job object does, so the choice is between a kill that is probably
// aimed at the right processes and no kill at all, and no kill is the one that
// cannot be wrong.
//
// Checking first with kill(-pgid, 0) was considered and rejected: a group that
// is non-empty now is not a group that was never empty, so the check narrows
// the window instead of closing it, and that would buy a claim this cannot
// honestly make.
//
// What survives, then, is a descendant of a command that exited cleanly before
// its deadline. That is reported as errorCommandAbandoned rather than killed,
// so the caller is told rather than reassured.
func (t *commandProcessTree) release() {}

// setRawCommandLine does nothing here. A command line is a Windows idea: on
// these systems a process is started from an argv, and the shell is handed the
// command as one element of it with no escaping in between -- which is why
// M26-TMP-008 is a Windows row.
//
// cmd.exe reached from WSL through interop is the exception, and the command
// line there is built by the interop layer out of the argv. It is not this
// package's to set and the old quoting stands on that path.
func setRawCommandLine(cmd *exec.Cmd, rawCommandLine string) {
	_, _ = cmd, rawCommandLine
}
