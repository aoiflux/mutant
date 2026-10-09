//go:build windows

package security

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobKillExitCode is the status Windows gives the processes TerminateJobObject
// kills. Nothing in Mutant reads it: a command killed at its deadline is
// reported as timed out with an exit code of -1, because the code the OS used
// to kill it is not an answer the command gave.
const jobKillExitCode = 1

// commandProcessTree is the set of processes one command may start, named by a
// job object.
//
// A job object is the only handle on Windows that names a process tree as a
// unit. A process started by a member of a job joins the job, so a grandchild
// is reached without anybody having to go and find it, and a limit on the job
// says what happens to whatever is still in it when the last handle closes.
//
// Killing the command's own process -- which is all exec.CommandContext does --
// leaves the rest. Measured at HEAD: `cmd /C ping -n 10 127.0.0.1` against a
// 3-second timeout returned after 9.14 seconds with timed_out true, because
// cmd.exe was killed on time and ping.exe went on holding the output pipe,
// and Wait reads that pipe to EOF (M26-TMP-006).
//
// The handle is written here, in newProcessTree, before cmd.Start, and only
// read afterwards: by adopt on the calling goroutine and by terminate on
// os/exec's cancellation goroutine. Creating that goroutine happens-after this
// write, and release cannot overlap terminate either, because os/exec sends
// its cancellation result only once Cancel has returned and Wait returns only
// once it has that result. Nothing here needs a lock.
type commandProcessTree struct {
	job windows.Handle
}

// newProcessTree creates the job the command will live in and points
// cmd.Cancel at it, so that the kill at the deadline is the job's and not one
// process's. It must be called before cmd.Start, which is when os/exec reads
// Cancel.
//
// The job is set to kill what is left in it when it closes. That makes the
// contract one sentence -- nothing a command starts outlives the call that
// started it -- and it holds on the successful path too, so a command that
// leaves a background process behind no longer leaves it behind. That is a
// change beyond reporting the timeout correctly, and it is deliberate: a 3
// second cap and an 8 KiB output cap describe a builtin for asking the host a
// question, not one for launching a service, and the alternative to killing it
// is an orphan nobody is waiting for.
func newProcessTree(cmd *exec.Cmd) (*commandProcessTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create the job object that bounds the command: %w", err)
	}

	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	// The pin is what makes the uintptr below legal, and it is not a
	// formality. unsafe's rules keep a Pointer converted to a uintptr valid
	// only where the conversion appears in the argument list of the syscall
	// itself, because that is the shape the compiler recognises and keeps the
	// referent alive and unmoved for. windows.SetInformationJobObject takes
	// the address as an ordinary Go uintptr argument, so the conversion is one
	// call too early: between it and the syscall there is a Go function entry,
	// which is where a stack grows, and growing a stack COPIES it -- a limits
	// that lived on this frame would move and the integer would name where it
	// used to be.
	//
	// Pin answers exactly that: the value goes to the heap and stays at one
	// address until Unpin, so what the kernel is given is where the value
	// still is. The alternative was to resolve kernel32!SetInformationJobObject
	// through a windows.LazyProc and call syscall.SyscallN directly, which is
	// the exempt shape; it was rejected because it swaps a documented x/sys
	// entry point for a hand-rolled one to answer a question Pin already
	// answers in two lines. Nothing in x/sys offers this call in a form that
	// takes the pointer.
	var pinner runtime.Pinner
	pinner.Pin(&limits)
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	)
	pinner.Unpin()
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("bound the command's job object: %w", err)
	}

	tree := &commandProcessTree{job: job}
	cmd.Cancel = tree.terminate
	return tree, nil
}

// adopt puts the started process, and so everything it goes on to start, into
// the job.
//
// It takes the handle os/exec already holds rather than reopening the process
// by its pid, which is both shorter and the only version with nothing to
// reason about: a pid can be reused, a handle cannot be anything else.
// os.Process.WithHandle is Go 1.26, which is the toolchain this tree pins.
//
// The error is not reported, and that is a decision and not an oversight. The
// failure that happens in practice is a command that has already exited by the
// time this runs -- `cmd /C echo hi` can be gone in a millisecond -- and
// Windows answers that with the same ERROR_ACCESS_DENIED as a policy refusal,
// so reporting it would be a false alarm most times it fired. Nothing in the
// result claims the tree was bound; what the result claims is that the call was
// bounded, and cmd.WaitDelay makes that true whether this succeeds or not.
func (t *commandProcessTree) adopt(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.WithHandle(func(handle uintptr) {
		_ = windows.AssignProcessToJobObject(t.job, windows.Handle(handle))
	})
}

// terminate kills every process in the job. It is cmd.Cancel, so os/exec calls
// it the moment the deadline passes, while Wait is still running.
func (t *commandProcessTree) terminate() error {
	return windows.TerminateJobObject(t.job, jobKillExitCode)
}

// release closes the job, which kills anything still in it.
func (t *commandProcessTree) release() {
	_ = windows.CloseHandle(t.job)
}

// setRawCommandLine hands the program the command line as written instead of
// letting os/exec build one by escaping the arguments into it.
//
// See rawCommandLineFor in command_exec.go for which shell needs this and what
// the quoting rule becomes. SysProcAttr.CmdLine is the documented way to say
// "this exact command line": syscall.StartProcess uses it in place of the
// escaped form and the argv is then only what resolves the executable.
func setRawCommandLine(cmd *exec.Cmd, rawCommandLine string) {
	if rawCommandLine == "" {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CmdLine = rawCommandLine
}
