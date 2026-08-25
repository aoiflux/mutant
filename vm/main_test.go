package vm

import (
	"os"
	"testing"
)

// Every hosted CI runner is a virtual machine. GitHub's ubuntu, windows and
// macOS images are all hypervisor guests, and the Linux one carries container
// markers on top of that, so security.IsSandboxed() answers true there and
// false on a developer's own box -- which is exactly the shape of failure that
// passes locally and breaks the build.
//
// It did. TestMutationNeverChangesTheReportedResult compiles with security
// opcode injection and runs the result through a secure-mode VM, where OpChkSnd
// finding a sandbox is a halt, not a warning. The test died on Linux and Windows
// CI with "sandbox detected, execution halted for security" while passing on the
// machine it was written on.
//
// Whether a host is a sandbox is the security package's subject and is tested
// there. This package's subject is what the VM does once a detector has
// answered, so the answer is pinned here and the tests that care about a
// different one -- TestVMDevModeWarnsOnSecurityOpcodes and
// TestVMSecureModeHaltsOnSecurityOpcodes -- set it themselves and restore it.
func TestMain(m *testing.M) {
	isDebuggerPresent = func() bool { return false }
	isSandboxed = func() bool { return false }

	os.Exit(m.Run())
}
