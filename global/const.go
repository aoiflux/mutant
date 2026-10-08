package global

// Initial capacities for VM storage. The VM grows these slices dynamically at runtime.
//
// The frame capacity used to be here too, as MaxFrames, where a name saying "max"
// sat one line under a comment saying the VM grows these dynamically. Readers took
// it for the recursion limit the VM did not have, and so did two comments in vm/
// (M26-VM-006, M26-VM-021). It is vm.initialFrameCapacity now, beside
// vm.maxCallDepth, which is the limit.
const (
	StackSize  = 2048
	GlobalSize = 65536

	MutantSourceCodeFileExtention       = ".mut"
	MutantByteCodeCompiledFileExtension = ".mu"
	WindowsPE32ExecutableExtension      = ".exe"
)

const (
	DARWIN  = "darwin"
	LINUX   = "linux"
	WINDOWS = "windows"
)

// Version is the release this build claims to be. It lives here rather than in
// package main because a case manifest has to name the tool that produced it
// (F-1), and `builtin` cannot import the command.
const Version = "2.5.0"
