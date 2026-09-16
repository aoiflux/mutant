package global

// Initial capacities for VM storage. The VM grows these slices dynamically at runtime.
const (
	StackSize  = 2048
	GlobalSize = 65536
	MaxFrames  = 2048

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
