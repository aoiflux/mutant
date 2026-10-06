package security

import "testing"

// debuggerNamesUnderTest is a list with the awkward entries in it: a
// two-letter name, a three-letter name, and one that is an application bundle
// rather than a command. Those are the three shapes that made the old
// substring search fire on ordinary words.
var debuggerNamesUnderTest = []string{
	"gdb", "lldb", "valgrind", "rr", "ida", "angr", "xcode", "sample", "vmmap",
}

// TestADebuggerIsRecognisedByItsExecutableNameAlone is M26-TMP-002 and
// M26-TMP-019 together. The check used to lowercase the parent's whole command
// line -- on macOS, a full path -- and search it for each name, so "rr" matched
// "current" and "xcode" matched every tool under /Applications/Xcode.app. In
// secure mode a match terminates the run, so an ordinary path stopped it.
//
// This test exists on no platform in particular, which is the point: the
// matching is separated from the per-OS reading of the parent's name so that
// the Linux and macOS rules can both be run from one host. Neither ever had
// been.
func TestADebuggerIsRecognisedByItsExecutableNameAlone(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
		why  string
	}{
		// What the check is for, in each shape a platform reports.
		{"gdb", true, "the bare name Linux reports in /proc/<pid>/comm"},
		{"/usr/bin/gdb", true, "a full path still names gdb"},
		{"rr", true, "a two-letter name is still a name"},
		{"GDB", true, "comm and ps output are compared without case"},
		{"gdb" + "\n", true, "/proc/<pid>/comm comes back newline-terminated"},
		{"gdb" + "\x00", true, "and NUL-padded"},
		{"  lldb  ", true, "ps pads its output"},
		{"/Applications/Xcode.app/Contents/MacOS/Xcode", true, "Xcode itself is the parent"},
		{"C:" + `\Tools\gdb.exe`, true, "a Windows image name loses its suffix"},

		// M26-TMP-002: an ordinary argument is not a debugger. Each of these
		// contains one of the names above and was reported as a debugger.
		{"current", false, "contains rr -- mutant cases/current/triage.mu stopped itself"},
		{"terraform", false, "contains rr"},
		{"error_handler", false, "contains rr"},
		{"arrow", false, "contains rr"},
		{"validate", false, "contains ida"},
		{"candidate", false, "contains ida"},
		{"nvidia-smi", false, "contains ida"},
		{"sh", false, "the wrapper a sweep runs its examples under"},
		{"sudo", false, "forensic users need it for raw devices"},
		{"bash", false, "the ordinary interactive parent"},

		// M26-TMP-019: a path is not a name.
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/make", false,
			"under Xcode.app, but make is not Xcode"},
		{"/Users/mew/samples/collect", false, "a path containing sample"},
		{"/opt/vmmaps/run", false, "a path containing vmmap"},

		// The acknowledged cost of exactness. gdbserver and a versioned gdb are
		// real things this no longer names -- and both set TracerPid once they
		// are actually tracing, which isTracingDetected reads and this does not.
		{"gdbserver", false, "a prefix is not a match; TracerPid catches it when attached"},
		{"gdb-12", false, "same, for a distribution's versioned build"},

		// Nothing to compare is not a match.
		{"", false, "nothing to compare"},
		{"   ", false, "whitespace only"},
		{"\x00", false, "an empty NUL-padded read"},
		{"/usr/bin/", false, "a path with no file at the end of it"},
	}

	for _, tc := range cases {
		if got := debuggerProcessNameMatches(tc.raw, debuggerNamesUnderTest); got != tc.want {
			t.Errorf("debuggerProcessNameMatches(%q) = %v, want %v -- %s",
				tc.raw, got, tc.want, tc.why)
		}
	}
}

// TestBothPlatformListsAreNamesAndNotPatterns holds the lists to what the
// matcher can now do with them. An entry with a path separator or a space in
// it can never equal a base name, so it would be an entry that matches
// nothing; and /proc/<pid>/comm is truncated by the kernel to fifteen
// characters, so a longer name cannot be matched on Linux however it is
// spelled.
//
// The list each platform uses is its own, because the tools differ: there is
// no vmmap on Linux and no rr on macOS.
func TestBothPlatformListsAreNamesAndNotPatterns(t *testing.T) {
	const linuxCommLimit = 15

	for _, entry := range linuxDebuggerProcessNames {
		if entry == "" {
			t.Error("the Linux list holds an empty entry")
		}
		if processBaseName(entry) != entry {
			t.Errorf("Linux entry %q is not a plain base name", entry)
		}
		if len(entry) > linuxCommLimit {
			t.Errorf("Linux entry %q is %d characters; /proc/<pid>/comm stops at %d",
				entry, len(entry), linuxCommLimit)
		}
	}

	for _, entry := range darwinDebuggerProcessNames {
		if entry == "" {
			t.Error("the macOS list holds an empty entry")
		}
		if processBaseName(entry) != entry {
			t.Errorf("macOS entry %q is not a plain base name", entry)
		}
	}
}
