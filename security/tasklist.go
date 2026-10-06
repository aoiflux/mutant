package security

import "strings"

// windowsImageNames reduces the output of tasklist /fo csv /nh to the set of
// image names it lists, lowercased.
//
// It is here rather than in sandbox_windows.go, and carries no build tag, so
// that reading the listing is covered by tests on any host. Only the Windows
// detector calls it, which is the same arrangement sandbox_cpuid.go and sutil.go
// already have in this package.
//
// The format is part of the contract. tasklist's default table truncates the
// image name at its column's 25 characters -- 13 of the 312 processes running on
// the machine this was written on have longer names than that -- and one of its
// rows is System Idle Process, whose name holds spaces, so neither a fixed
// column nor the first whitespace-delimited field reads the table reliably. The
// CSV form quotes the field and does not truncate it, and is already the form
// getWindowsParentProcessName asks for.
//
// A line with no quoted field is skipped, which is how the INFO: line tasklist
// prints in place of an empty listing comes to be ignored. The field is read
// without encoding/csv because a Windows image name cannot hold a quote, so it
// is simply what lies between the first two of them, and because a parser that
// can fail would need a way to carry on that cannot loop.
func windowsImageNames(csvOutput string) map[string]struct{} {
	names := map[string]struct{}{}
	for line := range strings.SplitSeq(csvOutput, "\n") {
		field, ok := firstQuotedField(line)
		if !ok {
			continue
		}
		if name := strings.ToLower(strings.TrimSpace(field)); name != "" {
			names[name] = struct{}{}
		}
	}
	return names
}

// firstQuotedField returns what lies between the first two quotes of a line.
func firstQuotedField(line string) (string, bool) {
	_, after, ok := strings.Cut(line, `"`)
	if !ok {
		return "", false
	}
	field, _, ok := strings.Cut(after, `"`)
	if !ok {
		return "", false
	}
	return field, true
}

// hasAnyImageName reports whether a process listing holds any of targets.
//
// targets are expected to be lowercase image names, and each is compared
// against a whole name from the listing rather than searched for inside the
// listing as a whole. That difference is the point. A process called
// notvmwp.exe is not vmwp.exe, and reading it as one told the detector this
// machine was a Hyper-V host, which switches every Hyper-V guest signal it has
// off; a process called myvmtoolsd.exe is not vmtoolsd.exe, and reading it as
// one halted the run. The same mistake on a parent process name was
// M26-TMP-003, and on the POSIX debugger lists it is M26-TMP-002 and
// M26-TMP-019, which are fixed separately and keep their own matcher because
// their entries are whole binary names where these are not.
func hasAnyImageName(names map[string]struct{}, targets []string) bool {
	for _, target := range targets {
		if _, ok := names[target]; ok {
			return true
		}
	}
	return false
}
