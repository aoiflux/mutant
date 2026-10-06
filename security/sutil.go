package security

import "strings"

// containsAny reports whether src holds any of targets as a substring, compared
// without case. targets are expected to be lowercase already.
//
// It is the match for searching a blob: a tasklist dump, the contents of a
// cgroup file. For a single name use equalsAny -- a substring search there
// matches far more than the list says.
func containsAny(src string, targets []string) bool {
	srclow := strings.ToLower(src)
	for _, target := range targets {
		if strings.Contains(srclow, target) {
			return true
		}
	}
	return false
}

// equalsAny reports whether src is exactly one of targets, compared without
// case. targets are expected to be lowercase already.
//
// It is the match for a single name -- a process image name, say. Using
// containsAny on one is how a parent process called notwsl.exe or gitbash.exe
// came to be scored as WSL at 90 points: both hold a name from the list without
// being one (M26-TMP-003).
func equalsAny(src string, targets []string) bool {
	srclow := strings.ToLower(src)
	for _, target := range targets {
		if srclow == target {
			return true
		}
	}
	return false
}
