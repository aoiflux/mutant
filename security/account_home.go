package security

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// usableHomeDir checks the home directory the account database gave for
// account. An empty or relative one would put the keystore under whatever
// directory Mutant happened to start in.
func usableHomeDir(account, dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("the account database records no home directory for %s", account)
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("the account database records a home directory for %s that is not absolute: %q", account, dir)
	}
	return filepath.Clean(dir), nil
}

// passwdHomeDir returns the home directory in uid's entry of an /etc/passwd
// file (name:password:uid:gid:gecos:home:shell), reading entries as os/user
// does: a blank line, a comment, an entry with fewer than seven fields, a
// non-numeric gid and a NIS inclusion (a name starting + or -) are not
// accounts.
func passwdHomeDir(passwd []byte, uid string) (string, bool) {
	for line := range strings.SplitSeq(string(passwd), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || strings.Count(line, ":") < 6 {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if fields[0] == "" || fields[0][0] == '+' || fields[0][0] == '-' || fields[2] != uid {
			continue
		}
		if _, err := strconv.Atoi(fields[3]); err != nil {
			continue
		}
		return fields[5], true
	}
	return "", false
}
