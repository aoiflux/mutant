//go:build darwin && !osusergo

package security

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// accountHomeDir asks the directory service, through libc's getpwuid_r, for the
// home directory of the uid this process runs as. On macOS os/user answers that
// way even without cgo and has no environment fallback (the fallback is Linux's,
// see account_home_passwd.go). Most accounts are not in /etc/passwd there, so
// the file cannot be read instead.
func accountHomeDir() (string, error) {
	uid := strconv.Itoa(os.Getuid())
	account, err := user.LookupId(uid)
	if err != nil {
		return "", fmt.Errorf("the account database has no entry for uid %s: %w", uid, err)
	}
	return usableHomeDir("uid "+uid, account.HomeDir)
}
