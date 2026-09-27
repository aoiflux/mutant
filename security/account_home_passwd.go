//go:build !windows && !(darwin && !osusergo)

package security

import (
	"fmt"
	"os"
	"strconv"
)

// passwdFile is the account database on the systems this file builds for.
const passwdFile = "/etc/passwd"

// accountHomeDir reads the home directory of the uid this process runs as from
// /etc/passwd.
//
// It reads the file itself because os/user would give the environment's answer.
// Built without cgo, as Mutant ships, user.Current answers for a uid missing
// from /etc/passwd -- an NSS, LDAP or container account -- with $HOME and
// $USER, and user.LookupId and user.Lookup return user.Current's answer
// whenever the uid or name is the caller's own. So an account the file does not
// list is refused.
func accountHomeDir() (string, error) {
	uid := strconv.Itoa(os.Getuid())
	passwd, err := os.ReadFile(passwdFile)
	if err != nil {
		return "", fmt.Errorf("read the account database: %w", err)
	}
	home, ok := passwdHomeDir(passwd, uid)
	if !ok {
		return "", fmt.Errorf("the account database (%s) has no entry for uid %s", passwdFile, uid)
	}
	return usableHomeDir("uid "+uid, home)
}
