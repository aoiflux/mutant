//go:build windows

package security

import (
	"fmt"
	"syscall"
)

// accountHomeDir returns the profile directory of the account whose token this
// process runs with: GetUserProfileDirectory looks it up by the token's SID in
// the registry's profile list, not in %USERPROFILE%.
func accountHomeDir() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open the process token: %w", err)
	}
	defer token.Close()

	dir, err := token.GetUserProfileDirectory()
	if err != nil {
		return "", fmt.Errorf("the account database has no profile directory for this process's account: %w", err)
	}
	return usableHomeDir("this process's account", dir)
}
