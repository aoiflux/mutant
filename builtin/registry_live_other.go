//go:build !windows

package builtin

import "fmt"

// openLiveRegistry is unavailable off Windows: there is no live registry to read.
// (Captured hive files still work everywhere via the regf backend.) Fails honestly.
func openLiveRegistry(_ string) (registryBackend, error) {
	return nil, fmt.Errorf("live registry access is only available on Windows (use a hive file instead)")
}
