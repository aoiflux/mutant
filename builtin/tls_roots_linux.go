//go:build linux

package builtin

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// clientRootCAs is the certificate authorities an https request,
// net_tls_connect and net_tls_upgrade_client trust when the script names none:
// the system's, read the way crypto/x509 reads them with SSL_CERT_FILE and
// SSL_CERT_DIR unset. Left to crypto/x509, the store came from wherever those
// variables pointed, so whoever set the examiner's environment chose whom
// Mutant trusted (M26-NET-010). It is read once, when a client first needs it.
var clientRootCAs = sync.OnceValues(func() (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	loaded := false
	var firstErr error
	for _, file := range linuxCertFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			loaded = roots.AppendCertsFromPEM(data) || loaded
			break
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}
	for _, dir := range linuxCertDirectories {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, entry := range entries {
			if sameDirectorySymlink(dir, entry) {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(dir, entry.Name())); err == nil {
				loaded = roots.AppendCertsFromPEM(data) || loaded
			}
		}
	}
	if loaded || firstErr == nil {
		return roots, nil
	}
	return nil, fmt.Errorf("the system's certificate authorities could not be read: %w", firstErr)
})

// sameDirectorySymlink reports whether entry is a link to another file in dir,
// the hash-named links c_rehash makes, which crypto/x509 skips as well.
func sameDirectorySymlink(dir string, entry fs.DirEntry) bool {
	if entry.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, entry.Name()))
	return err == nil && !strings.Contains(target, "/")
}
