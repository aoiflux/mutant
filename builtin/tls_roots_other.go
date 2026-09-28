//go:build !linux

package builtin

import "crypto/x509"

// clientRootCAs is nil off Linux, which leaves verification to the platform:
// Windows and macOS check a certificate against their own store, and read no
// variable to find it.
func clientRootCAs() (*x509.CertPool, error) { return nil, nil }
