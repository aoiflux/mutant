package builtin

// linuxCertFiles and linuxCertDirectories are where crypto/x509 reads the
// system's certificate authorities on Linux when neither SSL_CERT_FILE nor
// SSL_CERT_DIR is set (crypto/x509/root_linux.go): the first of the files that
// can be read, and every file in each directory. Mutant's TLS clients read the
// store from here themselves, because crypto/x509 reads it from wherever those
// two variables point when they are set (M26-NET-010).
// TestTheLinuxCertificateLocationsAreGos holds both lists to the toolchain's.
var (
	linuxCertFiles = []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		"/etc/pki/tls/cacert.pem",                           // OpenELEC
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
		"/etc/ssl/cert.pem",                                 // Alpine Linux
	}
	linuxCertDirectories = []string{
		"/etc/ssl/certs",     // SLES10/SLES11
		"/etc/pki/tls/certs", // Fedora/RHEL
	}
)
