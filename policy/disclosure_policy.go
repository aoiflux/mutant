package policy

// The third machine-checked policy in this package: the code that handles
// classified plaintext does not render it into text.
//
// A classified record's plaintext passes through a handful of files: the ones
// that open a segment, read a span, issue a grant, bundle a disclosure or
// verify one. In those files there are exactly two ways a byte of plaintext
// becomes part of a log line, a manifest, an error message or a report
// without anybody meaning it to:
//
//   - Inspect. On a buffer it renders the entire contents as hex -- it has to,
//     because it is the identity function for equality (see
//     object/bytesObj.go) -- so an Inspect call on the wrong value is a
//     complete disclosure in a string.
//   - A format string that is not a constant. fmt.Sprintf(plaintext) is a
//     disclosure by construction, and so is newError(anything assembled at
//     run time), and a reviewer reading a call cannot tell which it is
//     without tracing where the string came from.
//
// TestDisclosureCodeNeverRendersPlaintext makes both absent from these files a
// fact the build checks. It is the static half of the enforcement; the runtime
// half is object.Bytes.Classified, checked at every builtin that sends a value
// out of the process (builtin/classified.go). Neither is a taint analysis, and
// docs/DISCLOSURE_POLICY.md says so.

// DisclosureFiles are the files that handle classified plaintext or the key
// material that opens it.
//
// A new file in the record, grant or disclosure families belongs on this list.
// As with EvidenceReadOnlyFiles, leaving one off is not caught by anything,
// which is why the list is a declaration in source.
var DisclosureFiles = []string{
	// the key schedule, the container and the grant
	"security/record_crypto.go",
	"security/record_file.go",
	"security/record_grant.go",
	// the case key and the classification scheme
	"builtin/case_key.go",
	"builtin/class.go",
	// sealing, opening and reading records, and what a read is marked with
	"builtin/record.go",
	"builtin/record_read.go",
	"builtin/classified.go",
	// views and disclosures
	"builtin/view.go",
	"builtin/disclose.go",
	"builtin/disclose_history.go",
	"builtin/disclose_ledger.go",
	"builtin/disclose_reclassify.go",
}

// DisclosureFormatFuncs are the calls whose format argument must be a constant
// in DisclosureFiles, and which argument that is. `newError` is the builtin
// package's own Sprintf-shaped error constructor.
var DisclosureFormatFuncs = map[string]int{
	"fmt.Sprintf": 0,
	"fmt.Printf":  0,
	"fmt.Errorf":  0,
	"fmt.Fprintf": 1,
	"fmt.Appendf": 1,
	"newError":    0,
}
